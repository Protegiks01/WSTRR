### Title
Signer DoS via Unvalidated Signing Request Flooding from Coordinator

### Summary
The signer's `process()` function handles `NonceRequest` and `SignatureShareRequest` messages without validating round IDs or deduplicating requests, allowing a malicious or compromised coordinator to flood signers with valid messages that trigger expensive cryptographic operations. This can exhaust signer resources and prevent participation in legitimate signing rounds, causing transient consensus failures when multiple signers are targeted simultaneously.

### Finding Description

The vulnerability exists in the message handling logic within `src/state_machine/signer/mod.rs`. The `process()` function dispatches messages to specific handlers without any deduplication or round ID validation: [1](#0-0) 

Two critical handlers lack proper request validation:

**1. NonceRequest Handler (`nonce_request`):**
The function immediately generates fresh nonces for every request without checking if we've already responded to this `sign_id` or `sign_iter_id`: [2](#0-1) 

Nonce generation involves expensive operations including random number generation, SHA-256 hashing, and scalar multiplications: [3](#0-2) [4](#0-3) 

**2. SignatureShareRequest Handler (`sign_share_request`):**
This function performs even more expensive operations including signature share computation with multiple scalar and point operations, without any deduplication: [5](#0-4) [6](#0-5) 

**Root Cause:**
While the signer state tracks `sign_id` and `sign_iter_id` as part of its internal state: [7](#0-6) 

These fields are never validated against incoming requests in either handler. The protocol implements duplicate checking for DKG messages: [8](#0-7) [9](#0-8) 

But no such protection exists for signing-related messages.

**Why Existing Mitigations Fail:**
Packet signature verification authenticates the sender but doesn't prevent flooding by an authenticated coordinator: [10](#0-9) [11](#0-10) 

Each packet undergoes expensive ECDSA signature verification before processing, but there's no rate limiting or request tracking to prevent a flood of valid messages. The protocol assumes an honest coordinator but provides no defense against a compromised coordinator key.

### Impact Explanation

**Specific Harm:**
A compromised or malicious coordinator can send an unbounded stream of valid `NonceRequest` or `SignatureShareRequest` messages, each triggering:
- ECDSA signature verification (expensive elliptic curve operations)
- Nonce generation (RNG + 2×SHA256 + 2×scalar multiplications)  
- Signature share computation (multiple scalar operations, point operations, Lagrange coefficient calculations)

**Quantified Impact:**
- **Single Signer Target:** CPU exhaustion and resource starvation on one signer node, preventing it from processing legitimate requests
- **Multiple Signer Target:** If all or most signers are simultaneously flooded, the threshold cannot be met for any legitimate signing operation, preventing signature generation and transaction confirmation

**Affected Parties:**
All signers in the WSTS deployment are vulnerable to this attack when the coordinator's private key is compromised or the coordinator is malicious.

**Severity Justification:**
This maps to **Medium severity** ("Any transient consensus failures") because simultaneous DoS of multiple signers prevents the system from generating valid signatures, causing inability to confirm transactions until the attack ceases or signers recover. If the attack duration is brief and affects only some signers, it degrades to Low severity (DoS in individual nodes).

### Likelihood Explanation

**Required Attacker Capabilities:**
- Possession of the coordinator's ECDSA private key (through compromise, insider threat, or malicious coordinator deployment)
- Network access to send messages to signer nodes

**Attack Complexity:**
Low - once the coordinator key is obtained:
1. Craft `NonceRequest` messages with valid coordinator signatures
2. Send thousands of messages with varying or identical `sign_iter_id` values
3. Each message passes authentication and triggers expensive processing
4. Continue until signer resources are exhausted

**Economic Feasibility:**
Very feasible - the attack requires minimal resources on the attacker side (just network bandwidth to send messages) while forcing expensive cryptographic operations on victim signers.

**Detection Risk:**
Medium - all messages are validly signed by the coordinator, so standard authentication logs would not flag them as malicious. Detection requires monitoring for abnormal message volumes or duplicate round IDs, which is not currently implemented.

**Estimated Probability:**
- Coordinator key compromise: Medium likelihood (depends on operational security)
- Successful DoS once key is compromised: High (no mitigations in place)
- Overall: Medium to High for environments where coordinator security is not prioritized

### Recommendation

**Primary Fix - Add Request Deduplication:**
Track processed signing requests by `(dkg_id, sign_id, sign_iter_id)` tuple:

```rust
// Add to Signer state
pub struct Signer<SignerType: SignerTrait> {
    // ... existing fields ...
    /// Track processed signing requests to prevent duplicates
    processed_nonce_requests: HashSet<(u64, u64, u64)>, // (dkg_id, sign_id, sign_iter_id)
    processed_sign_requests: HashSet<(u64, u64, u64)>,
}

// In nonce_request():
fn nonce_request<R: RngCore + CryptoRng>(
    &mut self,
    nonce_request: &NonceRequest,
    rng: &mut R,
) -> Result<Vec<Message>, Error> {
    let request_id = (
        nonce_request.dkg_id,
        nonce_request.sign_id,
        nonce_request.sign_iter_id,
    );
    
    // Check if already processed
    if self.processed_nonce_requests.contains(&request_id) {
        debug!("Ignoring duplicate NonceRequest for {:?}", request_id);
        return Ok(vec![]);
    }
    
    // Process request...
    let result = // ... existing logic ...
    
    // Mark as processed
    self.processed_nonce_requests.insert(request_id);
    
    result
}
```

**Secondary Fix - Round ID Validation:**
Validate that incoming `sign_id`/`sign_iter_id` match expected progression:

```rust
// Reject requests with unexpected round IDs
if nonce_request.sign_id < self.sign_id {
    warn!("Rejecting NonceRequest with stale sign_id");
    return Ok(vec![]);
}
```

**Additional Protection - Rate Limiting:**
Implement per-coordinator rate limiting to cap message processing rate even for valid requests.

**Testing Recommendations:**
- Add unit tests for duplicate request rejection
- Add integration tests simulating coordinator message flooding
- Verify memory bounds of request tracking (consider LRU cache with size limits)

**Deployment Considerations:**
- The deduplication cache should be bounded (use LRU eviction) to prevent memory exhaustion
- Clear old entries when transitioning to new DKG rounds
- Consider logging duplicate request attempts for security monitoring

### Proof of Concept

**Exploitation Algorithm:**

```python
# Pseudocode for coordinator flooding attack

coordinator_private_key = obtain_compromised_key()
target_signers = get_all_signer_addresses()

# Generate valid NonceRequest messages
base_request = {
    "dkg_id": current_dkg_id,
    "sign_id": current_sign_id,
    "message": target_message,
    "signature_type": "Schnorr"
}

# Flood attack
for i in range(10000):  # Send 10k messages
    request = base_request.copy()
    request["sign_iter_id"] = i  # Different iteration IDs
    
    # Sign with coordinator key
    signature = ecdsa_sign(request, coordinator_private_key)
    packet = {"msg": request, "sig": signature}
    
    # Send to all signers
    for signer in target_signers:
        send_packet(signer, packet)
        
# Each signer will:
# 1. Verify ECDSA signature (expensive) - 10k times
# 2. Generate nonces (expensive) - 10k times  
# 3. Create responses - 10k times
# Result: CPU exhaustion, memory exhaustion, legitimate requests dropped
```

**Expected Behavior:**
Signers should reject duplicate requests or requests with unexpected round IDs.

**Actual Behavior:**
Signers process all 10,000 messages, performing expensive cryptographic operations for each, leading to resource exhaustion and inability to process legitimate signing requests.

**Reproduction Steps:**
1. Set up a WSTS deployment with coordinator and multiple signers
2. Obtain/generate coordinator private key
3. Send a rapid stream of `NonceRequest` messages with varying `sign_iter_id` values
4. Observe signer CPU usage spike to 100%
5. Attempt legitimate signing operation - it will fail or be severely delayed due to resource exhaustion

### Notes

This vulnerability is exacerbated by the protocol's trust assumption regarding the coordinator. While the protocol includes robust defenses against malicious signers (Byzantine fault tolerance), it provides no protection against a compromised coordinator beyond message authentication. The coordinator's private key is a critical single point of failure for availability attacks.

### Citations

**File:** src/state_machine/signer/mod.rs (L199-203)
```rust
    pub dkg_id: u64,
    /// current signing round ID
    pub sign_id: u64,
    /// current signing iteration ID
    pub sign_iter_id: u64,
```

**File:** src/state_machine/signer/mod.rs (L458-501)
```rust
    pub fn process<R: RngCore + CryptoRng>(
        &mut self,
        packet: &Packet,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        if self.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
        }
        let out_msgs = match &packet.msg {
            Message::DkgBegin(dkg_begin) => self.dkg_begin(dkg_begin, rng),
            Message::DkgPrivateBegin(dkg_private_begin) => {
                self.dkg_private_begin(dkg_private_begin, rng)
            }
            Message::DkgEndBegin(dkg_end_begin) => self.dkg_end_begin(dkg_end_begin),
            Message::DkgPublicShares(dkg_public_shares) => self.dkg_public_share(dkg_public_shares),
            Message::DkgPrivateShares(dkg_private_shares) => {
                self.dkg_private_shares(dkg_private_shares, rng)
            }
            Message::SignatureShareRequest(sign_share_request) => {
                self.sign_share_request(sign_share_request, rng)
            }
            Message::NonceRequest(nonce_request) => self.nonce_request(nonce_request, rng),
            Message::DkgEnd(_) | Message::NonceResponse(_) | Message::SignatureShareResponse(_) => {
                Ok(vec![])
            } // TODO
        };

        match out_msgs {
            Ok(mut out) => {
                if self.can_dkg_end() {
                    let dkg_end_msgs = self.dkg_ended(rng)?;
                    out.push(dkg_end_msgs);
                    self.move_to(State::Idle)?;
                }
                Ok(out)
            }
            Err(e) => Err(e),
        }
    }
```

**File:** src/state_machine/signer/mod.rs (L723-755)
```rust
    fn nonce_request<R: RngCore + CryptoRng>(
        &mut self,
        nonce_request: &NonceRequest,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let mut msgs = vec![];
        let signer_id = self.signer_id;
        let key_ids = self.signer.get_key_ids();
        let nonces = self.signer.gen_nonces(&self.network_private_key, rng);

        let response = NonceResponse {
            dkg_id: nonce_request.dkg_id,
            sign_id: nonce_request.sign_id,
            sign_iter_id: nonce_request.sign_iter_id,
            signer_id,
            key_ids,
            nonces,
            message: nonce_request.message.clone(),
        };

        let response = Message::NonceResponse(response);

        info!(
            %signer_id,
            dkg_id = %nonce_request.dkg_id,
            sign_id = %nonce_request.sign_id,
            sign_iter_id = %nonce_request.sign_iter_id,
            "sending NonceResponse"
        );
        msgs.push(response);

        Ok(msgs)
    }
```

**File:** src/state_machine/signer/mod.rs (L757-842)
```rust
    fn sign_share_request<R: RngCore + CryptoRng>(
        &mut self,
        sign_request: &SignatureShareRequest,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let signer_id_set = sign_request
            .nonce_responses
            .iter()
            .map(|nr| nr.signer_id)
            .collect::<BTreeSet<u32>>();

        // The expected usage is that Signer IDs start at zero and
        // increment by one until self.total_signers - 1. So the checks
        // here should be sufficient for catching empty signer ID sets,
        // duplicate signer IDs, or unknown signer IDs.
        let is_invalid_request = sign_request.nonce_responses.len() != signer_id_set.len()
            || signer_id_set.is_empty()
            || signer_id_set.last() >= Some(&self.total_signers);

        if is_invalid_request {
            warn!("received an invalid SignatureShareRequest");
            return Err(Error::InvalidNonceResponse);
        }

        let nonces = sign_request
            .nonce_responses
            .iter()
            .flat_map(|nr| nr.nonces.clone())
            .collect::<Vec<PublicNonce>>();

        for nonce in &nonces {
            if !nonce.is_valid() {
                warn!(
                    signer_id = %self.signer_id,
                    "received an SignatureShareRequest with invalid nonce"
                );
                return Err(Error::InvalidNonceResponse);
            }
        }

        debug!(signer_id = %self.signer_id, "received a valid SignatureShareRequest");

        if signer_id_set.contains(&self.signer_id) {
            let key_ids: Vec<u32> = sign_request
                .nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.iter().copied())
                .collect::<Vec<u32>>();

            let signer_ids = signer_id_set.into_iter().collect::<Vec<_>>();
            let msg = &sign_request.message;
            let signature_shares = match sign_request.signature_type {
                SignatureType::Taproot(merkle_root) => {
                    self.signer
                        .sign_taproot(msg, &signer_ids, &key_ids, &nonces, merkle_root)
                }
                SignatureType::Schnorr => {
                    self.signer
                        .sign_schnorr(msg, &signer_ids, &key_ids, &nonces)
                }
                SignatureType::Frost => self.signer.sign(msg, &signer_ids, &key_ids, &nonces),
            };

            self.signer.gen_nonces(&self.network_private_key, rng);

            let response = SignatureShareResponse {
                dkg_id: sign_request.dkg_id,
                sign_id: sign_request.sign_id,
                sign_iter_id: sign_request.sign_iter_id,
                signer_id: self.signer_id,
                signature_shares,
            };
            info!(
                signer_id = %self.signer_id,
                dkg_id = %sign_request.dkg_id,
                sign_id = %sign_request.sign_id,
                sign_iter_id = %sign_request.sign_iter_id,
                "sending SignatureShareResponse"
            );

            Ok(vec![Message::SignatureShareResponse(response)])
        } else {
            debug!(signer_id = %self.signer_id, "signer not included in SignatureShareRequest");
            Ok(Vec::new())
        }
    }
```

**File:** src/state_machine/signer/mod.rs (L1004-1011)
```rust
        let have_shares = self
            .dkg_public_shares
            .contains_key(&dkg_public_shares.signer_id);

        if have_shares {
            info!(signer_id = %dkg_public_shares.signer_id, "received duplicate DkgPublicShares");
            return Ok(vec![]);
        }
```

**File:** src/state_machine/signer/mod.rs (L1058-1061)
```rust
        if self.dkg_private_shares.contains_key(&src_signer_id) {
            info!(signer_id = %dkg_private_shares.signer_id, "received duplicate DkgPrivateShares");
            return Ok(vec![]);
        }
```

**File:** src/common.rs (L69-88)
```rust
    pub fn random<RNG: RngCore + CryptoRng>(secret_key: &Scalar, rng: &mut RNG) -> Self {
        Self {
            d: Self::gen(secret_key, rng),
            e: Self::gen(secret_key, rng),
        }
    }

    /// Use the IETF nonce generation function from section 4.1 of
    ///   https://datatracker.ietf.org/doc/rfc9591
    fn gen<RNG: RngCore + CryptoRng>(secret_key: &Scalar, rng: &mut RNG) -> Scalar {
        let mut bytes: [u8; 32] = [0; 32];
        rng.fill_bytes(&mut bytes);

        let mut hasher = Sha256::new();

        hasher.update(bytes);
        hasher.update(secret_key.to_bytes());

        hash_to_scalar(&mut hasher)
    }
```

**File:** src/v2.rs (L77-84)
```rust
    pub fn gen_nonce<RNG: RngCore + CryptoRng>(
        &mut self,
        secret_key: &Scalar,
        rng: &mut RNG,
    ) -> PublicNonce {
        self.nonce = Nonce::random(secret_key, rng);
        PublicNonce::from(&self.nonce)
    }
```

**File:** src/v2.rs (L225-276)
```rust
    pub fn sign_with_tweak(
        &self,
        msg: &[u8],
        party_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        tweak: Option<Scalar>,
    ) -> SignatureShare {
        // When using BIP-340 32-byte public keys, we have to invert the private key if the
        // public key is odd.  But if we're also using BIP-341 tweaked keys, we have to do
        // the same thing if the tweaked public key is odd.  In that case, only invert the
        // public key if exactly one of the internal or tweaked public keys is odd
        let mut cx_sign = Scalar::one();
        let tweaked_public_key = if let Some(t) = tweak {
            if t != Scalar::zero() {
                let key = compute::tweaked_public_key_from_tweak(&self.group_key, t);
                if key.has_even_y() ^ self.group_key.has_even_y() {
                    cx_sign = -cx_sign;
                }

                key
            } else {
                if !self.group_key.has_even_y() {
                    cx_sign = -cx_sign;
                }
                self.group_key
            }
        } else {
            self.group_key
        };
        let (_, R) = compute::intermediate(msg, party_ids, nonces);
        let c = compute::challenge(&tweaked_public_key, &R, msg);
        let mut r = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        if tweak.is_some() && !R.has_even_y() {
            r = -r;
        }

        let mut cx = Scalar::zero();
        for key_id in self.key_ids.iter() {
            cx += c * &self.private_keys[key_id] * compute::lambda(*key_id, key_ids);
        }

        cx = cx_sign * cx;

        let z = r + cx;

        SignatureShare {
            id: self.party_id,
            z_i: z,
            key_ids: self.key_ids.clone(),
        }
    }
```

**File:** src/net.rs (L485-601)
```rust
impl Packet {
    /// This function verifies the packet's signature, returning true if the signature is valid,
    /// i.e. is appropriately signed by either the provided coordinator or one of the provided signer public keys
    pub fn verify(
        &self,
        signers_public_keys: &PublicKeys,
        coordinator_public_key: &ecdsa::PublicKey,
    ) -> bool {
        match &self.msg {
            Message::DkgBegin(msg) => {
                if !msg.verify(&self.sig, coordinator_public_key) {
                    warn!("Received a DkgBegin message with an invalid signature.");
                    return false;
                }
            }
            Message::DkgPrivateBegin(msg) => {
                if !msg.verify(&self.sig, coordinator_public_key) {
                    warn!("Received a DkgPrivateBegin message with an invalid signature.");
                    return false;
                }
            }
            Message::DkgEndBegin(msg) => {
                if !msg.verify(&self.sig, coordinator_public_key) {
                    warn!("Received a DkgEndBegin message with an invalid signature.");
                    return false;
                }
            }
            Message::DkgEnd(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a DkgPublicEnd message with an invalid signature.");
                        return false;
                    }
                } else {
                    warn!(
                        "Received a DkgPublicEnd message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
            Message::DkgPublicShares(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a DkgPublicShares message with an invalid signature.");
                        return false;
                    }
                } else {
                    warn!(
                        "Received a DkgPublicShares message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
            Message::DkgPrivateShares(msg) => {
                // Private shares have key IDs from [0, N) to reference IDs from [1, N]
                // in Frost V4 to enable easy indexing hence ID + 1
                // TODO: Once Frost V5 is released, this off by one adjustment will no longer be required
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a DkgPrivateShares message with an invalid signature from signer_id {} key {}", msg.signer_id, &public_key);
                        return false;
                    }
                } else {
                    warn!(
                        "Received a DkgPrivateShares message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
            Message::NonceRequest(msg) => {
                if !msg.verify(&self.sig, coordinator_public_key) {
                    warn!("Received a NonceRequest message with an invalid signature.");
                    return false;
                }
            }
            Message::NonceResponse(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a NonceResponse message with an invalid signature.");
                        return false;
                    }
                } else {
                    warn!(
                        "Received a NonceResponse message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
            Message::SignatureShareRequest(msg) => {
                if !msg.verify(&self.sig, coordinator_public_key) {
                    warn!("Received a SignatureShareRequest message with an invalid signature.");
                    return false;
                }
            }
            Message::SignatureShareResponse(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!(
                            "Received a SignatureShareResponse message with an invalid signature."
                        );
                        return false;
                    }
                } else {
                    warn!(
                        "Received a SignatureShareResponse message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
        }
        true
    }
```
