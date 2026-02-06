### Title
Missing DKG ID Verification in Signature Share Generation Allows Cross-Round Key Usage

### Summary
The `sign_share_request()` function does not verify that the incoming `sign_request.dkg_id` matches the signer's current `self.dkg_id` before generating signature shares. This allows a malicious coordinator to trick signers into producing signature shares using keys from one DKG round while claiming they are from a different DKG round, violating the critical state machine invariant that "Round IDs (dkg_id, sign_id, sign_iter_id) must match expected values."

### Finding Description

**Exact Code Location:** [1](#0-0) 

The `sign_share_request()` function processes `SignatureShareRequest` messages from the coordinator without validating that `sign_request.dkg_id` matches `self.dkg_id`. The function performs several validation checks (lines 772-794) for signer IDs, duplicate detection, and nonce validity, but completely omits DKG ID validation. [2](#0-1) 

The function blindly echoes the coordinator's `dkg_id` back in the response (line 823) without verifying it corresponds to the keys being used for signing.

**Root Cause:**
The signer maintains private keys derived from a specific DKG round, stored in `self.signer.private_keys`. When a new DKG round begins, the `reset()` function updates `self.dkg_id` but does NOT clear the existing private keys: [3](#0-2) 

Keys are only replaced when `compute_secrets()` successfully completes a DKG round: [4](#0-3) 

This creates a window where `self.dkg_id` and the actual keys in `self.signer.private_keys` are from different DKG rounds. The `sign_share_request()` function uses `self.signer` to generate signature shares (lines 810-817) without validating that the requested `dkg_id` matches the round from which these keys originated.

**Why Existing Mitigations Fail:**
The coordinator validates `dkg_id` when receiving responses: [5](#0-4) 

However, this only ensures the response matches what the coordinator requested. It does NOT prevent the coordinator from requesting an incorrect `dkg_id` in the first place, nor does it validate that signers are using the correct keys for that `dkg_id`.

### Impact Explanation

**Specific Harm:**
A malicious or compromised coordinator can force signers to generate signature shares using keys from one DKG round while claiming they are from a different round. This enables several attacks:

1. **Key Rotation Bypass**: If DKG round 1 keys are compromised and a new DKG round 2 is initiated but fails or remains incomplete, signers will have `self.dkg_id=2` but still possess old keys from round 1. A malicious coordinator can send `SignatureShareRequest` with `dkg_id=1`, causing signers to use the compromised keys even though they believe they've moved to a new round.

2. **State Machine Invariant Violation**: The protocol explicitly requires "Round IDs (dkg_id, sign_id, sign_iter_id) must match expected values" as a critical state machine invariant. This vulnerability directly violates that invariant.

3. **Cross-Round Confusion**: Different signers may complete DKG rounds at different times. A coordinator can exploit this to mix keys from different rounds, creating signatures that are inconsistent or invalid.

4. **Auditability Breakdown**: Signatures are labeled with one `dkg_id` but created using keys from a different round, making it impossible to audit which keys were actually used.

**Severity: Medium to High**
- Maps to **Medium: "Any transient consensus failures"** if the cross-round key usage creates invalid signatures that fail verification, blocking consensus
- Maps to **High: "Any unintended chain split"** if some nodes accept signatures created with mismatched keys while others reject them, or if the key rotation bypass allows continued use of compromised keys

**Who is Affected:**
All signers in the WSTS protocol, and any dependent systems (Stacks blockchain) that rely on proper DKG round separation and key rotation mechanisms.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Compromised coordinator with ability to send malicious `SignatureShareRequest` messages
- OR malicious coordinator from the start of operations

**Attack Prerequisites:**
1. At least one DKG round has completed, giving signers a set of keys
2. A new DKG round has been initiated via `reset()` but has not completed (i.e., `compute_secrets()` has not been called)
3. Coordinator sends `SignatureShareRequest` with `dkg_id` not matching signer's current `self.dkg_id`

**Attack Complexity: Low**
The coordinator simply needs to construct a `SignatureShareRequest` message: [6](#0-5) 

And set the `dkg_id` field to any value. Signers will accept it and generate shares using their current keys.

**Economic Feasibility: High**
No special resources required beyond compromising the coordinator role.

**Detection Risk: Low**
Difficult to detect without external monitoring comparing expected vs. actual `dkg_id` values. Signers log the `dkg_id` but don't validate it, so no warnings are generated.

**Probability of Success: High**
The vulnerability is deterministic - if the prerequisites are met, the attack succeeds 100% of the time.

### Recommendation

**Immediate Fix:**
Add validation in `sign_share_request()` to verify that the incoming `dkg_id` matches the signer's current round:

```rust
fn sign_share_request<R: RngCore + CryptoRng>(
    &mut self,
    sign_request: &SignatureShareRequest,
    rng: &mut R,
) -> Result<Vec<Message>, Error> {
    // Add this check immediately after function entry
    if sign_request.dkg_id != self.dkg_id {
        warn!(
            signer_id = %self.signer_id,
            request_dkg_id = %sign_request.dkg_id,
            current_dkg_id = %self.dkg_id,
            "rejecting SignatureShareRequest with mismatched dkg_id"
        );
        return Err(Error::BadDkgId(sign_request.dkg_id, self.dkg_id));
    }
    
    // ... rest of existing validation
```

Where `Error::BadDkgId` should be added to the `Error` enum if it doesn't exist.

**Alternative Mitigation:**
Add a state machine check to prevent signing operations during DKG phases. Signers should only accept `SignatureShareRequest` when in `State::Idle` with completed DKG.

**Testing Recommendations:**
1. Add unit test where DKG round 2 is started but not completed, then send `SignatureShareRequest` with `dkg_id=1` - should be rejected
2. Add integration test simulating key rotation scenario where coordinator attempts to use old `dkg_id` after new round begins
3. Verify that legitimate signing requests with matching `dkg_id` continue to work

**Deployment Considerations:**
This is a protocol-level change that must be deployed to all signers simultaneously. Ensure coordinator implementations are updated to handle the new error case gracefully.

### Proof of Concept

**Attack Algorithm:**
1. Complete DKG round 1 successfully
   - All signers have `self.dkg_id = 1` and `private_keys` from round 1

2. Coordinator initiates DKG round 2 by sending `DkgBegin` with `dkg_id = 2`
   - Signers call `reset(2, rng)` which sets `self.dkg_id = 2`
   - Keys from round 1 remain in `self.signer.private_keys` per [7](#0-6) 

3. Before DKG round 2 completes, coordinator sends `SignatureShareRequest`:
   ```rust
   SignatureShareRequest {
       dkg_id: 1,  // Wrong DKG ID!
       sign_id: 100,
       sign_iter_id: 1,
       nonce_responses: [/* valid nonces */],
       message: b"malicious transaction",
       signature_type: SignatureType::Schnorr,
   }
   ```

4. Signer processes request in `sign_share_request()`:
   - No check that `request.dkg_id (1) != self.dkg_id (2)`
   - Generates signature shares using keys from round 1
   - Returns response with `dkg_id: 1`

5. Coordinator aggregates signature shares
   - All shares claim `dkg_id = 1`
   - But signers believed they were in round 2
   - Keys from round 1 are used despite being potentially compromised

**Expected Behavior:**
Signer should reject the request with an error indicating DKG ID mismatch.

**Actual Behavior:**
Signer accepts the request and generates signature shares using keys from a different DKG round than indicated by its current state.

### Notes

The same validation gap exists in the `nonce_request()` function, where the signer similarly does not validate that `nonce_request.dkg_id` matches `self.dkg_id`: [8](#0-7) 

However, nonce generation doesn't directly use the private keys, so the impact is less severe. The coordinator still validates `dkg_id` in nonce responses: [9](#0-8) 

The signature share vulnerability is more critical because it allows actual signing operations with mismatched DKG rounds, directly compromising the protocol's key isolation guarantees.

### Citations

**File:** src/state_machine/signer/mod.rs (L417-432)
```rust
    pub fn reset<T: RngCore + CryptoRng>(&mut self, dkg_id: u64, rng: &mut T) {
        self.dkg_id = dkg_id;
        self.commitments.clear();
        self.decrypted_shares.clear();
        self.decryption_keys.clear();
        self.invalid_private_shares.clear();
        self.public_nonces.clear();
        self.signer.reset_polys(rng);
        self.dkg_public_shares.clear();
        self.dkg_private_shares.clear();
        self.dkg_private_begin_msg = None;
        self.dkg_end_begin_msg = None;
        self.kex_private_key = Scalar::random(rng);
        self.kex_public_keys.clear();
        self.state = State::Idle;
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

**File:** src/v2.rs (L123-130)
```rust
    pub fn compute_secret(
        &mut self,
        private_shares: &HashMap<u32, HashMap<u32, Scalar>>,
        public_shares: &HashMap<u32, PolyCommitment>,
        ctx: &[u8],
    ) -> Result<(), DkgError> {
        self.private_keys.clear();
        self.group_key = Point::zero();
```

**File:** src/state_machine/coordinator/fire.rs (L850-852)
```rust
            if nonce_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    nonce_response.sign_id,
```

**File:** src/state_machine/coordinator/fire.rs (L1027-1032)
```rust
        if sig_share_response.dkg_id != self.current_dkg_id {
            return Err(Error::BadDkgId(
                sig_share_response.dkg_id,
                self.current_dkg_id,
            ));
        }
```

**File:** src/net.rs (L381-396)
```rust
#[derive(Clone, Serialize, Deserialize, PartialEq)]
/// Signature share request message from coordinator to signers
pub struct SignatureShareRequest {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Nonces responses used for this signature
    pub nonce_responses: Vec<NonceResponse>,
    /// Bytes to sign
    pub message: Vec<u8>,
    /// What type of signature to create
    pub signature_type: SignatureType,
}
```
