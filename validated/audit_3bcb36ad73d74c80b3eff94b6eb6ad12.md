# Audit Report

## Title
Missing sign_iter_id Validation in SignatureShareResponse Allows Cross-Iteration Signature Share Replay

## Summary
The FIRE coordinator validates `sign_iter_id` in `NonceResponse` messages but fails to validate it in `SignatureShareResponse` messages. When signature share gathering times out and retries with a new iteration, delayed signature shares from previous iterations can be accepted and aggregated with nonces from the current iteration, causing signature verification to fail and falsely identifying honest signers as malicious.

## Finding Description

The vulnerability exists in the FIRE coordinator's message validation logic, which shows a critical inconsistency between how `NonceResponse` and `SignatureShareResponse` messages are validated.

**NonceResponse Validation (Correct):**
The coordinator properly validates `sign_iter_id` when processing nonce responses, rejecting messages from previous iterations: [1](#0-0) 

**SignatureShareResponse Validation (Missing):**
The coordinator validates `dkg_id` and `sign_id` but completely omits `sign_iter_id` validation when processing signature share responses: [2](#0-1) 

**Retry Mechanism:**
When signature share gathering times out, the coordinator marks waiting signers as malicious and calls `request_nonces()` to retry: [3](#0-2) 

**Critical Vulnerability Flow:**
The `request_nonces()` method clears the entire `message_nonces` map and increments `sign_iter_id`: [4](#0-3) 

This clearing operation means:
1. Old nonces from iteration N are discarded
2. New nonces from iteration N+1 populate `message_nonces`
3. The `sign_wait_signer_ids` set is repopulated with signers from iteration N+1

When a delayed `SignatureShareResponse` from iteration N arrives during iteration N+1:
- The wait list check passes if the signer participated in both iterations: [5](#0-4) 
- Without `sign_iter_id` validation, the old signature share is accepted and stored: [6](#0-5) 
- The coordinator aggregates signature shares from iteration N with nonces from iteration N+1: [7](#0-6) 

**Signature Verification Failure:**
When signature shares computed with nonces from iteration N are aggregated with nonces from iteration N+1, signature verification fails. The aggregator then calls `check_signature_shares()` which verifies each share individually: [8](#0-7) 

The verification logic detects that the signature share is invalid and adds the honest signer to the bad parties list: [9](#0-8) 

**Hash Function Inconsistency:**
The vulnerability is compounded by the fact that `SignatureShareResponse` has a `sign_iter_id` field: [10](#0-9) 

But does not include `sign_iter_id` in its hash function: [11](#0-10) 

Unlike `NonceResponse` which properly includes it: [12](#0-11) 

## Impact Explanation

This vulnerability causes **transient consensus failures** (Medium severity):

1. **False Malicious Accusations:** Honest signers who experience network delays have their signature shares from previous iterations accepted in current iterations, causing verification to fail and falsely identifying them as malicious.

2. **Signing Round Failures:** When mismatched nonces cause signature verification to fail, the entire signing round fails even though all participants were honest.

3. **Potential Denial of Service:** If applications mark parties identified by `BadPartySigs` errors as permanently malicious, enough false accusations could prevent reaching the signing threshold in future rounds, causing a denial of service condition.

4. **Protocol Disruption:** Each failure requires additional retry attempts, which carry further risk of false accusations, potentially creating a cascading failure scenario.

The impact aligns with the Medium severity definition: "Any transient consensus failures" - the vulnerability causes signing operations to fail incorrectly and honest participants to be falsely identified as malicious, disrupting the threshold signature protocol without directly causing fund loss or permanent network shutdown.

## Likelihood Explanation

**Probability: High**

This vulnerability occurs naturally through normal network conditions without any active attacker:

1. **Natural Triggering:** Any network delay that causes a `SignatureShareResponse` to arrive after the coordinator's timeout threshold will trigger this vulnerability.

2. **Zero Attack Cost:** No special capabilities, cryptographic breaks, or privileged access required.

3. **Inevitable Occurrence:** In any deployment with variable network latency and configured timeouts, messages will eventually arrive late, making this vulnerability certain to manifest.

4. **Indistinguishable from Legitimate Errors:** The resulting `BadPartySigs` errors appear identical to actual malicious behavior, making the vulnerability difficult to detect and diagnose.

The coordinator's timeout and retry mechanism is a core feature of the FIRE protocol for handling transient failures, meaning this vulnerability is in a frequently-exercised code path.

## Recommendation

Add `sign_iter_id` validation in the `gather_sig_shares()` method, matching the validation performed for `NonceResponse`:

```rust
if sig_share_response.sign_iter_id != self.current_sign_iter_id {
    return Err(Error::BadSignIterId(
        sig_share_response.sign_iter_id,
        self.current_sign_iter_id,
    ));
}
```

This check should be added after the `sign_id` validation and before the wait list check in `gather_sig_shares()`.

Additionally, include `sign_iter_id` in the `SignatureShareResponse` hash function to maintain consistency with `NonceResponse`:

```rust
impl Signable for SignatureShareResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("SIGNATURE_SHARE_RESPONSE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.sign_iter_id.to_be_bytes()); // ADD THIS LINE
        hasher.update(self.signer_id.to_be_bytes());
        // ... rest of hash function
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_cross_iteration_signature_share_replay() {
    use crate::state_machine::coordinator::fire::FireCoordinator;
    use crate::v2;
    
    let mut rng = rand::thread_rng();
    let config = Config::new(3, 10, 7, Scalar::random(&mut rng));
    let mut coordinator = FireCoordinator::<v2::Aggregator>::new(config);
    
    // Setup: Complete DKG and start signing round
    coordinator.state = State::SigShareGather(SignatureType::Frost);
    coordinator.current_sign_iter_id = 0;
    coordinator.current_sign_id = 0;
    coordinator.current_dkg_id = 0;
    
    // Create message_nonces entry for iteration 0
    let message = vec![0u8; 32];
    coordinator.message = message.clone();
    let mut response_info = SignRoundInfo::default();
    response_info.sign_wait_signer_ids.insert(0);
    coordinator.message_nonces.insert(message.clone(), response_info);
    
    // Create old signature share from iteration 0
    let old_sig_share = SignatureShareResponse {
        dkg_id: 0,
        sign_id: 0,
        sign_iter_id: 0, // Old iteration
        signer_id: 0,
        signature_shares: vec![SignatureShare {
            id: 0,
            z_i: Scalar::random(&mut rng),
            key_ids: vec![1],
        }],
    };
    
    // Simulate timeout and retry - this increments sign_iter_id to 1
    coordinator.request_nonces(SignatureType::Frost).unwrap();
    assert_eq!(coordinator.current_sign_iter_id, 1);
    
    // Repopulate message_nonces with iteration 1 data
    let mut response_info = SignRoundInfo::default();
    response_info.sign_wait_signer_ids.insert(0);
    coordinator.message_nonces.insert(message.clone(), response_info);
    coordinator.state = State::SigShareGather(SignatureType::Frost);
    
    // Now deliver the OLD signature share from iteration 0
    let packet = Packet {
        msg: Message::SignatureShareResponse(old_sig_share),
        sig: vec![],
    };
    
    // BUG: This should fail with BadSignIterId but instead succeeds
    let result = coordinator.gather_sig_shares(&packet, SignatureType::Frost);
    
    // The old signature share is incorrectly accepted
    assert!(result.is_ok());
    assert_eq!(coordinator.signature_shares.len(), 1);
    
    // This demonstrates the vulnerability: signature shares from iteration 0
    // are mixed with nonces from iteration 1, which will cause signature
    // verification to fail and falsely identify the honest signer as malicious.
}
```

### Citations

**File:** src/state_machine/coordinator/fire.rs (L173-208)
```rust
            State::SigShareGather(signature_type) => {
                if let Some(start) = self.sign_start {
                    if let Some(timeout) = self.config.sign_timeout {
                        if now.duration_since(start) > timeout {
                            warn!("Timeout gathering signature shares for signing round {} iteration {}", self.current_sign_id, self.current_sign_iter_id);
                            for signer_id in &self
                                .message_nonces
                                .get(&self.message)
                                .ok_or(Error::MissingMessageNonceInfo)?
                                .sign_wait_signer_ids
                            {
                                warn!("Mark signer {signer_id} as malicious");
                                self.malicious_signer_ids.insert(*signer_id);
                            }

                            let num_malicious_keys: u32 =
                                self.compute_num_key_ids(self.malicious_signer_ids.iter())?;

                            if self.config.num_keys - num_malicious_keys < self.config.threshold {
                                error!("Insufficient non-malicious signers, unable to continue");
                                let mal = self.malicious_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::SignError(
                                        SignError::InsufficientSigners(mal),
                                    )),
                                ));
                            }

                            self.move_to(State::NonceRequest(signature_type))?;
                            let packet = self.request_nonces(signature_type)?;
                            return Ok((Some(packet), None));
                        }
                    }
                }
            }
```

**File:** src/state_machine/coordinator/fire.rs (L814-839)
```rust
    fn request_nonces(&mut self, signature_type: SignatureType) -> Result<Packet, Error> {
        self.message_nonces.clear();
        self.current_sign_iter_id = self.current_sign_iter_id.wrapping_add(1);
        info!(
            sign_id = %self.current_sign_id,
            sign_iter_id = %self.current_sign_iter_id,
            "Requesting Nonces"
        );
        let nonce_request = NonceRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            message: self.message.clone(),
            signature_type,
        };
        let nonce_request_msg = Packet {
            sig: nonce_request
                .sign(&self.config.message_private_key)
                .expect("Failed to sign NonceRequest"),
            msg: Message::NonceRequest(nonce_request),
        };
        self.move_to(State::NonceGather(signature_type))?;
        self.nonce_start = Some(Instant::now());

        Ok(nonce_request_msg)
    }
```

**File:** src/state_machine/coordinator/fire.rs (L856-860)
```rust
            if nonce_response.sign_iter_id != self.current_sign_iter_id {
                return Err(Error::BadSignIterId(
                    nonce_response.sign_iter_id,
                    self.current_sign_iter_id,
                ));
```

**File:** src/state_machine/coordinator/fire.rs (L1015-1025)
```rust
        let waiting = response_info
            .sign_wait_signer_ids
            .contains(&sig_share_response.signer_id);

        if !waiting {
            warn!(
                "Sign round {} SignatureShareResponse for round {} from signer {} not in the wait list",
                self.current_sign_id, sig_share_response.sign_id, sig_share_response.signer_id,
            );
            return Ok(());
        }
```

**File:** src/state_machine/coordinator/fire.rs (L1027-1038)
```rust
        if sig_share_response.dkg_id != self.current_dkg_id {
            return Err(Error::BadDkgId(
                sig_share_response.dkg_id,
                self.current_dkg_id,
            ));
        }
        if sig_share_response.sign_id != self.current_sign_id {
            return Err(Error::BadSignId(
                sig_share_response.sign_id,
                self.current_sign_id,
            ));
        }
```

**File:** src/state_machine/coordinator/fire.rs (L1088-1091)
```rust
        self.signature_shares.insert(
            sig_share_response.signer_id,
            sig_share_response.signature_shares.clone(),
        );
```

**File:** src/state_machine/coordinator/fire.rs (L1115-1169)
```rust
            let nonce_responses = message_nonce
                .public_nonces
                .values()
                .cloned()
                .collect::<Vec<NonceResponse>>();

            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();

            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();

            let shares = message_nonce
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();

            debug!(
                "aggregator.sign({}, {:?}, {:?}, {})",
                bs58::encode(&self.message).into_string(),
                nonces.len(),
                shares.len(),
                self.party_polynomials.len(),
            );

            self.aggregator.init(&self.party_polynomials)?;

            if let SignatureType::Taproot(merkle_root) = signature_type {
                let schnorr_proof = self.aggregator.sign_taproot(
                    &self.message,
                    &nonces,
                    &shares,
                    &key_ids,
                    merkle_root,
                )?;
                debug!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else if let SignatureType::Schnorr = signature_type {
                let schnorr_proof =
                    self.aggregator
                        .sign_schnorr(&self.message, &nonces, &shares, &key_ids)?;
                debug!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else {
                let signature = self
                    .aggregator
                    .sign(&self.message, &nonces, &shares, &key_ids)?;
                debug!("Signature ({}, {})", signature.R, signature.z);
                self.signature = Some(signature);
            }
```

**File:** src/v2.rs (L406-413)
```rust
            if z_i * G != (r_sign * Rs[i] + cx_sign * cx) {
                bad_party_sigs.push(sig_shares[i].id);
            }
        }
        if !bad_party_keys.is_empty() {
            AggregatorError::BadPartyKeys(bad_party_keys)
        } else if !bad_party_sigs.is_empty() {
            AggregatorError::BadPartySigs(bad_party_sigs)
```

**File:** src/v2.rs (L457-461)
```rust
        if sig.verify(&key, msg) {
            Ok(sig)
        } else {
            Err(self.check_signature_shares(msg, nonces, sig_shares, key_ids, None))
        }
```

**File:** src/net.rs (L349-367)
```rust
impl Signable for NonceResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("NONCE_RESPONSE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.sign_iter_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());

        for key_id in &self.key_ids {
            hasher.update(key_id.to_be_bytes());
        }

        for nonce in &self.nonces {
            hasher.update(nonce.D.compress().as_bytes());
            hasher.update(nonce.E.compress().as_bytes());
        }

        hasher.update(self.message.as_slice());
    }
```

**File:** src/net.rs (L435-448)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// Signature share response message from signers to coordinator
pub struct SignatureShareResponse {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// Signature shares from this Signer
    pub signature_shares: Vec<SignatureShare>,
}
```

**File:** src/net.rs (L450-464)
```rust
impl Signable for SignatureShareResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("SIGNATURE_SHARE_RESPONSE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());

        for signature_share in &self.signature_shares {
            hasher.update(signature_share.id.to_be_bytes());
            hasher.update(signature_share.z_i.to_bytes());
            for key_id in &signature_share.key_ids {
                hasher.update(key_id.to_be_bytes());
            }
        }
    }
```
