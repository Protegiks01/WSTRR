# Audit Report

## Title
Nonce Count Validation Bypass Enables Denial of Service in Signature Aggregation

## Summary
The FIRE and FROST coordinator state machines fail to validate that the number of nonces in a `NonceResponse` matches the protocol-specific expected count. This allows a single malicious signer to send malformed nonce responses that pass initial validation but cause aggregation failures, enabling indefinite denial of service without detection or attribution.

## Finding Description

Both FIRE and FROST coordinators validate individual nonce validity and key_ids set membership but do not enforce protocol-specific nonce count requirements during the `gather_nonces` phase.

In FIRE's `gather_nonces`, the coordinator performs the following validations:
- DKG/sign ID matching [1](#0-0) 
- Signer existence in configuration [2](#0-1) 
- Key_ids set equality with configuration [3](#0-2) 
- Individual nonce validity via `is_valid()` [4](#0-3) 

**Critically missing**: No validation that `nonces.len()` matches the expected count.

For v2 protocol, each signer must generate exactly 1 nonce regardless of key count [5](#0-4) , while v1 generates one nonce per key [6](#0-5) .

During signature aggregation, the coordinator flattens all nonces across signers [7](#0-6)  and passes them to the aggregator. The aggregator strictly validates `nonces.len() == sig_shares.len()` [8](#0-7) , returning a `BadNonceLen` error on mismatch.

**Attack scenario (v2 with threshold=2, 3 signers)**:
1. Malicious signer B sends NonceResponse with 0 nonces instead of 1
2. Coordinator accepts it (only validates each nonce individually, not count)
3. Honest signer A sends 1 nonce (correct)
4. Total flattened nonces = 1
5. Both signers generate 1 signature share each [9](#0-8)  (total = 2)
6. Aggregator receives nonces.len()=1, sig_shares.len()=2
7. Aggregation fails with `BadNonceLen(1, 2)`
8. Error does not identify which signer sent wrong count [10](#0-9) 

The identical vulnerability exists in FROST coordinator [11](#0-10) .

Existing mitigations fail because:
- Duplicate detection only prevents multiple responses from same signer [12](#0-11) 
- Key_ids validation checks set equality, not that nonces match keys [13](#0-12) 
- Error handling treats this as a coordinator error without malicious signer attribution [14](#0-13) 

## Impact Explanation

**Severity: Low** - "Any remotely-exploitable denial of service in a node"

A single compromised signer can completely prevent signature generation by sending NonceResponse messages with incorrect nonce counts (0 nonces, or 2+ nonces for v2; wrong count for v1). The coordinator accepts these malformed responses, but aggregation consistently fails with a generic error that does not identify the malicious party.

This results in:
- 100% denial of service for signing operations involving the malicious signer
- Attack is infinitely repeatable without detection
- Affects all signature types (Frost, Schnorr, Taproot)
- Malicious signer remains in good standing and is never banned
- Manual intervention required to identify and remove the attacker from configuration

In blockchain contexts using WSTS for threshold signatures (e.g., Stacks miners), this prevents block production until the malicious signer is manually removed.

## Likelihood Explanation

**Probability: Very High**

The attack is trivial to execute and requires only:
- Control of a single valid signer (within threat model of up to threshold-1 malicious signers)
- Ability to send protocol messages (normal network access)
- Simple modification: send NonceResponse with incorrect `nonces.len()`

The attack has:
- **Zero cryptographic requirements** - no key compromise or primitive breaks needed
- **Zero cost** - no rate limiting or economic penalties
- **Zero detection** - error is generic and doesn't identify malicious signer
- **Infinite repeatability** - attacker can repeat on every signing round
- **Minimal complexity** - one-line modification to nonce count

Economic feasibility is trivial as it only requires compromising one signer's implementation or communications channel.

## Recommendation

Add nonce count validation in `gather_nonces` for both FIRE and FROST coordinators:

**For v2 protocol**: Validate that `nonces.len() == 1` regardless of `key_ids.len()`

**For v1 protocol**: Validate that `nonces.len() == key_ids.len()`

The validation should be added after key_ids validation and before individual nonce validity checks. Return an error and optionally mark the signer as malicious when the count doesn't match expectations.

Example fix for FIRE coordinator (similar for FROST):
```rust
// After line 889 in fire.rs, add:
let expected_nonce_count = if /* is_v2 */ { 
    1 
} else { 
    signer_key_ids.len() 
};

if nonce_response.nonces.len() != expected_nonce_count {
    warn!(
        signer_id = %nonce_response.signer_id,
        expected = %expected_nonce_count,
        got = %nonce_response.nonces.len(),
        "Nonce response has wrong nonce count"
    );
    self.malicious_signer_ids.insert(nonce_response.signer_id);
    return Ok(());
}
```

## Proof of Concept

```rust
#[test]
fn test_nonce_count_bypass_dos() {
    use crate::state_machine::coordinator::fire::FireCoordinator;
    use crate::v2;
    
    // Setup coordinator with threshold=2
    let mut coordinator = setup_fire_coordinator_v2(2);
    coordinator.state = State::NonceGather(SignatureType::Frost);
    
    // Malicious signer sends empty nonces vector
    let malicious_response = NonceResponse {
        dkg_id: 0,
        sign_id: 0,
        sign_iter_id: 0,
        signer_id: 1,
        key_ids: vec![1], // Claims to have key 1
        nonces: vec![],   // But sends 0 nonces!
        message: vec![0u8],
    };
    
    // Coordinator accepts it (vulnerability)
    let result = coordinator.gather_nonces(
        &Packet { msg: Message::NonceResponse(malicious_response), sig: Default::default() },
        SignatureType::Frost
    );
    assert!(result.is_ok()); // Should reject but doesn't!
    
    // This will cause BadNonceLen during aggregation
}
```

## Notes

The vulnerability exists because the coordinator validates the key_ids set equality but assumes the nonces vector length is correct. The protocol specification requires specific nonce counts (1 for v2, N for v1 where N is the number of keys), but this invariant is not enforced at the message validation layer. Instead, the mismatch is only detected during aggregation when it's too late to identify the malicious party.

### Citations

**File:** src/state_machine/coordinator/fire.rs (L328-332)
```rust
                    if let Err(e) = self.gather_sig_shares(packet, signature_type) {
                        return Ok((
                            None,
                            Some(OperationResult::SignError(SignError::Coordinator(e))),
                        ));
```

**File:** src/state_machine/coordinator/fire.rs (L847-860)
```rust
            if nonce_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(nonce_response.dkg_id, self.current_dkg_id));
            }
            if nonce_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    nonce_response.sign_id,
                    self.current_sign_id,
                ));
            }
            if nonce_response.sign_iter_id != self.current_sign_iter_id {
                return Err(Error::BadSignIterId(
                    nonce_response.sign_iter_id,
                    self.current_sign_iter_id,
                ));
```

**File:** src/state_machine/coordinator/fire.rs (L864-868)
```rust
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&nonce_response.signer_id) {
                warn!(signer_id = %nonce_response.signer_id, "No public key in config");
                return Ok(());
            };
```

**File:** src/state_machine/coordinator/fire.rs (L881-889)
```rust
            let nonce_response_key_ids = nonce_response
                .key_ids
                .iter()
                .cloned()
                .collect::<HashSet<u32>>();
            if *signer_key_ids != nonce_response_key_ids {
                warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
                return Ok(());
            }
```

**File:** src/state_machine/coordinator/fire.rs (L891-901)
```rust
            for nonce in &nonce_response.nonces {
                if !nonce.is_valid() {
                    warn!(
                        sign_id = %nonce_response.sign_id,
                        sign_iter_id = %nonce_response.sign_iter_id,
                        signer_id = %nonce_response.signer_id,
                        "Received invalid nonce in NonceResponse"
                    );
                    return Ok(());
                }
            }
```

**File:** src/state_machine/coordinator/fire.rs (L922-929)
```rust
            let have_nonces = nonce_info
                .public_nonces
                .contains_key(&nonce_response.signer_id);

            if have_nonces {
                info!(signer_id = %nonce_response.signer_id, "Received duplicate NonceResponse");
                return Ok(());
            }
```

**File:** src/state_machine/coordinator/fire.rs (L1121-1124)
```rust
            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();
```

**File:** src/v2.rs (L304-306)
```rust
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }
```

**File:** src/v2.rs (L627-633)
```rust
    fn gen_nonces<RNG: RngCore + CryptoRng>(
        &mut self,
        secret_key: &Scalar,
        rng: &mut RNG,
    ) -> Vec<PublicNonce> {
        vec![self.gen_nonce(secret_key, rng)]
    }
```

**File:** src/v2.rs (L652-660)
```rust
    fn sign(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare> {
        vec![self.sign(msg, signer_ids, key_ids, nonces)]
    }
```

**File:** src/v1.rs (L676-685)
```rust
    fn gen_nonces<RNG: RngCore + CryptoRng>(
        &mut self,
        secret_key: &Scalar,
        rng: &mut RNG,
    ) -> Vec<PublicNonce> {
        self.parties
            .iter_mut()
            .map(|p| p.gen_nonce(secret_key, rng))
            .collect()
    }
```

**File:** src/errors.rs (L44-46)
```rust
    #[error("bad nonce length (expected {0} got {1}")]
    /// The nonce length was the wrong size
    BadNonceLen(usize, usize),
```

**File:** src/state_machine/coordinator/frost.rs (L523-533)
```rust
            for nonce in &nonce_response.nonces {
                if !nonce.is_valid() {
                    warn!(
                        sign_id = %nonce_response.sign_id,
                        sign_iter_id = %nonce_response.sign_iter_id,
                        signer_id = %nonce_response.signer_id,
                        "Received invalid nonce in NonceResponse"
                    );
                    return Ok(());
                }
            }
```
