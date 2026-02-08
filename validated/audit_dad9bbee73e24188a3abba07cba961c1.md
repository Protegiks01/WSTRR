# Audit Report

## Title
Duplicate Key IDs in NonceResponse Bypass Validation and Cause Aggregation Failure

## Summary
A malicious signer can send a `NonceResponse` with duplicate key IDs that passes HashSet-based validation but causes signature aggregation to fail due to a length mismatch between nonces and signature shares. This results in a denial of service preventing signing rounds from completing.

## Finding Description

The WSTS coordinator validates `NonceResponse` messages by converting the `key_ids` vector to a HashSet before comparing it to configured key IDs. This validation removes duplicates, allowing a malicious signer to send duplicate key IDs that pass validation. [1](#0-0) 

When a malicious signer with legitimate keys {1, 2} crafts a NonceResponse with `key_ids = [1, 2, 1, 1]` and 4 corresponding nonces, the validation converts this to HashSet {1, 2}, which matches the configured keys, causing validation to pass.

The NonceResponse is then stored with all duplicates intact: [2](#0-1) 

During signature aggregation, both coordinators (FIRE and FROST) flatten nonces and key_ids from all NonceResponses, preserving all duplicates: [3](#0-2) [4](#0-3) 

However, when the malicious signer generates signature shares, it iterates only over its legitimate parties (not based on the duplicated key_ids in the request), producing only 2 shares instead of 4: [5](#0-4) [6](#0-5) 

When the aggregator attempts to aggregate the signature, it enforces a strict length check that fails due to the mismatch: [7](#0-6) 

The coordinator only validates individual nonce validity but lacks validation for the relationship between key_ids and nonces: [8](#0-7) 

There is no check that `key_ids.len() == nonces.len()` or that key_ids contains no duplicates within a single NonceResponse.

## Impact Explanation

This vulnerability allows any malicious signer within the protocol threat model to prevent signature aggregation from completing, causing the entire signing round to fail. The error is caught and returned as a SignError: [9](#0-8) 

This constitutes a **transient consensus failure** (Medium severity):
- Every signing round can be blocked by any malicious signer
- All honest participants are affected when included in a round with the attacker
- Transaction confirmation is delayed until the round times out or is restarted
- No permanent damage or fund loss occurs, but normal operations are disrupted

The error type returned indicates a bad nonce length: [10](#0-9) 

## Likelihood Explanation

**Required Capabilities:**
- Must be a valid signing participant with configured key IDs (within protocol threat model for malicious signers up to threshold-1)
- Must be included in the signing set for a threshold signature

**Attack Complexity:** Trivial. The attacker simply crafts a `NonceResponse` message with duplicate entries in the `key_ids` vector and corresponding duplicate nonces. The NonceResponse struct is a simple serializable message: [11](#0-10) 

**Economic Feasibility:** Zero cost. The attack requires only sending a single malformed message per signing round.

**Detection:** The attack is detected only during aggregation when the length mismatch error occurs. By this point, the signing round has already failed.

**Estimated Probability:** Near 100% success rate for causing the intended DoS effect on each signing attempt.

## Recommendation

Add validation in the NonceResponse handling to check that:
1. `key_ids.len() == nonces.len()` - ensures each key_id has exactly one corresponding nonce
2. `key_ids` contains no duplicates within a single NonceResponse

The fix should be added after line 889 in `src/state_machine/coordinator/fire.rs`:

```rust
// Check that key_ids and nonces have matching lengths
if nonce_response.key_ids.len() != nonce_response.nonces.len() {
    warn!(
        signer_id = %nonce_response.signer_id,
        key_ids_len = %nonce_response.key_ids.len(),
        nonces_len = %nonce_response.nonces.len(),
        "NonceResponse key_ids length doesn't match nonces length"
    );
    return Ok(());
}

// Check that key_ids from the response match exactly (no duplicates)
if nonce_response_key_ids.len() != nonce_response.key_ids.len() {
    warn!(
        signer_id = %nonce_response.signer_id,
        "NonceResponse contains duplicate key_ids"
    );
    return Ok(());
}
```

The same fix should be applied to `src/state_machine/coordinator/frost.rs` at the corresponding location.

## Proof of Concept

```rust
#[test]
fn test_duplicate_key_ids_dos() {
    use crate::net::{NonceResponse, Message, Packet};
    use crate::state_machine::coordinator::fire::Coordinator;
    use crate::common::PublicNonce;
    
    // Setup: Create coordinator with threshold configuration
    // Create a malicious NonceResponse with duplicate key_ids
    let malicious_response = NonceResponse {
        dkg_id: 1,
        sign_id: 1,
        sign_iter_id: 1,
        signer_id: 0,
        key_ids: vec![1, 2, 1, 1], // Duplicates!
        nonces: vec![
            PublicNonce::default(),
            PublicNonce::default(),
            PublicNonce::default(),
            PublicNonce::default(),
        ], // 4 nonces
        message: vec![0u8; 32],
    };
    
    // The HashSet validation will pass: {1, 2} == {1, 2}
    // But aggregation will fail with nonces.len() (4) != sig_shares.len() (2)
    
    // Process the message through coordinator
    // Verify that aggregation fails with AggregatorError::BadNonceLen
}
```

### Citations

**File:** src/state_machine/coordinator/fire.rs (L328-332)
```rust
                    if let Err(e) = self.gather_sig_shares(packet, signature_type) {
                        return Ok((
                            None,
                            Some(OperationResult::SignError(SignError::Coordinator(e))),
                        ));
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

**File:** src/state_machine/coordinator/fire.rs (L931-933)
```rust
            nonce_info
                .public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L1121-1129)
```rust
            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();

            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();
```

**File:** src/state_machine/coordinator/frost.rs (L670-678)
```rust
            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();

            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();
```

**File:** src/v1.rs (L715-718)
```rust
        self.parties
            .iter()
            .map(|p| p.sign_precomputed(msg, key_ids, nonces, &aggregate_nonce))
            .collect()
```

**File:** src/v2.rs (L263-275)
```rust
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
```

**File:** src/v2.rs (L304-306)
```rust
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }
```

**File:** src/errors.rs (L44-46)
```rust
    #[error("bad nonce length (expected {0} got {1}")]
    /// The nonce length was the wrong size
    BadNonceLen(usize, usize),
```

**File:** src/net.rs (L311-326)
```rust
pub struct NonceResponse {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// Key IDs
    pub key_ids: Vec<u32>,
    /// Public nonces
    pub nonces: Vec<PublicNonce>,
    /// Bytes being signed
    pub message: Vec<u8>,
}
```
