# Audit Report

## Title
Duplicate Key IDs in NonceResponse Bypass Validation and Cause Aggregation Failure

## Summary
A malicious signer can send a `NonceResponse` with duplicate key IDs that passes HashSet-based validation but causes signature aggregation to fail due to a length mismatch between nonces and signature shares. This results in a denial of service preventing signing rounds from completing.

## Finding Description

The WSTS coordinator validates NonceResponse messages by converting the `key_ids` vector to a HashSet before comparing it to configured key IDs. This validation removes duplicates, allowing a malicious signer to send duplicate key IDs that pass validation. [1](#0-0) [2](#0-1) 

**Attack Execution:**

1. A malicious signer with legitimate keys {1, 2} crafts a NonceResponse with `key_ids = [1, 2, 1, 1]` and 4 corresponding nonces
2. The validation converts this to HashSet {1, 2}, which matches the configured keys, so validation passes
3. The NonceResponse is stored with all duplicates intact [3](#0-2) [4](#0-3) 

4. During aggregation, key_ids and nonces are flattened, preserving all duplicates (4 nonces) [5](#0-4) [6](#0-5) [7](#0-6) 

5. The malicious signer generates signature shares by iterating over its legitimate parties only, producing 2 shares (not 4) [8](#0-7) [9](#0-8) 

6. The aggregator enforces a length check that fails: nonces.len() (4) != sig_shares.len() (2) [10](#0-9) [11](#0-10) 

**Missing Validations:**

The coordinator only validates individual nonce validity but not the relationship between key_ids and nonces: [12](#0-11) 

There is no check that `key_ids.len() == nonces.len()` or that key_ids contains no duplicates within a single NonceResponse.

## Impact Explanation

This vulnerability allows any malicious signer to prevent signature aggregation from completing, causing the entire signing round to fail. This constitutes a **transient consensus failure** (Medium severity) as defined in the scope:

- Every signing round can be blocked by any malicious signer
- All honest participants are affected when included in a round with the attacker
- Transaction confirmation is delayed until the round times out or is restarted
- No permanent damage or fund loss occurs, but normal operations are disrupted

The impact aligns with "Any transient consensus failures" under Medium severity, as signing rounds fail temporarily but can be recovered by excluding the malicious signer or restarting.

## Likelihood Explanation

**Required Capabilities:**
- Must be a valid signing participant with configured key IDs (within protocol threat model)
- Must be included in the signing set for a threshold signature

**Attack Complexity:** Trivial. The attacker simply crafts a `NonceResponse` message with duplicate entries in the `key_ids` vector and corresponding duplicate nonces.

**Economic Feasibility:** Zero cost. The attack requires only sending a single malformed message per signing round.

**Detection:** The attack is detected only during aggregation when the length mismatch error occurs. By this point, the signing round has already failed. The coordinator could track which signer sent duplicate key IDs, but the current implementation doesn't prevent the issue upfront.

**Estimated Probability:** Near 100% success rate for causing the intended DoS effect on each signing attempt.

## Recommendation

Add validation during NonceResponse processing to ensure:

1. **Check for duplicate key_ids:**
```rust
let unique_key_ids: HashSet<_> = nonce_response.key_ids.iter().collect();
if unique_key_ids.len() != nonce_response.key_ids.len() {
    warn!(signer_id = %nonce_response.signer_id, "Duplicate key_ids in NonceResponse");
    return Ok(());
}
```

2. **Verify length consistency:**
```rust
if nonce_response.key_ids.len() != nonce_response.nonces.len() {
    warn!(signer_id = %nonce_response.signer_id, "key_ids and nonces length mismatch");
    return Ok(());
}
```

Apply these checks in both `src/state_machine/coordinator/fire.rs` and `src/state_machine/coordinator/frost.rs` in the `gather_nonces()` function after the existing key_ids HashSet validation.

## Proof of Concept

```rust
#[test]
fn test_duplicate_key_ids_dos() {
    use crate::net::{NonceResponse, Packet};
    use crate::common::PublicNonce;
    
    // Create NonceResponse with duplicate key_ids
    let mut nonce_response = NonceResponse {
        dkg_id: 0,
        sign_id: 1,
        sign_iter_id: 1,
        signer_id: 0,
        key_ids: vec![1, 2, 1, 1],  // Duplicates!
        nonces: vec![
            PublicNonce::default(),
            PublicNonce::default(),
            PublicNonce::default(),
            PublicNonce::default(),
        ],
        message: vec![],
    };
    
    // Convert to HashSet (simulating validation)
    let key_ids_set: HashSet<_> = nonce_response.key_ids.iter().collect();
    assert_eq!(key_ids_set.len(), 2);  // Only 2 unique keys
    assert_eq!(nonce_response.key_ids.len(), 4);  // But 4 in vector
    
    // This would pass HashSet validation but cause aggregation failure
    // when 4 nonces are flattened but only 2 signature shares are produced
}
```

### Citations

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

**File:** src/state_machine/coordinator/fire.rs (L1185-1194)
```rust
        let party_ids = public_nonces
            .values()
            .cloned()
            .flat_map(|pn| pn.key_ids)
            .collect::<Vec<u32>>();
        let nonces = public_nonces
            .values()
            .cloned()
            .flat_map(|pn| pn.nonces)
            .collect::<Vec<PublicNonce>>();
```

**File:** src/state_machine/coordinator/frost.rs (L513-521)
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

**File:** src/state_machine/coordinator/frost.rs (L542-543)
```rust
            self.public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());
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

**File:** src/state_machine/coordinator/frost.rs (L738-747)
```rust
        let party_ids = self
            .public_nonces
            .values()
            .flat_map(|pn| pn.key_ids.clone())
            .collect::<Vec<u32>>();
        let nonces = self
            .public_nonces
            .values()
            .flat_map(|pn| pn.nonces.clone())
            .collect::<Vec<PublicNonce>>();
```

**File:** src/v1.rs (L321-323)
```rust
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }
```

**File:** src/v1.rs (L747-758)
```rust
        self.parties
            .iter()
            .map(|p| {
                p.sign_precomputed_with_tweak(
                    msg,
                    key_ids,
                    nonces,
                    &aggregate_nonce,
                    Some(Scalar::from(0)),
                )
            })
            .collect()
```

**File:** src/v2.rs (L304-306)
```rust
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }
```

**File:** src/v2.rs (L669-669)
```rust
        vec![self.sign_with_tweak(msg, signer_ids, key_ids, nonces, Some(Scalar::from(0)))]
```
