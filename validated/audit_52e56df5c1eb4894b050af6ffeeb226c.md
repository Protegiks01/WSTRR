# Audit Report

## Title
Duplicate key_ids in NonceResponse Bypass Validation and Corrupt Lagrange Interpolation

## Summary
The coordinator's validation of `key_ids` in `NonceResponse` messages converts the `Vec<u32>` to a `HashSet<u32>` before comparing with configuration, silently removing duplicates. The original Vec with duplicates is stored and propagated to all signers, corrupting Lagrange interpolation coefficient calculations and causing complete signing round failure for all participants.

## Finding Description

This vulnerability breaks WSTS's threshold signature correctness guarantee through a validation bypass that allows duplicate key_ids to corrupt Lagrange interpolation.

**Root Cause - Validation Bypass:**

Both FROST and FIRE coordinators validate NonceResponse key_ids by converting the Vec to a HashSet: [1](#0-0) [2](#0-1) 

If a malicious signer sends `NonceResponse { key_ids: vec![1, 1, 2], ... }`, the HashSet conversion creates `{1, 2}`, which passes validation. However, the original Vec `[1, 1, 2]` remains in the message structure.

**Storage and Propagation:**

The coordinator stores the original, unmodified NonceResponse: [3](#0-2) 

When constructing SignatureShareRequest, all stored NonceResponses are collected and sent to every signer: [4](#0-3) 

**Duplicate Extraction by Signers:**

Each signer extracts the global key_ids list by flattening all key_ids from all nonce responses: [5](#0-4) 

The flat_map operation preserves duplicates. If any NonceResponse contains `[1, 1, 2]`, these duplicates appear in the global key_ids list.

**Lagrange Coefficient Corruption:**

The lambda function computes Lagrange interpolation coefficients without validating for duplicates: [6](#0-5) 

The function iterates over all j values in key_ids and multiplies `j/(j-i)` for each occurrence. If key_ids contains `[1, 1, 2, 3]` and we compute `lambda(3, [1, 1, 2, 3])`, the term `1/(1-3) = -1/2` is multiplied **twice**, producing `-1/2 * -1/2 * -2 = -1/2` instead of the correct value `-1/2 * -2 = 1`.

Signers call lambda with the corrupted global key_ids when computing signature shares: [7](#0-6) 

**Impact on All Signers:**

All participating signers compute their signature shares using incorrect Lagrange coefficients. The aggregated signature fails verification. The coordinator's check_signature_shares also uses the same corrupted key_ids: [8](#0-7) 

This may prevent correct identification of the malicious party since all parties used the same corrupted coefficients.

## Impact Explanation

**Severity: Medium** ("Any transient consensus failures")

A single malicious signer (within the t-1 threat model) can prevent any signing round from completing successfully by including duplicate key_ids in their NonceResponse. This causes:

1. **Complete signing round failure**: All signers compute incorrect signature shares due to corrupted Lagrange coefficients
2. **System-wide impact**: Affects all honest signers, not just the malicious party
3. **Potential misidentification**: The fault detection mechanism may fail to identify the malicious party correctly
4. **Transient consensus failure**: If WSTS is used for block signing or transaction confirmation, preventing signature generation causes transient consensus failures until the malicious signer is identified and removed

The system can recover by identifying and excluding the malicious signer, but this requires manual intervention and analysis of the signing failure.

## Likelihood Explanation

**Likelihood: High**

The attack has near-certain success probability:

1. **Low attacker requirements**: Requires only legitimate signer credentials (within threat model)
2. **Trivial attack complexity**: Send `NonceResponse` with `key_ids: vec![1, 1, 2]` instead of `vec![1, 2]`
3. **Deterministic success**: Validation always fails to detect duplicates due to HashSet conversion
4. **No computational cost**: Requires only normal message construction and signing
5. **Stealthy**: Validation passes without warnings; failure only detected at final signature verification

## Recommendation

Add duplicate detection before or after the HashSet conversion:

```rust
// In both frost.rs and fire.rs gather_nonces methods
let nonce_response_key_ids = nonce_response
    .key_ids
    .iter()
    .cloned()
    .collect::<HashSet<u32>>();

// Add this check
if nonce_response_key_ids.len() != nonce_response.key_ids.len() {
    warn!(
        signer_id = %nonce_response.signer_id, 
        "NonceResponse contains duplicate key_ids"
    );
    return Ok(());
}

if *signer_key_ids != nonce_response_key_ids {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
    return Ok(());
}
```

Alternatively, validate for duplicates in the lambda function itself by adding a duplicate check, though this is less efficient.

## Proof of Concept

```rust
#[test]
fn test_lambda_duplicate_corruption() {
    use wsts::compute::lambda;
    use wsts::curve::scalar::Scalar;
    use num_traits::One;

    // Correct key_ids without duplicates
    let correct_key_ids = vec![1, 2, 3];
    let lambda_correct = lambda(3, &correct_key_ids);
    
    // Malicious key_ids with duplicate 1
    let malicious_key_ids = vec![1, 1, 2, 3];
    let lambda_malicious = lambda(3, &malicious_key_ids);
    
    // The coefficients must be different, proving corruption
    assert_ne!(lambda_correct, lambda_malicious);
    
    // Expected: lambda(3, [1,2,3]) = (1/(1-3)) * (2/(2-3)) = (-1/2) * (-2) = 1
    assert_eq!(lambda_correct, Scalar::one());
    
    // With duplicates: lambda(3, [1,1,2,3]) = (-1/2) * (-1/2) * (-2) = -1/2
    // This proves the Lagrange coefficient is corrupted
    assert_ne!(lambda_malicious, Scalar::one());
}
```

This test demonstrates that passing duplicate key_ids to the lambda function produces incorrect Lagrange interpolation coefficients, which would cause all signature shares to be computed incorrectly.

### Citations

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

**File:** src/state_machine/coordinator/frost.rs (L571-581)
```rust
        let nonce_responses = (0..self.config.num_signers)
            .map(|i| self.public_nonces[&i].clone())
            .collect::<Vec<NonceResponse>>();
        let sig_share_request = SignatureShareRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            nonce_responses,
            message: self.message.clone(),
            signature_type,
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

**File:** src/state_machine/signer/mod.rs (L800-804)
```rust
            let key_ids: Vec<u32> = sign_request
                .nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.iter().copied())
                .collect::<Vec<u32>>();
```

**File:** src/compute.rs (L69-80)
```rust
/// Compute the Lagrange interpolation value
pub fn lambda(i: u32, key_ids: &[u32]) -> Scalar {
    let mut lambda = Scalar::one();
    let i_scalar = id(i);
    for j in key_ids {
        if i != *j {
            let j_scalar = id(*j);
            lambda *= j_scalar / (j_scalar - i_scalar);
        }
    }
    lambda
}
```

**File:** src/v2.rs (L263-265)
```rust
        for key_id in self.key_ids.iter() {
            cx += c * &self.private_keys[key_id] * compute::lambda(*key_id, key_ids);
        }
```

**File:** src/v2.rs (L393-408)
```rust
            for key_id in &sig_shares[i].key_ids {
                let kid = compute::id(*key_id);
                let public_key = match compute::poly(&kid, &self.poly) {
                    Ok(p) => p,
                    Err(_) => {
                        bad_party_keys.push(sig_shares[i].id);
                        Point::zero()
                    }
                };

                cx += compute::lambda(*key_id, key_ids) * c * public_key;
            }

            if z_i * G != (r_sign * Rs[i] + cx_sign * cx) {
                bad_party_sigs.push(sig_shares[i].id);
            }
```
