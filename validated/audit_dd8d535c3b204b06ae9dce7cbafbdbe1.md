# Audit Report

## Title
Duplicate Key IDs in NonceResponse Break Lagrange Interpolation and Cause Signing Denial of Service

## Summary
A malicious signer can send a `NonceResponse` message with duplicate `key_ids` that bypasses coordinator validation, causing all participants to compute incorrect Lagrange coefficients. This breaks the mathematical correctness of threshold signature aggregation, resulting in deterministic signing round failures that block transaction confirmation.

## Finding Description

The vulnerability exists in the coordinator's validation logic for `NonceResponse.key_ids` in both FROST and FIRE coordinators. The validation converts the received `key_ids` Vec to a HashSet for set equality comparison, which inadvertently allows duplicate values to pass validation. [1](#0-0) [2](#0-1) 

**Attack Flow:**

1. A malicious signer crafts a `NonceResponse` with duplicate `key_ids` (e.g., `[1, 2, 2]` instead of `[1, 2]`). The `NonceResponse` implements the `Signable` trait and includes `key_ids` in its hash, allowing the signer to sign this malicious message with their network private key. [3](#0-2) 

2. The coordinator's validation converts the key_ids to a HashSet for comparison. `HashSet([1, 2, 2])` equals `{1, 2}`, matching the expected configured keys, so validation passes. However, the original NonceResponse with duplicates is stored unchanged. [4](#0-3) [5](#0-4) 

3. When creating the `SignatureShareRequest`, the coordinator collects all stored NonceResponses (preserving duplicates) and sends them to all signers. [6](#0-5) [7](#0-6) 

4. Each signer flattens the key_ids from all NonceResponses WITHOUT de-duplication, resulting in a key_ids array containing duplicates. [8](#0-7) 

5. Signers compute their signature shares using these duplicate key_ids for Lagrange interpolation. The `compute::lambda` function iterates over ALL values in the key_ids array, including duplicates. [9](#0-8) 

For example, if `key_ids = [1, 2, 2, 3]` and computing `lambda(1, key_ids)`, the loop multiplies by `2/(2-1)` twice (once for each instance of 2), producing lambda = 6 instead of the correct value of 3. This breaks the mathematical correctness of Lagrange interpolation. [10](#0-9) 

6. The coordinator also flattens key_ids without de-duplication for aggregation. [11](#0-10) 

7. The aggregator sums all signature shares to create the final signature, then verifies it against the group public key. Because all signers used incorrect Lagrange coefficients, the aggregated signature is mathematically invalid and verification fails. [12](#0-11) [13](#0-12) 

8. The `check_signature_shares` method is called to diagnose the failure, but it uses the same flattened key_ids array with duplicates for Lagrange computation. Since all signers used the same incorrect lambdas, individual share checks pass, and the function returns `AggregatorError::BadGroupSig` without identifying any specific malicious party. [14](#0-13) [15](#0-14) 

## Impact Explanation

This vulnerability causes a **remotely-exploitable denial of service** classified as **Low severity** per the scope definition:

- A single malicious signer can block any signing round by including duplicate key_ids in their NonceResponse
- All participants compute invalid signature shares due to incorrect Lagrange coefficients
- Signature aggregation deterministically fails verification
- The signing round aborts without producing a valid signature
- Transaction confirmation is prevented until the malicious signer is identified and removed through external means
- The attack can be repeated indefinitely on subsequent rounds
- The malicious party cannot be automatically identified since `check_signature_shares` returns `AggregatorError::BadGroupSig` rather than identifying specific bad signers

This aligns with "Any remotely-exploitable denial of service in a node" as defined in the Low severity category.

## Likelihood Explanation

**High likelihood:**

- **Attacker capabilities:** Requires being a registered signer (within threat model) with standard network message capabilities
- **Attack complexity:** Trivial - craft NonceResponse with duplicate key_ids, sign it with network private key, and send through normal protocol flow
- **Success rate:** 100% - duplicates deterministically break Lagrange interpolation mathematics
- **Detection difficulty:** Low to moderate - requires inspecting NonceResponse message contents to identify duplicate key_ids, which is not performed by current validation
- **Economic cost:** Zero - no additional resources beyond normal signer operations

The attack is within the protocol threat model (malicious signer up to threshold-1) and can be executed through normal message flow without any special access or cryptographic breaks.

## Recommendation

Implement explicit duplicate detection in the NonceResponse validation logic. Replace the implicit HashSet comparison with an explicit check that ensures the Vec contains no duplicates:

**Option 1:** Check Vec length against HashSet length
```rust
let nonce_response_key_ids: HashSet<u32> = nonce_response
    .key_ids
    .iter()
    .cloned()
    .collect();

// Check for duplicates by comparing lengths
if nonce_response.key_ids.len() != nonce_response_key_ids.len() {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids contains duplicates");
    return Ok(());
}

if *signer_key_ids != nonce_response_key_ids {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
    return Ok(());
}
```

**Option 2:** De-duplicate when flattening
```rust
let key_ids: Vec<u32> = sign_request
    .nonce_responses
    .iter()
    .flat_map(|nr| nr.key_ids.iter().copied())
    .collect::<HashSet<u32>>()  // De-duplicate
    .into_iter()
    .collect();
```

**Option 3:** Add struct-level validation
Create a validated `NonceResponse` constructor that checks for duplicates at construction time and rejects invalid messages earlier in the protocol flow.

The fix should be applied consistently in both FIRE and FROST coordinators at the validation point before storing the NonceResponse.

## Proof of Concept

```rust
#[test]
fn test_duplicate_key_ids_break_lambda() {
    use crate::compute::lambda;
    
    // Correct lambda computation with unique key_ids
    let correct_key_ids = vec![1, 2, 3];
    let correct_lambda = lambda(1, &correct_key_ids);
    
    // Incorrect lambda computation with duplicate key_ids
    let duplicate_key_ids = vec![1, 2, 2, 3];
    let incorrect_lambda = lambda(1, &duplicate_key_ids);
    
    // The duplicates cause incorrect Lagrange coefficient
    // lambda(1, [1,2,3]) should be: (2/(2-1)) * (3/(3-1)) = 2 * 1.5 = 3
    // lambda(1, [1,2,2,3]) computes: (2/(2-1)) * (2/(2-1)) * (3/(3-1)) = 2 * 2 * 1.5 = 6
    assert_ne!(correct_lambda, incorrect_lambda);
    
    // Verify the incorrect lambda is exactly double due to duplicate 2
    assert_eq!(incorrect_lambda, correct_lambda * crate::curve::scalar::Scalar::from(2));
}
```

## Notes

This vulnerability demonstrates a subtle validation bypass where the use of HashSet for set equality checking inadvertently allows duplicate values in the original Vec to pass validation. The mathematical incorrectness of Lagrange interpolation with duplicates causes all honest participants to compute invalid signature shares, resulting in a deterministic denial of service that cannot identify the malicious party through the existing `check_signature_shares` mechanism.

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

**File:** src/state_machine/coordinator/fire.rs (L931-933)
```rust
            nonce_info
                .public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L970-977)
```rust
        let nonce_responses = self
            .message_nonces
            .get(&self.message)
            .ok_or(Error::MissingMessageNonceInfo)?
            .public_nonces
            .values()
            .cloned()
            .collect::<Vec<NonceResponse>>();
```

**File:** src/state_machine/coordinator/fire.rs (L1126-1129)
```rust
            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();
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

**File:** src/state_machine/coordinator/frost.rs (L571-573)
```rust
        let nonce_responses = (0..self.config.num_signers)
            .map(|i| self.public_nonces[&i].clone())
            .collect::<Vec<NonceResponse>>();
```

**File:** src/net.rs (L349-368)
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

**File:** src/compute.rs (L70-80)
```rust
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

**File:** src/v2.rs (L262-265)
```rust
        let mut cx = Scalar::zero();
        for key_id in self.key_ids.iter() {
            cx += c * &self.private_keys[key_id] * compute::lambda(*key_id, key_ids);
        }
```

**File:** src/v2.rs (L327-339)
```rust
        // optimistically try to create the aggregate signature without checking for bad keys or sig shares
        for sig_share in sig_shares {
            z += sig_share.z_i;
        }

        // The signature shares have already incorporated the private key adjustments, so we just have to add the tweak.  But the tweak itself needs to be adjusted if the tweaked public key is odd
        if let Some(t) = tweak {
            z += cx_sign * c * t;
        }

        let sig = Signature { R, z };

        Ok((tweaked_public_key, sig))
```

**File:** src/v2.rs (L347-354)
```rust
    pub fn check_signature_shares(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
        tweak: Option<Scalar>,
    ) -> AggregatorError {
```

**File:** src/v2.rs (L393-416)
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
        }
        if !bad_party_keys.is_empty() {
            AggregatorError::BadPartyKeys(bad_party_keys)
        } else if !bad_party_sigs.is_empty() {
            AggregatorError::BadPartySigs(bad_party_sigs)
        } else {
            AggregatorError::BadGroupSig
        }
```

**File:** src/v2.rs (L455-461)
```rust
        let (key, sig) = self.sign_with_tweak(msg, nonces, sig_shares, key_ids, None)?;

        if sig.verify(&key, msg) {
            Ok(sig)
        } else {
            Err(self.check_signature_shares(msg, nonces, sig_shares, key_ids, None))
        }
```
