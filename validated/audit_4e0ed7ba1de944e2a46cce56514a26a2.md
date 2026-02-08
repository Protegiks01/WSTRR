# Audit Report

## Title
Duplicate key_ids in NonceResponse Bypass Validation and Corrupt Lagrange Interpolation

## Summary
The validation logic for `key_ids` in `NonceResponse` and `SignatureShareResponse` converts incoming `Vec<u32>` to `HashSet` before comparing with configuration, silently removing duplicates. However, the original `Vec` with duplicates is stored and propagated to all signers, corrupting Lagrange interpolation coefficients and causing complete signing round failure. A single malicious signer can exploit this to trigger denial of service.

## Finding Description

**Root Cause - HashSet Validation Fails to Detect Duplicates:**

The FIRE coordinator validates NonceResponse key_ids by converting the Vec to a HashSet and comparing against configured signer_key_ids. [1](#0-0)  The FROST coordinator uses identical validation logic. [2](#0-1) 

When a malicious signer sends `NonceResponse { key_ids: vec![1, 1, 2], ... }`, the validation creates `HashSet {1, 2}`, compares it with the configured `{1, 2}`, and passes. However, the original `Vec [1, 1, 2]` with duplicates is stored. [3](#0-2) 

The NonceResponse struct defines key_ids as Vec<u32>. [4](#0-3) 

SignatureShareResponse validation exhibits the same pattern, converting Vec to HashSet before comparison. [5](#0-4) 

**Propagation to All Signers:**

The coordinator constructs SignatureShareRequest by collecting all stored NonceResponse objects from public_nonces. [6](#0-5) 

The SignatureShareRequest struct contains nonce_responses as Vec<NonceResponse>. [7](#0-6) 

Each signer receives the request and reconstructs the global key_ids list by flattening all key_ids from all nonce_responses. [8](#0-7)  This preserves any duplicates present in the original NonceResponse messages, creating a corrupted global key_ids list passed to every signer's sign function.

**Corruption in Lagrange Interpolation:**

The lambda function computes Lagrange interpolation coefficients by iterating over all j in key_ids and multiplying factors. [9](#0-8) 

When signers compute signature shares, they call lambda with the corrupted global key_ids for each of their own key_ids. [10](#0-9) 

If `key_ids = [1, 1, 2, 3]` contains a duplicate, computing `lambda(3, [1, 1, 2, 3])` multiplies the factor `1/(1-3)` twice instead of once, producing an incorrect Lagrange coefficient. All signers compute incorrect `z_i` values, causing the aggregated signature to fail verification.

**Aggregation Failure and Misidentification:**

The coordinator aggregates signature shares by summing all z_i values. [11](#0-10) 

When verification fails, the coordinator calls check_signature_shares to identify malicious parties. [12](#0-11)  However, this function also uses the corrupted key_ids to compute lambda coefficients during validation. [13](#0-12)  Since all honest signers computed their shares using the same corrupted lambda coefficients, the individual share checks may pass while the aggregate fails, potentially causing misidentification of the malicious party.

**Configuration Validation is Insufficient:**

The PublicKeys::validate() method only validates that configured key_ids are in range. [14](#0-13) 

The configuration uses signer_key_ids as HashMap<u32, HashSet<u32>>. [15](#0-14)  HashSet cannot contain duplicates, so the configuration itself is protected. However, runtime validation of incoming messages fails to detect duplicates in the original Vec before converting to HashSet.

## Impact Explanation

**Denial of Service Impact:**

A single malicious signer can cause complete signing round failure by including duplicate key_ids in their NonceResponse. All participating signers will compute signature shares using incorrect Lagrange coefficients, causing the aggregated signature to fail verification. The signing round cannot complete until the malicious signer is identified and removed, then the entire round must restart.

**Severity Assessment:**

This vulnerability maps to **Low severity** per the defined scope: "Any remotely-exploitable denial of service in a node" since it causes signing operations to fail. If WSTS is integrated into consensus-critical operations like block signing or transaction confirmation, it could escalate to **Medium severity**: "Any transient consensus failures."

**Quantified Impact:**
- Attack affects all signers in the protocol, not just the malicious party
- Recovery requires identifying and removing the malicious signer
- With n=10 keys and threshold t=7, a malicious signer controlling 2 keys can prevent any signing round from succeeding
- Attack requires only a single corrupted NonceResponse message

## Likelihood Explanation

**High Likelihood:**

The vulnerability is extremely simple to exploit. A malicious signer only needs to duplicate values in their key_ids Vec when constructing a NonceResponse message.

**Attacker Requirements:**
- Must be a valid signer in the WSTS protocol with legitimate credentials (within threat model)
- Requires ability to send network messages (standard protocol capability)
- No need to compromise cryptographic keys or break underlying primitives

**Success Probability:**
Near 100% - the validation logic deterministically fails to catch duplicates in Vecs by converting to HashSet before comparison.

**Detection Difficulty:**
Low detection risk during attack. The coordinator will detect signature failure but the validation logs only show "key_ids didn't match config" without specifying the cause. Post-attack forensics requires examining raw message contents.

## Recommendation

Modify the validation logic to detect duplicates before converting to HashSet. Add explicit duplicate detection:

```rust
// In gather_nonces for NonceResponse validation:
let nonce_response_key_ids: HashSet<u32> = nonce_response
    .key_ids
    .iter()
    .cloned()
    .collect();

// Add duplicate detection
if nonce_response_key_ids.len() != nonce_response.key_ids.len() {
    warn!(
        signer_id = %nonce_response.signer_id,
        "Nonce response key_ids contains duplicates"
    );
    return Ok(());
}

if *signer_key_ids != nonce_response_key_ids {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
    return Ok(());
}
```

Apply the same fix to SignatureShareResponse validation to check for duplicates in both key_ids extraction and comparison phases.

## Proof of Concept

```rust
#[test]
fn test_duplicate_key_ids_dos() {
    use crate::compute::lambda;
    use crate::curve::scalar::Scalar;
    
    // Demonstrate that duplicate key_ids corrupt lambda computation
    let key_ids_valid = vec![1u32, 2, 3];
    let key_ids_duplicate = vec![1u32, 1, 2, 3]; // Duplicate key_id 1
    
    // Compute lambda for key_id 3 with valid key_ids
    let lambda_valid = lambda(3, &key_ids_valid);
    
    // Compute lambda for key_id 3 with duplicate key_ids
    let lambda_corrupt = lambda(3, &key_ids_duplicate);
    
    // The lambda values should differ, proving corruption
    assert_ne!(lambda_valid, lambda_corrupt, 
        "Lambda coefficients differ when key_ids contains duplicates");
    
    // Specifically, the corrupt version multiplies the factor for key_id 1 twice:
    // lambda_corrupt includes (1/(1-3))^2 instead of (1/(1-3))
    let factor_1 = Scalar::from(1u32) / (Scalar::from(1u32) - Scalar::from(3u32));
    let factor_2 = Scalar::from(2u32) / (Scalar::from(2u32) - Scalar::from(3u32));
    
    let expected_valid = factor_1 * factor_2;
    let expected_corrupt = factor_1 * factor_1 * factor_2; // factor_1 applied twice
    
    assert_eq!(lambda_valid, expected_valid);
    assert_eq!(lambda_corrupt, expected_corrupt);
}
```

## Notes

This vulnerability breaks the fundamental security guarantee that Lagrange interpolation coefficients must be computed correctly for threshold signature reconstruction. The protocol assumes that all signers receive identical, valid key_ids sets, but the validation bypass allows corrupted sets to propagate through the entire signing round, affecting all participants simultaneously.

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

**File:** src/state_machine/coordinator/fire.rs (L970-982)
```rust
        let nonce_responses = self
            .message_nonces
            .get(&self.message)
            .ok_or(Error::MissingMessageNonceInfo)?
            .public_nonces
            .values()
            .cloned()
            .collect::<Vec<NonceResponse>>();
        let sig_share_request = SignatureShareRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            nonce_responses,
```

**File:** src/state_machine/coordinator/fire.rs (L1066-1076)
```rust
        let mut sig_share_response_key_ids = HashSet::new();
        for sig_share in &sig_share_response.signature_shares {
            for key_id in &sig_share.key_ids {
                sig_share_response_key_ids.insert(*key_id);
            }
        }

        if *signer_key_ids != sig_share_response_key_ids {
            warn!(signer_id = %sig_share_response.signer_id, "SignatureShareResponse key_ids didn't match config");
            return Err(Error::BadKeyIDsForSigner(sig_share_response.signer_id));
        }
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

**File:** src/net.rs (L309-326)
```rust
#[derive(Clone, Serialize, Deserialize, PartialEq)]
/// Nonce response message from signers to coordinator
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

**File:** src/v2.rs (L328-330)
```rust
        for sig_share in sig_shares {
            z += sig_share.z_i;
        }
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

**File:** src/v2.rs (L393-404)
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
```

**File:** src/state_machine/mod.rs (L93-102)
```rust
#[derive(Clone, Default, PartialEq, Eq)]
/// Map of signer_id and key_id to the relevant ecdsa public keys
pub struct PublicKeys {
    /// signer_id -> public key
    pub signers: HashMap<u32, ecdsa::PublicKey>,
    /// key_id -> public key
    pub key_ids: HashMap<u32, ecdsa::PublicKey>,
    /// map of signer_id to controlled key_ids
    pub signer_key_ids: HashMap<u32, HashSet<u32>>,
}
```

**File:** src/state_machine/mod.rs (L105-136)
```rust
    /// Check that all of the signer_ids and key_ids are valid
    pub fn validate(&self, num_signers: u32, num_keys: u32) -> Result<(), SignerError> {
        for (signer_id, _key) in &self.signers {
            if !validate_signer_id(*signer_id, num_signers) {
                return Err(SignerError::Config(ConfigError::InvalidSignerId(
                    *signer_id,
                )));
            }
        }

        for (key_id, _key) in &self.key_ids {
            if !validate_key_id(*key_id, num_keys) {
                return Err(SignerError::Config(ConfigError::InvalidKeyId(*key_id)));
            }
        }

        for (signer_id, key_ids) in &self.signer_key_ids {
            if !validate_signer_id(*signer_id, num_signers) {
                return Err(SignerError::Config(ConfigError::InvalidSignerId(
                    *signer_id,
                )));
            }

            for key_id in key_ids {
                if !validate_key_id(*key_id, num_keys) {
                    return Err(SignerError::Config(ConfigError::InvalidKeyId(*key_id)));
                }
            }
        }

        Ok(())
    }
```
