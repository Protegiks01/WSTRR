Audit Report

## Title
Duplicate Key IDs Bypass HashSet Validation Causing Signature Generation Denial of Service

## Summary
The `gather_nonces()` function in both FROST and FIRE coordinators validates nonce response key_ids by converting the Vec to a HashSet before comparison, which removes duplicates. A malicious signer can include duplicate key_ids in their NonceResponse that pass validation but cause all signature shares to be computed with incorrect Lagrange coefficients, resulting in signature verification failure and denial of service for all signing rounds involving the malicious signer.

## Finding Description

**Root Cause:**

The validation logic converts `nonce_response.key_ids` (a `Vec<u32>`) to a `HashSet<u32>` before comparing against the configured `signer_key_ids`. This conversion removes duplicates, allowing a Vec like `[1, 1, 2]` to pass validation as `{1, 2}` when the config expects `{1, 2}`. [1](#0-0) 

The same vulnerable validation exists in the FIRE coordinator: [2](#0-1) 

The NonceResponse struct stores `key_ids` as a `Vec<u32>`, and the entire NonceResponse with the original duplicated Vec is stored: [3](#0-2) [4](#0-3) 

**Propagation Through Protocol:**

1. The coordinator sends all stored nonce_responses to signers in the SignatureShareRequest: [5](#0-4) 

2. Each signer extracts key_ids by flattening all nonce_responses, preserving duplicates: [6](#0-5) 

3. The flattened key_ids (with duplicates) are passed to the signing functions: [7](#0-6) 

**Impact on Lagrange Coefficients:**

The duplicated key_ids list is passed to `compute::lambda`, which computes Lagrange interpolation coefficients. The lambda function iterates over all elements in the key_ids slice, including duplicates: [8](#0-7) 

When key_ids contains duplicates like `[1, 1, 2, 3]`, the lambda computation for `lambda(2, [1, 1, 2, 3])` multiplies the same factor multiple times. For example, with j=1 appearing twice, it multiplies by `1/(1-2) = -1` twice, resulting in `(-1) * (-1) = 1` instead of the correct single multiplication by `-1`.

Signers use these incorrect lambdas when generating signature shares: [9](#0-8) 

The aggregator uses the same incorrect lambdas when checking signature shares: [10](#0-9) 

**Security Invariant Broken:**

Lagrange interpolation requires unique evaluation points. The protocol assumes that key_ids contains no duplicates when computing Lagrange coefficients. Duplicates cause the lambda function to treat the same point as multiple distinct points, violating the mathematical correctness of polynomial interpolation and causing all signature shares to be computed with incorrect coefficients.

## Impact Explanation

**Specific Harm:**
A malicious signer can cause all signing rounds they participate in to fail by including duplicate key_ids in their NonceResponse. Since all signers compute signature shares using the incorrect (duplicated) key_ids list, and the Lagrange interpolation produces wrong coefficients, the aggregated signature will fail verification.

**Quantified Impact:**
- Every signing round involving the malicious signer will fail
- The attack is repeatable across multiple rounds until the malicious signer is detected and removed
- If the malicious signer is required for threshold (e.g., 2-of-3 with threshold=2), this blocks all signatures

**Who is Affected:**
- All honest signers participating in rounds with the malicious signer
- Any system depending on WSTS signatures for transaction signing or block confirmation
- The coordinator attempting to aggregate signatures

**Severity Justification:**
This maps to **Low** severity per the protocol scope: "Any remotely-exploitable denial of service in a node." The attack:
- Prevents signature generation (DoS)
- Does not allow invalid signatures to be accepted
- Does not compromise private keys or enable unauthorized signing
- Requires the attacker to be a valid signer in the configuration
- Is detectable (signature verification consistently fails)

## Likelihood Explanation

**Required Attacker Capabilities:**
- Must be a valid signer in the WSTS configuration with assigned key_ids
- Must have network access to send NonceResponse messages to the coordinator
- No cryptographic breaks required

**Attack Complexity:**
Low. The attacker simply needs to:
1. Receive a NonceRequest from the coordinator
2. Generate valid nonces
3. Modify their NonceResponse to include duplicate key_ids (e.g., change `[3, 4]` to `[3, 3, 4]`)
4. Send the modified response

**Economic Feasibility:**
The attack is essentially free for a malicious insider who is already a valid signer. There are no significant costs.

**Detection Risk:**
High detection probability:
- Signature verification will consistently fail for all rounds involving the attacker
- Logs will show the specific signer_id involved in failed rounds
- The pattern is easy to identify after 1-2 failed rounds

**Probability of Success:**
100% success at causing DoS if the attacker is a valid signer. However:
- The attack is easily detected and mitigated by removing the malicious signer
- The impact is limited to signing rounds requiring that signer
- Does not allow the attacker to create valid signatures or bypass security controls

## Recommendation

Add validation to check for duplicate key_ids before the HashSet conversion. The fix should be applied to both FROST and FIRE coordinators:

```rust
// Check for duplicates before converting to HashSet
let nonce_response_key_ids: Vec<u32> = nonce_response.key_ids.iter().cloned().collect();
let nonce_response_key_ids_set: HashSet<u32> = nonce_response_key_ids.iter().cloned().collect();

// If the lengths differ, there were duplicates
if nonce_response_key_ids.len() != nonce_response_key_ids_set.len() {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response contains duplicate key_ids");
    return Ok(());
}

// Now perform the existing validation
if *signer_key_ids != nonce_response_key_ids_set {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
    return Ok(());
}
```

Alternatively, validate that the original Vec has no duplicates by checking length equality:

```rust
let nonce_response_key_ids = nonce_response
    .key_ids
    .iter()
    .cloned()
    .collect::<HashSet<u32>>();

// Reject if duplicates were removed during conversion
if nonce_response.key_ids.len() != nonce_response_key_ids.len() {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response contains duplicate key_ids");
    return Ok(());
}

if *signer_key_ids != nonce_response_key_ids {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
    return Ok(());
}
```

## Proof of Concept

```rust
#[test]
fn test_duplicate_key_ids_bypass_validation() {
    use crate::state_machine::coordinator::frost::Coordinator;
    use crate::net::{NonceResponse, Message, Packet};
    use crate::common::PublicNonce;
    
    // Setup coordinator with signer having key_ids {1, 2}
    let mut coordinator = setup_test_coordinator();
    
    // Craft malicious NonceResponse with duplicate key_ids [1, 1, 2]
    let malicious_nonce_response = NonceResponse {
        dkg_id: coordinator.current_dkg_id,
        sign_id: coordinator.current_sign_id,
        sign_iter_id: coordinator.current_sign_iter_id,
        signer_id: 0,
        key_ids: vec![1, 1, 2], // Duplicate key_id 1
        nonces: vec![PublicNonce::random(), PublicNonce::random()],
        message: vec![0u8; 32],
    };
    
    let packet = Packet {
        sig: malicious_nonce_response.sign(&signer_private_key).unwrap(),
        msg: Message::NonceResponse(malicious_nonce_response),
    };
    
    // This should fail validation but currently passes due to HashSet conversion
    let result = coordinator.gather_nonces(&packet, SignatureType::Frost);
    
    // Verify the malicious nonce was accepted
    assert!(result.is_ok());
    assert!(coordinator.public_nonces.contains_key(&0));
    
    // Verify the stored NonceResponse still contains duplicates
    let stored_response = &coordinator.public_nonces[&0];
    assert_eq!(stored_response.key_ids, vec![1, 1, 2]); // Duplicates preserved!
    
    // When SignatureShareRequest is created, duplicates propagate to all signers
    // causing incorrect Lagrange coefficient computation and signature failure
}
```

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

**File:** src/state_machine/coordinator/frost.rs (L571-578)
```rust
        let nonce_responses = (0..self.config.num_signers)
            .map(|i| self.public_nonces[&i].clone())
            .collect::<Vec<NonceResponse>>();
        let sig_share_request = SignatureShareRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            nonce_responses,
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

**File:** src/state_machine/signer/mod.rs (L800-804)
```rust
            let key_ids: Vec<u32> = sign_request
                .nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.iter().copied())
                .collect::<Vec<u32>>();
```

**File:** src/state_machine/signer/mod.rs (L808-818)
```rust
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

**File:** src/v2.rs (L263-265)
```rust
        for key_id in self.key_ids.iter() {
            cx += c * &self.private_keys[key_id] * compute::lambda(*key_id, key_ids);
        }
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
