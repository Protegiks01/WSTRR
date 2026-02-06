### Title
Duplicate Key IDs in NonceResponse Break Lagrange Interpolation and Cause Signing Denial of Service

### Summary
A malicious signer can send a `NonceResponse` message with duplicate `key_ids`, which bypasses coordinator validation and causes all participants in the signing round to compute incorrect Lagrange coefficients. This results in invalid signature shares that cannot be aggregated, effectively blocking the entire signing round and preventing transaction confirmation.

### Finding Description

The vulnerability exists in the coordinator's validation of `NonceResponse.key_ids` in both FROST and FIRE coordinators: [1](#0-0) [2](#0-1) 

**Root Cause**: The validation converts the received `key_ids` Vec to a HashSet for comparison against the configured key IDs. This de-duplication means that a `NonceResponse` with duplicate key_ids (e.g., `[1, 1, 2]`) passes validation because it matches the expected set `{1, 2}`. However, the original NonceResponse containing duplicates is stored and propagated.

**Propagation Path**: 

1. The coordinator stores the NonceResponse with duplicates unchanged: [3](#0-2) 

2. When creating SignatureShareRequest, the coordinator sends all stored NonceResponses to signers: [4](#0-3) 

3. Signers flatten all key_ids from all NonceResponses WITHOUT de-duplication: [5](#0-4) 

4. Signers compute signature shares using these duplicate key_ids for Lagrange interpolation: [6](#0-5) 

5. The Lagrange coefficient calculation multiplies the same factor multiple times when duplicates exist: [7](#0-6) 

For example, if `key_ids = [1, 2, 2, 3]` and computing lambda for key 1, the loop iterates over all values including both instances of 2, causing `lambda *= 2/(2-1)` to execute twice, doubling the coefficient incorrectly.

6. The coordinator also flattens key_ids without de-duplication for aggregation: [8](#0-7) 

**Why Existing Mitigations Fail**: The signature verification in `check_signature_shares` uses the same incorrect key_ids array with duplicates, so it cannot detect the problem. The HashSet-based validation actually enables the vulnerability by accepting duplicates instead of rejecting them.

### Impact Explanation

**Specific Harm**: A single malicious signer can completely block any signing round by including duplicate key_ids in their NonceResponse. This causes:
1. All honest signers to compute invalid signature shares (wrong Lagrange coefficients)
2. Signature aggregation to fail verification
3. The entire signing round to abort without producing a valid signature

**Quantification**: 
- Attack success rate: 100% - duplicates always break Lagrange interpolation
- Scope: Affects all participants in the signing round
- Duration: Can be repeated indefinitely on subsequent rounds
- Recovery: Requires detecting and removing the malicious signer

**Who Is Affected**: All participants in WSTS signing rounds, including dependent systems that rely on threshold signatures for transaction confirmation.

**Severity Justification**: According to the protocol scope, this maps to **Low** severity as "any remotely-exploitable denial of service in a node." However, given that:
- A single malicious signer (representing >10% of miners in typical configurations) can block signing
- This prevents transaction confirmation for multiple blocks until detected
- The attack is trivial to execute and hard to attribute

This borderlines on **Medium** ("transient consensus failures") severity in practice.

### Likelihood Explanation

**Required Attacker Capabilities**:
- Must be a registered signer in the WSTS system
- Must be able to send network messages (standard signer capability)
- No cryptographic breaks required
- No special privileges beyond normal signer access

**Attack Complexity**: Trivial
1. Receive NonceRequest from coordinator
2. Create NonceResponse with duplicate key_ids (e.g., `[1, 1, 2]` instead of `[1, 2]`)
3. Sign and send the message
4. All subsequent signature shares will be invalid

**Economic Feasibility**: Zero cost to execute, requires no additional resources beyond normal signer operations.

**Detection Risk**: Low to moderate - the duplicate key_ids are visible in network traffic, but may not be immediately obvious as the cause of signing failures. Defenders would need to inspect message contents to identify the malicious signer.

**Estimated Probability of Success**: 100% - the vulnerability is deterministic and cannot be prevented by honest participants once a malicious NonceResponse is accepted.

### Recommendation

**Primary Fix**: Explicitly validate that `key_ids` contains no duplicates before comparing against the configuration:

```rust
// In gather_nonces() for both frost.rs and fire.rs
let nonce_response_key_ids = nonce_response
    .key_ids
    .iter()
    .cloned()
    .collect::<HashSet<u32>>();

// Add this check:
if nonce_response.key_ids.len() != nonce_response_key_ids.len() {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids contains duplicates");
    return Ok(());
}

if *signer_key_ids != nonce_response_key_ids {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
    return Ok(());
}
```

**Alternative Mitigation**: De-duplicate key_ids when flattening in signers and coordinator:
```rust
let key_ids: Vec<u32> = sign_request
    .nonce_responses
    .iter()
    .flat_map(|nr| nr.key_ids.iter().copied())
    .collect::<HashSet<u32>>()  // De-duplicate
    .into_iter()
    .collect();
```

However, this alternative is less safe as it silently accepts malformed messages rather than rejecting them.

**Testing Recommendations**:
1. Add unit tests that send NonceResponse with duplicate key_ids and verify rejection
2. Add integration tests verifying that signature aggregation works correctly only when all key_ids are unique
3. Test the edge case of a signer sending their entire key_id set duplicated

**Deployment Considerations**: This fix should be deployed urgently as it's a simple validation check with no protocol changes required. All coordinators must be updated simultaneously to prevent mixed-version attacks.

### Proof of Concept

**Exploitation Algorithm**:

```
Setup:
- Signer A controls key_ids [1, 2]
- Signer B controls key_ids [3, 4]  
- Threshold = 3 keys

Attack Steps:
1. Coordinator broadcasts NonceRequest(sign_id=X, message=M)

2. Malicious Signer A creates NonceResponse:
   - signer_id: 0
   - key_ids: [1, 1, 2]  // Duplicate key 1
   - nonces: [nonce_1, nonce_2]  // Valid nonces
   - Sign with private key

3. Honest Signer B creates NonceResponse:
   - signer_id: 1
   - key_ids: [3, 4]  // Correct
   - nonces: [nonce_3, nonce_4]
   - Sign with private key

4. Coordinator validation:
   - Converts [1, 1, 2] to HashSet {1, 2}
   - Compares {1, 2} == {1, 2} ✓ PASSES
   - Stores NonceResponse with [1, 1, 2]

5. Coordinator sends SignatureShareRequest with both NonceResponses

6. Signer B computes signature shares:
   - Flattens key_ids: [1, 1, 2, 3, 4]
   - For key 3: lambda(3, [1,1,2,3,4]) = incorrect value
   - Computes signature share with wrong lambda
   - Signature share is invalid

7. Aggregation fails:
   - Coordinator cannot verify signature shares
   - No valid group signature produced
   - Signing round aborted

Expected: Coordinator should reject NonceResponse from Signer A in step 4
Actual: Coordinator accepts it and signing round fails
```

**Reproduction with actual parameters**:
- Set up 2 signers with 2 keys each (total 4 keys, threshold 3)
- Modify Signer 0 to send `key_ids: vec![1, 1]` instead of `vec![1]` in NonceResponse
- Attempt to complete a signing round
- Observe that signature aggregation fails with invalid signature shares

### Notes

While `DkgPrivateBegin` and `DkgEndBegin` structs also contain `signer_ids` and `key_ids` fields, these are handled correctly:

For DKG messages, duplicate signer_ids are automatically de-duplicated when used: [9](#0-8) 

The `key_ids` fields in DKG messages are not actually used in processing, only for documentation/logging purposes.

The vulnerability is specific to the signing phase where `NonceResponse.key_ids` directly affects Lagrange interpolation calculations, creating a critical security invariant violation: "Lagrange interpolation must use the correct key set with no duplicates."

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

**File:** src/state_machine/coordinator/frost.rs (L675-678)
```rust
            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();
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

**File:** src/state_machine/signer/mod.rs (L529-534)
```rust
        let signer_ids_set: HashSet<u32> = dkg_end_begin
            .signer_ids
            .iter()
            .filter(|&&id| id < self.total_signers)
            .copied()
            .collect::<HashSet<u32>>();
```

**File:** src/state_machine/signer/mod.rs (L800-804)
```rust
            let key_ids: Vec<u32> = sign_request
                .nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.iter().copied())
                .collect::<Vec<u32>>();
```

**File:** src/v2.rs (L263-265)
```rust
        for key_id in self.key_ids.iter() {
            cx += c * &self.private_keys[key_id] * compute::lambda(*key_id, key_ids);
        }
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
