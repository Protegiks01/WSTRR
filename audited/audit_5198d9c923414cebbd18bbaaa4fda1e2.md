### Title
Duplicate Key IDs in NonceResponse Bypass Validation and Corrupt Lagrange Coefficient Computation

### Summary
A malicious signer can send NonceResponse messages with duplicate key_ids that pass coordinator validation but cause incorrect Lagrange coefficient computation during signature aggregation. The validation logic converts key_ids to a HashSet before comparison, masking duplicates, while the original vector with duplicates is stored and later used for cryptographic operations. This results in signature verification failure and prevents successful signing rounds.

### Finding Description

The vulnerability exists in the coordinator's NonceResponse validation logic. In both `frost.rs` and `fire.rs` coordinators, when validating a NonceResponse, the code converts the `key_ids` vector to a HashSet before comparing against the configured signer_key_ids: [1](#0-0) [2](#0-1) 

The NonceResponse struct stores key_ids as a Vec<u32>, not a HashSet: [3](#0-2) 

**Root Cause**: The validation converts `nonce_response.key_ids` to a HashSet, which automatically removes duplicates. The comparison then checks if this deduplicated set equals the configured `signer_key_ids`. If a malicious signer sends key_ids `[1, 1, 2]` and the configuration expects `{1, 2}`, the validation passes because `HashSet::from([1, 1, 2])` equals `{1, 2}`. However, the original NonceResponse with duplicate key_ids is stored and used later.

When collecting key_ids for signature aggregation, the coordinator uses flat_map on the stored NonceResponses, preserving duplicates: [4](#0-3) 

These duplicate key_ids are then passed to the aggregator and used in Lagrange coefficient computation: [5](#0-4) 

While the `if i != *j` check at line 74 prevents division by zero, duplicate values in `key_ids` cause the Lagrange coefficient to be computed incorrectly. For example, `lambda(2, [1, 1, 2])` would multiply by `(1/(1-2))` twice, yielding 1, whereas the correct `lambda(2, [1, 2])` should yield -1.

The aggregator uses these incorrect Lagrange coefficients during signature verification: [6](#0-5) 

**Why Existing Mitigations Fail**: The validation correctly checks that key_ids match the configuration, but the HashSet conversion masks the presence of duplicates in the original vector. No validation exists to ensure key_ids uniqueness within a single NonceResponse message.

### Impact Explanation

**Specific Harm**: A malicious signer can prevent signing rounds from completing successfully. When duplicate key_ids are present, the Lagrange coefficient computation produces incorrect values, causing signature aggregation to fail. Additionally, the `check_signature_shares` function uses the same corrupted key_ids list to identify malicious parties, potentially causing honest signers to be incorrectly flagged as malicious.

**Quantified Impact**: Any signing round where a single signer sends a NonceResponse with duplicate key_ids will fail to produce a valid signature. In a system with threshold T out of N signers, one malicious signer can block all signing operations, regardless of how many honest signers participate.

**Affected Parties**: All participants in the WSTS signing protocol are affected. The coordinator cannot complete signing rounds, and honest signers may be incorrectly blamed for signature failures due to incorrect Lagrange coefficient validation.

**Severity Justification**: This vulnerability maps to **Low** severity under the protocol scope: "Any remotely-exploitable denial of service in a node." While it prevents signing operations from succeeding, it does not cause direct fund loss, chain splits, or acceptance of invalid transactions. The attack is remotely exploitable by any participant in the signing protocol.

### Likelihood Explanation

**Required Attacker Capabilities**: The attacker must be a legitimate signer in the WSTS protocol with the ability to send network messages to the coordinator. They must modify their client code to construct NonceResponse messages with duplicate key_ids.

**Attack Complexity**: Low. The attacker only needs to:
1. Modify the NonceResponse construction to include duplicate key_ids
2. Send the crafted message to the coordinator
3. No cryptographic operations or complex timing required

**Economic Feasibility**: Trivial. The attack requires no special resources beyond being a participant in the signing protocol.

**Detection Risk**: Moderate to High. The coordinator logs NonceResponse receipt but does not validate for duplicates. The attack would be detected when signature verification fails, but the coordinator's diagnostic logic may incorrectly blame honest signers due to corrupted Lagrange coefficients in `check_signature_shares`.

**Estimated Probability**: High likelihood if any signer is malicious or misconfigured. The vulnerability is deterministic and requires no special conditions beyond a single malformed NonceResponse.

### Recommendation

**Primary Fix**: Add explicit validation to reject NonceResponse messages containing duplicate key_ids. In both coordinator implementations, after receiving a NonceResponse and before the HashSet conversion, check for uniqueness:

```rust
// Check for duplicate key_ids
let key_id_set: HashSet<u32> = nonce_response.key_ids.iter().cloned().collect();
if key_id_set.len() != nonce_response.key_ids.len() {
    warn!(signer_id = %nonce_response.signer_id, "NonceResponse contains duplicate key_ids");
    return Ok(());
}
```

Apply this check in:
- `src/state_machine/coordinator/frost.rs` before line 513
- `src/state_machine/coordinator/fire.rs` before line 881

**Secondary Fix**: Add validation in the signer state machine constructor to prevent signers from being created with duplicate key_ids: [7](#0-6) 

Add after line 312:
```rust
// Check for duplicate key_ids
let key_id_set: HashSet<u32> = key_ids.iter().cloned().collect();
if key_id_set.len() != key_ids.len() {
    return Err(Error::Config(ConfigError::DuplicateKeyId));
}
```

**Testing Recommendations**: Add unit tests that:
1. Attempt to create a signer with duplicate key_ids and verify it fails
2. Send NonceResponse with duplicate key_ids to coordinator and verify rejection
3. Verify lambda function behavior with duplicate inputs (for regression testing)

**Deployment Considerations**: This fix should be deployed immediately as it prevents a trivial DoS attack. The change is backward compatible as legitimate signers should never have duplicate key_ids.

### Proof of Concept

**Exploitation Algorithm**:

1. **Setup**: Assume a 2-of-3 threshold signature scheme with signers controlling key_ids as configured:
   - Signer 0: {1}
   - Signer 1: {2}
   - Malicious Signer 2: {3}

2. **Malicious Signer Action**: Signer 2 modifies their code to construct NonceResponse with duplicate key_ids:
   ```rust
   let response = NonceResponse {
       dkg_id: request.dkg_id,
       sign_id: request.sign_id,
       sign_iter_id: request.sign_iter_id,
       signer_id: 2,
       key_ids: vec![3, 3],  // Duplicate!
       nonces: vec![nonce1, nonce2],
       message: request.message.clone(),
   };
   ```

3. **Coordinator Processing**: 
   - Coordinator receives NonceResponse at frost.rs line 513
   - Converts `vec![3, 3]` to `HashSet {3}`
   - Compares against configured `signer_key_ids[2] = {3}` 
   - Validation passes! NonceResponse accepted.

4. **Key Collection for Signing** (frost.rs line 675-678):
   - Collects all key_ids: `[1, 2, 3, 3]`
   - Note duplicates preserved

5. **Aggregation**: Aggregator computes with incorrect Lagrange coefficients:
   - `lambda(1, [1, 2, 3, 3])` = `2/(2-1) * 3/(3-1) * 3/(3-1)` = `2 * 3/2 * 3/2` = `9/2`
   - Correct `lambda(1, [1, 2, 3])` = `2/(2-1) * 3/(3-1)` = `2 * 3/2` = `3`
   - Incorrect coefficient used in signature computation

6. **Result**: Signature verification fails at v1.rs line 466

**Expected vs Actual Behavior**:
- Expected: Coordinator rejects NonceResponse with duplicate key_ids
- Actual: Coordinator accepts NonceResponse, signature verification fails, signing round aborted

**Reproduction**: Modify any WSTS integration test to send a NonceResponse with duplicate key_ids and observe signature verification failure.

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

**File:** src/net.rs (L311-325)
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

**File:** src/v1.rs (L399-417)
```rust
        for i in 0..sig_shares.len() {
            let id = compute::id(sig_shares[i].id);
            let public_key = match compute::poly(&id, &self.poly) {
                Ok(p) => p,
                Err(_) => {
                    bad_party_keys.push(sig_shares[i].id);
                    Point::zero()
                }
            };

            let z_i = sig_shares[i].z_i;

            if z_i * G
                != r_sign * Rs[i]
                    + cx_sign * (compute::lambda(sig_shares[i].id, &signers) * c * public_key)
            {
                bad_party_sigs.push(sig_shares[i].id);
            }
        }
```

**File:** src/state_machine/signer/mod.rs (L308-312)
```rust
        for key_id in &key_ids {
            if !validate_key_id(*key_id, total_keys) {
                return Err(Error::Config(ConfigError::InvalidKeyId(*key_id)));
            }
        }
```
