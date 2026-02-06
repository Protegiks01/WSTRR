### Title
Duplicate key_ids Bypass Validation and Corrupt Lagrange Interpolation in Threshold Signing

### Summary
The validation loop in `Signer::new()` fails to check for duplicate key_ids, allowing a malicious signer to register with duplicate key IDs (e.g., `[3, 3]` instead of `[3]`). The coordinator's HashSet-based validation deduplicates the key_ids during comparison, inadvertently accepting the malformed NonceResponse. When this response is forwarded to honest signers during signing, the duplicate key_ids corrupt Lagrange coefficient calculations, causing all signatures to fail verification and resulting in denial of service.

### Finding Description

**Exact Code Location:** [1](#0-0) 

The validation loop only verifies that each key_id is within valid bounds (> 0 and ≤ total_keys) but does not check for duplicate values: [2](#0-1) 

**Root Cause:**
The `validate_key_id()` function performs range checking but has no uniqueness constraint. The validation loop iterates through all key_ids without maintaining a set to detect duplicates. This violates the security invariant: "Threshold and key ID bounds must be enforced; no duplicates or out-of-range IDs."

**Why Existing Mitigations Fail:**

The coordinator's validation appears protective but is insufficient: [3](#0-2) 

The coordinator converts `nonce_response.key_ids` to a HashSet for comparison. If a malicious signer sends `key_ids = [3, 3]`, this becomes `{3}`, which matches the configured `{3}`, passing validation. However, the coordinator then forwards the *original* NonceResponse with duplicate key_ids: [4](#0-3) 

When honest signers extract key_ids from the SignatureShareRequest, they include duplicates: [5](#0-4) 

These duplicate key_ids are then passed to signing functions and used in Lagrange interpolation: [6](#0-5) 

The lambda function multiplies by `j/(j-i)` for each occurrence of `j` in the key_ids list. With duplicate key_id 3 appearing twice, a signer with key_id 2 computes:
- Correct: `lambda(2, [1,2,3]) = 1/(1-2) * 3/(3-2) = -1 * 3 = -3`
- Corrupted: `lambda(2, [1,2,3,3]) = 1/(1-2) * 3/(3-2) * 3/(3-2) = -1 * 3 * 3 = -9`

### Impact Explanation

**Specific Harm:**
All signature operations involving the malicious signer fail verification due to incorrect Lagrange coefficients. This prevents the threshold signature protocol from producing valid signatures.

**Quantification:**
- With threshold t=7 and n=10 keys, if 7 signers participate and 1 has duplicate key_ids, 100% of signing attempts fail
- In v1 implementation, the malicious signer generates multiple nonces (one per duplicate), amplifying the corruption
- In v2 implementation, nonce count mismatches cause silent truncation in the intermediate computation, producing invalid aggregate nonces

**Who is Affected:**
All honest participants in any signing round that includes the malicious signer. The coordinator and all other signers waste computational resources on failed signing attempts.

**Severity Justification:**
This maps to **Medium severity** under the protocol scope: "Any transient consensus failures." While not causing permanent damage or fund loss, it prevents signature generation, which could:
- Block critical operations requiring threshold signatures (e.g., Bitcoin peg operations in Stacks)
- Force repeated signing attempts until the malicious signer is excluded
- Cause operational delays in time-sensitive scenarios

The denial of service is transient because excluding the malicious signer from the signing set restores functionality.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Attacker must be a registered signer in the threshold configuration
- Attacker must control signer initialization to pass duplicate key_ids to `Signer::new()`
- No cryptographic breaks required; attack uses protocol logic flaws only

**Attack Complexity:**
Low. The attacker simply needs to:
1. Initialize their signer with `key_ids = vec![k, k]` instead of `vec![k]`
2. Respond normally to nonce requests
3. The malicious data propagates automatically through the protocol

**Economic Feasibility:**
Very high. The attack costs nothing beyond normal participation and wastes other participants' resources.

**Detection Risk:**
Medium. Signature failures are observable, but diagnosing the root cause requires:
- Access to NonceResponse messages to inspect key_ids
- Understanding that duplicates are the cause
- The malicious signer appears to follow protocol normally

**Estimated Probability:**
High in adversarial scenarios where a signer is compromised or intentionally malicious. Low in honest deployments where configuration is derived from HashSet-based PublicKeys structure: [7](#0-6) 

### Recommendation

**Primary Fix:**
Add duplicate detection to the validation loop in `Signer::new()`:

```rust
// After line 312, add:
let mut seen_keys = HashSet::new();
for key_id in &key_ids {
    if !seen_keys.insert(*key_id) {
        return Err(Error::Config(ConfigError::InvalidKeyId(*key_id)));
    }
}
```

**Alternative Mitigation:**
The coordinator should validate that `nonce_response.key_ids.len() == signer_key_ids.len()` in addition to set equality:

```rust
// After line 889, add:
if nonce_response.key_ids.len() != signer_key_ids.len() {
    warn!(signer_id = %nonce_response.signer_id, 
          "Nonce response key_ids count mismatch");
    return Ok(());
}
```

**Testing Recommendations:**
1. Add unit test: `Signer::new()` with duplicate key_ids should return `ConfigError::InvalidKeyId`
2. Add integration test: coordinator should reject NonceResponse with duplicate key_ids
3. Add test verifying lambda() produces different results with and without duplicates

**Deployment Considerations:**
- This is a configuration-time vulnerability; no runtime state migration needed
- Existing signers initialized with duplicate key_ids (if any) must be recreated
- The fix is backward compatible with honest configurations

### Proof of Concept

**Exploitation Algorithm:**

1. **Malicious Signer Initialization:**
   ```
   Setup: 3 signers, threshold=2
   - Honest signer 0: key_ids = [1]
   - Honest signer 1: key_ids = [2]  
   - Malicious signer 2: key_ids = [3, 3]  // DUPLICATE
   ```

2. **Validation Bypass:** [1](#0-0) 
   
   Both instances of key_id=3 pass `validate_key_id(3, 3)` individually.

3. **V1 Specific - Multiple Party Creation:** [8](#0-7) 
   
   Creates two Party objects both with id=3.

4. **Nonce Generation:** [9](#0-8) 
   
   Generates 2 nonces in v1 (one per Party), 1 nonce in v2.

5. **Coordinator Validation (Bypassed):** [3](#0-2) 
   
   `[3, 3] -> {3}` matches configured `{3}` ✓

6. **Corruption During Signing:** [5](#0-4) 
   
   Honest signers extract key_ids: `[1, 2, 3, 3]`

7. **Lambda Corruption:** [10](#0-9) 
   
   For signer 1 (key_id=2):
   - Expected: `lambda(2, [1,2,3]) = -3`
   - Actual: `lambda(2, [1,2,3,3]) = -9`

8. **Signature Failure:**
   All signature shares have incorrect coefficients. Aggregated signature fails verification.

**Expected vs Actual Behavior:**
- Expected: `Signer::new()` rejects duplicate key_ids with `ConfigError::InvalidKeyId`
- Actual: Duplicate key_ids are accepted and corrupt signing operations

**Reproduction Instructions:**
Create a test with malicious signer using `vec![1, 1]` as key_ids, perform DKG and signing, observe signature verification failure.

### Notes

This vulnerability specifically violates the stated security invariant: "Lagrange interpolation must use the correct key set with no duplicates." The gap exists because signer initialization validation and coordinator set-based validation both fail to enforce the uniqueness constraint that downstream cryptographic operations require.

### Citations

**File:** src/state_machine/signer/mod.rs (L308-312)
```rust
        for key_id in &key_ids {
            if !validate_key_id(*key_id, total_keys) {
                return Err(Error::Config(ConfigError::InvalidKeyId(*key_id)));
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

**File:** src/common.rs (L314-316)
```rust
pub fn validate_key_id(key_id: u32, num_keys: u32) -> bool {
    key_id > 0 && key_id <= num_keys
}
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

**File:** src/state_machine/mod.rs (L100-102)
```rust
    /// map of signer_id to controlled key_ids
    pub signer_key_ids: HashMap<u32, HashSet<u32>>,
}
```

**File:** src/v1.rs (L537-540)
```rust
        let parties = key_ids
            .iter()
            .map(|id| Party::new(*id, num_keys, threshold, rng))
            .collect();
```

**File:** src/v1.rs (L681-684)
```rust
        self.parties
            .iter_mut()
            .map(|p| p.gen_nonce(secret_key, rng))
            .collect()
```
