### Title
Arithmetic Overflow in DKG Operations Due to Insufficient Validation of total_keys Parameter

### Summary
The validation in `Signer::new()` at lines 292-294 does not prevent the edge case where `total_signers` is 1 and `total_keys` is `u32::MAX`. This allows arithmetic overflows in multiple DKG operations, specifically in the computation of key share ranges where `num_keys + 1` wraps to 0, causing `get_shares()` to return an empty HashMap and resulting in complete DKG failure.

### Finding Description

**Exact Code Locations:**

The insufficient validation exists in: [1](#0-0) 

This validation only checks if `total_signers > total_keys` but does not prevent `total_keys = u32::MAX`. When `total_keys = u32::MAX`, arithmetic overflows occur at multiple critical locations:

**Overflow Location 1 - v1.rs:** [2](#0-1) 

**Overflow Location 2 - v2.rs:** [3](#0-2) 

**Overflow Location 3 - FROST Coordinator:** [4](#0-3) 

**Overflow Location 4 - FIRE Coordinator:** [5](#0-4) 

**Root Cause:**

The root cause is that the validation logic assumes `total_keys` will be a reasonable value and does not account for the maximum value case. In Rust, `u32::MAX + 1` wraps to 0 in release mode, causing the range expressions `1..num_keys + 1` to become `1..0`, which is an empty range.

**Why Existing Mitigations Fail:**

The threshold validation at lines 296-298 checks `if threshold == 0 || threshold > total_keys` but does not prevent `total_keys = u32::MAX`: [6](#0-5) 

The `PublicKeys::validate()` function only validates individual key IDs against the range, not the `num_keys` parameter itself: [7](#0-6) 

The `validate_key_id()` helper checks `key_id > 0 && key_id <= num_keys`, which allows all values when `num_keys = u32::MAX`: [8](#0-7) 

### Impact Explanation

**Specific Harm:**

When `total_keys = u32::MAX`, the DKG protocol fails completely:

1. In v1 and v2 implementations, `get_shares()` returns an empty HashMap because the loop range `1..0` executes zero iterations
2. No private shares are generated or distributed during DKG
3. The DKG protocol cannot complete, preventing group key generation
4. Without a valid group key, no threshold signatures can be produced

**Quantified Impact:**

- **Complete DKG Failure**: 100% of DKG attempts fail when `total_keys = u32::MAX`
- **No Group Key Generation**: The aggregate public key cannot be computed
- **Chain-level Impact**: If WSTS is used in Stacks blockchain or similar systems, this prevents signing of new transactions, causing the network to halt

**Affected Parties:**

All participants in a DKG round where `total_keys = u32::MAX` is configured. The entire signing group is unable to generate keys or produce signatures.

**Severity Justification:**

This maps to **Critical** severity under the protocol scope definition: "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks." The complete failure of DKG prevents transaction confirmation indefinitely until the configuration is corrected and DKG is restarted with valid parameters.

### Likelihood Explanation

**Required Attacker Capabilities:**

The attacker must be able to control or influence the initialization parameters passed to `Signer::new()` or `Coordinator::new()`. This could occur through:
- A compromised or malicious coordinator
- Untrusted configuration files or network messages
- An API endpoint that accepts user-supplied DKG parameters without proper validation

**Attack Complexity:**

Low. The attacker simply needs to set `total_keys = u32::MAX` during initialization. No cryptographic operations or complex timing attacks are required.

**Attack Steps:**
1. Attacker controls initialization of Signer or Coordinator
2. Set parameters: `total_signers = 1`, `total_keys = u32::MAX`, `threshold = u32::MAX`
3. Validation at lines 292-294 passes because `1 > u32::MAX` is false
4. During DKG, `get_shares()` produces empty HashMap due to overflow
5. DKG fails; no group key is generated
6. Network cannot produce signatures

**Economic Feasibility:**

No economic cost required beyond gaining access to configuration parameters.

**Detection Risk:**

Medium. The DKG failure would be observable through monitoring, but may initially appear as a configuration error rather than a deliberate attack.

**Estimated Probability:**

- If parameters come from untrusted sources: High
- If coordinator or setup is compromised: High  
- If parameters are hardcoded or properly validated elsewhere: Low

### Recommendation

**Primary Fix:**

Add an explicit check in `Signer::new()` to reject unreasonably large `total_keys` values:

```rust
// After line 294, add:
if total_keys == u32::MAX {
    return Err(Error::Config(ConfigError::InvalidThreshold));
}
```

Or use saturating arithmetic in the affected loops:

```rust
// In v1.rs and v2.rs, replace:
for i in 1..self.num_keys + 1 {
// With:
for i in 1..self.num_keys.saturating_add(1) {
```

However, note that even with saturating arithmetic, `u32::MAX` is an unrealistic value for `num_keys` that should be rejected at validation time.

**Recommended Approach:**

Implement a reasonable upper bound check:

```rust
const MAX_KEYS: u32 = 10_000_000; // Or appropriate limit

if total_keys > MAX_KEYS {
    return Err(Error::Config(ConfigError::InvalidKeyId(total_keys)));
}
```

**Testing Recommendations:**

1. Add unit tests that attempt to create Signer with `total_keys = u32::MAX` and verify it's rejected
2. Add integration tests for boundary values: `u32::MAX`, `u32::MAX - 1`, etc.
3. Verify that `get_shares()` produces the expected number of shares for valid configurations

**Deployment Considerations:**

This is a breaking change that adds stricter validation. Document the maximum supported `total_keys` value and ensure existing deployments are within the limit before upgrading.

### Proof of Concept

**Exploitation Algorithm:**

```
1. Initialize Signer with:
   - total_signers = 1
   - total_keys = u32::MAX (4,294,967,295)
   - threshold = u32::MAX
   - signer_id = 0
   - key_ids = [1]

2. Validation passes:
   - Line 292: 1 > 4294967295 → false, passes
   - Line 296: u32::MAX == 0 → false, u32::MAX > u32::MAX → false, passes
   - Line 304: validate_signer_id(0, 1) → 0 < 1 → true, passes
   - Line 309: validate_key_id(1, u32::MAX) → 1 > 0 && 1 <= u32::MAX → true, passes

3. During DKG, in get_shares():
   - Loop: for i in 1..self.num_keys + 1
   - Evaluates: for i in 1..(u32::MAX + 1)
   - u32::MAX + 1 wraps to 0 in release mode
   - Range becomes: 1..0 (empty)
   - No iterations execute
   - Returns empty HashMap

4. DKG fails:
   - No shares generated
   - Cannot compute secrets
   - Group key generation impossible
```

**Expected vs Actual Behavior:**

- **Expected**: Validation rejects `total_keys = u32::MAX` as invalid
- **Actual**: Validation passes, DKG proceeds but fails due to empty shares

**Reproduction Steps:**

1. Create a test Signer with the parameters above
2. Call `get_shares()` or initiate DKG
3. Observe that the returned shares HashMap is empty
4. Verify that DKG cannot complete

**Notes**

While `total_keys = u32::MAX` is an extreme and unrealistic value in practice, the lack of validation represents a fundamental gap in input validation that could be exploited if parameters come from untrusted sources. The validation should explicitly reject values that would cause arithmetic overflow in downstream operations, following secure coding practices for systems that handle critical cryptographic operations.

### Citations

**File:** src/state_machine/signer/mod.rs (L292-294)
```rust
        if total_signers > total_keys {
            return Err(Error::Config(ConfigError::InsufficientKeys));
        }
```

**File:** src/state_machine/signer/mod.rs (L296-298)
```rust
        if threshold == 0 || threshold > total_keys {
            return Err(Error::Config(ConfigError::InvalidThreshold));
        }
```

**File:** src/v1.rs (L139-139)
```rust
            for i in 1..self.num_keys + 1 {
```

**File:** src/v2.rs (L109-109)
```rust
            for i in 1..self.num_keys + 1 {
```

**File:** src/state_machine/coordinator/frost.rs (L257-257)
```rust
            key_ids: (1..self.config.num_keys + 1).collect(),
```

**File:** src/state_machine/coordinator/fire.rs (L191-191)
```rust
                            if self.config.num_keys - num_malicious_keys < self.config.threshold {
```

**File:** src/state_machine/mod.rs (L106-136)
```rust
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

**File:** src/common.rs (L314-316)
```rust
pub fn validate_key_id(key_id: u32, num_keys: u32) -> bool {
    key_id > 0 && key_id <= num_keys
}
```
