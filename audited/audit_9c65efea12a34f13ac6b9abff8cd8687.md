### Title
Missing Duplicate Key ID Validation Enables Signature Generation Denial of Service

### Summary
The `compute_intermediate()` function does not validate that `key_ids` contains no duplicates or that all values are within valid bounds. A malicious signer can exploit the coordinator's HashSet-based validation to inject duplicate key IDs into the signing protocol, causing all honest signers to compute incorrect Lagrange coefficients and produce invalid signature shares, resulting in signature generation failure.

### Finding Description

**Exact Code Location:**

The `compute::intermediate()` function performs no validation on the `party_ids` parameter: [1](#0-0) 

The `Signer` trait implementations directly pass key_ids to this function without validation: [2](#0-1) [3](#0-2) 

**Root Cause:**

The coordinator validates incoming `NonceResponse` messages by converting the received `key_ids` to a HashSet and comparing against configured key IDs: [4](#0-3) 

This validation **passes** even when the original `nonce_response.key_ids` contains duplicates (e.g., `[1, 2, 3, 3]`) because the HashSet conversion automatically removes duplicates before comparison. The original `NonceResponse` with duplicates is then stored: [5](#0-4) 

**Why Existing Mitigations Fail:**

The coordinator creates `SignatureShareRequest` messages by directly collecting stored `NonceResponse` objects without additional validation: [6](#0-5) 

When signers process this request, they extract all key_ids using `flat_map`, which preserves duplicates: [7](#0-6) 

These duplicate key_ids are then used in signature share computation, specifically in the `compute::lambda()` function: [8](#0-7) 

When `lambda()` receives duplicate key_ids (e.g., `[1, 2, 3, 3]`), it multiplies the Lagrange coefficient by the same factor multiple times (for the duplicate `j=3`), producing mathematically incorrect values.

### Impact Explanation

**Specific Harm:**
A single malicious signer can prevent the entire signing group from producing valid signatures by sending a `NonceResponse` with duplicate key IDs. All honest signers will compute incorrect Lagrange coefficients, produce invalid signature shares, and cause aggregate signature verification to fail.

**Quantified Impact:**
- **Denial of Service**: Signature generation completely fails for all messages in the affected signing round
- **Scope**: Affects all participating signers and the coordinator
- **Duration**: Persists until the malicious signer is identified and removed, or a new signing round is initiated

**Who Is Affected:**
All participants in a signing ceremony where at least one malicious signer sends duplicate key IDs in their `NonceResponse`.

**Severity Justification:**
This vulnerability maps to **Low severity** under the protocol scope definition: "Any remotely-exploitable denial of service in a node." The attack:
- Does NOT cause direct fund loss
- Does NOT cause chain splits or invalid transaction confirmations
- Does NOT shut down the network
- Is a DoS attack that prevents valid signatures from being created
- Is detectable when signature verification fails

### Likelihood Explanation

**Required Attacker Capabilities:**
- Attacker must be a legitimate signer in the DKG group
- Attacker must have completed DKG successfully and possess valid private keys
- Attacker can modify their signer implementation to return duplicate key_ids

**Attack Complexity:**
Low. The attacker simply needs to modify their `NonceResponse` message to include duplicate key_ids before sending to the coordinator.

**Economic Feasibility:**
High. No additional resources required beyond being a participant in the signing group.

**Detection Risk:**
High. The attack is immediately detected when the aggregate signature fails verification. However, identifying which specific signer sent duplicate key_ids requires inspecting stored `NonceResponse` messages.

**Estimated Probability:**
High for a motivated malicious signer, as the attack is trivial to execute and guaranteed to succeed.

### Recommendation

**Proposed Code Changes:**

1. Add explicit validation in the coordinator's `gather_nonces` method to check for duplicate key_ids before storing the `NonceResponse`:

```rust
// After line 885 in src/state_machine/coordinator/fire.rs
if nonce_response.key_ids.len() != nonce_response_key_ids.len() {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response contains duplicate key_ids");
    return Ok(());
}
```

2. Add a validation function in `compute::intermediate()` or before calling it to verify:
   - No duplicate party_ids
   - All party_ids are within valid range [1, num_keys]
   - Length of party_ids matches length of nonces

3. Add similar validation in `compute::lambda()` to detect and reject duplicate key_ids.

**Alternative Mitigations:**
- Store key_ids as HashSet in `NonceResponse` to prevent duplicates at the data structure level
- Add comprehensive validation in signers' `sign_share_request()` to reject malformed requests

**Testing Recommendations:**
- Add unit tests with duplicate key_ids in `NonceResponse` to verify rejection
- Add integration tests simulating malicious signer behavior
- Test edge cases: empty key_ids, out-of-range values, mismatched lengths

**Deployment Considerations:**
- This is a protocol-level fix requiring coordinator upgrade
- Backward compatibility: reject messages with duplicate key_ids
- Monitor for failed signature attempts to detect attacks

### Proof of Concept

**Exploitation Algorithm:**

1. Malicious signer receives `NonceRequest` from coordinator
2. Signer generates valid nonces using `gen_nonces()`
3. Instead of using `get_key_ids()` directly, signer constructs malicious key_ids:
   ```
   Original: [1, 2, 3]
   Malicious: [1, 2, 3, 3]  // Add duplicate
   ```
4. Signer creates `NonceResponse` with duplicate key_ids and sends to coordinator
5. Coordinator validates: `{1,2,3} == {1,2,3}` → PASSES
6. Coordinator stores malicious `NonceResponse` and broadcasts in `SignatureShareRequest`
7. All honest signers extract key_ids: `[..., 1, 2, 3, 3, ...]`
8. All honest signers compute `lambda(i, [1, 2, 3, 3])` with incorrect multiplication
9. All signature shares have incorrect `z_i` values
10. Aggregation produces invalid signature
11. Signature verification fails

**Expected vs Actual Behavior:**

Expected (with key_ids=[1,2,3]):
- `lambda(1, [1,2,3])` = 1 × (2/(2-1)) × (3/(3-1)) = 3

Actual (with key_ids=[1,2,3,3]):
- `lambda(1, [1,2,3,3])` = 1 × (2/(2-1)) × (3/(3-1)) × (3/(3-1)) = 9/2

**Reproduction Instructions:**

1. Set up a signing group with threshold signature configuration
2. Modify one signer's `nonce_request()` handler to inject duplicate key_ids
3. Initiate a signing round
4. Observe that signature verification fails with `AggregatorError`
5. Inspect stored `NonceResponse` messages to identify duplicates

**Notes:**

The vulnerability exists in both the v1 and v2 implementations, though v2 uses `signer_ids` instead of `key_ids` in some contexts. The same HashSet validation pattern is used in both coordinator implementations (fire.rs and frost.rs), making both vulnerable to this attack. The configured `PublicKeys` are validated to have key_ids within range [1, num_keys], but this validation does not protect against duplicate key_ids in runtime messages.

### Citations

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

**File:** src/compute.rs (L85-96)
```rust
pub fn intermediate(msg: &[u8], party_ids: &[u32], nonces: &[PublicNonce]) -> (Vec<Point>, Point) {
    let rhos: Vec<Scalar> = party_ids
        .iter()
        .map(|&i| binding(&id(i), nonces, msg))
        .collect();
    let R_vec: Vec<Point> = zip(nonces, rhos)
        .map(|(nonce, rho)| nonce.D + rho * nonce.E)
        .collect();

    let R = R_vec.iter().fold(Point::zero(), |R, &R_i| R + R_i);
    (R_vec, R)
}
```

**File:** src/v1.rs (L687-694)
```rust
    fn compute_intermediate(
        msg: &[u8],
        _signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> (Vec<Point>, Point) {
        compute::intermediate(msg, key_ids, nonces)
    }
```

**File:** src/v2.rs (L635-642)
```rust
    fn compute_intermediate(
        msg: &[u8],
        signer_ids: &[u32],
        _key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> (Vec<Point>, Point) {
        compute::intermediate(msg, signer_ids, nonces)
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

**File:** src/state_machine/signer/mod.rs (L800-804)
```rust
            let key_ids: Vec<u32> = sign_request
                .nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.iter().copied())
                .collect::<Vec<u32>>();
```
