### Title
Missing Nonce Count Validation Allows Denial of Service in Signing Rounds

### Summary
The `gather_nonces()` function in both FROST and FIRE coordinator implementations fails to validate that the number of nonces matches the number of key_ids in each `NonceResponse`. This allows a malicious or buggy signer to cause signing rounds to fail by sending mismatched counts, resulting in incorrect aggregate nonce computation and signature verification failures.

### Finding Description

**Exact Code Location:**

The vulnerability exists in two locations:

1. FROST coordinator: [1](#0-0) 

2. FIRE coordinator: [2](#0-1) 

**Root Cause:**

Both implementations validate that the `key_ids` in a `NonceResponse` match the expected configuration (checking set equality), and validate that each individual nonce is valid (non-zero, not the generator point). However, neither implementation validates that `nonces.len() == key_ids.len()`.

The `NonceResponse` structure contains two separate vectors: [3](#0-2) 

When computing the aggregate nonce, both coordinators use `flat_map` to extract all key_ids and all nonces from all responses into separate vectors: [4](#0-3) 

If any `NonceResponse` has mismatched counts, the resulting `party_ids` and `nonces` vectors will have different lengths.

These mismatched-length vectors are then passed to `compute::intermediate()`: [5](#0-4) 

The `zip` operation on line 90 silently truncates to the shorter length, causing nonces to be paired with incorrect party IDs and binding values, resulting in an invalid aggregate nonce.

**Why Existing Mitigations Fail:**

The existing validation checks key_id set equality and individual nonce validity, but completely misses the structural requirement that each key_id must have exactly one corresponding nonce. The code assumes this invariant without enforcing it.

### Impact Explanation

**Specific Harm:**
A malicious or buggy signer can cause any signing round they participate in to fail by sending a `NonceResponse` with mismatched nonce and key_id counts (e.g., 3 key_ids but only 2 nonces). The coordinator will accept this response, compute an incorrect aggregate nonce, and send a `SignatureShareRequest` that causes honest signers to produce invalid signature shares. The aggregated signature will fail verification, causing the signing round to abort.

**Quantified Impact:**
- Any single signer can unilaterally abort signing rounds they participate in
- Affects all signature types (FROST, Schnorr, Taproot)
- No recovery mechanism exists within the signing round
- Requires coordinator to restart the signing round with a new nonce request

**Who is Affected:**
All nodes relying on the affected coordinator for signing operations. If a malicious signer is frequently included in signing committees, this can create sustained denial of service.

**Severity Justification:**
This maps to **Low** severity per the protocol scope: "Any remotely-exploitable denial of service in a node" and "Any network denial of service impacting more than 10 percent of miners that does not shut down the network." A single malicious signer can disrupt signing operations but cannot cause consensus failures, chain splits, or funds loss.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Must be a registered signer with valid credentials
- Must be included in a signing round (selected by the coordinator)
- No cryptographic breaks required
- No special network position required

**Attack Complexity:**
Trivial. The attacker simply sends a `NonceResponse` with mismatched vector lengths:
```
NonceResponse {
    key_ids: vec![1, 2, 3],  // 3 key IDs
    nonces: vec![nonce1, nonce2],  // only 2 nonces
    ...
}
```

**Economic Feasibility:**
Minimal cost. The attack requires only sending a single malformed message per signing round.

**Detection Risk:**
Low. The malicious response passes all validation checks and only causes signing to fail, which could be attributed to network issues or honest errors.

**Estimated Probability:**
High. Any signer can execute this attack at will with 100% success rate for any signing round they participate in.

### Recommendation

**Proposed Code Changes:**

Add explicit validation in both FROST and FIRE coordinator `gather_nonces()` functions immediately after key_ids validation:

```rust
// After line 521 in frost.rs and line 889 in fire.rs
if nonce_response.nonces.len() != nonce_response.key_ids.len() {
    warn!(
        signer_id = %nonce_response.signer_id,
        nonces_len = %nonce_response.nonces.len(),
        key_ids_len = %nonce_response.key_ids.len(),
        "Nonce count does not match key_ids count"
    );
    return Ok(());
}
```

Additionally, add the same validation in the signer's `sign_share_request()` function after line 795 in `src/state_machine/signer/mod.rs` to detect malicious coordinators attempting the same attack.

**Testing Recommendations:**
1. Add unit tests that send `NonceResponse` with fewer nonces than key_ids
2. Add unit tests that send `NonceResponse` with more nonces than key_ids  
3. Add integration tests that verify signing rounds fail gracefully with proper error messages
4. Add fuzz testing to catch similar structural mismatches in other message types

**Deployment Considerations:**
This fix has no impact on legitimate signers and can be deployed immediately. It only rejects messages that would have caused signing failures anyway.

### Proof of Concept

**Exploitation Steps:**

1. Malicious signer registers with key_ids [1, 2, 3]
2. Coordinator starts signing round and requests nonces
3. Honest signers send valid `NonceResponse` messages
4. Malicious signer sends:
   ```
   NonceResponse {
       dkg_id: <correct>,
       sign_id: <correct>,
       sign_iter_id: <correct>,
       signer_id: <attacker_id>,
       key_ids: vec![1, 2, 3],  // 3 key IDs
       nonces: vec![D1/E1, D2/E2],  // only 2 nonces
       message: <correct>
   }
   ```
5. Coordinator accepts this response (passes all existing validations)
6. When computing aggregate nonce:
   - Extracts party_ids: [... honest signers ..., 1, 2, 3]
   - Extracts nonces: [... honest nonces ..., D1/E1, D2/E2]
   - Vectors have mismatched lengths
7. `compute::intermediate()` uses `zip`, silently truncating
8. Aggregate nonce R is computed incorrectly
9. Coordinator sends `SignatureShareRequest` with incorrect R
10. Honest signers compute signature shares using incorrect aggregate nonce
11. Aggregated signature fails verification
12. Signing round aborts

**Expected vs Actual Behavior:**

Expected: `gather_nonces()` should reject `NonceResponse` with mismatched counts and log malicious signer

Actual: Coordinator accepts the message and proceeds to compute invalid aggregate nonce, causing signing failure

**Reproduction:**
Use the test infrastructure in `src/state_machine/coordinator/mod.rs` test module, modify the `feedback_mutated_messages` helper to inject a `NonceResponse` with `nonces.len() != key_ids.len()` during a signing round, and observe that the signing round fails without detecting the malicious signer.

### Citations

**File:** src/state_machine/coordinator/frost.rs (L502-533)
```rust
            // check that the key_ids match the config
            let Some(signer_key_ids) = self
                .config
                .public_keys
                .signer_key_ids
                .get(&nonce_response.signer_id)
            else {
                warn!(signer_id = %nonce_response.signer_id, "No keys IDs configured");
                return Ok(());
            };

            let nonce_response_key_ids = nonce_response
                .key_ids
                .iter()
                .cloned()
                .collect::<HashSet<u32>>();
            if *signer_key_ids != nonce_response_key_ids {
                warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
                return Ok(());
            }

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

**File:** src/state_machine/coordinator/fire.rs (L870-901)
```rust
            // check that the key_ids match the config
            let Some(signer_key_ids) = self
                .config
                .public_keys
                .signer_key_ids
                .get(&nonce_response.signer_id)
            else {
                warn!(signer_id = %nonce_response.signer_id, "No keys IDs configured");
                return Ok(());
            };

            let nonce_response_key_ids = nonce_response
                .key_ids
                .iter()
                .cloned()
                .collect::<HashSet<u32>>();
            if *signer_key_ids != nonce_response_key_ids {
                warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
                return Ok(());
            }

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

**File:** src/net.rs (L311-326)
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
}
```

**File:** src/compute.rs (L85-95)
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
```
