### Title
Duplicate Key IDs in NonceResponse Bypass Validation and Cause Aggregation Failure

### Summary
A malicious signer can send duplicate key IDs in their `NonceResponse` message, which passes HashSet-based validation but causes signature aggregation to fail due to a length mismatch between nonces and signature shares. This results in a denial of service that prevents the signing round from completing, causing transient consensus failures.

### Finding Description

**Location**: `src/state_machine/coordinator/fire.rs`, function `gather_nonces()` lines 881-889 and `compute_aggregate_nonce()` lines 1185-1194; aggregation functions in `src/v1.rs` line 321 and `src/v2.rs` line 304.

**Root Cause**: The validation logic converts the `key_ids` vector to a `HashSet` before comparing it to the configured key IDs, which removes duplicates. [1](#0-0) 

This allows a malicious signer to send a `NonceResponse` with duplicate key IDs (e.g., `[1, 2, 1, 1]`) that becomes `{1, 2}` after HashSet conversion and matches the configured set `{1, 2}`.

When nonces are flattened for aggregation, duplicates are preserved: [2](#0-1) 

However, signers produce only one signature share per unique key ID (iterating over their legitimate parties), not one per flattened nonce. This creates a length mismatch that causes aggregation to fail.

**Why Existing Mitigations Fail**:

1. The validation only checks individual nonce validity (not zero, not generator) but not for duplicates within a single NonceResponse: [3](#0-2) 

2. There is no validation that `key_ids.len() == nonces.len()` within a NonceResponse: [4](#0-3) 

3. The threshold check uses configured key IDs, not the flattened duplicates, so it doesn't detect the issue: [5](#0-4) 

4. The aggregator enforces a length check that fails when duplicates are present: [6](#0-5) 

### Impact Explanation

**Specific Harm**: A malicious signing participant can prevent signature aggregation from completing, causing the signing round to fail. This blocks transaction signing for all participants until the round times out or is restarted.

**Quantified Impact**: 
- Every signing round can be blocked by any malicious signer
- Affects all participants in the signing protocol
- Causes delays in transaction confirmation
- No fund loss, but disrupts normal operation

**Who is Affected**: All honest participants in signing rounds that include the malicious signer.

**Severity Justification**: This maps to **Medium severity** under the protocol scope as "any transient consensus failures." While it doesn't permanently disable the system, it causes signing rounds to fail, preventing valid transactions from being confirmed until the issue is detected and the malicious signer is excluded.

### Likelihood Explanation

**Required Attacker Capabilities**: 
- Must be a valid signing participant with configured key IDs
- Must be included in the signing set for a threshold signature
- No special cryptographic knowledge required

**Attack Complexity**: Trivial. The attacker simply crafts a `NonceResponse` message with duplicate entries in the `key_ids` vector and corresponding duplicate nonces.

**Economic Feasibility**: Zero cost. The attack involves sending a single malformed message per signing round.

**Detection Risk**: The attack is detected only during aggregation when the length mismatch error occurs: [7](#0-6) 

By this point, the signing round has already failed. The coordinator could track which signer sent duplicate key IDs, but the current implementation doesn't prevent the issue upfront.

**Estimated Probability**: Near 100% success rate for causing the intended DoS effect on each signing attempt.

### Recommendation

**Proposed Code Changes**:

1. Add validation in `gather_nonces()` to reject `NonceResponse` messages where `key_ids` contains duplicates:
   ```rust
   let nonce_response_key_ids: HashSet<u32> = nonce_response
       .key_ids
       .iter()
       .cloned()
       .collect();
   
   // Check for duplicates
   if nonce_response.key_ids.len() != nonce_response_key_ids.len() {
       warn!(signer_id = %nonce_response.signer_id, "NonceResponse contains duplicate key_ids");
       return Ok(());
   }
   
   // Check length match
   if nonce_response.key_ids.len() != nonce_response.nonces.len() {
       warn!(signer_id = %nonce_response.signer_id, "NonceResponse key_ids and nonces length mismatch");
       return Ok(());
   }
   ```

2. Add the same validation in the signer's `sign_share_request()` function when processing `SignatureShareRequest` to detect malicious coordinators: [8](#0-7) 

**Testing Recommendations**:
- Add unit tests that attempt to send NonceResponse with duplicate key_ids
- Verify the validation rejects such messages
- Test that legitimate messages with unique key_ids continue to work

**Deployment Considerations**: This is a protocol-level fix that requires all coordinators to be updated. The validation is backward-compatible in the sense that honest signers already send properly-formed messages.

### Proof of Concept

**Exploitation Algorithm**:

1. Malicious signer participates in DKG and has configured key_ids `{1, 2}`

2. When coordinator sends `NonceRequest`, malicious signer generates nonces normally but crafts response with duplicates:
   ```
   NonceResponse {
       key_ids: vec![1, 2, 1, 1],  // Duplicate key_id 1 three times
       nonces: vec![N1, N2, N1_dup1, N1_dup2],  // Four nonces total
       ...
   }
   ```

3. Validation passes because `HashSet::from([1, 2, 1, 1]) == HashSet::from([1, 2])`: [9](#0-8) 

4. Coordinator flattens nonces, preserving duplicates: 4 nonces in flattened array

5. When producing signature shares, malicious signer iterates over 2 parties (key_ids 1 and 2), producing 2 signature shares: [10](#0-9) 

6. Coordinator attempts aggregation with 4 nonces and 2 shares

7. Aggregator length check fails: `4 != 2`, returns `BadNonceLen(4, 2)` error: [6](#0-5) 

8. Signature aggregation fails, signing round is blocked

**Expected vs Actual Behavior**:
- Expected: Invalid NonceResponse rejected during validation
- Actual: Invalid NonceResponse passes validation, causes aggregation failure

**Reproduction**: Create a test case that constructs a NonceResponse with duplicate key_ids and verifies the current validation incorrectly accepts it, then confirms the aggregation fails with BadNonceLen error.

### Notes

This vulnerability exploits the mismatch between validation (which uses HashSet) and aggregation (which uses Vec). The fix requires validating that no duplicates exist in the vectors before they are processed. The issue affects both v1 and v2 implementations of the aggregator.

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

**File:** src/state_machine/coordinator/fire.rs (L891-901)
```rust
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

**File:** src/state_machine/coordinator/fire.rs (L935-952)
```rust
            // ignore the passed key_ids
            for key_id in signer_key_ids {
                nonce_info.nonce_recv_key_ids.insert(*key_id);
            }

            nonce_info
                .sign_wait_signer_ids
                .insert(nonce_response.signer_id);
            // Because of entry call, it is safe to unwrap here
            info!(
                sign_id = %nonce_response.sign_id,
                sign_iter_id = %nonce_response.sign_iter_id,
                signer_id = %nonce_response.signer_id,
                recv_keys = %nonce_info.nonce_recv_key_ids.len(),
                threshold = %self.config.threshold,
                "Received NonceResponse"
            );
            if nonce_info.nonce_recv_key_ids.len() >= self.config.threshold as usize {
```

**File:** src/state_machine/coordinator/fire.rs (L1185-1194)
```rust
        let party_ids = public_nonces
            .values()
            .cloned()
            .flat_map(|pn| pn.key_ids)
            .collect::<Vec<u32>>();
        let nonces = public_nonces
            .values()
            .cloned()
            .flat_map(|pn| pn.nonces)
            .collect::<Vec<PublicNonce>>();
```

**File:** src/net.rs (L320-323)
```rust
    /// Key IDs
    pub key_ids: Vec<u32>,
    /// Public nonces
    pub nonces: Vec<PublicNonce>,
```

**File:** src/v1.rs (L321-323)
```rust
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }
```

**File:** src/v1.rs (L715-718)
```rust
        self.parties
            .iter()
            .map(|p| p.sign_precomputed(msg, key_ids, nonces, &aggregate_nonce))
            .collect()
```

**File:** src/v2.rs (L304-306)
```rust
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }
```

**File:** src/state_machine/signer/mod.rs (L781-795)
```rust
        let nonces = sign_request
            .nonce_responses
            .iter()
            .flat_map(|nr| nr.nonces.clone())
            .collect::<Vec<PublicNonce>>();

        for nonce in &nonces {
            if !nonce.is_valid() {
                warn!(
                    signer_id = %self.signer_id,
                    "received an SignatureShareRequest with invalid nonce"
                );
                return Err(Error::InvalidNonceResponse);
            }
        }
```
