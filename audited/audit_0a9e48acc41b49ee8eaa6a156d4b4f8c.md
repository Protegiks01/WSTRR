### Title
Missing Nonce Count Validation Enables Denial of Service in Signing Protocol

### Summary
The coordinator's nonce gathering logic does not validate that signers provide the required number of nonces in their `NonceResponse` messages. A malicious signer can send empty nonces while claiming to control keys, causing the coordinator to count those keys toward the threshold but later fail during signature aggregation, forcing signing rounds to abort and requiring retries.

### Finding Description

**Location**: `src/state_machine/coordinator/fire.rs`, function `gather_nonces()`, lines 841-962

**Root Cause**: The `gather_nonces()` function validates that `key_ids` in the `NonceResponse` match the configured keys for a signer, and validates each individual nonce for validity, but it does NOT validate that the number of nonces is correct. Specifically: [1](#0-0) 

This check only validates that the `key_ids` set matches the configuration, but does not ensure `nonces` is non-empty. [2](#0-1) 

This loop validates each nonce, but if `nonces` is empty, the loop executes zero times and passes without error.

In v2 protocol, each signer must provide exactly 1 nonce regardless of how many keys they control: [3](#0-2) 

However, a malicious signer can modify their code to return an empty `nonces` vector while keeping `key_ids` populated. The coordinator then proceeds to add the signer's keys to the threshold count: [4](#0-3) 

This uses the CONFIG's key_ids, not the response's nonces, so the keys are counted even though no nonces were provided.

**Why Existing Mitigations Fail**: During aggregation, the nonces and signature shares are collected: [5](#0-4) 

The malicious signer's empty nonces contribute nothing to the `nonces` vector, but their signature shares are still collected. This causes a length mismatch that is only caught during aggregation: [6](#0-5) 

By this point, significant resources have been wasted and the signing round must be aborted.

### Impact Explanation

**Harm**: A malicious signer can force signing rounds to fail repeatedly, causing denial of service. Each failed round wastes:
- Network bandwidth for message exchanges
- CPU cycles for nonce generation and validation by honest signers  
- Coordinator processing time
- Time waiting for signature share responses

**Quantification**: With threshold=7 and 4 signers controlling 10 keys total, a single malicious signer can:
1. Cause their keys to be counted toward meeting the threshold (false progress signal)
2. Force aggregation failure after all honest signers have generated signature shares
3. Trigger timeout and retry logic, delaying signing by seconds to minutes per attempt
4. Repeat indefinitely for persistent DoS

**Who is Affected**: All participants in the signing protocol, including the coordinator and all honest signers who must regenerate nonces and signature shares for each retry.

**Severity Justification**: This maps to **Low** severity under the defined scope: "Any remotely-exploitable denial of service in a node." The attack prevents signing operations from completing but does not compromise cryptographic security, cause fund loss, or create consensus failures.

### Likelihood Explanation

**Attacker Capabilities Required**:
- Be a configured signer in the WSTS protocol
- Ability to send modified `NonceResponse` messages (requires control over signer node code)
- No cryptographic secrets needed beyond legitimate signer credentials

**Attack Complexity**: Low. The attacker simply needs to:
1. Modify their signer implementation to return empty `nonces` vector
2. Keep `key_ids` vector matching their configuration
3. Send the malformed `NonceResponse` to the coordinator

**Economic Feasibility**: Very low cost. The attack requires no computational resources and can be repeated indefinitely with minimal bandwidth.

**Detection Risk**: Medium. The coordinator logs show that nonces were received, but may not immediately reveal that a specific signer provided zero nonces. The failure only manifests during aggregation with a generic length mismatch error.

**Probability of Success**: Near 100% if attacker is a configured signer. The validation logic has no mechanism to reject empty nonces before counting the signer's keys toward the threshold.

### Recommendation

**Primary Fix**: Add explicit validation in `gather_nonces()` to check that the number of nonces matches the expected count for each signer:

```rust
// After line 889, add:
if nonce_response.nonces.is_empty() {
    warn!(
        signer_id = %nonce_response.signer_id,
        "NonceResponse contained no nonces"
    );
    return Ok(());
}

// For v2, validate exactly 1 nonce per signer:
if nonce_response.nonces.len() != 1 {
    warn!(
        signer_id = %nonce_response.signer_id,
        nonce_count = %nonce_response.nonces.len(),
        "NonceResponse contained unexpected nonce count, expected 1"
    );
    return Ok(());
}
```

**Alternative Mitigation**: At configuration time, validate that all signers have non-empty `key_ids`: [7](#0-6) 

Add a check that each signer controls at least one key:
```rust
if key_ids.is_empty() {
    return Err(SignerError::Config(ConfigError::EmptyKeyIds(*signer_id)));
}
```

**Testing Recommendations**:
1. Add unit test with signer sending empty `nonces` vector, verify rejection
2. Add integration test with malicious signer, verify signing round continues without them
3. Test with minimum threshold signers (t signers with exactly t keys total)

**Deployment Considerations**: This is a protocol-level validation change. All coordinators must be updated to include the validation. Backward compatibility is maintained as honest signers already provide the correct nonce count.

### Proof of Concept

**Exploitation Steps**:

1. Configure WSTS network with:
   - 3 signers: Signer A (keys 1,2,3), Signer B (keys 4,5), Malicious Signer M (keys 6,7)
   - Threshold = 5 keys
   
2. Coordinator sends `NonceRequest` for message signing

3. Malicious Signer M modifies response:
   ```rust
   // In signer's nonce_request handler, replace gen_nonces() call:
   let nonces = vec![]; // Empty instead of self.signer.gen_nonces()
   
   let response = NonceResponse {
       dkg_id: nonce_request.dkg_id,
       sign_id: nonce_request.sign_id,
       sign_iter_id: nonce_request.sign_iter_id,
       signer_id: self.signer_id,
       key_ids: vec![6, 7], // Valid keys from config
       nonces: vec![],       // EMPTY - malicious
       message: nonce_request.message.clone(),
   };
   ```

4. Coordinator receives responses:
   - Signer A: key_ids=[1,2,3], nonces=[N_A]
   - Signer B: key_ids=[4,5], nonces=[N_B]
   - Signer M: key_ids=[6,7], nonces=[] (EMPTY)

5. Coordinator validation at line 886: `{1,2,3,4,5,6,7} contains threshold 5` ✓
   - key_ids check for M: config {6,7} == response {6,7} ✓
   - nonces loop for M: iterates 0 times ✓ (no rejection)
   - Coordinator adds 2 keys from M to `nonce_recv_key_ids`
   - Total keys = 7 >= threshold 5, proceeds to signature share request

6. Coordinator sends `SignatureShareRequest` with all nonce responses

7. All signers generate signature shares (3 shares total)

8. Aggregation collects:
   - nonces = [N_A, N_B] (2 elements)
   - sig_shares = [share_A, share_B, share_M] (3 elements)

9. Aggregator check at line 304: `nonces.len() != sig_shares.len()` → `2 != 3` → FAIL

10. Signing round aborts with `AggregatorError::BadNonceLen(2, 3)`

**Expected vs Actual Behavior**:
- Expected: Coordinator rejects M's empty nonces, continues with A and B only
- Actual: Coordinator accepts M's response, counts M's keys, then fails aggregation

**Reproduction**: Deploy WSTS with test configuration above, modify one signer to return empty nonces, observe signing round failure with nonce length mismatch error.

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

**File:** src/state_machine/coordinator/fire.rs (L936-938)
```rust
            for key_id in signer_key_ids {
                nonce_info.nonce_recv_key_ids.insert(*key_id);
            }
```

**File:** src/state_machine/coordinator/fire.rs (L1121-1135)
```rust
            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();

            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();

            let shares = message_nonce
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();
```

**File:** src/v2.rs (L304-306)
```rust
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }
```

**File:** src/v2.rs (L627-633)
```rust
    fn gen_nonces<RNG: RngCore + CryptoRng>(
        &mut self,
        secret_key: &Scalar,
        rng: &mut RNG,
    ) -> Vec<PublicNonce> {
        vec![self.gen_nonce(secret_key, rng)]
    }
```

**File:** src/state_machine/mod.rs (L121-133)
```rust
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
```
