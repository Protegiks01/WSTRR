### Title
Malicious Signers Not Marked When Providing Invalid Signature Shares

### Summary
When a signer provides cryptographically invalid signature shares detected during aggregation (via `BadPartySigs` error), the coordinator removes them from `sign_wait_signer_ids` but fails to add them to `malicious_signer_ids`. This allows malicious signers to repeatedly participate in signing rounds and cause persistent signing failures, potentially preventing transaction confirmation in blockchain systems using WSTS.

### Finding Description

**Exact Code Location:**

The vulnerability exists in the FIRE coordinator's signature share gathering and aggregation logic: [1](#0-0) 

When a signature share response is received, the signer is immediately removed from `sign_wait_signer_ids`. [2](#0-1) 

Aggregation occurs and can fail with `BadPartySigs` error identifying malicious parties. [3](#0-2) 

The error is caught and returned as an `OperationResult`, but `malicious_signer_ids` is never updated with the bad parties identified in the error. [4](#0-3) 

The timeout handler only marks signers still remaining in `sign_wait_signer_ids` as malicious, missing signers who already responded with bad data.

**Root Cause:**

The coordinator maintains two separate tracking mechanisms:
1. `sign_wait_signer_ids` - tracks which signers we're waiting for responses from
2. `malicious_signer_ids` - tracks which signers should be excluded from future rounds

When signature aggregation fails, the aggregator's `check_signature_shares` function correctly identifies bad parties: [5](#0-4) 

However, this information is returned as an error but never used to update `malicious_signer_ids`. Since the bad signer was already removed from `sign_wait_signer_ids` when they responded, the timeout handler won't catch them either. [6](#0-5) 

In subsequent rounds, the check for malicious signers only examines `malicious_signer_ids`, which was never updated, allowing the bad signer to participate again.

**Why Existing Mitigations Fail:**

The timeout-based malicious detection only catches non-responsive signers, not signers who respond with invalid cryptographic data. The aggregator correctly identifies bad signature shares but this detection is not integrated with the coordinator's malicious signer tracking.

### Impact Explanation

**Specific Harm:**
- Malicious signers can repeatedly provide invalid signature shares across unlimited signing iterations
- Each invalid share causes the entire signing round to fail and restart via FIRE protocol
- Since bad signers are never marked as malicious, they continue participating indefinitely
- This can permanently prevent signature completion if sufficient malicious signers coordinate

**Quantified Impact:**

With `n` total signers and threshold `t`:
- If `(n - t + 1)` malicious signers coordinate, signing cannot complete
- Example: 10 signers with threshold 7 → 4 colluding malicious signers permanently block signing
- Each failed iteration wastes network bandwidth and computation resources
- In blockchain contexts, this directly prevents transaction confirmation

**Who is Affected:**

All systems using WSTS for threshold signatures, including:
- Stacks blockchain miners relying on threshold signing for block production
- Multi-party wallet implementations
- Any distributed signing protocol using WSTS coordinators

**Severity Justification:**

**HIGH** severity per protocol scope definition: This enables attackers to "shut down the network or otherwise not confirm new valid transactions for multiple blocks" by preventing the threshold signature generation required for block production or transaction validation in blockchain systems.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control of at least one signer in the signing committee (e.g., through compromised node or malicious participant in permissioned setting)
- Ability to execute normal signing protocol (generate valid nonces)
- Ability to craft invalid signature shares (trivial: modify `z_i` by adding any non-zero scalar)

**Attack Complexity:**

**LOW** - The attack requires minimal sophistication:
1. Participate normally in nonce exchange round
2. Compute valid signature share `z_i` 
3. Modify the share (e.g., `z_i = z_i + 1`)
4. Submit the invalid share
5. Repeat in next signing iteration (not filtered out)

**Economic Feasibility:**

No additional economic cost beyond normal signer participation. The attack provides value to adversaries seeking to:
- Disrupt network operations (denial of service)
- Block specific transactions (censorship)
- Force protocol timeouts and resource exhaustion

**Detection Risk:**

**LOW** - While the protocol returns `BadPartySigs` errors identifying the malicious party, the coordinator doesn't act on this information. External monitoring systems would need manual implementation to track and respond to these errors.

**Estimated Probability of Success:**

**VERY HIGH** (>95%) - Once a signer is compromised, the attack is deterministic with no cryptographic or protocol barriers. The vulnerability is exploitable in every signing round.

### Recommendation

**Primary Fix:**

Modify `gather_sig_shares` function to catch `BadPartySigs` errors and update `malicious_signer_ids`:

In `src/state_machine/coordinator/fire.rs`, after the aggregation calls (around lines 1145-1169), wrap the aggregator calls in error handling that marks bad parties as malicious before returning the error. Specifically, when `BadPartySigs(party_ids)` is returned, insert each party_id into `self.malicious_signer_ids` before propagating the error.

**Alternative Mitigation:**

Add a post-aggregation check in `process_message` (around line 328-332) to extract party IDs from `BadPartySigs` errors and update `malicious_signer_ids` before returning the error to the caller.

**Testing Recommendations:**

1. Add test case verifying signers providing invalid shares are marked malicious
2. Add test case verifying marked malicious signers are rejected in subsequent rounds  
3. Add integration test with multiple signing iterations to verify persistent exclusion
4. Extend existing `check_signature_shares` test to verify malicious tracking across iterations

**Deployment Considerations:**

- This changes coordinator state management behavior
- Requires coordinated update of all coordinators in a deployment
- Consider migration for in-flight signing rounds
- Add monitoring/alerting for malicious signer detection events

### Proof of Concept

**Attack Algorithm:**

```
Setup:
- WSTS deployment: 5 signers, threshold 3
- Attacker controls: signer_id 0

Iteration 1:
1. Coordinator sends NonceRequest
2. All signers (including attacker) respond with valid nonces
3. Signer 0 added to sign_wait_signer_ids (line 940-942)
4. Coordinator sends SignatureShareRequest  
5. Attacker computes valid z_0, submits z_0 + 1
6. Attacker removed from sign_wait_signer_ids (line 1042-1044)
7. Other signers submit valid shares
8. Aggregation fails, check_signature_shares returns BadPartySigs([0])
9. Error returned BUT malicious_signer_ids not updated
10. Coordinator state: malicious_signer_ids = {}, sign_wait_signer_ids = {}

Iteration 2 (automatic retry via FIRE):
1. Coordinator sends NonceRequest again
2. Signer 0 NOT filtered (line 903-915 checks empty malicious_signer_ids)
3. Signer 0 participates and provides another bad share
4. Process repeats indefinitely

Expected: After step 9, malicious_signer_ids = {0}, signer 0 rejected at step 2
Actual: malicious_signer_ids = {}, signer 0 participates forever
```

**Reproduction Steps:**

1. Use test framework from `src/state_machine/coordinator/mod.rs::test::check_signature_shares`
2. Modify test to run multiple signing iterations without resetting coordinator state
3. After first iteration with bad shares, check `coordinator.malicious_signer_ids` 
4. Observe it remains empty despite `BadPartySigs` error
5. Verify signer 0 participates in iteration 2 (not rejected at nonce gathering)

**Expected vs Actual Behavior:**

Expected: Signer providing invalid signature shares is marked malicious and excluded from future iterations

Actual: Signer provides invalid shares repeatedly across unlimited iterations, causing persistent signing failure

### Citations

**File:** src/state_machine/coordinator/fire.rs (L178-186)
```rust
                            for signer_id in &self
                                .message_nonces
                                .get(&self.message)
                                .ok_or(Error::MissingMessageNonceInfo)?
                                .sign_wait_signer_ids
                            {
                                warn!("Mark signer {signer_id} as malicious");
                                self.malicious_signer_ids.insert(*signer_id);
                            }
```

**File:** src/state_machine/coordinator/fire.rs (L328-332)
```rust
                    if let Err(e) = self.gather_sig_shares(packet, signature_type) {
                        return Ok((
                            None,
                            Some(OperationResult::SignError(SignError::Coordinator(e))),
                        ));
```

**File:** src/state_machine/coordinator/fire.rs (L903-915)
```rust
            if self
                .malicious_signer_ids
                .contains(&nonce_response.signer_id)
            {
                warn!(
                    sign_id = %nonce_response.sign_id,
                    sign_iter_id = %nonce_response.sign_iter_id,
                    signer_id = %nonce_response.signer_id,
                    "Received malicious NonceResponse"
                );
                //return Err(Error::MaliciousSigner(nonce_response.signer_id));
                return Ok(());
            }
```

**File:** src/state_machine/coordinator/fire.rs (L1042-1044)
```rust
        response_info
            .sign_wait_signer_ids
            .remove(&sig_share_response.signer_id);
```

**File:** src/state_machine/coordinator/fire.rs (L1145-1169)
```rust
            self.aggregator.init(&self.party_polynomials)?;

            if let SignatureType::Taproot(merkle_root) = signature_type {
                let schnorr_proof = self.aggregator.sign_taproot(
                    &self.message,
                    &nonces,
                    &shares,
                    &key_ids,
                    merkle_root,
                )?;
                debug!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else if let SignatureType::Schnorr = signature_type {
                let schnorr_proof =
                    self.aggregator
                        .sign_schnorr(&self.message, &nonces, &shares, &key_ids)?;
                debug!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else {
                let signature = self
                    .aggregator
                    .sign(&self.message, &nonces, &shares, &key_ids)?;
                debug!("Signature ({}, {})", signature.R, signature.z);
                self.signature = Some(signature);
            }
```

**File:** src/v2.rs (L406-407)
```rust
            if z_i * G != (r_sign * Rs[i] + cx_sign * cx) {
                bad_party_sigs.push(sig_shares[i].id);
```
