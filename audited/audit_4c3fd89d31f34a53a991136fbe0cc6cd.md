# Audit Report

## Title
Incorrect Threshold Check After Marking Signers Malicious Causes Denial of Service

## Summary
The FIRE coordinator's signature share timeout handler uses the configured total number of keys (`config.num_keys`) instead of the actual number of keys that completed DKG (`party_polynomials.len()`) when checking if sufficient non-malicious signers remain. This causes the coordinator to incorrectly retry signature rounds that cannot succeed, leading to a persistent denial of service where no signatures can be produced until manual restart.

## Finding Description
The vulnerability exists in the `process_timeout` function when handling signature share timeouts in state `SigShareGather`. [1](#0-0) 

When a signature share timeout occurs, the coordinator marks all non-responding signers as malicious and then checks if sufficient non-malicious keys remain. The critical flaw is at line 191, which compares against `self.config.num_keys`. [2](#0-1) 

The `config.num_keys` field represents the **configured** total number of keys in the system. [3](#0-2) 

However, DKG can complete with fewer keys than configured when `dkg_threshold < num_keys`. During DKG public share timeout, if `dkg_threshold` is met, the coordinator proceeds even though not all configured signers participated. [4](#0-3) 

The actual participating keys are stored in `party_polynomials`, which is populated only from signers that completed DKG. [5](#0-4) 

**Attack Scenario:**
1. System configured with 10 keys, threshold=7, dkg_threshold=9
2. DKG completes with 9 signers (one drops during DKG)
3. `party_polynomials` contains 9 keys, but `config.num_keys` remains 10
4. During signing, 3 signers timeout and are marked malicious
5. Check: `10 - 3 = 7 >= 7` → **PASSES** (incorrect)
6. Actual: `9 - 3 = 6 < 7` → **SHOULD FAIL**
7. Coordinator moves to `NonceRequest` state instead of returning `InsufficientSigners`
8. During nonce gathering, malicious signers are rejected [6](#0-5) 
9. Only 6 non-malicious signers remain (below threshold)
10. Nonce gathering times out, returns `NonceTimeout` error
11. The `malicious_signer_ids` field persists across signing attempts [7](#0-6) 
12. All future signing attempts fail at nonce gathering stage

## Impact Explanation
This vulnerability causes a **persistent denial of service** in the coordinator node. Once triggered, the coordinator cannot produce any signatures for any message until manually restarted, as the `malicious_signer_ids` set is never cleared and insufficient non-malicious signers remain to meet the threshold.

**Specific Harm:**
- Complete loss of signing capability for the coordinator node
- Wasted network bandwidth and CPU on repeated failed signing attempts  
- Requires manual intervention (restart) to recover
- Multiple coordinator nodes can be simultaneously affected
- Loss of accumulated malicious signer tracking state on restart

This aligns with **Low** severity per the scope definition: "Any remotely-exploitable denial of service in a node." While it prevents signature generation, it does not directly cause fund loss, chain splits, or invalid transactions.

## Likelihood Explanation
**Likelihood: Medium to High**

The vulnerability can be triggered without any malicious actor through natural network conditions:

**Required Conditions:**
- System configured with `dkg_threshold < num_keys` (standard per test configuration) [8](#0-7) 
- DKG completes with fewer than `num_keys` participants (one or more signers experience network issues during DKG)
- During signing, enough signers timeout such that: `config.num_keys - malicious_keys >= threshold` but `actual_dkg_keys - malicious_keys < threshold`

**Attack Complexity:** Low
- No cryptographic operations required
- No privileged access needed
- Can occur naturally through network instability
- Attacker only needs to cause network delays/drops to individual signers

**Economic Feasibility:** Trivial
- No funds at risk for attacker
- Simple network disruption is sufficient
- Effect persists until manual restart

**Detection Risk:** Low
- Appears as normal timeout behavior
- Difficult to distinguish from legitimate network issues
- No cryptographic evidence of malicious activity

In networks with unreliable connectivity or presence of adversarial participants, this probability increases significantly.

## Recommendation
Replace the threshold check at line 191 to use the actual number of keys that completed DKG:

```rust
// Calculate the actual number of non-malicious keys from party_polynomials
let actual_total_keys: u32 = self.party_polynomials.len().try_into()
    .map_err(Error::TryFromInt)?;

if actual_total_keys - num_malicious_keys < self.config.threshold {
    error!("Insufficient non-malicious signers, unable to continue");
    let mal = self.malicious_signer_ids.iter().copied().collect();
    return Ok((
        None,
        Some(OperationResult::SignError(
            SignError::InsufficientSigners(mal),
        )),
    ));
}
```

Additionally, consider clearing `malicious_signer_ids` in the `reset()` function or providing a mechanism to clear it between signing rounds to prevent permanent DoS.

## Proof of Concept
```rust
#[test]
fn test_threshold_check_with_partial_dkg() {
    use std::thread;
    use std::time::Duration;
    
    let num_signers = 10;
    let keys_per_signer = 1;
    
    // Setup with dkg_threshold < num_keys
    let (mut coordinators, mut signers) = setup_with_timeouts::<
        FireCoordinator<v2::Aggregator>, 
        v2::Signer
    >(
        num_signers,
        keys_per_signer,
        Some(Duration::from_millis(100)), // dkg_public_timeout
        Some(Duration::from_millis(100)), // dkg_private_timeout  
        Some(Duration::from_millis(100)), // dkg_end_timeout
        Some(Duration::from_millis(100)), // nonce_timeout
        Some(Duration::from_millis(100)), // sign_timeout
    );
    
    // Verify config: num_keys=10, threshold=7, dkg_threshold=9
    let config = coordinators.first().unwrap().get_config();
    assert_eq!(config.num_keys, 10);
    assert_eq!(config.threshold, 7);
    assert_eq!(config.dkg_threshold, 9);
    
    // Start DKG
    let message = coordinators.first_mut().unwrap()
        .start_dkg_round(None).unwrap();
    
    // Remove one signer before DKG public shares complete
    signers.pop();
    
    // Complete DKG with only 9 signers
    let (msgs, _) = feedback_messages(&mut coordinators, &mut signers, &[message]);
    let (msgs, _) = feedback_messages(&mut coordinators, &mut signers, &msgs);
    let (_, results) = feedback_messages(&mut coordinators, &mut signers, &msgs);
    
    // Verify DKG completed with 9 keys
    assert_eq!(coordinators.first().unwrap().party_polynomials.len(), 9);
    
    // Start signing round
    let msg = b"test message";
    let message = coordinators.first_mut().unwrap()
        .start_signing_round(msg, SignatureType::Frost, None).unwrap();
    
    // Gather nonces successfully (7 signers respond)
    let (msgs, _) = feedback_messages(&mut coordinators, &mut signers, &[message]);
    
    // Remove 3 signers to trigger signature share timeout
    for _ in 0..3 {
        signers.pop();
    }
    
    // Send signature share request but 3 signers don't respond
    let _ = feedback_messages(&mut coordinators, &mut signers, &msgs);
    
    // Wait for timeout
    thread::sleep(Duration::from_millis(150));
    
    // Process timeout - should return InsufficientSigners but incorrectly retries
    let (outbound, result) = coordinators.first_mut().unwrap()
        .process_timeout().unwrap();
    
    // BUG: Coordinator incorrectly moves to NonceGather instead of returning error
    // Expected: result.is_some() && matches InsufficientSigners
    // Actual: outbound.is_some() && state is NonceGather
    assert!(outbound.is_some(), "Coordinator should return error, not retry");
    assert_eq!(coordinators.first().unwrap().state, 
        State::NonceGather(SignatureType::Frost));
    
    // This demonstrates the vulnerability: coordinator will now fail all future
    // signing attempts because only 6 non-malicious signers remain (below threshold of 7)
}
```

### Citations

**File:** src/state_machine/coordinator/fire.rs (L82-98)
```rust
                            let dkg_size = self.compute_dkg_public_size()?;

                            if self.config.dkg_threshold > dkg_size {
                                error!("Timeout gathering DkgPublicShares for dkg round {} signing round {} iteration {}, dkg_threshold not met ({dkg_size}/{}), unable to continue", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, self.config.dkg_threshold);
                                let wait = self.dkg_wait_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::DkgError(DkgError::DkgPublicTimeout(
                                        wait,
                                    ))),
                                ));
                            } else {
                                // we hit the timeout but met the threshold, continue
                                warn!("Timeout gathering DkgPublicShares for dkg round {} signing round {} iteration {}, dkg_threshold was met ({dkg_size}/{}), ", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, self.config.dkg_threshold);
                                self.public_shares_gathered()?;
                                let packet = self.start_private_shares()?;
                                return Ok((Some(packet), None));
```

**File:** src/state_machine/coordinator/fire.rs (L173-208)
```rust
            State::SigShareGather(signature_type) => {
                if let Some(start) = self.sign_start {
                    if let Some(timeout) = self.config.sign_timeout {
                        if now.duration_since(start) > timeout {
                            warn!("Timeout gathering signature shares for signing round {} iteration {}", self.current_sign_id, self.current_sign_iter_id);
                            for signer_id in &self
                                .message_nonces
                                .get(&self.message)
                                .ok_or(Error::MissingMessageNonceInfo)?
                                .sign_wait_signer_ids
                            {
                                warn!("Mark signer {signer_id} as malicious");
                                self.malicious_signer_ids.insert(*signer_id);
                            }

                            let num_malicious_keys: u32 =
                                self.compute_num_key_ids(self.malicious_signer_ids.iter())?;

                            if self.config.num_keys - num_malicious_keys < self.config.threshold {
                                error!("Insufficient non-malicious signers, unable to continue");
                                let mal = self.malicious_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::SignError(
                                        SignError::InsufficientSigners(mal),
                                    )),
                                ));
                            }

                            self.move_to(State::NonceRequest(signature_type))?;
                            let packet = self.request_nonces(signature_type)?;
                            return Ok((Some(packet), None));
                        }
                    }
                }
            }
```

**File:** src/state_machine/coordinator/fire.rs (L794-799)
```rust
    fn dkg_end_gathered(&mut self) -> Result<(), Error> {
        // Cache the polynomials used in DKG for the aggregator
        for signer_id in self.dkg_private_shares.keys() {
            for (party_id, comm) in &self.dkg_public_shares[signer_id].comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
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

**File:** src/state_machine/coordinator/fire.rs (L1479-1490)
```rust
    fn reset(&mut self) {
        self.state = State::Idle;
        self.dkg_public_shares.clear();
        self.dkg_private_shares.clear();
        self.dkg_end_messages.clear();
        self.party_polynomials.clear();
        self.message_nonces.clear();
        self.signature_shares.clear();
        self.dkg_wait_signer_ids.clear();
        self.nonce_start = None;
        self.sign_start = None;
    }
```

**File:** src/state_machine/coordinator/mod.rs (L136-137)
```rust
    /// total number of keys
    pub num_keys: u32,
```

**File:** src/state_machine/coordinator/mod.rs (L580-582)
```rust
        let num_keys = num_signers * keys_per_signer;
        let threshold = (num_keys * 7) / 10;
        let dkg_threshold = (num_keys * 9) / 10;
```
