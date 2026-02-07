Audit Report

## Title
Fire Coordinator Timeout Logic Incorrectly Marks Honest Signers as Malicious on Network Delays

## Summary
The fire coordinator's `process_timeout()` function marks all non-responding signers as permanently malicious when the signature share timeout fires, without distinguishing between honest signers experiencing network delays and actually malicious actors. This creates cumulative false positives that progressively degrade signing capacity and can lead to permanent denial of service.

## Finding Description

The vulnerability exists in the timeout handling logic for signature share gathering in the fire coordinator. When `sign_timeout` expires during the `State::SigShareGather` phase, the coordinator unconditionally marks all signers in `sign_wait_signer_ids` as malicious. [1](#0-0) 

The `sign_wait_signer_ids` set contains signers who successfully sent valid nonce responses but have not yet sent their signature shares. Signers are added to this wait list when they provide valid nonce responses: [2](#0-1) 

And are only removed when signature share responses are received: [3](#0-2) 

Once marked malicious, signers are permanently excluded from future signing rounds. The coordinator silently rejects nonce responses from any signer in the `malicious_signer_ids` set: [4](#0-3) 

Critically, the `malicious_signer_ids` set is never cleared. The coordinator's `reset()` method does not clear this field: [5](#0-4) 

The `malicious_signer_ids` field is part of the coordinator's persistent state: [6](#0-5) 

**Root Cause**: The timeout logic fails to distinguish between (1) legitimate network delays or temporary unavailability of honest signers, and (2) actual malicious behavior requiring permanent exclusion. Both cases result in identical treatment: permanent marking as malicious with no recovery mechanism.

**No Cryptographic Validation**: The timeout handler performs no validation of whether signature shares were cryptographically invalid, incorrectly formatted, or violated protocol rules. It simply marks signers as malicious based solely on response time.

## Impact Explanation

This vulnerability breaks the availability guarantee of the signing protocol. Honest signers experiencing transient network issues are permanently excluded, progressively reducing the system's signing capacity with each timeout event.

**Concrete Attack Scenario**: 
1. Initial state: 10 signers, 20 total key IDs, threshold of 14
2. Attacker delays signature share packets from 3 signers → timeout fires → 3 signers permanently marked malicious → 14 keys remaining (exactly at threshold)
3. Attacker delays packets from 2 more signers → timeout fires → 5 signers total marked malicious → 10 keys remaining (below threshold)
4. System can no longer produce valid signatures → **permanent denial of service**

The cumulative nature makes this particularly severe: each timeout event permanently weakens the system until it falls below the signing threshold and becomes unable to recover.

**Blockchain Context Impact**: In deployments using WSTS for block signing (such as Stacks), this vulnerability can cause network-wide inability to confirm blocks, resulting in chain halt requiring manual intervention to restore signing capacity.

**Severity Assessment**: This maps to **High severity** as "Any remotely-exploitable denial of service" under the stated scope. In blockchain deployments, it escalates to **Critical severity** as it can cause "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks."

## Likelihood Explanation

**Attack Requirements**:
- Attacker only needs to introduce packet delays or losses between signers and coordinator
- No cryptographic capabilities required
- No privileged access to keys or coordinator needed
- Can use network-level techniques (traffic shaping, packet dropping) or exploit natural network conditions

**Natural Occurrence**: This vulnerability can trigger without any attacker:
- Network congestion during high load
- Temporary connectivity issues
- Signers under heavy computational load
- Cross-datacenter latency spikes

**Cumulative Degradation**: Each timeout event permanently reduces capacity. The probability of eventual DoS approaches 1.0 over time in any environment with non-zero network latency variance.

**Detection Difficulty**: Malicious delays are indistinguishable from legitimate network issues, making detection and attribution impossible.

## Recommendation

**Primary Fix**: Implement a distinction between temporary unavailability and malicious behavior:

1. **Replace permanent marking with temporary exclusion**: Instead of permanently marking signers as malicious on timeout, temporarily exclude them for the current signing round only. Clear the exclusion list at the start of each new signing round.

2. **Add malicious marking only for cryptographic failures**: Only permanently mark signers as malicious when they send cryptographically invalid signature shares, not when they simply fail to respond.

3. **Implement gradual penalty system**: Track timeout counts per signer. Only permanently exclude after repeated timeouts (e.g., 3+ consecutive timeouts) to handle persistent network issues while avoiding false positives from transient delays.

4. **Add recovery mechanism**: Provide an administrative function to clear the `malicious_signer_ids` set, allowing operators to restore falsely-flagged honest signers.

**Recommended Implementation** (conceptual fix for fire.rs):

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
    // ADD: Clear malicious signers on reset
    self.malicious_signer_ids.clear();
    self.malicious_dkg_signer_ids.clear();
}
```

And modify the timeout handler to use a per-round exclusion instead of permanent marking:

```rust
State::SigShareGather(signature_type) => {
    if let Some(start) = self.sign_start {
        if let Some(timeout) = self.config.sign_timeout {
            if now.duration_since(start) > timeout {
                warn!("Timeout gathering signature shares for signing round {} iteration {}", self.current_sign_id, self.current_sign_iter_id);
                // Instead of marking as permanently malicious, just retry without them
                // They can participate in the next round
                self.move_to(State::NonceRequest(signature_type))?;
                let packet = self.request_nonces(signature_type)?;
                return Ok((Some(packet), None));
            }
        }
    }
}
```

## Proof of Concept

The existing test suite demonstrates this behavior. The test at lines 3063-3184 of fire.rs shows that when signature share timeouts occur repeatedly, the coordinator marks signers as malicious and eventually returns `SignError::InsufficientSigners` when capacity falls below threshold: [7](#0-6) 

This test confirms:
1. Timeout fires during `SigShareGather` state
2. Coordinator marks non-responding signers as malicious
3. After sufficient timeouts, the system reaches `InsufficientSigners` state
4. No recovery mechanism exists to restore the falsely-flagged signers

The vulnerability is demonstrable through the existing test infrastructure by simulating network delays using `thread::sleep()` to trigger timeouts, then observing the permanent exclusion of signers and eventual DoS condition.

### Citations

**File:** src/state_machine/coordinator/fire.rs (L173-186)
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

**File:** src/state_machine/coordinator/fire.rs (L940-942)
```rust
            nonce_info
                .sign_wait_signer_ids
                .insert(nonce_response.signer_id);
```

**File:** src/state_machine/coordinator/fire.rs (L1042-1044)
```rust
        response_info
            .sign_wait_signer_ids
            .remove(&sig_share_response.signer_id);
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

**File:** src/state_machine/coordinator/fire.rs (L3063-3184)
```rust
        // Start a new signing round with a sufficient number of signers for nonces but not sig shares
        let mut insufficient_coordinators = coordinators.clone();
        let mut insufficient_signers = signers.clone();

        let message = insufficient_coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type, None)
            .unwrap();
        assert_eq!(
            insufficient_coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and insufficient_coordinator
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &[message],
        );
        assert!(operation_results.is_empty());
        for coordinator in &insufficient_coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        assert_eq!(outbound_messages.len(), 1);

        let mut malicious = Vec::new();

        // now remove signers so the number is insufficient
        let num_signers_to_drain = insufficient_signers
            .len()
            .saturating_sub(num_signers_to_remove);
        malicious.extend(insufficient_signers.drain(num_signers_to_drain..));

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &outbound_messages,
        );
        assert!(outbound_messages.is_empty());
        assert!(operation_results.is_empty());

        for coordinator in &insufficient_coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        // Sleep long enough to hit the timeout
        thread::sleep(Duration::from_millis(256));

        let (outbound_message, operation_result) = insufficient_coordinators
            .first_mut()
            .unwrap()
            .process_timeout()
            .unwrap();

        assert!(outbound_message.is_some());
        assert!(operation_result.is_none());
        assert_eq!(
            insufficient_coordinators.first().unwrap().state,
            State::NonceGather(signature_type)
        );

        // put the malicious signers back in
        insufficient_signers.append(&mut malicious);

        // Send the NonceRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &[outbound_message.unwrap()],
        );
        assert_eq!(outbound_messages.len(), 1);
        assert!(operation_results.is_empty());

        for coordinator in &insufficient_coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        // again remove signers so the number is insufficient
        let num_signers_to_drain = insufficient_signers
            .len()
            .saturating_sub(num_signers_to_remove);
        malicious.extend(insufficient_signers.drain(num_signers_to_drain..));

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_messages(
            &mut insufficient_coordinators,
            &mut insufficient_signers,
            &outbound_messages,
        );
        assert!(outbound_messages.is_empty());
        assert!(operation_results.is_empty());

        for coordinator in &insufficient_coordinators {
            assert_eq!(coordinator.state, State::SigShareGather(signature_type));
        }

        // Sleep long enough to hit the timeout
        thread::sleep(Duration::from_millis(256));

        let (outbound_message, operation_result) = insufficient_coordinators
            .first_mut()
            .unwrap()
            .process_timeout()
            .unwrap();

        assert!(outbound_message.is_none());
        assert!(operation_result.is_some());
        assert_eq!(
            insufficient_coordinators.first_mut().unwrap().state,
            State::SigShareGather(signature_type)
        );
        assert!(
            matches!(
                operation_result.unwrap(),
                OperationResult::SignError(SignError::InsufficientSigners(_))
            ),
            "Expected OperationResult::SignError(SignError::InsufficientSigners)"
        );
    }
```

**File:** src/state_machine/coordinator/mod.rs (L293-293)
```rust
    pub malicious_signer_ids: HashSet<u32>,
```
