### Title
FIRE Coordinator Bypasses Packet Signature Verification on Timeout Processing

### Summary
The FIRE coordinator implementation processes timeouts and performs state machine operations before verifying packet signatures, allowing unauthenticated packets to trigger critical state changes when timeouts fire. This violates the security invariant that message authentication must be enforced when `verify_packet_sigs` is true, enabling attackers to mark honest signers as malicious and cause protocol failures without proper authentication.

### Finding Description

**Exact Code Location:** [1](#0-0) 

**Root Cause:**
The FIRE coordinator's `process()` function calls `process_timeout()` before `process_message()`. When a timeout fires, the function returns immediately with the timeout result without ever calling `process_message()`, which is where packet signature verification occurs: [2](#0-1) 

The signature verification only happens in `process_message()`: [3](#0-2) 

**Why Existing Mitigations Fail:**
The timeout processing in `process_timeout()` performs critical state changes including marking signers as malicious: [4](#0-3) 

These operations execute without any packet signature verification when a timeout fires. The `verify_packet_sigs` configuration flag is completely bypassed in this code path.

**Contrast with FROST Implementation:**
The FROST coordinator correctly verifies signatures before all processing: [5](#0-4) [6](#0-5) 

### Impact Explanation

**Specific Harm:**
- Attackers can send unauthenticated packets to trigger timeout-based state changes
- Honest signers can be marked as malicious without authentication (line 185 in fire.rs)
- State transitions occur without proper authentication (line 202 in fire.rs)  
- New protocol messages are generated in response to unauthenticated packets (line 203 in fire.rs)
- DKG and signing rounds can fail due to unauthenticated state manipulation

**Quantified Impact:**
In a signing round with signature share timeout, an attacker sending unauthenticated packets can cause honest signers to be marked malicious. If enough honest signers are marked malicious to fall below the threshold, the signing round fails permanently. This maps to **Medium severity** (transient consensus failures) as it can prevent signature generation temporarily until coordinators are reset.

**Affected Parties:**
All FIRE coordinator deployments with `verify_packet_sigs=true` are vulnerable. Based on the test code, this appears to be the default: [7](#0-6) 

**Severity Justification:**
This violates the critical security invariant that "message authentication must be enforced where configured." It enables denial of service attacks against the signing protocol and can cause transient consensus failures, mapping to **Medium severity** in the protocol scope.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Network access to send packets to the coordinator
- Timing knowledge to send packets when timeouts are likely to fire
- No cryptographic secrets required
- No special privileges needed

**Attack Complexity:**
Low. The attacker simply needs to:
1. Identify when the coordinator is in a timeout-sensitive state (e.g., DkgPublicGather, NonceGather, SigShareGather)
2. Send unauthenticated/malformed packets to the coordinator
3. If a timeout fires during packet processing, state changes occur without authentication

**Economic Feasibility:**
Trivial. The attack requires only basic network access and costs essentially nothing to execute repeatedly.

**Detection Risk:**
Low. The coordinator will log timeout events but cannot distinguish between legitimate timeout-triggered state changes and those caused by attacker packets, since signature verification never occurs.

**Estimated Probability:**
High. The vulnerability is always present in FIRE coordinator deployments with `verify_packet_sigs=true`. Exploitation timing depends on timeout windows but becomes highly probable over multiple rounds.

### Recommendation

**Proposed Code Change:**
Move packet signature verification before timeout processing in the FIRE coordinator's `process()` function. The signature should be verified immediately upon entry, before any state changes:

```rust
fn process(
    &mut self,
    packet: &Packet,
) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
    // Verify signature FIRST, before any processing
    if self.config.verify_packet_sigs {
        let Some(coordinator_public_key) = self.coordinator_public_key else {
            return Err(Error::MissingCoordinatorPublicKey);
        };
        if !packet.verify(&self.config.public_keys, &coordinator_public_key) {
            return Err(Error::InvalidPacketSignature);
        }
    }
    
    // Then process timeouts
    let (outbound_packet, operation_result) = self.process_timeout()?;
    if outbound_packet.is_some() || operation_result.is_some() {
        return Ok((outbound_packet, operation_result));
    }

    // Finally process the message (signature already verified)
    self.process_message(packet)
}
```

**Alternative Mitigation:**
Alternatively, extract the signature verification into a separate function and call it from both `process()` and `process_message()`, ensuring it always runs first.

**Testing Recommendations:**
1. Add test cases that send unsigned packets during timeout windows
2. Verify that signature verification errors occur before any state changes
3. Test all timeout scenarios (DKG public, DKG private, DKG end, nonce, signature share)
4. Ensure FROST coordinator behavior remains unchanged

**Deployment Considerations:**
This fix should be deployed urgently to all FIRE coordinator deployments. The change is backward compatible as it only affects the timing of authentication checks.

### Proof of Concept

**Exploitation Algorithm:**

1. **Setup:** Deploy a FIRE coordinator with `verify_packet_sigs=true` and configure signing timeouts (e.g., 5 seconds)

2. **Attack Execution:**
   - Wait for coordinator to enter `SigShareGather` state
   - Continuously send unsigned/invalid Packet messages to the coordinator
   - Wait for the signing timeout to expire (5+ seconds)

3. **Expected vs Actual Behavior:**
   - **Expected:** All packets should be rejected with `Error::InvalidPacketSignature` before any processing
   - **Actual:** When the timeout fires, `process_timeout()` executes and marks signers as malicious (line 185) without verifying the packet signature

4. **Verification:**
   - Check coordinator logs for "Mark signer X as malicious" messages
   - Verify state transition to `NonceRequest` occurred (line 202)
   - Confirm the unsigned packet was never verified (no signature error logged)
   - Observe that honest signers are now in `malicious_signer_ids` set

5. **Reproduction Steps:**
   ```
   1. Start FIRE coordinator with verify_packet_sigs=true, sign_timeout=5s
   2. Initiate a signing round
   3. Send malformed packets: Packet { sig: vec![], msg: Message::DkgBegin(...) }
   4. Wait for sign_timeout to expire
   5. Observe malicious signer marking without signature verification
   ```

**Impact Demonstration:**
After successful exploitation, the attacker has caused honest signers to be marked malicious without providing any authenticated messages, violating the security requirement and potentially causing the signing round to fail if the threshold is no longer met.

### Citations

**File:** src/state_machine/coordinator/fire.rs (L173-210)
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
        }
        Ok((None, None))
```

**File:** src/state_machine/coordinator/fire.rs (L218-225)
```rust
        if self.config.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.config.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
        }
```

**File:** src/state_machine/coordinator/fire.rs (L1444-1454)
```rust
    fn process(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        let (outbound_packet, operation_result) = self.process_timeout()?;
        if outbound_packet.is_some() || operation_result.is_some() {
            return Ok((outbound_packet, operation_result));
        }

        self.process_message(packet)
    }
```

**File:** src/state_machine/coordinator/frost.rs (L63-70)
```rust
        if self.config.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.config.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
        }
```

**File:** src/state_machine/coordinator/frost.rs (L929-934)
```rust
    fn process(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        self.process_message(packet)
    }
```

**File:** src/state_machine/coordinator/mod.rs (L198-199)
```rust
            verify_packet_sigs: true,
        }
```
