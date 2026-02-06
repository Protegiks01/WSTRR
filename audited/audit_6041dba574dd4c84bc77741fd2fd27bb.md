### Title
Coordinator State Divergence on Identical Packet Flows with Mismatched SignatureType

### Summary
Different coordinator instances may transition to inconsistent state machines if they process NonceRequest packets with the same identifiers (`sign_id`, etc.) but different `SignatureType` values. This enables a scenario where coordinators disagree on protocol round type, resulting in transient consensus failures and coordination breakdown.

### Finding Description
The `State` enum for the coordinator state machine encodes `SignatureType` as part of its signing-related states (e.g., `NonceGather(SignatureType)`, `SigShareGather(SignatureType)`) [1](#0-0) . When NonceRequest packets are received, each coordinator extracts the requested `signature_type` from the message and transitions to the corresponding state using that exact value, with only the `sign_id` and other round identifiers checked for replay or ordering. There is no cross-coordinator check or consensus to ensure all coordinators transition to the same `SignatureType` for a given round; thus, if packets differ in `signature_type` but share the same round IDs, different coordinators may process them and permanently disagree on state. The root cause is shown in the FROST Coordinator's `process_message` method, and mirrored in the FIRE coordinator implementation as well [2](#0-1) [3](#0-2) . Because `State` derives `PartialEq` and includes `SignatureType`, this results in persistent state machine imbalance even if all other identifiers match. State acceptance logic (e.g., `can_move_to`) does not resolve such split states [4](#0-3) .

### Impact Explanation
If different coordinators diverge on `SignatureType` for the same protocol signing round, they execute incompatible flows (Schnorr, FROST, Taproot, etc.) for the same operation. This state mismatch causes the distributed protocol to become stuck: no future messages will be accepted across all coordinators, and operation halts. If WSTS is security-critical for block production or transaction signing (as is typical in Stacks usage), this presents a **transient consensus failure** and threatens liveness, meeting the "Medium" severity definition. No cryptography is broken, but distributed coordination is irreparably lost for the round.

### Likelihood Explanation
Exploitation requires the ability to inject or reorder NonceRequest packets arriving at different coordinators—possible under partial network partition, delay, or by a malicious coordinator in a redundancy configuration. Coordinators process any validly signed NonceRequest with new `sign_id`, so attackers need only race or partition conflicting packets to replicas. This does not require secret information nor breaking primitives, and can be achieved by controlling any coordinator or a key network segment.

### Recommendation
Enforce strong uniqueness and consensus for (dkg_id, sign_id, sign_iter_id, signature_type) tuples before transitioning state. Reject NonceRequest packets if their (sign_id, sign_iter_id) match an active round but use a different `signature_type` than previously accepted, logging and optionally penalizing the sender. At a minimum, all coordinators must reject packets which would diverge on protocol state for the same round. Add end-to-end tests with conflicting NonceRequest `signature_type` values to verify detection and safe recovery.

### Proof of Concept
- Spawn two coordinators using normal test setup.
- Send NonceRequest{sign_id: 1, signature_type: FROST} to coordinator A, and NonceRequest{sign_id: 1, signature_type: SCHNORR} to coordinator B (both packets valid and signed).
- Each accepts its packet, transitioning to `State::NonceGather(FROST)` and `State::NonceGather(SCHNORR)` respectively.
- Subsequent signature share request and result messages are never accepted by both coordinators; protocol cannot advance or recover for this round. [1](#0-0) [2](#0-1) [4](#0-3) [3](#0-2) 

Notes:
- This issue is not mitigated by normal packet signing as all packets may be valid and authenticated.
- The impact is limited to coordination/liveness; no direct funds loss or cryptographic disaster.
- The protocol, as designed, expects strict state agreement among coordinator replicas.
- All references used are strictly within the cited repository.

### Citations

**File:** src/state_machine/coordinator/mod.rs (L40-46)
```rust
    NonceRequest(SignatureType),
    /// The coordinator is gathering nonces
    NonceGather(SignatureType),
    /// The coordinator is requesting signature shares
    SigShareRequest(SignatureType),
    /// The coordinator is gathering signature shares
    SigShareGather(SignatureType),
```

**File:** src/state_machine/coordinator/frost.rs (L83-95)
```rust
                    } else if let Message::NonceRequest(nonce_request) = &packet.msg {
                        if self.current_sign_id == nonce_request.sign_id {
                            // We have already processed this sign round
                            return Ok((None, None));
                        }
                        self.current_sign_iter_id = nonce_request.sign_iter_id;
                        // use sign_id from NonceRequest
                        let packet = self.start_signing_round(
                            nonce_request.message.as_slice(),
                            nonce_request.signature_type,
                            Some(nonce_request.sign_id),
                        )?;
                        return Ok((Some(packet), None));
```

**File:** src/state_machine/coordinator/frost.rs (L761-799)
```rust
    fn can_move_to(&self, state: &State) -> Result<(), Error> {
        let prev_state = &self.state;
        let accepted = match state {
            State::Idle => true,
            State::DkgPublicDistribute => prev_state == &State::Idle,
            State::DkgPublicGather => {
                prev_state == &State::DkgPublicDistribute || prev_state == &State::DkgPublicGather
            }
            State::DkgPrivateDistribute => prev_state == &State::DkgPublicGather,
            State::DkgPrivateGather => {
                prev_state == &State::DkgPrivateDistribute || prev_state == &State::DkgPrivateGather
            }
            State::DkgEndDistribute => prev_state == &State::DkgPrivateGather,
            State::DkgEndGather => prev_state == &State::DkgEndDistribute,
            State::NonceRequest(_) => {
                prev_state == &State::Idle || prev_state == &State::DkgEndGather
            }
            State::NonceGather(signature_type) => {
                prev_state == &State::NonceRequest(*signature_type)
                    || prev_state == &State::NonceGather(*signature_type)
            }
            State::SigShareRequest(signature_type) => {
                prev_state == &State::NonceGather(*signature_type)
            }
            State::SigShareGather(signature_type) => {
                prev_state == &State::SigShareRequest(*signature_type)
                    || prev_state == &State::SigShareGather(*signature_type)
            }
        };
        if accepted {
            debug!("state change from {prev_state:?} to {state:?}");
            Ok(())
        } else {
            Err(Error::BadStateChange(format!(
                "{prev_state:?} to {state:?}"
            )))
        }
    }
}
```

**File:** src/state_machine/coordinator/fire.rs (L230-250)
```rust
                    if let Message::DkgBegin(dkg_begin) = &packet.msg {
                        if self.current_dkg_id == dkg_begin.dkg_id {
                            // We have already processed this DKG round
                            return Ok((None, None));
                        }
                        // use dkg_id from DkgBegin
                        let packet = self.start_dkg_round(Some(dkg_begin.dkg_id))?;
                        return Ok((Some(packet), None));
                    } else if let Message::NonceRequest(nonce_request) = &packet.msg {
                        if self.current_sign_id == nonce_request.sign_id {
                            // We have already processed this sign round
                            return Ok((None, None));
                        }
                        self.current_sign_iter_id = nonce_request.sign_iter_id.wrapping_sub(1);
                        // use sign_id from NonceRequest
                        let packet = self.start_signing_round(
                            nonce_request.message.as_slice(),
                            nonce_request.signature_type,
                            Some(nonce_request.sign_id),
                        )?;
                        return Ok((Some(packet), None));
```
