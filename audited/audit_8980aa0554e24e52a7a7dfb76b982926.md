### Title
Coordinator Enters Unrecoverable State After DKG Failure Without Documented Recovery Path

### Summary
When DKG fails during the `DkgEndGather` phase, the FIRE coordinator returns a `DkgError` but remains in the `DkgEndGather` state instead of transitioning to `Idle`. This leaves the coordinator in an inconsistent state where it cannot start a new DKG round or signing round without explicitly calling `reset()`. However, this recovery requirement is undocumented and untested, causing coordinator nodes to become permanently stuck after DKG failures unless the application layer knows to call `reset()`.

### Finding Description

**Exact Code Location:**
- File: `src/state_machine/coordinator/fire.rs`
- Function: `process_message()`
- Lines: 281-296 [1](#0-0) 

**Root Cause:**
When `gather_dkg_end()` detects DKG failures from signers, it returns `Error::DkgFailure` with reported failures and malicious signer information. [2](#0-1)  The `process_message()` function catches this error and converts it to `OperationResult::DkgError`, then returns immediately without changing the coordinator's state. [3](#0-2) 

This leaves the coordinator in an inconsistent state where:
1. `self.state` remains `State::DkgEndGather` (not transitioned to `Idle`)
2. `self.dkg_wait_signer_ids` is empty (all expected messages were received) [4](#0-3) 
3. `self.aggregate_public_key` is `None` (not computed due to failure)
4. `self.malicious_dkg_signer_ids` has been updated [5](#0-4) 
5. `self.dkg_end_messages` contains all collected messages

**Why Recovery Fails:**

The coordinator cannot recover through normal API calls:

1. **`start_dkg_round()` fails:** This function attempts to transition from current state to `DkgPublicDistribute`. [6](#0-5)  However, the state transition validator only allows `DkgPublicDistribute` from `Idle` state. [7](#0-6)  Since the coordinator is in `DkgEndGather`, this returns `Error::BadStateChange`.

2. **`start_signing_round()` fails:** This function requires `aggregate_public_key` to be set. [8](#0-7)  Since DKG didn't complete, this is `None`, causing `Error::MissingAggregatePublicKey`.

3. **`process_message()` enters infinite loop:** On subsequent calls with any packet, the state machine matches `DkgEndGather` again and calls `gather_dkg_end()`. [9](#0-8)  Since `dkg_wait_signer_ids` is empty, the function immediately processes all `dkg_end_messages` again, finds the same failures, and returns the same `DkgFailure` error without making progress.

**Why Existing Mitigations Fail:**

The only recovery mechanism is the `reset()` function, which clears internal state and returns to `Idle`. [10](#0-9)  However:

1. The `reset()` function is minimally documented in the trait definition with only "Reset internal state". [11](#0-10) 
2. No tests demonstrate calling `reset()` after a `DkgEndFailure` to retry DKG.
3. Test cases that trigger `DkgEndFailure` simply return without attempting recovery. [12](#0-11) 
4. The codebase documentation suggests applications can "retry DKG by calling `start_dkg_round()` again," but this is incorrect without first calling `reset()`.

### Impact Explanation

**Specific Harm:**
A coordinator node becomes permanently unable to perform DKG after any DKG failure, effectively removing it from the threshold signature system. This occurs when:
- A malicious signer sends bad public or private shares
- Network issues cause validation failures
- Any condition that causes signers to report failures in `DkgEnd` messages

**Quantified Impact:**
- **Single node:** If one coordinator node's application layer doesn't call `reset()`, that node cannot participate in future DKG rounds (denial of service to that node).
- **Multiple nodes:** If multiple coordinator nodes are affected simultaneously and their application layers don't handle this correctly, the network cannot complete DKG, preventing any threshold signatures from being generated.
- **Network-wide:** If all coordinator nodes hit this condition, the entire threshold signature network becomes inoperable until manual intervention.

**Who Is Affected:**
- Applications using WSTS coordinators that don't explicitly call `reset()` after receiving `DkgError::DkgEndFailure`
- Dependent systems (e.g., Stacks blockchain) that rely on WSTS for threshold signatures

**Severity Justification:**
- **Single node impact:** LOW severity - "Any remotely-exploitable denial of service in a node"
- **Multi-node impact:** MEDIUM severity - "Any transient consensus failures" (if multiple signers cannot complete DKG, dependent consensus systems cannot progress)
- The severity depends on deployment architecture and whether the application layer correctly handles the undocumented recovery requirement

### Likelihood Explanation

**Required Attacker Capabilities:**
- A malicious signer participating in DKG can trigger this by sending invalid shares
- No special access or cryptographic breaks required
- Can be triggered remotely through normal protocol participation

**Attack Complexity:**
- **Low complexity:** A malicious signer simply needs to send `DkgPublicShares` with invalid polynomial commitments or `DkgPrivateShares` with bad encrypted shares
- The coordinator will detect these failures during validation and enter the stuck state
- No timing attacks or race conditions required

**Economic Feasibility:**
- Free to execute - requires only participation in DKG
- No computational cost beyond normal DKG participation
- Repeatable attack - can be executed on every DKG round

**Detection Risk:**
- The attack appears as a legitimate DKG failure
- Malicious signers are identified and tracked in `malicious_dkg_signer_ids`, but this doesn't prevent the coordinator from entering the stuck state
- Application logs would show `DkgError::DkgEndFailure` but may not indicate the coordinator is stuck

**Probability of Success:**
- **Near 100%** if the application layer doesn't call `reset()` after `DkgEndFailure`
- DKG failures are expected in adversarial environments, so this condition will occur naturally even without malicious intent
- The vulnerability is deterministic and reproducible

### Recommendation

**Primary Fix Option 1 - Automatic State Reset:**
Modify `process_message()` to automatically transition to `Idle` when returning `DkgError::DkgEndFailure`. After line 293, add:
```rust
self.move_to(State::Idle)?;
```

This ensures the coordinator can start a new DKG round without requiring application-layer intervention.

**Primary Fix Option 2 - Enhanced `start_dkg_round()`:**
Modify `start_dkg_round()` to automatically call `reset()` if not in `Idle` state: [13](#0-12) 

Add before line 1430:
```rust
if self.state != State::Idle {
    self.reset();
}
```

**Documentation Requirements:**
1. Document that `reset()` must be called after `DkgError::DkgEndFailure` if using manual recovery
2. Add code examples showing proper error handling for `DkgError` variants
3. Update the coordinator state machine wiki page to show the DKG failure recovery path

**Testing Requirements:**
1. Add test cases that trigger `DkgEndFailure` and verify recovery by calling `reset()` followed by `start_dkg_round()`
2. Add test case that demonstrates the stuck state by attempting `start_dkg_round()` without `reset()` after failure
3. Add integration tests showing multi-round DKG with failures and recovery

**Deployment Considerations:**
- This is a breaking behavior change if applications rely on the current state retention
- Include migration guidance for applications currently using WSTS coordinators
- Consider backward compatibility if applications have built workarounds

### Proof of Concept

**Exploitation Steps:**

1. **Setup:** Initialize a FIRE coordinator with standard configuration and multiple signers.

2. **Start DKG:** Call `coordinator.start_dkg_round(None)` - coordinator enters `DkgPublicGather` state.

3. **Inject malicious shares:** Have one signer send `DkgPublicShares` with an invalid polynomial (wrong length or invalid commitment). [14](#0-13) 

4. **Complete DKG phases:** Process through `DkgPrivateGather` and into `DkgEndGather`. [15](#0-14) 

5. **Trigger failure:** Honest signers detect bad shares and report `DkgFailure::BadPublicShares` in their `DkgEnd` messages. [16](#0-15) 

6. **Coordinator stuck:** Coordinator returns `OperationResult::DkgError(DkgError::DkgEndFailure {...})` but remains in `DkgEndGather` state.

7. **Demonstrate stuck state:**
   - Call `coordinator.start_dkg_round(None)` → Returns `Error::BadStateChange("DkgEndGather to DkgPublicDistribute")`
   - Call `coordinator.start_signing_round(msg, sig_type, None)` → Returns `Error::MissingAggregatePublicKey`
   - Call `coordinator.process_message(any_packet)` → Returns same `DkgError::DkgEndFailure` in infinite loop

8. **Only recovery:** Call `coordinator.reset()` to clear state and return to `Idle`, then retry DKG.

**Expected vs Actual Behavior:**
- **Expected:** After `DkgEndFailure`, coordinator should either automatically reset to `Idle` or provide clear guidance that `reset()` must be called
- **Actual:** Coordinator remains in `DkgEndGather` state with no documented recovery path, requiring application-layer knowledge of the undocumented `reset()` requirement

**Reproduction Instructions:**
Use existing test infrastructure in `src/state_machine/coordinator/fire.rs` test module. Modify any test that generates `DkgEndFailure` (e.g., `bad_poly_length_dkg`) to attempt calling `start_dkg_round()` after the failure without calling `reset()`. The call will fail with `BadStateChange` error, demonstrating the stuck state.

### Citations

**File:** src/state_machine/coordinator/fire.rs (L280-296)
```rust
                State::DkgEndGather => {
                    if let Err(error) = self.gather_dkg_end(packet) {
                        if let Error::DkgFailure {
                            reported_failures,
                            malicious_signers,
                        } = error
                        {
                            return Ok((
                                None,
                                Some(OperationResult::DkgError(DkgError::DkgEndFailure {
                                    reported_failures,
                                    malicious_signers,
                                })),
                            ));
                        } else {
                            return Err(error);
                        }
```

**File:** src/state_machine/coordinator/fire.rs (L605-606)
```rust
        if self.dkg_wait_signer_ids.is_empty() {
            // if there are any errors, mark signers malicious and retry
```

**File:** src/state_machine/coordinator/fire.rs (L608-610)
```rust
                if let DkgStatus::Failure(dkg_failure) = &dkg_end.status {
                    warn!(%signer_id, ?dkg_failure, "DkgEnd failure");
                    reported_failures.insert(*signer_id, dkg_failure.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L620-649)
```rust
                        DkgFailure::BadPublicShares(bad_shares) => {
                            // bad_shares is a set of signer_ids
                            for bad_signer_id in bad_shares {
                                // verify public shares are bad
                                let Some(dkg_public_shares) =
                                    self.dkg_public_shares.get(bad_signer_id)
                                else {
                                    warn!("Signer {signer_id} reported BadPublicShares from {bad_signer_id} but there are no public shares from that signer, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                    continue;
                                };
                                let mut bad_party_ids = Vec::new();
                                for (party_id, comm) in &dkg_public_shares.comms {
                                    if !check_public_shares(
                                        comm,
                                        threshold,
                                        &self.current_dkg_id.to_be_bytes(),
                                    ) {
                                        bad_party_ids.push(party_id);
                                    }
                                }

                                // if none of the shares were bad sender was malicious
                                if bad_party_ids.is_empty() {
                                    warn!("Signer {signer_id} reported BadPublicShares from {bad_signer_id} but the shares were valid, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                } else {
                                    warn!("Signer {signer_id} reported BadPublicShares from {bad_signer_id}, mark {bad_signer_id} as malicious");
                                    malicious_signers.insert(*bad_signer_id);
                                }
```

**File:** src/state_machine/coordinator/fire.rs (L775-777)
```rust
            for id in &malicious_signers {
                self.malicious_dkg_signer_ids.insert(*id);
            }
```

**File:** src/state_machine/coordinator/fire.rs (L785-788)
```rust
                return Err(Error::DkgFailure {
                    reported_failures,
                    malicious_signers,
                });
```

**File:** src/state_machine/coordinator/fire.rs (L1239-1239)
```rust
            State::DkgPublicDistribute => prev_state == &State::Idle,
```

**File:** src/state_machine/coordinator/fire.rs (L1429-1438)
```rust
    fn start_dkg_round(&mut self, dkg_id: Option<u64>) -> Result<Packet, Error> {
        if let Some(id) = dkg_id {
            self.current_dkg_id = id;
        } else {
            self.current_dkg_id = self.current_dkg_id.wrapping_add(1);
        }

        info!("Starting DKG round {}", self.current_dkg_id);
        self.move_to(State::DkgPublicDistribute)?;
        self.start_public_shares()
```

**File:** src/state_machine/coordinator/fire.rs (L1464-1466)
```rust
        if self.aggregate_public_key.is_none() {
            return Err(Error::MissingAggregatePublicKey);
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

**File:** src/state_machine/coordinator/fire.rs (L2680-2695)
```rust
        let OperationResult::DkgError(DkgError::DkgEndFailure {
            reported_failures, ..
        }) = &operation_results[0]
        else {
            panic!("Expected OperationResult::DkgError(DkgError::DkgEndFailure)");
        };

        for (_signer_id, dkg_failure) in reported_failures {
            let DkgFailure::BadPublicShares(bad_shares) = dkg_failure else {
                panic!("Expected DkgFailure::BadPublicShares");
            };
            for bad_signer_id in bad_shares {
                assert!(*bad_signer_id == 0u32 || *bad_signer_id == 1u32);
            }
        }
        (coordinators, signers)
```

**File:** src/state_machine/coordinator/mod.rs (L359-360)
```rust
    /// Reset internal state
    fn reset(&mut self);
```
