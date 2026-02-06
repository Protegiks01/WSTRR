### Title
Coordinator Fails to Identify Malicious Signers in Missing Shares DKG Failures

### Summary
The coordinator does not identify or mark malicious signers when processing `DkgFailure::MissingPublicShares` or `DkgFailure::MissingPrivateShares` during DKG end gathering, despite these failure messages explicitly containing the IDs of signers who failed to provide shares. The test `empty_public_shares` does not verify that malicious signers are properly identified, only that failures are reported, allowing this gap to persist undetected.

### Finding Description

**Exact Code Locations:**

1. **Test Gap** - The `empty_public_shares` test ignores the `malicious_signers` field: [1](#0-0) 

The test uses `..` to ignore the `malicious_signers` field, only verifying that `reported_failures` is populated correctly. The same issue exists in the `empty_private_shares` test: [2](#0-1) 

2. **FireCoordinator Implementation** - No handling for MissingPublicShares/MissingPrivateShares: [3](#0-2) 

The code contains only TODO comments with no implementation to mark signers as malicious, despite processing other DKG failures correctly: [4](#0-3) 

3. **FrostCoordinator Implementation** - Returns empty malicious_signers set: [5](#0-4) 

The FrostCoordinator returns `malicious_signers: Default::default()`, which is an empty HashSet, regardless of which failures were reported.

**Root Cause:**

When honest signers detect missing public or private shares during DKG end processing, they correctly report this via `DkgFailure::MissingPublicShares(HashSet<u32>)` or `DkgFailure::MissingPrivateShares(HashSet<u32>)`, where the HashSet contains the IDs of the malicious signers: [6](#0-5) 

Signers populate these sets accurately when detecting missing shares: [7](#0-6) [8](#0-7) 

However, the coordinator fails to extract the malicious signer IDs from these failure messages and populate the `malicious_signers` field in the returned error: [9](#0-8) 

**Why Existing Mitigations Fail:**

The coordinator correctly handles and verifies `BadPublicShares` and `BadPrivateShares` failures, marking signers as malicious when appropriate. However, for `MissingPublicShares` and `MissingPrivateShares`, there is no verification or identification logic implemented. The information needed to identify malicious signers is present in the failure messages but is never extracted.

### Impact Explanation

**Specific Harm:**

A malicious signer can repeatedly send empty public shares or private shares (or omit them entirely) to disrupt DKG rounds. Each honest signer will correctly detect and report the missing shares, but the coordinator will return a `DkgError::DkgEndFailure` with an empty `malicious_signers` set: [10](#0-9) 

This allows the malicious signer to repeatedly attack without being identified or blacklisted.

**Quantified Impact:**

- **DKG Disruption**: Each DKG round fails when a signer sends empty shares, requiring a retry
- **Unidentified Attacker**: The malicious signer's ID is never added to `malicious_dkg_signer_ids`, allowing repeated attacks
- **Consensus Delay**: Each failed DKG round delays the establishment of the threshold signature scheme
- **Resource Waste**: Computational and network resources are consumed in failed DKG attempts

**Who Is Affected:**

All participants in the WSTS protocol who rely on DKG to establish the distributed key. If WSTS is used in a blockchain context (as suggested by the Stacks references in the scope), this affects the ability to establish threshold signing capabilities for block signing or transaction validation.

**Severity Justification:**

This maps to **Medium severity** per the protocol scope definition: "Any transient consensus failures." The DKG repeatedly fails to complete, preventing the establishment of consensus on the distributed key, but the protocol can theoretically retry. However, without identifying the malicious signer, the attacks can continue indefinitely.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Access to send messages as a valid signer in the DKG protocol
- Ability to craft and send DkgPublicShares or DkgPrivateShares messages with empty share lists

**Attack Complexity:**
- **Low** - The attack is trivial to execute. A malicious signer simply sends empty share messages: [11](#0-10) 

**Economic Feasibility:**
- **High** - No cryptographic computation required, minimal network bandwidth consumed
- The attacker can repeat the attack indefinitely with no cost escalation
- No detection mechanism exists to identify and penalize the attacker

**Detection Risk:**
- **Low** - While honest signers detect the missing shares, the coordinator does not identify the attacker
- Application-level monitoring could potentially detect repeated DKG failures, but without the `malicious_signers` field populated, automated remediation is impossible

**Estimated Probability of Success:**
- **100%** - The attack always succeeds in disrupting DKG
- The attacker is never identified in the coordinator's error response
- Can be repeated indefinitely

### Recommendation

**Immediate Fix:**

Modify the FireCoordinator's `gather_dkg_end` function to extract malicious signer IDs from `MissingPublicShares` and `MissingPrivateShares` failures:

```rust
// In fire.rs around lines 765-770, replace the empty match arms with:
DkgFailure::MissingPublicShares(missing_signers) => {
    for missing_signer_id in missing_signers {
        malicious_signers.insert(*missing_signer_id);
    }
}
DkgFailure::MissingPrivateShares(missing_signers) => {
    for missing_signer_id in missing_signers {
        malicious_signers.insert(*missing_signer_id);
    }
}
```

Apply the same fix to FrostCoordinator's `gather_dkg_end` function to process failures and populate the `malicious_signers` set before returning the error.

**Test Updates:**

Update the `empty_public_shares` and `empty_private_shares` tests to verify that the `malicious_signers` field is correctly populated:

```rust
// In mod.rs around line 1751, replace the pattern match with:
let OperationResult::DkgError(DkgError::DkgEndFailure {
    reported_failures,
    malicious_signers,
}) = &operation_results[0]

// Then add assertion:
assert_eq!(malicious_signers.len(), 1, "Expected 1 malicious signer");
assert!(malicious_signers.contains(&0), "Expected signer 0 to be marked malicious");
```

**Deployment Considerations:**

- This fix is backward compatible - it only adds information to the error response
- Applications already handling `DkgError::DkgEndFailure` will benefit from the populated `malicious_signers` field
- Consider implementing logic to exclude signers in `malicious_dkg_signer_ids` from future DKG rounds

### Proof of Concept

**Exploitation Algorithm:**

1. Setup: Deploy WSTS with multiple signers participating in DKG
2. Attack: Malicious signer (ID 0) modifies their DkgPublicShares message to send empty commitments:
   - Set `comms` vector to empty: `vec![]`
   - Set `kex_public_key` to identity point: `Point::new()`
3. Protocol execution continues through DkgPrivateBegin and DkgEndBegin phases
4. All honest signers detect the missing shares and report `DkgFailure::MissingPublicShares({0})`
5. Coordinator processes these failures but does NOT mark signer 0 as malicious
6. Result: `DkgError::DkgEndFailure` is returned with `malicious_signers` = empty set

**Expected vs Actual Behavior:**

- **Expected**: `malicious_signers` should contain `{0}` identifying the attacker
- **Actual**: `malicious_signers` is an empty HashSet

**Reproduction Instructions:**

The existing test demonstrates this vulnerability: [12](#0-11) 

To expose the vulnerability, modify the test to check the `malicious_signers` field:
1. Change line 1751 to capture `malicious_signers` instead of ignoring it with `..`
2. Add assertion: `assert!(!malicious_signers.is_empty())`
3. Run the test - it will fail, confirming the vulnerability

The test currently passes only because it ignores the `malicious_signers` field entirely.

### Citations

**File:** src/state_machine/coordinator/mod.rs (L97-102)
```rust
    DkgFailure {
        /// failures reported by signers during DkgEnd
        reported_failures: HashMap<u32, DkgFailure>,
        /// signers who were discovered to be malicious during this DKG round
        malicious_signers: HashSet<u32>,
    },
```

**File:** src/state_machine/coordinator/mod.rs (L1673-1775)
```rust
    pub fn empty_public_shares<Coordinator: CoordinatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) {
        let (mut coordinators, mut signers) =
            setup::<Coordinator, SignerType>(num_signers, keys_per_signer);

        // We have started a dkg round
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_dkg_round(None)
            .unwrap();
        assert!(coordinators
            .first_mut()
            .unwrap()
            .get_aggregate_public_key()
            .is_none());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::DkgPublicGather
        );

        // Send the DKG Begin message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) = feedback_mutated_messages(
            &mut coordinators,
            &mut signers,
            &[message],
            |signer, packets| {
                if signer.signer_id != 0 {
                    return packets.clone();
                }
                packets
                    .iter()
                    .map(|packet| {
                        let Message::DkgPublicShares(shares) = &packet.msg else {
                            return packet.clone();
                        };
                        let public_shares = crate::net::DkgPublicShares {
                            dkg_id: shares.dkg_id,
                            signer_id: shares.signer_id,
                            comms: vec![],
                            kex_public_key: Point::new(),
                        };
                        Packet {
                            msg: Message::DkgPublicShares(public_shares),
                            sig: vec![],
                        }
                    })
                    .collect()
            },
        );
        assert!(operation_results.is_empty());
        for coordinator in coordinators.iter() {
            assert_eq!(coordinator.get_state(), State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgPrivateBegin(_)),
            "Expected DkgPrivateBegin message"
        );
        // Send the DKG Private Begin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert_eq!(operation_results.len(), 0);
        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgEndBegin(_)),
            "Expected DkgEndBegin message"
        );

        // Send the DkgEndBegin message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert_eq!(outbound_messages.len(), 0);
        assert_eq!(operation_results.len(), 1);
        let OperationResult::DkgError(DkgError::DkgEndFailure {
            reported_failures, ..
        }) = &operation_results[0]
        else {
            panic!(
                "Expected OperationResult::DkgError got {:?}",
                &operation_results[0]
            );
        };
        assert_eq!(
            reported_failures.len(),
            num_signers as usize,
            "Expected {num_signers} DkgFailures got {}",
            reported_failures.len()
        );
        let expected_signer_ids = (0..1).collect::<HashSet<u32>>();
        for dkg_failure in reported_failures {
            let (_, DkgFailure::MissingPublicShares(signer_ids)) = dkg_failure else {
                panic!("Expected DkgFailure::MissingPublicShares got {dkg_failure:?}");
            };
            assert_eq!(
                expected_signer_ids, *signer_ids,
                "Expected signer_ids {expected_signer_ids:?} got {signer_ids:?}"
            );
        }
    }
```

**File:** src/state_machine/coordinator/mod.rs (L1854-1856)
```rust
        let OperationResult::DkgError(DkgError::DkgEndFailure {
            reported_failures, ..
        }) = &operation_results[0]
```

**File:** src/state_machine/coordinator/fire.rs (L620-650)
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
                            }
```

**File:** src/state_machine/coordinator/fire.rs (L765-770)
```rust
                        DkgFailure::MissingPublicShares(_) => {
                            // this shouldn't happen, maybe mark signer malicious?
                        }
                        DkgFailure::MissingPrivateShares(_) => {
                            // this shouldn't happen, maybe mark signer malicious?
                        }
```

**File:** src/state_machine/coordinator/frost.rs (L410-416)
```rust
            if reported_failures.is_empty() {
                self.dkg_end_gathered()?;
            } else {
                return Err(Error::DkgFailure {
                    reported_failures,
                    malicious_signers: Default::default(),
                });
```

**File:** src/net.rs (L64-69)
```rust
    /// DKG public shares were missing from these signer_ids
    MissingPublicShares(HashSet<u32>),
    /// DKG public shares were bad from these signer_ids
    BadPublicShares(HashSet<u32>),
    /// DKG private shares were missing from these signer_ids
    MissingPrivateShares(HashSet<u32>),
```

**File:** src/state_machine/signer/mod.rs (L551-566)
```rust
        for signer_id in &signer_ids_set {
            if let Some(shares) = self.dkg_public_shares.get(signer_id) {
                if shares.comms.is_empty() {
                    missing_public_shares.insert(*signer_id);
                } else {
                    for (party_id, comm) in shares.comms.iter() {
                        if !check_public_shares(comm, threshold, &self.dkg_id.to_be_bytes()) {
                            bad_public_shares.insert(*signer_id);
                        } else {
                            self.commitments.insert(*party_id, comm.clone());
                        }
                    }
                }
            } else {
                missing_public_shares.insert(*signer_id);
            }
```

**File:** src/state_machine/signer/mod.rs (L585-590)
```rust
        if !missing_public_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::MissingPublicShares(missing_public_shares)),
            }));
```

**File:** src/state_machine/mod.rs (L48-55)
```rust
    /// DKG end failure
    #[error("DKG end failure")]
    DkgEndFailure {
        /// failures reported by signers during DkgEnd
        reported_failures: HashMap<u32, DkgFailure>,
        /// signers who were discovered to be malicious during this DKG round
        malicious_signers: HashSet<u32>,
    },
```
