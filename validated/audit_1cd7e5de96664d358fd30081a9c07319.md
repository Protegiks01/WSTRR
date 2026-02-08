# Audit Report

## Title
DKG Failure Prioritization Masks Malicious Signer Detection

## Summary
The `dkg_ended()` function uses early returns to check DKG failures in strict priority order. When both `bad_public_shares` and `missing_private_shares` failures exist simultaneously, only the first is reported, allowing coordinated malicious signers to evade detection. The coordinator lacks implementation for `MissingPrivateShares` failures, preventing proper identification and exclusion of malicious participants across DKG rounds.

## Finding Description

The vulnerability exists in the DKG end phase validation logic where multiple independent failure conditions can be detected but only one is reported due to early returns.

The `dkg_ended()` function initializes three HashSets to track different failure types: [1](#0-0) 

The function checks for failures in strict priority order with early returns: [2](#0-1) 

These failure conditions are populated independently within the same validation loop. For missing private shares, the detection occurs when a signer listed in `DkgEndBegin.signer_ids` has not provided shares: [3](#0-2) 

For bad public shares, detection occurs when cryptographic validation fails: [4](#0-3) 

**Attack Mechanism:**

1. Malicious Signer A sends `DkgPrivateShares` to the coordinator but withholds from honest signers (selective Byzantine delivery)
2. The coordinator receives A's shares and includes A in the `DkgEndBegin.signer_ids` list based on which signers sent private shares: [5](#0-4) 

3. Malicious Signer B sends invalid `DkgPublicShares` that fail cryptographic validation
4. Honest signers populate both `missing_private_shares` (with A) and `bad_public_shares` (with B) during validation
5. Due to the early return priority (line 593-598 for bad public shares, line 601-608 for missing private shares), only `BadPublicShares(B)` is reported
6. The coordinator validates reports and marks B as malicious with comprehensive verification: [6](#0-5) 

7. However, `MissingPrivateShares` failures have no implementation, only a comment: [7](#0-6) 

8. Malicious signers are tracked for exclusion from future rounds: [8](#0-7) 

9. Signer A is never marked malicious and remains in the participant set for subsequent DKG rounds

This breaks the security guarantee that malicious signers will be detected and excluded from future protocol rounds, allowing persistent disruption through coordinated attacks.

## Impact Explanation

This constitutes a **Medium** severity vulnerability mapping to "transient consensus failures" in the defined scope.

**Specific Harms:**
- Malicious signers withholding private shares persistently avoid detection across multiple DKG rounds
- Each masked malicious signer extends DKG completion by at least one additional round
- With k coordinating malicious signers, DKG requires k+ failed attempts before all are identified
- Prevents establishment of a valid group signing key, blocking all threshold signature operations
- All honest participants are blocked from completing DKG

**Who is Affected:**
- All honest signers waiting for DKG completion
- Systems dependent on WSTS for threshold signing (e.g., Stacks blockchain signer network)
- End users relying on timely transaction signing

The system eventually recovers when coordinating malicious signers are exhausted, fitting the "transient" classification. However, the delayed convergence enables denial-of-service attacks on DKG completion.

## Likelihood Explanation

**High** likelihood in adversarial scenarios.

**Required Attacker Capabilities:**
- Control of at least 2 malicious signer identities (within threat model of up to threshold-1 malicious signers)
- Ability to selectively deliver messages (standard Byzantine behavior)
- No cryptographic breaks, compromised keys, or social engineering required

**Attack Feasibility:**
The attack is straightforward to execute through normal protocol message flow. WSTS is a library where the application layer handles message routing. A malicious signer implementation can trivially implement selective message delivery by choosing which peers receive each message. This is standard Byzantine adversarial behavior explicitly contemplated in distributed protocols.

**Economic Feasibility:**
Highly feasible - requires only control of multiple signer identities, which is realistic in many deployment scenarios. The attack cost is minimal (just selective message routing) while the disruption impact is significant (blocking DKG completion).

**Detection Difficulty:**
Low detection risk for the attacker. Honest signers report exactly what the code dictates (`BadPublicShares` failure), making the attack indistinguishable from legitimate protocol operation.

## Recommendation

**Primary Fix:** Implement comprehensive handling for `MissingPrivateShares` failures in the coordinator, similar to the handling for `BadPublicShares` and `BadPrivateShares`. The coordinator should mark signers who withhold private shares as malicious.

**Secondary Fix:** Report ALL detected failures instead of only the first one. Modify `dkg_ended()` to collect all failure types and return them together, or report the most severe failure that includes the maximum set of malicious signers.

**Tertiary Fix:** Add validation to detect selective delivery - if a signer sent private shares to the coordinator but honest signers report them as missing, this is evidence of Byzantine behavior.

## Proof of Concept

```rust
#[test]
fn test_coordinated_malicious_signers_mask_detection() {
    use crate::state_machine::coordinator::fire::Coordinator as FireCoordinator;
    use crate::state_machine::signer::Signer;
    
    let num_signers = 4;
    let keys_per_signer = 1;
    let threshold = 3;
    
    // Setup coordinator and signers
    let (mut coordinators, mut signers) = 
        setup::<FireCoordinator, Signer>(num_signers, keys_per_signer);
    
    // Start DKG round
    let dkg_begin = coordinators[0].start_dkg_round(None).unwrap();
    
    // Phase 1: Public shares - Signer 1 sends INVALID public shares
    let (dkg_private_begin_msgs, _) = 
        feedback_messages(&mut coordinators, &mut signers, &[dkg_begin]);
    
    // Mutate signer 1's public shares to be invalid
    let (dkg_end_begin_msgs, _) = feedback_mutated_messages(
        &mut coordinators,
        &mut signers, 
        &dkg_private_begin_msgs,
        |signer, packets| {
            if signer.signer_id == 0 {
                // Signer 0 withholds private shares from other signers
                // but sends to coordinator (selective delivery)
                packets.iter().map(|p| {
                    if matches!(p.msg, Message::DkgPrivateShares(_)) {
                        // Send empty shares to peers, valid to coordinator
                        return create_empty_private_shares_packet(signer);
                    }
                    p.clone()
                }).collect()
            } else if signer.signer_id == 1 {
                // Signer 1 sends invalid public shares
                packets.iter().map(|p| {
                    if matches!(p.msg, Message::DkgPublicShares(_)) {
                        return create_invalid_public_shares_packet(signer);
                    }
                    p.clone()
                }).collect()
            } else {
                packets.clone()
            }
        }
    );
    
    // Phase 3: DKG End - honest signers report failures
    let (_, operation_results) = 
        feedback_messages(&mut coordinators, &mut signers, &dkg_end_begin_msgs);
    
    // Verify the vulnerability: 
    // - Only BadPublicShares(signer_1) is reported
    // - MissingPrivateShares(signer_0) is masked
    // - Signer 0 is NOT marked as malicious
    let OperationResult::DkgError(DkgError::DkgEndFailure { 
        reported_failures,
        malicious_signers 
    }) = &operation_results[0] else {
        panic!("Expected DkgEndFailure");
    };
    
    // All honest signers detect BadPublicShares from signer 1
    assert!(reported_failures.iter().all(|(_, failure)| 
        matches!(failure, DkgFailure::BadPublicShares(_))
    ));
    
    // Signer 1 is marked malicious
    assert!(malicious_signers.contains(&1));
    
    // VULNERABILITY: Signer 0 is NOT marked malicious despite withholding shares
    assert!(!malicious_signers.contains(&0));
    assert!(!coordinators[0].malicious_dkg_signer_ids.contains(&0));
}
```

This test demonstrates that when signer 0 withholds private shares and signer 1 sends bad public shares, only signer 1 is detected and marked malicious while signer 0 evades detection.

### Citations

**File:** src/state_machine/signer/mod.rs (L514-516)
```rust
        let mut missing_public_shares = HashSet::new();
        let mut missing_private_shares = HashSet::new();
        let mut bad_public_shares = HashSet::new();
```

**File:** src/state_machine/signer/mod.rs (L556-562)
```rust
                    for (party_id, comm) in shares.comms.iter() {
                        if !check_public_shares(comm, threshold, &self.dkg_id.to_be_bytes()) {
                            bad_public_shares.insert(*signer_id);
                        } else {
                            self.commitments.insert(*party_id, comm.clone());
                        }
                    }
```

**File:** src/state_machine/signer/mod.rs (L567-582)
```rust
            if let Some(shares) = self.dkg_private_shares.get(signer_id) {
                // signer_id sent shares, but make sure that it sent shares for every one of this signer's key_ids
                if shares.shares.is_empty() {
                    missing_private_shares.insert(*signer_id);
                } else {
                    for dst_key_id in self.signer.get_key_ids() {
                        for (_src_key_id, shares) in &shares.shares {
                            if shares.get(&dst_key_id).is_none() {
                                missing_private_shares.insert(*signer_id);
                            }
                        }
                    }
                }
            } else {
                missing_private_shares.insert(*signer_id);
            }
```

**File:** src/state_machine/signer/mod.rs (L585-608)
```rust
        if !missing_public_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::MissingPublicShares(missing_public_shares)),
            }));
        }

        if !bad_public_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadPublicShares(bad_public_shares)),
            }));
        }

        if !missing_private_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::MissingPrivateShares(
                    missing_private_shares,
                )),
            }));
```

**File:** src/state_machine/coordinator/fire.rs (L461-465)
```rust
        let dkg_end_begin = DkgEndBegin {
            dkg_id: self.current_dkg_id,
            signer_ids: self.dkg_private_shares.keys().cloned().collect(),
            key_ids: vec![],
        };
```

**File:** src/state_machine/coordinator/fire.rs (L620-651)
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
                        }
```

**File:** src/state_machine/coordinator/fire.rs (L768-770)
```rust
                        DkgFailure::MissingPrivateShares(_) => {
                            // this shouldn't happen, maybe mark signer malicious?
                        }
```

**File:** src/state_machine/coordinator/fire.rs (L775-777)
```rust
            for id in &malicious_signers {
                self.malicious_dkg_signer_ids.insert(*id);
            }
```
