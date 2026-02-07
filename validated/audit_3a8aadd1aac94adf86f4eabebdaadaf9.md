Audit Report

## Title
Malicious Signer Memory Loss Enables Persistent DKG Denial of Service

## Summary
A single malicious signer can indefinitely prevent DKG completion by sending invalid private shares. The vulnerability arises from two critical flaws: (1) signers lose memory of previously detected malicious actors when `reset()` is called at the start of each DKG round, and (2) the coordinator tracks but never excludes identified malicious signers from subsequent DKG attempts, allowing the same attacker to repeat the attack infinitely.

## Finding Description

The vulnerability exists at the intersection of signer state management and coordinator signer selection logic, creating a persistent denial of service condition.

**Signer Memory Loss:**
When a new DKG round begins, the `reset()` function unconditionally clears the `invalid_private_shares` HashMap that tracks signers who previously sent invalid encrypted shares. [1](#0-0)  This reset is triggered by the `dkg_begin()` handler at the start of every DKG round. [2](#0-1) 

The `invalid_private_shares` field is populated when signers detect decryption failures or invalid scalar values in received private shares. [3](#0-2)  These invalid shares are then reported to the coordinator in `DkgEnd` messages with status `DkgFailure::BadPrivateShares`. [4](#0-3) 

**Coordinator Fails to Exclude Malicious Signers:**
The FIRE coordinator correctly validates bad private share reports and identifies malicious signers during the DKG end phase. [5](#0-4)  Identified malicious signers are added to the `malicious_dkg_signer_ids` HashSet. [6](#0-5) 

However, when the coordinator immediately returns a `DkgFailure` error without checking if sufficient honest signers remain, as acknowledged by the TODO comment. [7](#0-6) 

Most critically, when starting a new DKG round via `start_public_shares()`, the coordinator includes ALL signers without any filtering based on `malicious_dkg_signer_ids`. [8](#0-7)  The `dkg_wait_signer_ids` is initialized to the full range `(0..self.config.num_signers)` at line 399, with no exclusion mechanism.

Furthermore, the `start_dkg_round()` API provides no parameter to exclude specific signers, only accepting an optional `dkg_id`. [9](#0-8) [10](#0-9) 

**Attack Execution Path:**
1. Malicious signer sends DkgPrivateShares with invalid encrypted data (random bytes or invalid scalars)
2. Honest signers detect failures during decryption and add to `invalid_private_shares`
3. Honest signers report `DkgFailure::BadPrivateShares` in DkgEnd messages
4. Coordinator validates reports, identifies malicious signer, adds to `malicious_dkg_signer_ids`, and returns `Error::DkgFailure`
5. Application layer retries by calling `start_dkg_round()` again
6. Coordinator sends DkgBegin to ALL signers (including the malicious one)
7. Signers call `reset()` which clears `invalid_private_shares`, losing all memory of the malicious actor
8. Attack repeats from step 1 indefinitely

The `malicious_dkg_signer_ids` field is persisted in SavedState [11](#0-10)  but is never consulted during signer selection, rendering it effectively useless for mitigation.

## Impact Explanation

This vulnerability enables a single malicious signer to cause complete network shutdown by preventing DKG completion indefinitely. Without a successful DKG, the signing group cannot generate the aggregate public key required for any signature operations. This directly prevents transaction confirmation.

The attack produces a CRITICAL impact that precisely matches the defined scope: "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks." The denial of service is not transient—it persists indefinitely until manual intervention reconfigures the signer set at the deployment level to physically exclude the malicious signer.

Unlike timeout-based DoS attacks that only affect unresponsive signers, this attack succeeds even when the malicious signer actively participates in the protocol. The coordinator's timeout mechanisms cannot help because the malicious signer responds to all messages promptly—it simply includes invalid cryptographic data that gets detected too late to prevent DKG failure.

The severity escalates beyond typical DoS because:
- It requires only ONE compromised signer (not threshold-1)
- It causes COMPLETE signing failure (not degraded performance)  
- It has ZERO cost to repeat indefinitely (no cryptographic or computational barriers)
- It has NO automatic recovery mechanism (application must manually exclude the signer from configuration)

## Likelihood Explanation

**Attacker Requirements:**
The attack requires minimal capabilities within the WSTS threat model:
- Control of a single signer node that is already configured in the signing group
- Standard network access to participate in the DKG protocol
- No cryptographic knowledge beyond basic message formatting
- No special privileges or insider access beyond being a configured signer

**Attack Complexity: TRIVIAL**
The attacker simply sends a DkgPrivateShares message containing random bytes or validly encrypted invalid scalar values. No sophisticated cryptographic attacks are needed. The attack succeeds because the validation that detects the malicious behavior occurs AFTER the DKG round has already been marked as failed.

**Reproducibility: 100%**
The attack has no probabilistic elements:
- It succeeds on every DKG round attempt
- It requires no timing windows or race conditions  
- It has no dependency on network conditions or other signers' behavior
- The malicious signer is guaranteed to be included in every retry because `start_public_shares()` deterministically includes all signers

**Detection vs. Prevention:**
The vulnerability is particularly severe because the coordinator DOES detect the malicious behavior correctly [12](#0-11)  but this detection produces no enforcement action. The malicious signer is identified and logged, but remains eligible for the next DKG round, making detection useless for prevention.

**Economic Analysis:**
The attack costs essentially zero to execute repeatedly. The malicious signer expends minimal CPU time sending invalid data, while honest signers waste computational resources on decryption attempts and cryptographic validation that ultimately fails. The asymmetry heavily favors the attacker.

## Recommendation

Implement a three-part fix to address both the memory loss and the lack of enforcement:

**1. Coordinator Must Exclude Tracked Malicious Signers:**
Modify `start_public_shares()` to filter out signers in `malicious_dkg_signer_ids`:
```rust
pub fn start_public_shares(&mut self) -> Result<Packet, Error> {
    self.dkg_public_shares.clear();
    self.party_polynomials.clear();
    
    // FIXED: Exclude malicious signers from DKG participation
    self.dkg_wait_signer_ids = (0..self.config.num_signers)
        .filter(|id| !self.malicious_dkg_signer_ids.contains(id))
        .collect();
    
    if self.dkg_wait_signer_ids.is_empty() {
        return Err(Error::InsufficientHonestSigners);
    }
    
    // ... rest of function
}
```

**2. Coordinator Should Attempt DKG With Remaining Honest Signers:**
Implement the TODO at line 783 to check if sufficient non-malicious signers remain:
```rust
if reported_failures.is_empty() {
    self.dkg_end_gathered()?;
} else {
    // Check if we have sufficient non-malicious signers to continue
    let honest_signer_count = self.config.num_signers - malicious_signers.len() as u32;
    if honest_signer_count >= self.config.dkg_threshold {
        warn!("DKG failures detected but sufficient honest signers remain, excluding malicious signers and retrying");
        // Coordinator could potentially retry automatically here
        return Err(Error::DkgFailure {
            reported_failures,
            malicious_signers,
        });
    } else {
        error!("Insufficient honest signers to complete DKG");
        return Err(Error::InsufficientHonestSigners);
    }
}
```

**3. Add API to Reset Malicious Signer Tracking (Optional):**
Allow applications to clear `malicious_dkg_signer_ids` between signing rounds if desired, while maintaining exclusion within a single DKG retry sequence.

## Proof of Concept

```rust
#[test]
fn test_malicious_signer_persistent_dos() {
    use crate::state_machine::coordinator::fire::Coordinator as FireCoordinator;
    use crate::v2::Aggregator;
    use crate::net::{DkgPrivateShares, Message, Packet};
    
    // Setup: Create coordinator with 3 signers, threshold 2
    let (mut coordinator, signers, mut rng) = setup_coordinator_and_signers(3, 2);
    
    // Round 1: Start DKG
    let dkg_begin_packet = coordinator.start_dkg_round(None).unwrap();
    
    // Honest signers send valid DkgPublicShares
    let public_packets = send_public_shares(&mut signers[0..2], &dkg_begin_packet, &mut rng);
    for packet in &public_packets {
        coordinator.process(packet, &mut rng).unwrap();
    }
    
    // Malicious signer (signer_id=2) sends valid public shares but INVALID private shares
    let malicious_public = send_public_shares(&mut signers[2..3], &dkg_begin_packet, &mut rng)[0].clone();
    coordinator.process(&malicious_public, &mut rng).unwrap();
    
    // Coordinator sends DkgPrivateBegin
    let private_begin_packet = coordinator.start_private_shares().unwrap();
    
    // Honest signers send valid private shares
    let private_packets = send_private_shares(&mut signers[0..2], &private_begin_packet, &mut rng);
    for packet in &private_packets {
        coordinator.process(packet, &mut rng).unwrap();
    }
    
    // Malicious signer sends INVALID private shares (random bytes)
    let malicious_private = create_invalid_private_shares(2, &private_begin_packet);
    coordinator.process(&malicious_private, &mut rng).unwrap();
    
    // Coordinator sends DkgEndBegin
    let end_begin_packet = coordinator.start_dkg_end().unwrap();
    
    // Process DkgEnd - should detect malicious signer
    let end_packets = send_dkg_end(&mut signers[0..2], &end_begin_packet, &mut rng);
    for packet in &end_packets {
        let result = coordinator.process(packet, &mut rng);
        // Should get DkgFailure error identifying signer 2 as malicious
        assert!(matches!(result, Err(OperationResult::DkgError(DkgError::DkgEndFailure { malicious_signers, .. })) 
            if malicious_signers.contains(&2)));
    }
    
    // Verify malicious signer was tracked
    assert!(coordinator.malicious_dkg_signer_ids.contains(&2));
    
    // Round 2: Retry DKG - VULNERABILITY: malicious signer included again
    let dkg_begin_packet_2 = coordinator.start_dkg_round(None).unwrap();
    
    // PROOF: Check that signer 2 is still in dkg_wait_signer_ids
    assert!(coordinator.dkg_wait_signer_ids.contains(&2), 
        "VULNERABILITY: Malicious signer 2 was not excluded from round 2");
    
    // PROOF: Signers lose memory when processing DkgBegin
    signers[0].process_message(&dkg_begin_packet_2.msg, &mut rng).unwrap();
    assert!(signers[0].invalid_private_shares.is_empty(),
        "VULNERABILITY: Signer memory of malicious actors was cleared");
    
    // Attack can repeat indefinitely...
}
```

**Notes:**
This vulnerability affects production code in `src/state_machine/` and represents a fundamental flaw in the DKG retry logic. The fix requires coordinated changes to both the coordinator's signer selection logic and the DKG failure handling. The `malicious_dkg_signer_ids` tracking mechanism exists but is completely ineffective without enforcement during `start_public_shares()`.

### Citations

**File:** src/state_machine/signer/mod.rs (L417-432)
```rust
    pub fn reset<T: RngCore + CryptoRng>(&mut self, dkg_id: u64, rng: &mut T) {
        self.dkg_id = dkg_id;
        self.commitments.clear();
        self.decrypted_shares.clear();
        self.decryption_keys.clear();
        self.invalid_private_shares.clear();
        self.public_nonces.clear();
        self.signer.reset_polys(rng);
        self.dkg_public_shares.clear();
        self.dkg_private_shares.clear();
        self.dkg_private_begin_msg = None;
        self.dkg_end_begin_msg = None;
        self.kex_private_key = Scalar::random(rng);
        self.kex_public_keys.clear();
        self.state = State::Idle;
    }
```

**File:** src/state_machine/signer/mod.rs (L652-660)
```rust
        } else {
            DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadPrivateShares(
                    self.invalid_private_shares.clone(),
                )),
            }
        };
```

**File:** src/state_machine/signer/mod.rs (L844-855)
```rust
    fn dkg_begin<R: RngCore + CryptoRng>(
        &mut self,
        dkg_begin: &DkgBegin,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        self.reset(dkg_begin.dkg_id, rng);
        self.move_to(State::DkgPublicDistribute)?;

        //let _party_state = self.signer.save();

        self.dkg_public_begin(rng)
    }
```

**File:** src/state_machine/signer/mod.rs (L1076-1096)
```rust
                    match decrypt(&shared_secret, bytes) {
                        Ok(plain) => match Scalar::try_from(&plain[..]) {
                            Ok(s) => {
                                decrypted_shares.insert(*dst_key_id, s);
                            }
                            Err(e) => {
                                warn!("Failed to parse Scalar for dkg private share from src_id {src_id} to dst_id {dst_key_id}: {e:?}");
                                self.invalid_private_shares.insert(
                                    src_signer_id,
                                    self.make_bad_private_share(src_signer_id, rng)?,
                                );
                            }
                        },
                        Err(e) => {
                            warn!("Failed to decrypt dkg private share from src_id {src_id} to dst_id {dst_key_id}: {e:?}");
                            self.invalid_private_shares.insert(
                                src_signer_id,
                                self.make_bad_private_share(src_signer_id, rng)?,
                            );
                        }
                    }
```

**File:** src/state_machine/coordinator/fire.rs (L396-417)
```rust
    pub fn start_public_shares(&mut self) -> Result<Packet, Error> {
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        self.dkg_wait_signer_ids = (0..self.config.num_signers).collect();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting Public Share Distribution"
        );
        let dkg_begin = DkgBegin {
            dkg_id: self.current_dkg_id,
        };
        let dkg_begin_packet = Packet {
            sig: dkg_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgBegin"),
            msg: Message::DkgBegin(dkg_begin),
        };

        self.move_to(State::DkgPublicGather)?;
        self.dkg_public_start = Some(Instant::now());
        Ok(dkg_begin_packet)
    }
```

**File:** src/state_machine/coordinator/fire.rs (L650-763)
```rust
                            }
                        }
                        DkgFailure::BadPrivateShares(bad_shares) => {
                            // bad_shares is a map of signer_id to BadPrivateShare
                            for (bad_signer_id, bad_private_share) in bad_shares {
                                // verify the DH tuple proof first so we know the shared key is correct
                                let Some(signer_key_ids) =
                                    self.config.public_keys.signer_key_ids.get(signer_id)
                                else {
                                    warn!("No key IDs for signer_id {signer_id} DkgEnd");
                                    continue;
                                };
                                let Some(signer_public_shares) =
                                    self.dkg_public_shares.get(signer_id)
                                else {
                                    warn!("Signer {signer_id} reported BadPrivateShares from {bad_signer_id} but there are no public shares from {signer_id}");
                                    continue;
                                };
                                let signer_public_key = signer_public_shares.kex_public_key;

                                let Some(bad_signer_public_shares) =
                                    self.dkg_public_shares.get(bad_signer_id)
                                else {
                                    warn!("Signer {signer_id} reported BadPrivateShares from {bad_signer_id} but there are no public shares from {bad_signer_id}, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                    continue;
                                };
                                let bad_signer_public_key = bad_signer_public_shares.kex_public_key;

                                let mut is_bad = false;

                                if bad_private_share.tuple_proof.verify(
                                    &signer_public_key,
                                    &bad_signer_public_key,
                                    &bad_private_share.shared_key,
                                ) {
                                    // verify at least one bad private share for one of signer_id's key_ids
                                    let shared_secret =
                                        make_shared_secret_from_key(&bad_private_share.shared_key);

                                    let polys = bad_signer_public_shares
                                        .comms
                                        .iter()
                                        .cloned()
                                        .collect::<HashMap<u32, PolyCommitment>>();
                                    let Some(dkg_private_shares) =
                                        self.dkg_private_shares.get(bad_signer_id)
                                    else {
                                        warn!("Signer {signer_id} reported BadPrivateShare from signer {bad_signer_id} who didn't send public shares, mark {signer_id} as malicious");
                                        malicious_signers.insert(*signer_id);
                                        continue;
                                    };

                                    for (src_party_id, key_shares) in &dkg_private_shares.shares {
                                        let Some(poly) = polys.get(src_party_id) else {
                                            warn!("Signer {signer_id} reported BadPrivateShares from {bad_signer_id} but the private shares from {bad_signer_id} dont have a polynomial for party {src_party_id}");
                                            continue;
                                        };
                                        for key_id in signer_key_ids {
                                            let Some(bytes) = key_shares.get(key_id) else {
                                                warn!("DkgPrivateShares from party_id {src_party_id} did not include a share for key_id {key_id}");
                                                continue;
                                            };
                                            match decrypt(&shared_secret, bytes) {
                                                Ok(plain) => match Scalar::try_from(&plain[..]) {
                                                    Ok(private_eval) => {
                                                        let poly_eval = match compute::poly(
                                                            &compute::id(*key_id),
                                                            &poly.poly,
                                                        ) {
                                                            Ok(p) => p,
                                                            Err(e) => {
                                                                warn!("Failed to evaluate public poly from signer_id {bad_signer_id} to key_id {key_id}: {e:?}");
                                                                is_bad = true;
                                                                break;
                                                            }
                                                        };

                                                        if private_eval * G != poly_eval {
                                                            warn!("Invalid dkg private share from signer_id {bad_signer_id} to key_id {key_id}");

                                                            is_bad = true;
                                                            break;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!("Failed to parse Scalar for dkg private share from signer_id {bad_signer_id} to key_id {key_id}: {e:?}");

                                                        is_bad = true;
                                                        break;
                                                    }
                                                },
                                                Err(e) => {
                                                    warn!("Failed to decrypt dkg private share from signer_id {bad_signer_id} to key_id {key_id}: {e:?}");
                                                    is_bad = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    warn!("TupleProof failed to verify, mark {signer_id} as malicious");
                                    is_bad = false;
                                }

                                // if tuple proof failed or none of the shares were bad sender was malicious
                                if !is_bad {
                                    warn!("Signer {signer_id} reported BadPrivateShare from {bad_signer_id} but the shares were valid, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                } else {
                                    warn!("Signer {signer_id} reported BadPrivateShare from {bad_signer_id}, mark {bad_signer_id} as malicious");
                                    malicious_signers.insert(*bad_signer_id);
                                }
                            }
```

**File:** src/state_machine/coordinator/fire.rs (L775-776)
```rust
            for id in &malicious_signers {
                self.malicious_dkg_signer_ids.insert(*id);
```

**File:** src/state_machine/coordinator/fire.rs (L783-789)
```rust
                // TODO: see if we have sufficient non-malicious signers to continue
                warn!("got dkg failures");
                return Err(Error::DkgFailure {
                    reported_failures,
                    malicious_signers,
                });
            }
```

**File:** src/state_machine/coordinator/fire.rs (L1363-1363)
```rust
            malicious_dkg_signer_ids: self.malicious_dkg_signer_ids.clone(),
```

**File:** src/state_machine/coordinator/fire.rs (L1429-1439)
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
    }
```

**File:** src/state_machine/coordinator/mod.rs (L349-349)
```rust
    fn start_dkg_round(&mut self, dkg_id: Option<u64>) -> Result<Packet, Error>;
```
