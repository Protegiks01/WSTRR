### Title
DKG Failure Prioritization Masks Malicious Signer Detection

### Summary
The `dkg_ended()` function prioritizes reporting `bad_public_shares` over `missing_private_shares` when both failure conditions exist simultaneously. This allows coordinated malicious signers to evade detection by having one send bad public shares while another selectively withholds private shares, preventing the coordinator from identifying and excluding all malicious participants across DKG rounds.

### Finding Description

**Code Location:** [1](#0-0) 

The `dkg_ended()` function collects multiple failure types into separate HashSets (`missing_public_shares`, `bad_public_shares`, `missing_private_shares`) during validation. [2](#0-1) 

The function then uses early returns to report failures in strict priority order:

1. First checks `missing_public_shares` [3](#0-2) 
2. Then checks `bad_public_shares` [4](#0-3) 
3. Finally checks `missing_private_shares` [5](#0-4) 

**Both sets can be non-empty simultaneously:**

- `bad_public_shares` is populated when commitment validation fails [6](#0-5) 
- `missing_private_shares` is populated when expected private shares are absent or incomplete [7](#0-6) 

These are independent checks on different signers' messages, so both can fail in the same DKG round.

**Why existing mitigations fail:**

The coordinator's handling of `MissingPrivateShares` failures is completely unimplemented - it only contains a TODO comment with no action taken: [8](#0-7) 

In contrast, `BadPublicShares` failures are properly verified and result in marking malicious signers: [9](#0-8) 

### Impact Explanation

**Specific Harm:**
- Malicious signers who selectively withhold private shares can avoid detection indefinitely if coordinated with another malicious signer sending bad public shares
- Causes multiple failed DKG rounds as malicious participants persist across retries
- Leads to transient consensus failures as the system cannot establish a valid group key

**Quantified Impact:**
- Each masked malicious signer extends DKG completion by at least one additional round
- With coordinated adversaries, this pattern repeats until the adversary sending bad public shares exhausts their ability to generate invalid commitments
- In a system with 10 signers where 3 are malicious and coordinating, DKG could fail 3+ times before all malicious parties are identified

**Who is affected:**
- All honest participants waiting for DKG completion
- Systems dependent on WSTS for threshold signing (e.g., Stacks blockchain signer network)

**Severity Justification:**
This constitutes a **Medium** severity "transient consensus failure" as defined in the protocol scope. While the system eventually recovers, the delayed DKG convergence prevents normal operation and can be exploited for denial-of-service.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control of at least 2 malicious signers in the DKG participant set
- Ability to send messages selectively to the coordinator vs. other signers
- No cryptographic breaks required

**Attack Complexity:**
1. Malicious Signer A sends `DkgPrivateShares` to the coordinator but withholds from some/all honest signers
2. Coordinator includes A in `dkg_end_begin.signer_ids` [10](#0-9) 
3. Malicious Signer B sends invalid `DkgPublicShares` with commitments that fail validation
4. Honest signers populate both `bad_public_shares` (with B) and `missing_private_shares` (with A)
5. Due to prioritization, honest signers report only `DkgFailure::BadPublicShares(B)`
6. Coordinator marks B as malicious but never learns about A's misbehavior
7. Next round: A repeats the attack with a different accomplice

**Economic Feasibility:**
Highly feasible - requires only control of multiple signer identities and selective message routing, which are standard adversarial capabilities in distributed systems.

**Detection Risk:**
Low - the attack is masked by the legitimate-looking failure reporting mechanism. Honest signers report exactly what the code dictates.

**Estimated Probability:**
High in adversarial scenarios where multiple signers collude. Medium even with network partitioning alone (non-malicious but selective message delivery).

### Recommendation

**Primary Fix:**
Aggregate all failure types and report them together instead of using early returns:

```rust
// In dkg_ended(), replace the early return pattern (lines 585-609) with:
let mut all_failures = Vec::new();

if !missing_public_shares.is_empty() {
    all_failures.push(DkgFailure::MissingPublicShares(missing_public_shares));
}
if !bad_public_shares.is_empty() {
    all_failures.push(DkgFailure::BadPublicShares(bad_public_shares));
}
if !missing_private_shares.is_empty() {
    all_failures.push(DkgFailure::MissingPrivateShares(missing_private_shares));
}

if !all_failures.is_empty() {
    return Ok(Message::DkgEnd(DkgEnd {
        dkg_id: self.dkg_id,
        signer_id: self.signer_id,
        status: DkgStatus::Failure(DkgFailure::MultipleFailures(all_failures)),
    }));
}
```

**Coordinator Fix:**
Implement proper handling for `MissingPrivateShares` in the coordinator to mark signers as malicious: [8](#0-7) 

**Testing Recommendations:**
1. Add integration test where two malicious signers coordinate (one sends bad public shares, one withholds private shares)
2. Verify all malicious signers are identified within a single DKG round
3. Test with various network partition scenarios

**Deployment Considerations:**
This requires protocol message format changes. Deploy with backward compatibility period or coordinate upgrade across all participants.

### Proof of Concept

**Exploitation Algorithm:**

```
Setup:
- 5 total signers: 3 honest (H1, H2, H3), 2 malicious (M1, M2)
- DKG threshold = 3
- Coordinator receives messages from all signers

Step 1: DKG Public Shares Phase
- All signers send DkgPublicShares to coordinator
- M2 sends invalid polynomial commitments that fail check_public_shares()

Step 2: DKG Private Shares Phase  
- M1 sends DkgPrivateShares to ONLY the coordinator
- M1 does NOT send DkgPrivateShares to H1, H2, H3
- All other signers send normally

Step 3: DKG End Phase
- Coordinator sends DkgEndBegin with signer_ids = [H1, H2, H3, M1, M2]
  (M1 included because coordinator received its shares)
  
Step 4: Honest Signer Processing (e.g., H1)
- H1 checks public shares from M2 -> INVALID -> adds M2 to bad_public_shares
- H1 checks private shares from M1 -> MISSING -> adds M1 to missing_private_shares
- H1.dkg_ended() hits line 593 first, returns DkgFailure::BadPublicShares({M2})
- missing_private_shares never reported

Step 5: Coordinator Processing
- Receives DkgEnd from H1, H2, H3 all reporting BadPublicShares({M2})
- Marks M2 as malicious
- M1 escapes detection

Step 6: Next DKG Round
- M2 excluded (marked malicious)
- M1 still participates
- M1 can repeat attack with different accomplice
```

**Expected vs Actual Behavior:**
- Expected: Both M1 and M2 should be marked as malicious in round 1
- Actual: Only M2 is marked as malicious; M1 remains undetected

**Reproduction:**
Create a test with the above setup in the WSTS test suite. Monitor `malicious_dkg_signer_ids` in the coordinator after the first failed DKG round. Verify that M1 is NOT in the set despite withholding private shares.

### Citations

**File:** src/state_machine/signer/mod.rs (L504-671)
```rust
    pub fn dkg_ended<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<Message, Error> {
        if !self.can_dkg_end() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadState),
            }));
        }

        // only use the public shares from the DkgEndBegin signers
        let mut missing_public_shares = HashSet::new();
        let mut missing_private_shares = HashSet::new();
        let mut bad_public_shares = HashSet::new();
        let threshold: usize = self.threshold.try_into().unwrap();

        let Some(dkg_end_begin) = &self.dkg_end_begin_msg else {
            // no cached DkgEndBegin message
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadState),
            }));
        };

        // fist check to see if dkg_threshold has been met
        let signer_ids_set: HashSet<u32> = dkg_end_begin
            .signer_ids
            .iter()
            .filter(|&&id| id < self.total_signers)
            .copied()
            .collect::<HashSet<u32>>();
        let mut num_dkg_keys = 0u32;
        for id in &signer_ids_set {
            if let Some(key_ids) = self.public_keys.signer_key_ids.get(id) {
                let len: u32 = key_ids.len().try_into()?;
                num_dkg_keys = num_dkg_keys.saturating_add(len);
            }
        }

        if num_dkg_keys < self.dkg_threshold {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::Threshold),
            }));
        }

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
        }

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
        }

        let dkg_end = if self.invalid_private_shares.is_empty() {
            match self.signer.compute_secrets(
                &self.decrypted_shares,
                &self.commitments,
                &self.dkg_id.to_be_bytes(),
            ) {
                Ok(()) => DkgEnd {
                    dkg_id: self.dkg_id,
                    signer_id: self.signer_id,
                    status: DkgStatus::Success,
                },
                Err(dkg_error_map) => {
                    // we've handled everything except BadPrivateShares and Point both of which should map to DkgFailure::BadPrivateShares
                    let mut bad_private_shares = HashMap::new();
                    for (_my_party_id, dkg_error) in dkg_error_map {
                        if let DkgError::BadPrivateShares(party_ids) = dkg_error {
                            for party_id in party_ids {
                                if let Some((party_signer_id, _shared_key)) =
                                    &self.decryption_keys.get(&party_id)
                                {
                                    bad_private_shares.insert(
                                        *party_signer_id,
                                        self.make_bad_private_share(*party_signer_id, rng)?,
                                    );
                                } else {
                                    warn!("DkgError::BadPrivateShares from party_id {party_id} but no (signer_id, shared_secret) cached");
                                }
                            }
                        } else {
                            warn!("Got unexpected dkg_error {dkg_error:?}");
                        }
                    }
                    DkgEnd {
                        dkg_id: self.dkg_id,
                        signer_id: self.signer_id,
                        status: DkgStatus::Failure(DkgFailure::BadPrivateShares(
                            bad_private_shares,
                        )),
                    }
                }
            }
        } else {
            DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadPrivateShares(
                    self.invalid_private_shares.clone(),
                )),
            }
        };

        info!(
            signer_id = %self.signer_id,
            dkg_id = %self.dkg_id,
            status = ?dkg_end.status,
            "sending DkgEnd"
        );

        let dkg_end = Message::DkgEnd(dkg_end);
        Ok(dkg_end)
    }
```

**File:** src/state_machine/coordinator/fire.rs (L449-475)
```rust
    pub fn start_dkg_end(&mut self) -> Result<Packet, Error> {
        // only wait for signers that returned DkgPublicShares
        self.dkg_wait_signer_ids = self
            .dkg_private_shares
            .keys()
            .cloned()
            .collect::<HashSet<u32>>();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting DkgEnd Distribution"
        );

        let dkg_end_begin = DkgEndBegin {
            dkg_id: self.current_dkg_id,
            signer_ids: self.dkg_private_shares.keys().cloned().collect(),
            key_ids: vec![],
        };
        let dkg_end_begin_msg = Packet {
            sig: dkg_end_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgPrivateBegin"),
            msg: Message::DkgEndBegin(dkg_end_begin),
        };
        self.move_to(State::DkgEndGather)?;
        self.dkg_end_start = Some(Instant::now());
        Ok(dkg_end_begin_msg)
    }
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

**File:** src/state_machine/coordinator/fire.rs (L768-770)
```rust
                        DkgFailure::MissingPrivateShares(_) => {
                            // this shouldn't happen, maybe mark signer malicious?
                        }
```
