### Title
Coordinator Accepts Unvalidated DKG Public Shares Leading to Persistent Denial of Service

### Summary
The FIRE coordinator's `gather_public_shares()` function stores DkgPublicShares without validating polynomial commitments, Schnorr ID proofs, or polynomial degrees. When all participating signers are malicious and collude to send polynomials shorter than the threshold value, the coordinator crashes during signature aggregation with an index-out-of-bounds panic, permanently preventing transaction signing even after restart.

### Finding Description

**Exact Code Location:** [1](#0-0) 

The `gather_public_shares()` function performs only basic validation (DKG ID matching, signer ID existence checks, and duplicate detection) before storing the received DkgPublicShares directly. At lines 505-506, it inserts the shares without calling the available `check_public_shares()` validation function. [2](#0-1) 

The codebase provides a `check_public_shares()` function that validates both the Schnorr ID proof and polynomial degree, but it is not invoked by the coordinator during share gathering.

**Root Cause:**
The coordinator relies entirely on honest signers to detect and report invalid shares through DkgEnd messages with `DkgFailure::BadPublicShares` status. When honest signers detect bad shares, they report them and the coordinator performs reactive validation: [3](#0-2) 

However, this defense-in-depth is bypassed when all participating signers are malicious.

**Why Existing Mitigations Fail:**
Honest signers do validate shares during `dkg_ended()`: [4](#0-3) 

But this mitigation requires at least one honest signer to participate in the DKG round. If the attacker controls all >= `dkg_threshold` signers and prevents honest signers from participating, no validation occurs.

When the DKG completes, invalid commitments are copied to `party_polynomials`: [5](#0-4) 

During signing, the aggregator attempts to access polynomial coefficients without bounds checking: [6](#0-5) 

Line 438 accesses `comm.poly[i]` where `i` ranges from 0 to `threshold-1`. If any commitment has `poly.len() < threshold`, this causes an index-out-of-bounds panic.

The same vulnerability exists in v1: [7](#0-6) 

The FROST coordinator implementation has the identical issue: [8](#0-7) 

### Impact Explanation

**Specific Harm:**
1. Coordinator crashes with panic during `aggregator.init()` when attempting to sign
2. Signing operations permanently fail - the bad commitments persist in saved state
3. No transactions or blocks can be signed by the coordinator
4. Network cannot progress if the coordinator is critical for consensus

**Quantified Impact:**
- **Threshold Configuration:** With typical parameters (e.g., 28 threshold out of 40 keys as seen in tests), attacker needs control of 28+ signers
- **Persistence:** Even after coordinator restart, the corrupted `party_polynomials` are restored from saved state, maintaining the DoS
- **Scope:** All transactions requiring threshold signatures are blocked indefinitely

**Affected Parties:**
- Blockchain networks using WSTS for consensus signing
- Users unable to confirm transactions
- Applications dependent on the coordinator for multisig operations

**Severity Justification:**
This maps to **Critical** severity per the audit scope: "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks." The coordinator cannot sign any transactions after the attack, effectively shutting down transaction confirmation.

### Likelihood Explanation

**Required Attacker Capabilities:**
1. Control of >= `dkg_threshold` signers (e.g., 28 out of 40 in typical configurations)
2. Ability to ensure only malicious signers participate in a DKG round
3. Coordination among all malicious signers to send invalid shares consistently

**Attack Complexity:**
- **High Barrier:** Compromising majority of signers requires significant resources and access
- **Coordination:** All controlled signers must participate in the same DKG round without honest signers
- **Detection Risk:** If even one honest signer participates, they will detect and report the attack, causing the DKG to fail with error rather than proceeding

**Economic Feasibility:**
- Requires long-term compromise of signing infrastructure
- Cost depends on security of individual signer deployments
- May be feasible for nation-state adversaries or insiders with privileged access

**Estimated Probability:**
- **Low but Non-Zero:** While difficult, the attack is technically feasible without breaking cryptographic assumptions
- **Permanent Impact:** Once successful, the attack persists until manual intervention
- **No Detection:** If all signers are malicious, the attack proceeds silently without triggering any alarms

The coordinator invitation mechanism makes it harder to exclude honest signers: [9](#0-8) 

All configured signers are invited (line 399), making selective exclusion difficult without additional network-layer attacks.

### Recommendation

**Primary Fix - Add Proactive Validation:**
Modify `gather_public_shares()` to validate all received polynomial commitments immediately:

```rust
fn gather_public_shares(&mut self, packet: &Packet) -> Result<(), Error> {
    if let Message::DkgPublicShares(dkg_public_shares) = &packet.msg {
        // ... existing validation (dkg_id, signer_id, duplicates) ...
        
        // ADD: Validate polynomial commitments
        let threshold: usize = self.config.threshold.try_into()
            .map_err(|e| Error::InvalidThreshold)?;
        
        for (party_id, comm) in &dkg_public_shares.comms {
            if !check_public_shares(comm, threshold, &self.current_dkg_id.to_be_bytes()) {
                warn!(
                    signer_id = %dkg_public_shares.signer_id,
                    party_id = %party_id,
                    "Invalid polynomial commitment: bad Schnorr proof or wrong degree"
                );
                // Mark as malicious and reject
                self.malicious_dkg_signer_ids.insert(dkg_public_shares.signer_id);
                return Ok(());
            }
        }
        
        // ... rest of existing logic ...
    }
    Ok(())
}
```

Apply the same fix to the FROST coordinator's `gather_public_shares()` function.

**Alternative Mitigation - Bounds Checking:**
Add defensive bounds checking in aggregator initialization:

```rust
fn init(&mut self, comms: &HashMap<u32, PolyCommitment>) -> Result<(), AggregatorError> {
    let threshold: usize = self.threshold.try_into()?;
    
    // Validate all polynomials have correct length
    for (party_id, comm) in comms {
        if comm.poly.len() != threshold {
            return Err(AggregatorError::InvalidPolynomialDegree {
                party_id: *party_id,
                expected: threshold,
                actual: comm.poly.len(),
            });
        }
    }
    
    // ... rest of existing logic ...
}
```

**Testing Recommendations:**
1. Add test case where ALL signers send invalid polynomials (modify existing `bad_poly_length_dkg` test)
2. Verify coordinator rejects invalid shares even without honest signer reports
3. Test recovery scenarios after rejected DKG attempts
4. Validate that malicious signers are properly tracked and excluded

**Deployment Considerations:**
- This fix should be applied before deployment in any production blockchain environment
- Existing deployments should upgrade immediately as the vulnerability allows permanent DoS
- Review signer infrastructure security to reduce likelihood of mass compromise

### Proof of Concept

**Exploitation Algorithm:**

1. **Setup:** Attacker compromises >= `dkg_threshold` signers (e.g., 28 out of 40)

2. **Initiate DKG:** Wait for or trigger a new DKG round via `DkgBegin` message

3. **Send Malicious Shares:** Each malicious signer generates DkgPublicShares with truncated polynomials:
   ```
   // Normal polynomial has length = threshold
   // Malicious polynomial has length = threshold - 1
   let mut poly = generate_normal_polynomial(threshold);
   poly.pop(); // Remove last coefficient
   
   // Package into DkgPublicShares with invalid commitment
   let malicious_shares = DkgPublicShares {
       dkg_id: current_dkg_id,
       signer_id: attacker_signer_id,
       comms: vec![(party_id, PolyCommitment {
           id: schnorr_id, // Can be invalid since not checked
           poly: poly,     // Length < threshold
       })],
       kex_public_key: ephemeral_key,
   };
   ```

4. **Complete DKG:** All malicious signers send valid DkgPrivateShares and DkgEnd with Success status

5. **Trigger Signing:** Coordinator receives signing request and attempts to create signature

6. **Coordinator Crashes:** At `aggregator.init()`, line 438 (v2) or 447 (v1) panics:
   ```
   thread 'main' panicked at 'index out of bounds: the len is 27 but the index is 27'
   ```

**Expected vs Actual Behavior:**
- **Expected:** Coordinator validates polynomial commitments and rejects invalid shares, marking signers as malicious
- **Actual:** Coordinator accepts invalid shares, stores them, and later crashes when attempting to use them

**Reproduction:**
The existing test demonstrates the vulnerability relies on honest signers: [10](#0-9) 

To reproduce the vulnerability, modify this test to have ALL signers send bad polynomials and verify the coordinator crashes during signing instead of detecting the issue during DKG.

### Citations

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

**File:** src/state_machine/coordinator/fire.rs (L477-518)
```rust
    fn gather_public_shares(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Message::DkgPublicShares(dkg_public_shares) = &packet.msg {
            if dkg_public_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_public_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&dkg_public_shares.signer_id) {
                warn!(signer_id = %dkg_public_shares.signer_id, "No public key in config");
                return Ok(());
            };

            let have_shares = self
                .dkg_public_shares
                .contains_key(&dkg_public_shares.signer_id);

            if have_shares {
                info!(signer_id = %dkg_public_shares.signer_id, "received duplicate DkgPublicShares");
                return Ok(());
            }

            self.dkg_wait_signer_ids
                .remove(&dkg_public_shares.signer_id);

            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            debug!(
                dkg_id = %dkg_public_shares.dkg_id,
                signer_id = %dkg_public_shares.signer_id,
                "DkgPublicShares received"
            );
        }

        if self.dkg_wait_signer_ids.is_empty() {
            self.public_shares_gathered()?;
        }
        Ok(())
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

**File:** src/state_machine/coordinator/fire.rs (L794-812)
```rust
    fn dkg_end_gathered(&mut self) -> Result<(), Error> {
        // Cache the polynomials used in DKG for the aggregator
        for signer_id in self.dkg_private_shares.keys() {
            for (party_id, comm) in &self.dkg_public_shares[signer_id].comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
        }

        // Calculate the aggregate public key
        let key = self
            .dkg_end_messages
            .keys()
            .flat_map(|signer_id| self.dkg_public_shares[signer_id].comms.clone())
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

        info!("Aggregate public key: {key}");
        self.aggregate_public_key = Some(key);
        self.move_to(State::Idle)
    }
```

**File:** src/state_machine/coordinator/fire.rs (L2598-2696)
```rust
    fn bad_poly_length_dkg<Aggregator: AggregatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
    ) -> (Vec<FireCoordinator<Aggregator>>, Vec<Signer<SignerType>>) {
        let (mut coordinators, mut signers) =
            setup::<FireCoordinator<Aggregator>, SignerType>(num_signers, keys_per_signer);

        // We have started a dkg round
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_dkg_round(None)
            .unwrap();
        assert!(coordinators.first().unwrap().aggregate_public_key.is_none());
        assert_eq!(coordinators.first().unwrap().state, State::DkgPublicGather);

        // Send the DkgBegin message to all signers and share their responses with the coordinators and signers, but mutate two signers' DkgPublicShares: make one polynomial larger than the threshold, and the other smaller
        let (outbound_messages, operation_results) = feedback_mutated_messages(
            &mut coordinators,
            &mut signers,
            &[message],
            |signer, msgs| {
                if signer.signer_id != 0 && signer.signer_id != 1 {
                    return msgs;
                }
                msgs.iter()
                    .map(|packet| {
                        let Message::DkgPublicShares(shares) = &packet.msg else {
                            return packet.clone();
                        };
                        let comms = shares
                            .comms
                            .iter()
                            .map(|(id, comm)| {
                                let mut c = comm.clone();
                                if signer.signer_id == 0 {
                                    c.poly.push(Point::new());
                                } else {
                                    c.poly.pop();
                                }
                                (*id, c)
                            })
                            .collect();
                        Packet {
                            msg: Message::DkgPublicShares(DkgPublicShares {
                                dkg_id: shares.dkg_id,
                                signer_id: shares.signer_id,
                                comms,
                                kex_public_key: Point::new(),
                            }),
                            sig: vec![],
                        }
                    })
                    .collect()
            },
        );

        assert!(operation_results.is_empty());
        for coordinator in &coordinators {
            assert_eq!(coordinator.state, State::DkgPrivateGather);
        }

        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgPrivateBegin(_)),
            "Expected DkgPrivateBegin message"
        );

        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(operation_results.is_empty());
        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::DkgEndBegin(_)),
            "Expected DkgEndBegin message"
        );

        // Send the DkgEndBegin message to all signers and share their responses with the coordinators and signers
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &outbound_messages);
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
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
    }
```

**File:** src/common.rs (L318-321)
```rust
/// Check that the PolyCommitment is properly signed and has the correct degree polynomial
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```

**File:** src/state_machine/signer/mod.rs (L550-563)
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
```

**File:** src/v2.rs (L431-445)
```rust
    fn init(&mut self, comms: &HashMap<u32, PolyCommitment>) -> Result<(), AggregatorError> {
        let threshold: usize = self.threshold.try_into()?;
        let mut poly = Vec::with_capacity(threshold);

        for i in 0..poly.capacity() {
            poly.push(Point::zero());
            for (_, comm) in comms {
                poly[i] += &comm.poly[i];
            }
        }

        self.poly = poly;

        Ok(())
    }
```

**File:** src/v1.rs (L440-454)
```rust
    fn init(&mut self, comms: &HashMap<u32, PolyCommitment>) -> Result<(), AggregatorError> {
        let threshold = self.threshold.try_into()?;
        let mut poly = Vec::with_capacity(threshold);

        for i in 0..poly.capacity() {
            poly.push(Point::zero());
            for (_, p) in comms {
                poly[i] += &p.poly[i];
            }
        }

        self.poly = poly;

        Ok(())
    }
```

**File:** src/state_machine/coordinator/frost.rs (L290-334)
```rust
    fn gather_public_shares(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Message::DkgPublicShares(dkg_public_shares) = &packet.msg {
            if dkg_public_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_public_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&dkg_public_shares.signer_id) {
                warn!(signer_id = %dkg_public_shares.signer_id, "No public key in config");
                return Ok(());
            };

            let have_shares = self
                .dkg_public_shares
                .contains_key(&dkg_public_shares.signer_id);

            if have_shares {
                info!(signer_id = %dkg_public_shares.signer_id, "received duplicate DkgPublicShares");
                return Ok(());
            }

            self.ids_to_await.remove(&dkg_public_shares.signer_id);

            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            for (party_id, comm) in &dkg_public_shares.comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }

            debug!(
                dkg_id = %dkg_public_shares.dkg_id,
                signer_id = %dkg_public_shares.signer_id,
                "DkgPublicShares received"
            );
        }

        if self.ids_to_await.is_empty() {
            self.move_to(State::DkgPrivateDistribute)?;
        }
        Ok(())
    }
```
