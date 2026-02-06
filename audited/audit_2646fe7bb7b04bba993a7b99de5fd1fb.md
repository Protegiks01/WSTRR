### Title
Byzantine Equivocation Attack Causes DKG State Desynchronization and False Malicious Signer Detection

### Summary
A Byzantine adversary can send different `DkgPublicShares` messages to different honest signers, causing them to detect different sets of bad public shares during DKG completion. This leads to state machine desynchronization where some honest signers successfully compute their secret shares while others abort, and critically, causes the coordinator to incorrectly mark honest signers as malicious, permanently excluding them from future DKG rounds.

### Finding Description

**Exact Code Location:**
- Signer public share validation: [1](#0-0) 
- Coordinator malicious signer marking: [2](#0-1) 
- Coordinator persistent malicious tracking: [3](#0-2) 
- Signer state divergence point: [4](#0-3) 

**Root Cause:**

The DKG protocol lacks a Byzantine Consistent Broadcast mechanism for `DkgPublicShares` messages. The network topology is all-to-all broadcast where each signer sends their public shares to all other signers and the coordinator independently. [5](#0-4)  Each signer stores the first `DkgPublicShares` message received from each `signer_id` and ignores duplicates.

A Byzantine adversary can exploit this by sending different `DkgPublicShares` messages (equivocation) to different honest parties. Since each honest party only sees their local view and the validation is performed independently on locally-stored data, different honest parties will detect different sets of bad shares.

During the DKG completion phase, when the coordinator sends `DkgEndBegin`, each signer validates their locally-stored public shares. [6](#0-5)  The `check_public_shares` function performs deterministic cryptographic validation [7](#0-6) , but operates on potentially different data at each honest signer.

**Why Existing Mitigations Fail:**

1. **Message Authentication**: While ECDSA signatures prevent impersonation (per Security Model), they do not prevent equivocation. A malicious signer can validly sign multiple different messages. [8](#0-7) 

2. **Coordinator Validation**: The coordinator independently validates reported bad shares against its own stored copies. [9](#0-8)  However, the coordinator only has one version of each signer's public shares. If the coordinator received a valid version but an honest signer received an invalid version, the coordinator incorrectly concludes the reporting signer is malicious. [10](#0-9) 

3. **No Equivocation Detection**: There is no mechanism for honest parties to compare what they received or for the coordinator to detect that different parties received different messages from the same source.

### Impact Explanation

**Specific Harm:**

1. **State Machine Desynchronization**: Honest signers that received valid public shares successfully call `compute_secrets()` and derive their secret key shares. [11](#0-10)  Honest signers that received invalid shares abort early and never compute secrets. [12](#0-11)  This creates inconsistent state where some honest signers have active key material while others don't.

2. **False Malicious Detection**: The coordinator marks honest signers as malicious when they correctly report bad shares that the coordinator didn't see. These false accusations are persisted in `malicious_dkg_signer_ids`. [3](#0-2) 

3. **Permanent Exclusion**: Falsely-accused honest signers may be excluded from subsequent DKG rounds if the coordinator uses the malicious signer tracking to filter participants.

4. **DKG Denial of Service**: The coordinator aborts DKG when any failures are reported. [13](#0-12)  A single Byzantine adversary can repeatedly trigger DKG failures.

**Quantified Impact:**

In a threshold signature system with `n` total signers and threshold `t`, a single Byzantine adversary can:
- Force DKG restart indefinitely (100% DoS)
- Cause `n-2` honest signers to be falsely marked as malicious (worst case: adversary sends valid shares to coordinator and 1 signer, invalid to all others)
- In WSTS's weighted threshold model, if falsely-accused signers control significant key weight, the remaining honest signers may fall below threshold

**Severity Justification:**

This maps to **Medium: Any transient consensus failures**. In blockchain contexts where WSTS is used for validator signatures or multisig custody:
- Prevents validator DKG from completing (transient consensus failure)
- Blocks multisig wallet key generation (DoS)
- Creates adversarial validator selection if honest validators are excluded

While not a permanent network halt, repeated exploitation prevents consensus formation and can create extended service disruption.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Single Byzantine adversary participating in DKG as a valid signer
- Ability to send different network messages to different recipients (standard network-level capability)
- Valid ECDSA signing key to authenticate messages

**Attack Complexity:** Low
1. Generate two different `DkgPublicShares` messages: one valid (passes `check_public_shares`), one invalid (fails verification)
2. Send valid version to coordinator and select honest signers
3. Send invalid version to remaining honest signers
4. Sign both messages with valid private key
5. Honest signers process their respective versions, report inconsistent results
6. Coordinator incorrectly blames honest reporters as malicious

**Economic Feasibility:** 
Extremely low cost. Requires only:
- Network bandwidth to send differentiated messages (trivial)
- Computational resources to create two polynomial commitments (milliseconds)
- One malicious signer position (assumed in Byzantine threat model per Security Model)

**Detection Risk:** 
Low. The equivocation is not detected by the protocol. From the coordinator's perspective, it appears that honest signers are falsely reporting bad shares. From each honest signer's perspective, they correctly reported what they observed.

**Estimated Probability of Success:** 
~100% given Byzantine adversary participation. The protocol has no defenses against this attack vector. Success only requires network-level message routing control, which any participant has for their own outgoing messages.

### Recommendation

**Primary Fix: Implement Byzantine Consistent Broadcast**

Modify the DKG protocol to ensure all honest parties receive the same `DkgPublicShares` from each sender:

1. **Coordinator Relay Pattern**: 
   - Require all signers to send `DkgPublicShares` only to coordinator
   - Coordinator validates and signs a digest of all received shares
   - Coordinator broadcasts the complete set with its signature to all signers
   - Signers validate coordinator signature before accepting shares
   
2. **Code Changes**:
   - Modify `start_public_shares()` [14](#0-13)  to collect shares first, then broadcast
   - Add coordinator signature over collected shares in `DkgPublicBegin` message
   - Modify signer `dkg_public_share()` [15](#0-14)  to only accept coordinator-relayed shares
   - Remove direct signer-to-signer `DkgPublicShares` transmission

**Alternative Mitigation: Proof of Equivocation**

If coordinator relay is not feasible:

1. Require honest signers reporting `BadPublicShares` to include the actual invalid `PolyCommitment` data in their `DkgEnd` message
2. Coordinator verifies the included commitment against its own copy
3. If commitments differ, mark the sender as equivocating (malicious), not the reporter
4. Extend `BadPrivateShare` proof pattern [16](#0-15)  to public shares

**Testing Recommendations:**

1. Add test case where malicious signer sends different `DkgPublicShares` to coordinator vs. other signers
2. Verify coordinator correctly identifies equivocating party, not honest reporter
3. Test that all honest signers reach consensus on DKG outcome
4. Verify `malicious_dkg_signer_ids` only contains actual malicious parties

**Deployment Considerations:**

- Protocol version bump required (message format changes)
- Backward compatibility: maintain separate code paths for legacy vs. fixed protocol
- Performance: coordinator relay adds one additional round-trip but eliminates vulnerability

### Proof of Concept

**Exploitation Algorithm:**

```
Setup: n=4 signers (S1, S2, S3 honest; M malicious), threshold t=3

Step 1: DKG Initialization
- Coordinator sends DkgBegin to all signers
- All signers generate polynomial commitments

Step 2: Malicious Equivocation
- M generates two PolyCommitment sets:
  * Valid_Poly: degree t-1, valid Schnorr ID proof
  * Invalid_Poly: degree t (wrong length) OR invalid Schnorr proof
  
- M sends DkgPublicShares(Valid_Poly) to Coordinator and S1
- M sends DkgPublicShares(Invalid_Poly) to S2 and S3
- Both messages validly signed with M's private key

Step 3: Signer Processing
- S1 receives Valid_Poly, stores it, passes check_public_shares() ✓
- S2 receives Invalid_Poly, stores it, fails check_public_shares() ✗
- S3 receives Invalid_Poly, stores it, fails check_public_shares() ✗
- Coordinator receives Valid_Poly, stores it ✓

Step 4: DKG Completion
- Coordinator sends DkgEndBegin with signer_ids=[S1,S2,S3,M]
- S1 validates Valid_Poly ✓, calls compute_secrets(), sends DkgEnd(Success)
- S2 validates Invalid_Poly ✗, aborts, sends DkgEnd(Failure(BadPublicShares({M})))
- S3 validates Invalid_Poly ✗, aborts, sends DkgEnd(Failure(BadPublicShares({M})))

Step 5: Coordinator False Accusation
- Coordinator receives S2's DkgEnd(BadPublicShares({M}))
- Coordinator checks its Valid_Poly from M ✓
- Coordinator marks S2 as malicious (line 645)
- Coordinator receives S3's DkgEnd(BadPublicShares({M}))
- Coordinator marks S3 as malicious
- Coordinator returns DkgFailure error

Result:
- S1 has computed secrets (state: DKG complete)
- S2,S3 do not have computed secrets (state: DKG aborted)
- S2,S3 permanently marked malicious despite being honest
- DKG round failed, must restart with reduced honest signer set
- M can repeat attack indefinitely
```

**Expected vs Actual Behavior:**

Expected: Coordinator detects M as malicious equivocator, excludes M, completes DKG with honest signers.

Actual: Coordinator marks honest S2 and S3 as malicious, M remains trusted, DKG fails, state desynchronization persists between S1 and S2/S3.

**Reproduction:**

1. Deploy 4-party WSTS with threshold 3
2. Modify one party to send different `DkgPublicShares` to different recipients (invalid to 2 signers, valid to coordinator and 1 signer)
3. Execute DKG round
4. Observe coordinator `malicious_dkg_signer_ids` contains honest signers, not the equivocating party
5. Observe honest signers in inconsistent states (some with secrets, some without)

### Citations

**File:** src/state_machine/signer/mod.rs (L551-598)
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
```

**File:** src/state_machine/signer/mod.rs (L611-621)
```rust
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
```

**File:** src/state_machine/signer/mod.rs (L973-1026)
```rust
    /// handle incoming DkgPublicShares
    pub fn dkg_public_share(
        &mut self,
        dkg_public_shares: &DkgPublicShares,
    ) -> Result<Vec<Message>, Error> {
        debug!(
            "received DkgPublicShares from signer {} {}/{}",
            dkg_public_shares.signer_id,
            self.commitments.len(),
            self.signer.get_num_parties(),
        );

        let signer_id = dkg_public_shares.signer_id;

        // check that the signer_id exists in the config
        let Some(_signer_public_key) = self.public_keys.signers.get(&signer_id) else {
            warn!(%signer_id, "No public key configured");
            return Ok(vec![]);
        };

        for (party_id, _) in &dkg_public_shares.comms {
            if !SignerType::validate_party_id(
                signer_id,
                *party_id,
                &self.public_keys.signer_key_ids,
            ) {
                warn!(%signer_id, %party_id, "signer sent polynomial commitment for wrong party");
                return Ok(vec![]);
            }
        }

        let have_shares = self
            .dkg_public_shares
            .contains_key(&dkg_public_shares.signer_id);

        if have_shares {
            info!(signer_id = %dkg_public_shares.signer_id, "received duplicate DkgPublicShares");
            return Ok(vec![]);
        }

        let Some(signer_key_ids) = self.public_keys.signer_key_ids.get(&signer_id) else {
            warn!(%signer_id, "No key_ids configured");
            return Ok(vec![]);
        };

        for key_id in signer_key_ids {
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
        }

        self.dkg_public_shares
            .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
        Ok(vec![])
    }
```

**File:** src/state_machine/coordinator/fire.rs (L396-423)
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

    /// Ask signers to send DKG private shares
    pub fn start_private_shares(&mut self) -> Result<Packet, Error> {
        // only wait for signers that returned DkgPublicShares
        self.dkg_wait_signer_ids = self
            .dkg_public_shares
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

**File:** src/state_machine/coordinator/fire.rs (L775-777)
```rust
            for id in &malicious_signers {
                self.malicious_dkg_signer_ids.insert(*id);
            }
```

**File:** src/state_machine/coordinator/fire.rs (L782-789)
```rust
            } else {
                // TODO: see if we have sufficient non-malicious signers to continue
                warn!("got dkg failures");
                return Err(Error::DkgFailure {
                    reported_failures,
                    malicious_signers,
                });
            }
```

**File:** src/common.rs (L318-321)
```rust
/// Check that the PolyCommitment is properly signed and has the correct degree polynomial
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```

**File:** src/net.rs (L48-55)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// A bad private share
pub struct BadPrivateShare {
    /// the DH shared key between these participants
    pub shared_key: Point,
    /// prooof that the shared key is a valid DH tuple as per chaum-pedersen
    pub tuple_proof: TupleProof,
}
```

**File:** src/net.rs (L526-539)
```rust
            Message::DkgPublicShares(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a DkgPublicShares message with an invalid signature.");
                        return false;
                    }
                } else {
                    warn!(
                        "Received a DkgPublicShares message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
```
