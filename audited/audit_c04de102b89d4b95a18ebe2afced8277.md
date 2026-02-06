### Title
Coordinator Fails to Attribute Blame for Missing Private Shares Enabling Persistent DKG Denial of Service

### Summary
A malicious signer can selectively distribute encrypted private shares to only a subset of participants (e.g., colluding parties) during DKG, causing honest signers to report `MissingPrivateShares` failures. The coordinator fails to validate these claims or identify the malicious party, resulting in DKG failure without attribution. This enables persistent denial of service as the malicious signer can participate in retry attempts and repeat the attack indefinitely, preventing threshold signature operations from completing.

### Finding Description

**Exact Code Location:**

The vulnerability exists in `src/state_machine/coordinator/fire.rs` in the `gather_dkg_end` function: [1](#0-0) 

**Root Cause:**

When processing `DkgFailure::MissingPrivateShares` reports, the coordinator has only a TODO comment and performs no validation, in stark contrast to the extensive validation performed for `BadPrivateShares`: [2](#0-1) 

**How the Attack Works:**

1. During `dkg_private_begin`, each signer creates a `DkgPrivateShares` message containing encrypted shares for all active key_ids: [3](#0-2) 

A malicious signer can selectively omit certain destination key_ids from the HashMap when constructing this message, controlling which parties receive shares.

2. Honest signers detect missing shares during `dkg_ended`: [4](#0-3) 

The detection logic correctly identifies when shares for expected key_ids are missing from a signer's `DkgPrivateShares` message.

3. Honest signers report the failure: [5](#0-4) 

4. The coordinator collects reported failures but cannot distinguish between a malicious dealer who withheld shares and a malicious reporter making false claims: [6](#0-5) 

5. The coordinator returns `Error::DkgFailure` without marking anyone as malicious: [7](#0-6) 

**Why Existing Mitigations Fail:**

The coordinator has all necessary data to validate `MissingPrivateShares` claims:
- All `DkgPrivateShares` messages are stored: [8](#0-7) 

- The coordinator knows which key_ids each signer should control: [9](#0-8) 

However, no validation is performed to check if the accused signer's `DkgPrivateShares` actually contains shares for all expected key_ids.

### Impact Explanation

**Specific Harm:**

A malicious signer participating in DKG can prevent honest parties from completing the ceremony by selectively withholding shares. This results in:

1. **DKG Operation Failure:** The DKG round fails with `DkgError::DkgEndFailure` containing `reported_failures` but no identified `malicious_signers`: [10](#0-9) 

2. **No Malicious Party Identification:** The malicious signer is not added to `malicious_dkg_signer_ids`: [11](#0-10) 

This means retry attempts will include the same malicious signer.

3. **Persistent Denial of Service:** The attacker can repeat this attack on every DKG retry indefinitely, preventing the system from ever establishing a functioning threshold signing group.

4. **Selective Party Control:** The attacker controls exactly which subset of parties can complete DKG by choosing which key_ids to include in their shares, enabling collusion attacks.

**Quantified Impact:**

In a setup with N signers and threshold T:
- A single malicious signer can prevent (N - 1) honest signers from completing DKG
- The malicious signer can allow exactly their chosen colluding parties to succeed
- Each DKG retry will fail with the same attacker participating
- Zero successful DKG completions possible with the malicious signer present

**Who is Affected:**

Any WSTS deployment requiring DKG for threshold signature operations, including:
- Stacks blockchain miners using WSTS for block signing
- Multi-party custody systems using threshold signatures
- Any protocol depending on WSTS for distributed key generation

**Severity Justification:**

This maps to **HIGH** severity under the protocol scope:
- **"Any unintended chain split or network partition"**: If different nodes complete DKG with different participant subsets, they will have incompatible signing groups, causing network partition when attempting coordinated signing operations.
- Could escalate to **MEDIUM** ("Any transient consensus failures") if it causes signing failures affecting block production.
- At minimum **LOW** ("Any network denial of service impacting more than 10 percent of miners") if 10% or more miners cannot complete DKG.

The lack of blame attribution transforms what should be a detectable and recoverable failure into a persistent DoS vulnerability.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control of at least one signer identity participating in DKG
- Ability to send network messages to the coordinator
- No special privileges, cryptographic secrets, or timing advantages required

**Attack Complexity:**
- **Trivial to execute**: The attacker simply modifies the `encrypted_shares` HashMap in `dkg_private_begin` to omit certain destination key_ids before creating the `DkgPrivateShares` message
- **No cryptographic operations required**: No need to break encryption, forge signatures, or compromise key material
- **No race conditions**: The attack works in normal protocol flow
- **Deterministic success**: Every execution succeeds if the attacker controls a signer

**Economic Feasibility:**
- Near-zero cost if attacker already controls a signer identity
- No computational resources beyond normal participation required
- No financial incentive needed beyond desire to disrupt DKG

**Detection Risk:**
- **Zero detection risk**: The coordinator explicitly does not attribute blame, so the attacker cannot be identified
- The attack appears identical to legitimate network failures from the coordinator's perspective
- No cryptographic evidence distinguishes selective withholding from network issues

**Estimated Probability of Success:**
- **100%** per attempt if the attacker controls any participating signer
- **100%** sustainability across retry attempts since no blame attribution occurs
- Works against any configuration (any N, T, or number of key_ids per signer)

### Recommendation

**Primary Fix: Implement Blame Attribution for MissingPrivateShares**

Replace the TODO comment in `src/state_machine/coordinator/fire.rs` lines 768-770 with validation logic similar to `BadPrivateShares`:

```rust
DkgFailure::MissingPrivateShares(missing_from_signers) => {
    for accused_signer_id in missing_from_signers {
        // Get the accused signer's DkgPrivateShares message
        if let Some(accused_shares) = self.dkg_private_shares.get(accused_signer_id) {
            // Get the reporting signer's key_ids
            if let Some(reporter_key_ids) = self.config.public_keys.signer_key_ids.get(signer_id) {
                // Check if accused signer's shares contain all reporter's key_ids
                let mut missing_key_ids = Vec::new();
                
                for reporter_key_id in reporter_key_ids {
                    let mut found = false;
                    for (_src_party_id, key_shares) in &accused_shares.shares {
                        if key_shares.contains_key(reporter_key_id) {
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        missing_key_ids.push(*reporter_key_id);
                    }
                }
                
                if !missing_key_ids.is_empty() {
                    // Accused signer truly withheld shares - mark as malicious
                    warn!("Signer {signer_id} correctly reported MissingPrivateShares from {accused_signer_id} for key_ids {missing_key_ids:?}");
                    malicious_signers.insert(*accused_signer_id);
                } else {
                    // Shares are present in coordinator's view - reporter may be malicious
                    // or had network issues, but since coordinator received them, likely false report
                    warn!("Signer {signer_id} reported MissingPrivateShares from {accused_signer_id} but shares were present, mark {signer_id} as malicious");
                    malicious_signers.insert(*signer_id);
                }
            }
        } else {
            // Accused signer never sent DkgPrivateShares - definitely malicious
            warn!("Signer {signer_id} reported MissingPrivateShares from {accused_signer_id} who didn't send any shares");
            malicious_signers.insert(*accused_signer_id);
        }
    }
}
```

**Testing Recommendations:**
1. Add test case where a signer sends `DkgPrivateShares` with selective key_id omissions
2. Verify coordinator correctly identifies the malicious signer
3. Verify malicious signer is added to `malicious_dkg_signer_ids`
4. Test retry scenario excludes identified malicious signers
5. Test false reporting scenario (honest reporter claims missing but shares present)

**Deployment Considerations:**
- This fix requires coordinator code update only
- No protocol changes needed - uses existing data structures
- Backward compatible - doesn't change message formats
- Should be deployed before production use of DKG

### Proof of Concept

**Setup:**
- 5 signers (S0-S4), each with 2 key_ids
- S0 is malicious, S1 is colluding
- Threshold = 3

**Exploitation Steps:**

1. **Normal DKG Initiation:** All signers send `DkgPublicShares` successfully and coordinator broadcasts `DkgPrivateBegin`.

2. **Malicious Share Distribution:** S0 modifies `dkg_private_begin` execution:
   - Constructs `DkgPrivateShares` message
   - For its polynomial party_id, creates `encrypted_shares` HashMap
   - **Includes** shares for S1's key_ids (2, 3) - colluding party
   - **Omits** shares for S2's key_ids (4, 5) - honest parties
   - **Omits** shares for S3's key_ids (6, 7)
   - **Omits** shares for S4's key_ids (8, 9)
   - Sends this incomplete `DkgPrivateShares` message

3. **Detection by Honest Signers:** 
   - S2, S3, S4 each check received shares in `dkg_ended`
   - Each discovers S0's shares are missing for their key_ids
   - Each reports `DkgEnd` with `DkgStatus::Failure(DkgFailure::MissingPrivateShares([0]))`

4. **Coordinator Processing:**
   - Receives 3 `DkgEnd` messages reporting `MissingPrivateShares([0])`
   - Executes lines 768-770: does nothing
   - Collects in `reported_failures` (line 610)
   - Returns `Error::DkgFailure` with empty `malicious_signers` (line 785-788)

5. **Result:**
   - DKG fails with `DkgError::DkgEndFailure`
   - S0 is not in `malicious_dkg_signer_ids`
   - S1 successfully received shares and could complete if others did
   - Only S0 and S1 have complete share sets
   - No party is excluded from retry

**Expected vs Actual Behavior:**

Expected: Coordinator identifies S0 as malicious for withholding shares, adds to `malicious_dkg_signer_ids`, future retries exclude S0.

Actual: Coordinator cannot attribute blame, S0 remains eligible for retries, attack repeats indefinitely.

**Reproduction:**
Test case following the pattern in `empty_private_shares` test but with selective omission instead of empty shares: [12](#0-11) 

Modify line 1832 to selectively omit key_ids instead of sending empty vector, and verify coordinator fails to identify malicious signer.

### Citations

**File:** src/state_machine/coordinator/fire.rs (L552-553)
```rust
            self.dkg_private_shares
                .insert(dkg_private_shares.signer_id, dkg_private_shares.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L600-610)
```rust
        let mut reported_failures = HashMap::new();
        // this will be used to report signers who were malicious in this DKG round, as opposed to
        // self.malicious_dkg_signer_ids which contains all DKG signers who were ever malicious
        let mut malicious_signers = HashSet::new();
        let threshold: usize = self.config.threshold.try_into().unwrap();
        if self.dkg_wait_signer_ids.is_empty() {
            // if there are any errors, mark signers malicious and retry
            for (signer_id, dkg_end) in &self.dkg_end_messages {
                if let DkgStatus::Failure(dkg_failure) = &dkg_end.status {
                    warn!(%signer_id, ?dkg_failure, "DkgEnd failure");
                    reported_failures.insert(*signer_id, dkg_failure.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L652-763)
```rust
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

**File:** src/state_machine/coordinator/fire.rs (L768-770)
```rust
                        DkgFailure::MissingPrivateShares(_) => {
                            // this shouldn't happen, maybe mark signer malicious?
                        }
```

**File:** src/state_machine/coordinator/fire.rs (L775-788)
```rust
            for id in &malicious_signers {
                self.malicious_dkg_signer_ids.insert(*id);
            }

            if reported_failures.is_empty() {
                debug!("no dkg failures");
                self.dkg_end_gathered()?;
            } else {
                // TODO: see if we have sufficient non-malicious signers to continue
                warn!("got dkg failures");
                return Err(Error::DkgFailure {
                    reported_failures,
                    malicious_signers,
                });
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

**File:** src/state_machine/signer/mod.rs (L601-608)
```rust
        if !missing_private_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::MissingPrivateShares(
                    missing_private_shares,
                )),
            }));
```

**File:** src/state_machine/signer/mod.rs (L926-949)
```rust
        for (party_id, shares) in &self.signer.get_shares() {
            debug!(
                "Signer {} addding dkg private share for party_id {party_id}",
                self.signer_id
            );
            // encrypt each share for the recipient
            let mut encrypted_shares = HashMap::new();

            for (dst_key_id, private_share) in shares {
                if active_key_ids.contains(dst_key_id) {
                    debug!("encrypting dkg private share for key_id {dst_key_id}");
                    let Some(kex_public_key) = self.kex_public_keys.get(dst_key_id) else {
                        error!("No KEX public key for key_id {dst_key_id}");
                        return Err(Error::MissingKexPublicKey(*dst_key_id));
                    };
                    let shared_secret = make_shared_secret(&self.kex_private_key, kex_public_key);
                    let encrypted_share = encrypt(&shared_secret, &private_share.to_bytes(), rng)?;

                    encrypted_shares.insert(*dst_key_id, encrypted_share);
                }
            }

            private_shares.shares.push((*party_id, encrypted_shares));
        }
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

**File:** src/state_machine/mod.rs (L100-101)
```rust
    /// map of signer_id to controlled key_ids
    pub signer_key_ids: HashMap<u32, HashSet<u32>>,
```

**File:** src/state_machine/coordinator/mod.rs (L1830-1878)
```rust
                            dkg_id: shares.dkg_id,
                            signer_id: shares.signer_id,
                            shares: vec![],
                        };
                        Packet {
                            msg: Message::DkgPrivateShares(private_shares),
                            sig: vec![],
                        }
                    })
                    .collect()
            },
        );
        assert_eq!(operation_results.len(), 0);
        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(&outbound_messages[0].msg, Message::DkgEndBegin(_)),
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
                "Expected OperationResult::DkgError(DkgError::DkgEndFailure) got {:?}",
                operation_results[0]
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
            let (_, DkgFailure::MissingPrivateShares(signer_ids)) = dkg_failure else {
                panic!("Expected DkgFailure::MissingPublicShares got {dkg_failure:?}");
            };
            assert_eq!(
                expected_signer_ids, *signer_ids,
                "Expected signer_ids {expected_signer_ids:?} got {signer_ids:?}"
            );
        }
```
