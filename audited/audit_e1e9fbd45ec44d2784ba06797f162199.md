### Title
Incomplete DKG Private Share Validation Allows Undetected Malicious Signer Denial of Service

### Summary
The `dkg_ended()` function fails to validate that all expected party_ids (key_ids) from each signer are present in the received private shares. While `compute_secrets()` later detects missing shares, the error handling doesn't properly process `DkgError::MissingPrivateShares`, preventing identification of the malicious signer. This enables a persistent DKG denial-of-service where the bad actor cannot be excluded from subsequent rounds.

### Finding Description

**Exact Location:** `src/state_machine/signer/mod.rs`, function `dkg_ended()`, lines 567-582 [1](#0-0) 

**Root Cause:** The validation logic checks only that `shares.shares` is non-empty and that each entry within it contains shares for all destination key_ids controlled by the receiving signer. It does NOT verify that the `shares.shares` vector contains entries for ALL party_ids (key_ids) that the sending signer controls.

In WSTS, each signer can control multiple key_ids (weighted threshold). During DKG private share distribution, a signer creates polynomial shares for each of its party_ids (which equal its key_ids). The structure is: [2](#0-1) 

When creating shares, a signer iterates through all its parties: [3](#0-2) 

The expected party_ids for each signer_id are stored in `public_keys.signer_key_ids`: [4](#0-3) 

**Why Existing Mitigations Fail:**

While `compute_secrets()` does detect missing shares and returns `DkgError::MissingPrivateShares`: [5](#0-4) 

The error handling in `dkg_ended()` fails to process this error type: [6](#0-5) 

When `DkgError::MissingPrivateShares` is returned, line 640 logs "Got unexpected dkg_error" but doesn't add any entries to `bad_private_shares`. The function then returns `DkgFailure::BadPrivateShares` with an empty HashMap. The coordinator receives this failure but cannot identify which signer is malicious: [7](#0-6) 

When `bad_shares` is empty, the loop at line 654 doesn't execute, and no malicious signer is identified.

### Impact Explanation

**Specific Harm:** A malicious signer can repeatedly prevent DKG completion without being detected and excluded. This blocks the generation of the distributed key required for threshold signatures.

**Quantification:** If WSTS DKG must complete before the system can generate signatures for blockchain operations (e.g., Stacks block signing), this attack prevents new blocks from being produced. With a malicious signer controlling even one key out of N keys, and assuming:
- DKG retry interval: 30-60 seconds
- Network of M signing nodes
- Attack can persist indefinitely since the bad actor is never excluded

**Who Is Affected:** All participants in the WSTS signing group, and downstream systems that depend on threshold signatures for consensus (e.g., Stacks blockchain miners and users).

**Severity Justification:** **Critical** - Maps to "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks." If the DKG cannot complete, threshold signatures cannot be generated. If these signatures are required for block production or validation, the blockchain network cannot progress, preventing transaction confirmation indefinitely.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control of at least one signer node in the WSTS signing group
- Ability to send network messages (DkgPrivateShares) 
- No need for cryptographic breaks or secret knowledge

**Attack Complexity:** Low
1. Malicious signer generates valid public shares for all its key_ids during DKG public phase
2. During private phase, sends encrypted private shares for only a SUBSET of its party_ids (e.g., if controlling key_ids [0,1,2], send shares only for party_id 0)
3. The validation at lines 569-579 passes because shares.shares is non-empty and contains the required dst_key_ids
4. Other signers' compute_secrets() detect missing shares but error handling fails
5. DKG fails without identifying the malicious signer
6. Coordinator retries DKG with same participants, attack repeats

**Economic Feasibility:** Trivial - requires only participation in the signing group (which may be permissioned or have economic barriers to entry, but once in, the attack costs nothing to execute)

**Detection Risk:** Low - The attack appears as a DKG failure rather than obvious malicious behavior. Logs show "Got unexpected dkg_error" but this requires manual log inspection.

**Estimated Probability of Success:** Near 100% if the attacker controls any signer node with multiple key_ids.

### Recommendation

**Primary Fix:** Add validation that the set of party_ids in `shares.shares` matches the expected key_ids for the sending signer:

```rust
// After line 567, add:
if let Some(expected_key_ids) = self.public_keys.signer_key_ids.get(signer_id) {
    let received_party_ids: HashSet<u32> = shares.shares
        .iter()
        .map(|(party_id, _)| *party_id)
        .collect();
    
    if received_party_ids != *expected_key_ids {
        let missing: Vec<u32> = expected_key_ids
            .difference(&received_party_ids)
            .copied()
            .collect();
        if !missing.is_empty() {
            missing_private_shares.insert(*signer_id);
        }
    }
}
```

**Secondary Fix:** Update error handling to properly process `DkgError::MissingPrivateShares`:

```rust
// Replace lines 626-641 with:
match dkg_error {
    DkgError::BadPrivateShares(party_ids) => {
        // existing BadPrivateShares handling
    }
    DkgError::MissingPrivateShares(missing_pairs) => {
        // Extract signer_ids from missing (party_id, src_party_id) pairs
        let mut missing_signer_ids = HashSet::new();
        for (_dst_party_id, src_party_id) in missing_pairs {
            if let Some((signer_id, _)) = self.decryption_keys.get(&src_party_id) {
                missing_signer_ids.insert(*signer_id);
            }
        }
        return Ok(Message::DkgEnd(DkgEnd {
            dkg_id: self.dkg_id,
            signer_id: self.signer_id,
            status: DkgStatus::Failure(DkgFailure::MissingPrivateShares(missing_signer_ids)),
        }));
    }
    _ => {
        warn!("Got unexpected dkg_error {dkg_error:?}");
    }
}
```

**Testing Recommendations:**
1. Add unit test with malicious signer sending incomplete party_id shares
2. Verify validation catches missing party_ids before compute_secrets
3. Test that MissingPrivateShares errors are properly converted to DkgFailure
4. Integration test confirming coordinator excludes malicious signer on retry

**Deployment Considerations:** This is a consensus-critical fix. All nodes must upgrade simultaneously to maintain consistent DKG failure detection.

### Proof of Concept

**Scenario Setup:**
- Signer 1 (malicious) controls key_ids: [0, 1, 2]
- Signer 2 (honest) controls key_ids: [3]
- Signer 3 (honest) controls key_ids: [4]
- Threshold requires 3 keys

**Attack Steps:**

1. **DKG Public Phase:** Signer 1 sends valid public shares for all party_ids [0, 1, 2]

2. **DKG Private Phase:** Signer 1 crafts malicious `DkgPrivateShares`:
   ```
   DkgPrivateShares {
       dkg_id: current_dkg_id,
       signer_id: 1,
       shares: vec![
           (0, hashmap!{3 => encrypt_share(...), 4 => encrypt_share(...)}),
           // Omit entries for party_ids 1 and 2
       ]
   }
   ```

3. **Signer 2 receives and processes:**
   - Line 567-579 validation: `shares.shares` is not empty ✓, contains dst_key_id 3 ✓
   - Validation PASSES (incorrectly)
   - Line 612: `compute_secrets()` called with commitments for [0,1,2] but shares only for [0]
   - Line 173-179 in v1.rs: Detects missing shares for party_ids [1, 2]
   - Returns `DkgError::MissingPrivateShares([(3, 1), (3, 2)])`
   - Line 640: Logs "Got unexpected dkg_error"
   - Line 643-649: Returns `DkgFailure::BadPrivateShares(HashMap::new())`

4. **Coordinator processes DkgEnd:**
   - Line 608: Detects Failure status
   - Line 610: Adds to `reported_failures`
   - Line 652: Processes `BadPrivateShares(empty HashMap)`
   - Line 654: Loop doesn't execute (empty HashMap)
   - No malicious signer identified
   - Line 785: DKG fails but `malicious_signers` is empty

5. **Result:** DKG fails, coordinator retries with same participants including Signer 1. Attack repeats indefinitely.

**Expected vs Actual Behavior:**
- **Expected:** Validation detects missing party_ids [1, 2] from Signer 1, reports `DkgFailure::MissingPrivateShares({1})`, coordinator marks Signer 1 as malicious
- **Actual:** Validation passes, `compute_secrets` error mishandled, empty `BadPrivateShares` reported, no malicious signer identified, infinite DKG failure loop

### Citations

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

**File:** src/state_machine/signer/mod.rs (L622-650)
```rust
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

**File:** src/net.rs (L190-199)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// DKG private shares message from signer to all signers and coordinator
pub struct DkgPrivateShares {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// List of (src_party_id, Map(dst_key_id, encrypted_share))
    pub shares: Vec<(u32, HashMap<u32, Vec<u8>>)>,
}
```

**File:** src/state_machine/mod.rs (L93-102)
```rust
#[derive(Clone, Default, PartialEq, Eq)]
/// Map of signer_id and key_id to the relevant ecdsa public keys
pub struct PublicKeys {
    /// signer_id -> public key
    pub signers: HashMap<u32, ecdsa::PublicKey>,
    /// key_id -> public key
    pub key_ids: HashMap<u32, ecdsa::PublicKey>,
    /// map of signer_id to controlled key_ids
    pub signer_key_ids: HashMap<u32, HashSet<u32>>,
}
```

**File:** src/v1.rs (L172-180)
```rust
        let mut missing_shares = Vec::new();
        for i in public_shares.keys() {
            if private_shares.get(i).is_none() {
                missing_shares.push((self.id, *i));
            }
        }
        if !missing_shares.is_empty() {
            return Err(DkgError::MissingPrivateShares(missing_shares));
        }
```

**File:** src/state_machine/coordinator/fire.rs (L652-664)
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
```
