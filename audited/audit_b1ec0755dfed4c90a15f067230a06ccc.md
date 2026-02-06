### Title
Unvalidated Private Shares Corruption in DKG Secret Computation

### Summary
The `Party::compute_secret()` function in both v1 and v2 implementations sums ALL private shares into the private key, including shares that have no corresponding public polynomial commitments and thus are never validated. A malicious signer can inject arbitrary unvalidated scalar values into victims' private keys by sending private shares without sending valid public commitments, corrupting the DKG and causing signature verification failures.

### Finding Description

**Exact Code Location:**
- [1](#0-0) 
- [2](#0-1) 

**Root Cause:**
The `compute_secret()` function validates that each key in `public_shares` has a corresponding entry in `private_shares` [3](#0-2) , but does NOT validate the reverse direction. The validation loop only checks private shares that have corresponding public commitments [4](#0-3) . When a private share has no corresponding public commitment, it logs a warning but continues [5](#0-4) . Critically, the final private key is computed by summing ALL values from `private_shares` [6](#0-5) , including the unvalidated shares.

**Why Existing Mitigations Fail:**
The state machine's `dkg_ended` method builds `self.commitments` from only valid participants [7](#0-6) , but `self.decrypted_shares` contains shares from ALL signers who sent `DkgPrivateShares`. The `dkg_private_shares` handler accepts and decrypts shares from any configured signer [8](#0-7)  without checking if they are in the expected participant list. When `compute_secrets` is called [9](#0-8) , it receives mismatched inputs where `decrypted_shares` contains more entries than `commitments`.

The same vulnerability exists in v2, where unvalidated shares are summed at [10](#0-9) .

### Impact Explanation

**Specific Harm:**
An attacker can add arbitrary scalar values to victims' private key shares, corrupting the distributed key. The aggregated group public key will not match the actual sum of private keys, causing all signatures to fail verification or verify under an incorrect public key.

**Quantification:**
- All parties receiving the malicious shares have corrupted keys
- DKG appears to succeed (returns `Ok(())`) but produces unusable keys
- 100% of subsequent signature operations will fail
- If different nodes have different subsets of corrupted keys, they will produce different signatures for the same message

**Who is Affected:**
All signers participating in a DKG round where a malicious actor sends unvalidated private shares.

**Severity Justification:**
This maps to **Medium** severity under "Any transient consensus failures" as it causes DKG to produce keys that cannot create valid signatures. It could escalate to **High** ("Any chain split caused by different nodes processing the same block or transaction and yielding different results") if different nodes have different corrupted key sets, leading them to produce and accept different signatures.

### Likelihood Explanation

**Required Attacker Capabilities:**
1. Network access to send P2P DKG messages
2. Valid signer configuration (exists in `public_keys.signers`)
3. Ability to send `DkgPrivateShares` messages

**Attack Complexity:**
Low. The attacker:
1. Monitors the DKG protocol
2. Sends `DkgPrivateShares` with crafted scalar values
3. Does not send valid `DkgPublicShares` OR gets excluded from final participant set
4. Victims decrypt and store the malicious shares
5. During `dkg_ended`, malicious shares have no commitments to validate against
6. Unvalidated shares are summed into private keys

**Economic Feasibility:**
High. Requires only network access, no cryptographic breaks or significant computational resources.

**Detection Risk:**
Low. The attack is logged as a warning [11](#0-10)  but does not cause DKG failure. The corruption is only detected when signatures fail to verify, by which point the attack has succeeded.

**Estimated Probability:**
High. The vulnerability is easily exploitable by any signer with network access.

### Recommendation

**Proposed Code Changes:**
In `Party::compute_secret()` (both v1 and v2), add validation that `private_shares` does not contain extra keys beyond those in `public_shares`:

```rust
// After line 180 in v1.rs, add:
for i in private_shares.keys() {
    if public_shares.get(i).is_none() {
        return Err(DkgError::BadPrivateShares(vec![*i]));
    }
}
```

Alternatively, filter the sum to only include validated shares:
```rust
// Replace line 205 in v1.rs:
self.private_key = private_shares.iter()
    .filter(|(k, _)| public_shares.contains_key(k))
    .map(|(_, v)| v)
    .sum();
```

**State Machine Fix:**
In `dkg_ended` [9](#0-8) , filter `self.decrypted_shares` to only include entries for signers in `signer_ids_set` before passing to `compute_secrets`.

**Testing Recommendations:**
1. Add test case where a signer sends private shares but no public commitments
2. Add test case where a non-participant sends private shares
3. Verify DKG fails with `BadPrivateShares` error in both cases

### Proof of Concept

**Exploitation Algorithm:**
```
1. Setup: DKG round with N participants, threshold T
2. Attacker A is configured but excluded from final signer_ids_set
   (or sends invalid/no DkgPublicShares)
3. A crafts DkgPrivateShares with malicious scalar M for victim V:
   - shares = [(A_party_id, {V_key_id: encrypt(M)})]
4. A sends DkgPrivateShares to V
5. V processes message in dkg_private_shares():
   - Validates A exists in config ✓
   - Validates A_party_id belongs to A ✓
   - Decrypts and stores in self.decrypted_shares[A_party_id][V_key_id] = M
6. Coordinator sends DkgEndBegin with signer_ids excluding A
7. V processes in dkg_ended():
   - Builds self.commitments from only participants in signer_ids (A excluded)
   - self.decrypted_shares still contains A's shares
   - Calls compute_secrets(&self.decrypted_shares, &self.commitments, ...)
8. In compute_secret():
   - Check at lines 172-180: passes (all public_shares have private_shares)
   - Validation at lines 191-203: A's share not in public_shares, logs warning
   - Line 205: private_key = sum(ALL private_shares including M)
   - Returns Ok(())
9. V's private_key = (legitimate_sum + M), corrupted
10. Group key mismatch: signatures fail verification
```

**Parameter Values:**
- N = 10 parties, T = 7 threshold
- Attacker scalar M = 0x123456... (arbitrary 32-byte value)
- Victim key_id = 5

**Expected vs Actual:**
- Expected: DKG fails with error when unvalidated share detected
- Actual: DKG succeeds, warning logged, corrupted key produced

**Reproduction:**
Use existing test framework with modification to inject unvalidated private shares. The test at [12](#0-11)  can be modified to demonstrate the attack by adding extra entries to `private_shares` that are not in `comms`.

### Notes

This vulnerability affects both the v1 and v2 implementations identically. The issue stems from an asymmetric validation: checking that all public shares have private shares, but not that all private shares have public shares. The developer comment "even though we checked for it above" indicates awareness that this case could occur, but it was treated as a warning rather than an error condition.

### Citations

**File:** src/v1.rs (L150-209)
```rust
    pub fn compute_secret(
        &mut self,
        private_shares: HashMap<u32, Scalar>,
        public_shares: &HashMap<u32, PolyCommitment>,
        ctx: &[u8],
    ) -> Result<(), DkgError> {
        self.private_key = Scalar::zero();
        self.group_key = Point::zero();

        let threshold: usize = self.threshold.try_into()?;
        let mut bad_ids = Vec::new(); //: Vec<u32> = polys
        for (i, comm) in public_shares.iter() {
            if !check_public_shares(comm, threshold, ctx) {
                bad_ids.push(*i);
            } else {
                self.group_key += comm.poly[0];
            }
        }
        if !bad_ids.is_empty() {
            return Err(DkgError::BadPublicShares(bad_ids));
        }

        let mut missing_shares = Vec::new();
        for i in public_shares.keys() {
            if private_shares.get(i).is_none() {
                missing_shares.push((self.id, *i));
            }
        }
        if !missing_shares.is_empty() {
            return Err(DkgError::MissingPrivateShares(missing_shares));
        }

        // batch verification requires that we multiply each term by a random scalar in order to
        // prevent a bypass attack.  Doing this using p256k1's MultiMult trait is problematic,
        // because it needs to have every term available so it can return references to them,
        // so we wouldn't be able to save any memory since we'd have to multiple each polynomial
        // coefficient by a different random scalar.
        // we could implement a MultiMultCopy trait that allows us to do the multiplication inline,
        // at the cost of many copies, or use large amounts of memory and do a standard multimult.
        // Or we could just verify each set of public and private shares separately, using extra CPU
        let mut bad_shares = Vec::new();
        for (i, s) in private_shares.iter() {
            if let Some(comm) = public_shares.get(i) {
                if s * G != compute::poly(&self.id(), &comm.poly)? {
                    bad_shares.push(*i);
                }
            } else {
                warn!("unable to check private share from {}: no corresponding public share, even though we checked for it above", i);
            }
        }

        if !bad_shares.is_empty() {
            return Err(DkgError::BadPrivateShares(bad_shares));
        }

        self.private_key = private_shares.values().sum();
        self.public_key = self.private_key * G;

        Ok(())
    }
```

**File:** src/v1.rs (L773-805)
```rust
    /// Run a distributed key generation round
    pub fn dkg<RNG: RngCore + CryptoRng>(
        signers: &mut [v1::Signer],
        rng: &mut RNG,
    ) -> Result<HashMap<u32, PolyCommitment>, HashMap<u32, DkgError>> {
        let ctx = 0u64.to_be_bytes();
        let comms: HashMap<u32, PolyCommitment> = signers
            .iter()
            .flat_map(|s| s.get_poly_commitments(&ctx, rng))
            .map(|comm| (comm.id.id.get_u32(), comm))
            .collect();

        let mut private_shares = HashMap::new();
        for signer in signers.iter() {
            for (signer_id, signer_shares) in signer.get_shares() {
                private_shares.insert(signer_id, signer_shares);
            }
        }

        let mut secret_errors = HashMap::new();
        for signer in signers.iter_mut() {
            if let Err(signer_secret_errors) = signer.compute_secrets(&private_shares, &comms, &ctx)
            {
                secret_errors.extend(signer_secret_errors.into_iter());
            }
        }

        if secret_errors.is_empty() {
            Ok(comms)
        } else {
            Err(secret_errors)
        }
    }
```

**File:** src/v2.rs (L123-200)
```rust
    pub fn compute_secret(
        &mut self,
        private_shares: &HashMap<u32, HashMap<u32, Scalar>>,
        public_shares: &HashMap<u32, PolyCommitment>,
        ctx: &[u8],
    ) -> Result<(), DkgError> {
        self.private_keys.clear();
        self.group_key = Point::zero();

        let threshold: usize = self.threshold.try_into()?;

        let mut bad_ids = Vec::new();
        for (i, comm) in public_shares.iter() {
            if !check_public_shares(comm, threshold, ctx) {
                bad_ids.push(*i);
            } else {
                self.group_key += comm.poly[0];
            }
        }
        if !bad_ids.is_empty() {
            return Err(DkgError::BadPublicShares(bad_ids));
        }

        let mut missing_shares = Vec::new();
        for dst_key_id in &self.key_ids {
            for src_key_id in public_shares.keys() {
                match private_shares.get(dst_key_id) {
                    Some(shares) => {
                        if shares.get(src_key_id).is_none() {
                            missing_shares.push((*dst_key_id, *src_key_id));
                        }
                    }
                    None => {
                        missing_shares.push((*dst_key_id, *src_key_id));
                    }
                }
            }
        }
        if !missing_shares.is_empty() {
            return Err(DkgError::MissingPrivateShares(missing_shares));
        }

        let mut bad_shares = Vec::new();
        for key_id in &self.key_ids {
            if let Some(shares) = private_shares.get(key_id) {
                for (sender, s) in shares {
                    if let Some(comm) = public_shares.get(sender) {
                        if s * G != compute::poly(&compute::id(*key_id), &comm.poly)? {
                            bad_shares.push(*sender);
                        }
                    } else {
                        warn!("unable to check private share from {}: no corresponding public share, even though we checked for it above", sender);
                    }
                }
            } else {
                warn!(
                    "no private shares for key_id {}, even though we checked for it above",
                    key_id
                );
            }
        }
        if !bad_shares.is_empty() {
            return Err(DkgError::BadPrivateShares(bad_shares));
        }

        for key_id in &self.key_ids {
            self.private_keys.insert(*key_id, Scalar::zero());
            if let Some(shares) = private_shares.get(key_id) {
                let secret = shares.values().sum();
                self.private_keys.insert(*key_id, secret);
            } else {
                warn!(
                    "no private shares for key_id {}, even though we checked for it above",
                    key_id
                );
            }
        }

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

**File:** src/state_machine/signer/mod.rs (L612-616)
```rust
            match self.signer.compute_secrets(
                &self.decrypted_shares,
                &self.commitments,
                &self.dkg_id.to_be_bytes(),
            ) {
```

**File:** src/state_machine/signer/mod.rs (L1037-1056)
```rust
        // check that the signer_id exists in the config
        let Some(_signer_public_key) = self.public_keys.signers.get(&src_signer_id) else {
            warn!(%src_signer_id, "No public key configured");
            return Ok(vec![]);
        };

        let Ok(kex_public_key) = self.get_kex_public_key(src_signer_id) else {
            return Ok(vec![]);
        };

        for (party_id, _shares) in &dkg_private_shares.shares {
            if !SignerType::validate_party_id(
                src_signer_id,
                *party_id,
                &self.public_keys.signer_key_ids,
            ) {
                warn!("Signer {src_signer_id} sent a polynomial commitment for party {party_id}");
                return Ok(vec![]);
            }
        }
```
