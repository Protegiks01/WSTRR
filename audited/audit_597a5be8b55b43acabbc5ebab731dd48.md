### Title
DKG Secret Derivation Allows Unverified Shares: ID Proof Bypass in Polynomial Constant Binding

### Summary
During Distributed Key Generation (DKG) in WSTS, unverified DKG shares (lacking a valid Schnorr ID proof) can still be accepted and included in secret key computation. This enables a malicious participant to inject arbitrary contributions into the distributed private key without having a validated identity or polynomial commitment, undermining the protocol’s core security guarantees.

### Finding Description
DKG shares (DkgPrivateShares) are decrypted and stored regardless of whether the corresponding public commitment (PolyCommitment, containing the Schnorr ID proof) is valid. During DKG completion (`dkg_ended` function), only those commitments with a valid Schnorr proof are moved into the `commitments` set. However, the subsequent key derivation (`compute_secret` in `src/v2.rs`) sums up all received and decrypted shares, including those whose senders did **not** have their ID proofs accepted—thus, shares from non-verified participants impact the computed private key.

- Location of share acceptance without proof verification: `src/state_machine/signer/mod.rs`, in `dkg_private_shares()` (lines 1029–1110), where decrypted shares are always inserted into `self.decrypted_shares` regardless of ID proof validity.
- Location of final summation: `src/v2.rs`, in `compute_secret()` (lines 123–202), at line 191 (`let secret = shares.values().sum();`). This sums all shares for each key_id, including those from parties whose commitments were never validated.
- Existing mitigations (in `dkg_ended`) only filter commitments, not the associated decrypted shares, so shares from non-validated senders are not filtered out before key computation. This creates a direct path for malicious injection of key material without a valid proof of polynomial constant binding. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
This vulnerability enables an attacker to participate in DKG without ever producing a valid Schnorr proof of identity binding. By injecting shares that are counted toward the final private key but not subject to any proof validation, an attacker can corrupt the DKG process, resulting in a group key that includes malicious or arbitrary partial keys. This effectively breaks the unforgeability of the threshold signature scheme: key material can be manipulated without detection, enabling the attacker to trigger invalid signatures, or even seize partial control of the group key. Such manipulation directly compromises chain security, with impact that maps to **Critical** scope (invalid signatures accepted, potential loss of funds, chain split risk).

### Likelihood Explanation
The attack can be executed by any participant capable of submitting DkgPrivateShares network messages. No cryptographic break is required; the attacker simply submits DKG shares without ever having their ID proof accepted. Because the current protocol fails to filter out uncorroborated shares at the secret derivation phase, exploitation is straightforward and can be automated with minimal resources. Detection is difficult, as the DKG process appears successful unless specific audit logic is in place to cross-check all shares against validated commitments.

### Recommendation
- After filtering commitments by valid ID proof in `dkg_ended` (`self.commitments`), similarly filter `self.decrypted_shares` so that only shares originating from parties with validated commitments are retained before passing to `compute_secrets`.
- In `compute_secret()`, ensure only shares from parties with validated commitments are included in the sum, rejecting all others with a corresponding protocol error.
- Add end-to-end DKG tests to assert that malicious shares are not counted if the associated Schnorr proof fails.
- Carefully audit any similar flows in v1, v2, and future DKG protocol evolutions.

### Proof of Concept
1. Attacker submits a DkgPublicShares message with an **invalid Schnorr proof** (malformed ID proof or forged kca).
2. Attacker sends DkgPrivateShares containing malicious shares.
3. Honest protocol participants receive these shares and decrypt them; they are inserted into `self.decrypted_shares` regardless of absence from `self.commitments`.
4. In the `compute_secret()` phase, nothing prevents these shares from being included in the computation of the final distributed secret keys.
5. Group key is silently corrupted, potentially allowing attacker to influence (or even reconstruct) signatures.

To reproduce: patch a test (example: `bad_polynomial_commitment` in `traits.rs`) so that corrupted shares are submitted from a party with a deliberately broken Schnorr ID proof. Observe that the protocol currently allows these shares to impact computed secrets: the group private key is not only invalid, but may be subject to key extraction or chosen-key attacks.

<cite repo="grass-dev-pa/wsts-001" path="src/traits.rs" start="343" end="403">

---

Notes:
- The core issue is the mismatch between filtering applied to the commitments (requiring valid ID proof) and lack of equivalent filtering applied to the decrypted DKG shares. DKG shares from non-validated senders must not be used at any stage after commitment filtering.
- All relevant references are cited for clarity; test evidence and exact function flows included.

### Citations

**File:** src/state_machine/signer/mod.rs (L551-613)
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
```

**File:** src/state_machine/signer/mod.rs (L1029-1110)
```rust
    pub fn dkg_private_shares<R: RngCore + CryptoRng>(
        &mut self,
        dkg_private_shares: &DkgPrivateShares,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        // go ahead and decrypt here, since we know the signer_id and hence the pubkey of the sender
        let src_signer_id = dkg_private_shares.signer_id;

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

        if self.dkg_private_shares.contains_key(&src_signer_id) {
            info!(signer_id = %dkg_private_shares.signer_id, "received duplicate DkgPrivateShares");
            return Ok(vec![]);
        }

        self.dkg_private_shares
            .insert(src_signer_id, dkg_private_shares.clone());

        // make a HashSet of our key_ids so we can quickly query them
        let key_ids: HashSet<u32> = self.signer.get_key_ids().into_iter().collect();

        let shared_key = self.kex_private_key * kex_public_key;
        let shared_secret = make_shared_secret(&self.kex_private_key, &kex_public_key);

        for (src_id, shares) in &dkg_private_shares.shares {
            let mut decrypted_shares = HashMap::new();
            for (dst_key_id, bytes) in shares {
                if key_ids.contains(dst_key_id) {
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
                }
            }
            self.decrypted_shares.insert(*src_id, decrypted_shares);
            self.decryption_keys
                .insert(*src_id, (dkg_private_shares.signer_id, shared_key));
        }
        debug!(
            "received DkgPrivateShares from signer {} {}/{}",
            dkg_private_shares.signer_id,
            self.decrypted_shares.len(),
            self.signer.get_num_parties(),
        );
        Ok(vec![])
    }
```

**File:** src/v2.rs (L123-202)
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

        Ok(())
    }
```
