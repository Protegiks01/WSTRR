# Audit Report

## Title
Missing Zero Private Key Validation Enables Targeted Party Exclusion During DKG

## Summary
The `Party::compute_secret()` function in both v1 and v2 implementations fails to validate that the computed private key is non-zero after summing all received private shares. A malicious party can exploit the public nature of polynomial commitments during DKG to craft shares that force a targeted victim's private key to zero, effectively excluding them from future signing operations and causing signature verification failures.

## Finding Description

The vulnerability exists in the DKG secret computation phase where parties sum received private shares to derive their private keys. The WSTS DKG protocol follows a three-phase structure:

**Phase 1 - Public Commitment Broadcast**: All parties generate random polynomials and broadcast their polynomial commitments publicly before any private share distribution occurs. [1](#0-0) 

**Phase 2 - Private Share Distribution**: After observing all public commitments, parties evaluate their polynomials at each key ID and send encrypted private shares. [2](#0-1) 

**Phase 3 - Secret Computation**: Each party validates received shares and computes their private key by summing all shares. [3](#0-2) 

**The Core Vulnerability**: In `compute_secret()`, the function validates that each individual private share matches its corresponding polynomial commitment, but performs no validation on the final computed private key value. [4](#0-3) 

The share validation check at line 193 only verifies the equation `s * G == compute::poly(&self.id(), &comm.poly)`, ensuring each share is consistent with its polynomial commitment. [5](#0-4)  This validation passes even when shares are deliberately crafted to sum to zero, because each share individually remains valid against its corresponding (malicious) commitment.

**Attack Mechanism**:

1. **Observation Phase**: The malicious party M observes all honest parties' polynomial commitments, which are broadcast publicly before private share distribution begins.

2. **Computation Phase**: Using the public polynomial commitments, M computes the sum of all honest polynomial evaluations at the victim's key ID using `compute::poly()`. [6](#0-5)  This function evaluates public polynomials at any point, computing Σ(coefficient_i * x^i).

3. **Crafting Phase**: M generates a malicious polynomial f_M where f_M(victim_id) = -sum_honest(victim_id). Since polynomials of degree threshold-1 have threshold coefficients, constraining one evaluation point leaves threshold-1 degrees of freedom, making this mathematically trivial.

4. **Proof Generation**: M creates a valid Schnorr ID proof for their malicious polynomial's constant term. [7](#0-6)  The Schnorr proof system only proves knowledge of the constant term without constraining what value it can be.

5. **Execution**: M broadcasts their malicious polynomial commitment (which passes `check_public_shares` validation) and sends the crafted share f_M(victim_id) to the victim.

6. **Result**: The victim sums all shares: secret_victim = sum_honest(victim_id) + f_M(victim_id) = sum_honest(victim_id) + (-sum_honest(victim_id)) = 0.

7. **Completion**: The DKG completes with `DkgStatus::Success` because no zero-validation exists. [8](#0-7) 

This breaks the DKG security guarantee that all parties compute valid, non-zero private key shares.

## Impact Explanation

**Direct Impact on Signing**: When a party attempts to sign with a zero private key, their signature share computation includes the term `challenge * &self.private_key * lambda`. [9](#0-8)  With a zero private key, this entire term vanishes, producing a signature share that lacks the required private key component. When the coordinator aggregates signature shares, the resulting group signature will be missing the victim's contribution and will fail verification against the group public key.

**Threshold Bypass**: If the malicious party targets k victims where k + remaining_honest_parties < threshold, the signing group cannot produce valid signatures even with all honest parties participating. This effectively raises the operational threshold, potentially making the system unable to sign.

**Severity Justification**: This vulnerability maps to **Medium severity** under the "transient consensus failures" category. In a Stacks blockchain integration, WSTS is used for signing blocks and transactions. Successful exploitation could prevent the signing threshold from being reached, blocking block production and transaction confirmation until DKG is re-run with different participants. The impact is transient because it's limited to the current DKG cohort and doesn't cause permanent state corruption or fund loss.

**Why Not Higher Severity**: The attack requires a new DKG round to persist, doesn't cause deep forks or chain splits, and doesn't directly cause fund loss. It's a availability attack on signing capability rather than a consensus safety violation.

## Likelihood Explanation

**Attacker Capabilities Required**:
- Participation in DKG as a signer (standard protocol participant role)
- Ability to observe public polynomial commitments (broadcast in plaintext by protocol design)
- Basic polynomial arithmetic capability (computationally trivial)
- No special privileges or compromised keys required

**Attack Complexity**: LOW. The attack algorithm is straightforward:
```
1. Collect all public polynomial commitments from DkgPublicShares messages
2. For target victim_id: compute honest_sum = Σ compute::poly(victim_id, honest_commitments)
3. Choose random coefficients a_1, ..., a_{threshold-1}
4. Compute a_0 = -honest_sum - Σ(a_i * victim_id^i)
5. Generate Schnorr proof for a_0
6. Broadcast malicious commitment and send crafted share
```

**Detection Difficulty**: The attack is difficult to detect because:
- Each individual share passes cryptographic validation
- The malicious commitment has a valid Schnorr proof
- The zero private key is only discovered during signing, not during DKG
- No protocol-level monitoring or alerts exist for zero private keys
- The codebase explicitly validates for zero nonces but omits this check for private keys [10](#0-9) 

**Economic Feasibility**: Requires only standard participation costs in DKG. No additional computational resources, staking, or economic attacks needed.

**Estimated Probability**: HIGH for single-party targeting by one malicious signer. The probability scales linearly with the number of malicious participants (each can target different victims independently).

## Recommendation

Add zero-validation for computed private keys in both `v1::Party::compute_secret()` and `v2::Party::compute_secret()` after the summation step.

**For v1 implementation** (after line 205 in src/v1.rs):
```rust
self.private_key = private_shares.values().sum();

// Add validation
if self.private_key == Scalar::zero() {
    return Err(DkgError::BadPrivateShares(
        public_shares.keys().copied().collect()
    ));
}

self.public_key = self.private_key * G;
```

**For v2 implementation** (in the loop at line 188-198 in src/v2.rs):
```rust
for key_id in &self.key_ids {
    self.private_keys.insert(*key_id, Scalar::zero());
    if let Some(shares) = private_shares.get(key_id) {
        let secret = shares.values().sum();
        
        // Add validation
        if secret == Scalar::zero() {
            return Err(DkgError::BadPrivateShares(
                public_shares.keys().copied().collect()
            ));
        }
        
        self.private_keys.insert(*key_id, secret);
    }
}
```

Additionally, update the DkgError enum in src/errors.rs to support reporting this specific failure mode if desired, though the existing `BadPrivateShares` error is sufficient to signal DKG failure.

This mirrors the existing zero-validation for nonces and ensures the fundamental security property that all parties compute non-trivial private keys during DKG.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Set up a DKG round with N parties including one malicious party M
2. Have M observe all honest polynomial commitments during Phase 1
3. Have M compute the sum of honest evaluations at victim's key_id
4. Have M generate a malicious polynomial that evaluates to the negative of this sum
5. Complete DKG and verify victim's private key equals zero
6. Attempt signing with the victim and observe signature verification failure

The core validation can be demonstrated with:

```rust
#[test]
fn test_zero_private_key_not_detected() {
    // Setup honest parties and collect their public commitments
    // Malicious party computes honest_sum at victim_id using compute::poly
    // Malicious party crafts polynomial with f_M(victim_id) = -honest_sum
    // Victim calls compute_secret with crafted shares
    // Assert: compute_secret returns Ok(()) despite zero private key
    // Assert: victim.private_key == Scalar::zero()
    // Assert: signing with victim produces invalid signature
}
```

The test would demonstrate that `compute_secret()` accepts shares that sum to zero and returns success, violating the invariant that private keys must be non-zero for secure signing operations.

### Citations

**File:** src/state_machine/signer/mod.rs (L643-670)
```rust
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
```

**File:** src/state_machine/signer/mod.rs (L857-890)
```rust
    fn dkg_public_begin<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let mut msgs = vec![];
        let comms = self
            .signer
            .get_poly_commitments(&self.dkg_id.to_be_bytes(), rng);

        info!(
            signer_id = %self.signer_id,
            dkg_id = %self.dkg_id,
            "sending DkgPublicShares"
        );

        let mut public_share = DkgPublicShares {
            dkg_id: self.dkg_id,
            signer_id: self.signer_id,
            comms: Vec::new(),
            kex_public_key: self.kex_private_key * G,
        };

        for poly in &comms {
            public_share
                .comms
                .push((poly.id.id.get_u32(), poly.clone()));
        }

        let public_share = Message::DkgPublicShares(public_share);
        msgs.push(public_share);

        self.move_to(State::DkgPublicGather)?;
        Ok(msgs)
    }
```

**File:** src/state_machine/signer/mod.rs (L892-956)
```rust
    fn dkg_private_begin<R: RngCore + CryptoRng>(
        &mut self,
        dkg_private_begin: &DkgPrivateBegin,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let mut msgs = vec![];
        let mut private_shares = DkgPrivateShares {
            dkg_id: self.dkg_id,
            signer_id: self.signer_id,
            shares: Vec::new(),
        };
        let mut active_key_ids = HashSet::new();
        for signer_id in &dkg_private_begin.signer_ids {
            if let Some(key_ids) = self.public_keys.signer_key_ids.get(signer_id) {
                for key_id in key_ids {
                    active_key_ids.insert(*key_id);
                }
            }
        }

        self.dkg_private_begin_msg = Some(dkg_private_begin.clone());
        self.move_to(State::DkgPrivateDistribute)?;

        info!(
            signer_id = %self.signer_id,
            dkg_id = %self.dkg_id,
            "sending DkgPrivateShares"
        );

        trace!(
            "Signer {} shares {:?}",
            self.signer_id,
            &self.signer.get_shares()
        );
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

        let private_shares = Message::DkgPrivateShares(private_shares);
        msgs.push(private_shares);

        self.move_to(State::DkgPrivateGather)?;
        Ok(msgs)
    }
```

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

**File:** src/v1.rs (L217-229)
```rust
    pub fn sign(&self, msg: &[u8], signers: &[u32], nonces: &[PublicNonce]) -> SignatureShare {
        let (_, aggregate_nonce) = compute::intermediate(msg, signers, nonces);
        let mut z = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        z += compute::challenge(&self.group_key, &aggregate_nonce, msg)
            * &self.private_key
            * compute::lambda(self.id, signers);

        SignatureShare {
            id: self.id,
            z_i: z,
            key_ids: vec![self.id],
        }
    }
```

**File:** src/compute.rs (L128-139)
```rust
/// Evaluate the public polynomial `f` at scalar `x` using multi-exponentiation
#[allow(clippy::ptr_arg)]
pub fn poly(x: &Scalar, f: &Vec<Point>) -> Result<Point, PointError> {
    let mut s = Vec::with_capacity(f.len());
    let mut pow = Scalar::one();
    for _ in 0..f.len() {
        s.push(pow);
        pow *= x;
    }

    Point::multimult(s, f.clone())
}
```

**File:** src/schnorr.rs (L31-45)
```rust
    pub fn new<RNG: RngCore + CryptoRng>(
        id: &Scalar,
        a: &Scalar,
        ctx: &[u8],
        rng: &mut RNG,
    ) -> Self {
        let k = Scalar::random(rng);
        let c = Self::challenge(id, &(&k * &G), &(a * &G), ctx);

        Self {
            id: *id,
            kG: &k * G,
            kca: &k + c * a,
        }
    }
```

**File:** src/common.rs (L90-93)
```rust
    /// Check that the nonces are not zero since that can lead to attacks
    pub fn is_valid(&self) -> bool {
        !self.is_zero() && !self.is_one()
    }
```
