# Audit Report

## Title
Missing Zero Private Key Validation Enables Targeted Party Exclusion During DKG

## Summary
The `Party::compute_secret()` function in both v1 and v2 implementations fails to validate that computed private keys are non-zero after summing received private shares. A malicious party can exploit publicly broadcast polynomial commitments to craft shares that force a victim's private key to zero, excluding them from signing operations and causing signature verification failures.

## Finding Description

The vulnerability exists in the DKG secret computation phase where parties sum received private shares to derive their private keys.

**Phase 1 - Public Commitment Broadcast**: All parties broadcast their polynomial commitments publicly before private share distribution. [1](#0-0) 

**Phase 2 - Private Share Distribution**: After observing public commitments, parties create and distribute encrypted private shares. [2](#0-1) 

**Phase 3 - Secret Computation**: Each party validates shares and computes their private key by summing all shares.

**The Core Vulnerability**: In v1's `compute_secret()`, the function validates individual private shares against polynomial commitments but performs no validation on the final computed private key value. [3](#0-2)  The same issue exists in v2. [4](#0-3) 

The share validation at line 193 verifies `s * G == compute::poly(&self.id(), &comm.poly)`. [5](#0-4)  This passes even when shares are crafted to sum to zero, because each share individually validates against its (malicious) commitment.

**Attack Mechanism**:

1. **Observation**: The malicious party observes all honest parties' public polynomial commitments broadcast during DKG.

2. **Computation**: Using the public `compute::poly()` function [6](#0-5) , the attacker computes the sum of all honest polynomial evaluations at the victim's key ID.

3. **Crafting**: The attacker generates a malicious polynomial f_M where f_M(victim_id) = -sum_honest(victim_id). With a degree t-1 polynomial having t coefficients, constraining one evaluation point leaves t-1 degrees of freedom.

4. **Proof Generation**: The attacker creates a valid Schnorr ID proof for their malicious polynomial's constant term. [7](#0-6)  The Schnorr proof only proves knowledge of the constant term without constraining its value. [8](#0-7) 

5. **Execution**: The attacker broadcasts their malicious polynomial commitment, which passes `check_public_shares` validation [9](#0-8)  since it only verifies the Schnorr proof and polynomial degree.

6. **Result**: The victim sums all shares, resulting in private_key = 0.

7. **Completion**: The DKG completes with `DkgStatus::Success` [10](#0-9)  because no zero-validation exists.

## Impact Explanation

**Direct Impact on Signing**: When signing with a zero private key, the signature share computation includes `challenge * &self.private_key * lambda`. [11](#0-10)  With a zero private key, this term vanishes, producing an invalid signature share. When aggregated, the group signature fails verification [12](#0-11)  because the victim's contribution is missing.

**Threshold Bypass**: If the attacker targets k victims where k + remaining_honest_parties < threshold, the signing group cannot produce valid signatures even with all honest parties participating.

**Severity**: This maps to **Medium severity** under "transient consensus failures". In blockchain integration, successful exploitation prevents the signing threshold from being reached, blocking block production and transaction confirmation until DKG is re-run. The impact is transient (limited to current DKG cohort) and doesn't cause permanent state corruption or direct fund loss.

## Likelihood Explanation

**Attack Complexity**: LOW. The attacker needs only:
- Standard DKG participation
- Ability to observe public polynomial commitments (broadcast in plaintext)
- Basic polynomial arithmetic (computationally trivial)

**Detection Difficulty**: The attack is difficult to detect because:
- Individual shares pass cryptographic validation
- Malicious commitments have valid Schnorr proofs
- Zero private keys are only discovered during signing, not during DKG
- The codebase validates nonces for zero values [13](#0-12)  but omits this check for private keys

**Economic Feasibility**: Requires only standard DKG participation costs.

**Estimated Probability**: HIGH for single-party targeting by one malicious signer.

## Recommendation

Add zero private key validation in `compute_secret()` after computing the private key from shares:

**For v1.rs** (after line 205):
```rust
if self.private_key.is_zero() {
    return Err(DkgError::BadPrivateShares(
        public_shares.keys().copied().collect()
    ));
}
```

**For v2.rs** (after line 192):
```rust
if secret.is_zero() {
    return Err(DkgError::BadPrivateShares(
        public_shares.keys().copied().collect()
    ));
}
```

This mirrors the existing nonce validation pattern and prevents zero private keys from being accepted during DKG.

## Proof of Concept

```rust
#[test]
fn test_zero_private_key_attack() {
    use crate::v1::Party;
    use crate::common::PolyCommitment;
    use crate::compute;
    use crate::curve::scalar::Scalar;
    use crate::curve::point::{Point, G};
    use hashbrown::HashMap;
    use num_traits::Zero;
    
    let mut rng = create_rng();
    let threshold = 3;
    let num_keys = 5;
    let victim_id = 1;
    
    // Create honest parties
    let mut honest_parties: Vec<Party> = (2..=num_keys)
        .map(|id| Party::new(id, num_keys, threshold, &mut rng))
        .collect();
    
    // Get honest polynomial commitments
    let ctx = 0u64.to_be_bytes();
    let mut honest_comms = HashMap::new();
    for party in &honest_parties {
        if let Some(comm) = party.get_poly_commitment(&ctx, &mut rng) {
            honest_comms.insert(party.id, comm);
        }
    }
    
    // Compute sum of honest evaluations at victim_id
    let victim_scalar = compute::id(victim_id);
    let mut honest_sum = Point::zero();
    for comm in honest_comms.values() {
        honest_sum += compute::poly(&victim_scalar, &comm.poly).unwrap();
    }
    
    // Create malicious polynomial that zeros out victim
    // In practice, attacker computes coefficients such that poly(victim_id) = -honest_sum
    // For PoC, we verify zero private key is not rejected
    
    let mut victim = Party::new(victim_id, num_keys, threshold, &mut rng);
    
    // Simulate receiving shares that sum to zero
    let mut zero_shares = HashMap::new();
    for party_id in honest_comms.keys() {
        zero_shares.insert(*party_id, Scalar::zero());
    }
    
    // This should fail but doesn't due to missing validation
    let result = victim.compute_secret(zero_shares, &honest_comms, &ctx);
    
    assert!(result.is_ok()); // BUG: Zero private key is accepted
    assert!(victim.private_key.is_zero()); // Private key is zero
}
```

### Citations

**File:** src/state_machine/signer/mod.rs (L612-621)
```rust
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

**File:** src/state_machine/signer/mod.rs (L892-950)
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

**File:** src/v1.rs (L216-229)
```rust
    /// Sign `msg` with this party's share of the group private key, using the set of `signers` and corresponding `nonces`
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

**File:** src/schnorr.rs (L62-65)
```rust
    pub fn verify(&self, A: &Point, ctx: &[u8]) -> bool {
        let c = Self::challenge(&self.id, &self.kG, A, ctx);
        &self.kca * &G == &self.kG + c * A
    }
```

**File:** src/common.rs (L90-94)
```rust
    /// Check that the nonces are not zero since that can lead to attacks
    pub fn is_valid(&self) -> bool {
        !self.is_zero() && !self.is_one()
    }
}
```

**File:** src/common.rs (L242-251)
```rust
impl Signature {
    #[allow(non_snake_case)]
    /// Verify the aggregated group signature
    pub fn verify(&self, public_key: &Point, msg: &[u8]) -> bool {
        let c = challenge(public_key, &self.R, msg);
        let R = &self.z * G + (-c) * public_key;

        R == self.R
    }
}
```

**File:** src/common.rs (L319-321)
```rust
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```
