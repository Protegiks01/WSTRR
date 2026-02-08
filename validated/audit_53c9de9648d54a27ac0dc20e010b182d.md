# Audit Report

## Title
DKG Can Produce Identity Point as Aggregate Public Key Through Collusion

## Summary
The FIRE coordinator's `dkg_end_gathered()` function computes the aggregate public key by summing polynomial constant terms without validating the result is not the identity point. Colluding malicious signers (within threshold-1 Byzantine tolerance) can coordinate to choose secrets that sum to zero modulo the curve order, causing DKG to produce an identity key that completely breaks the signing protocol's cryptographic security.

## Finding Description

The FIRE coordinator computes the aggregate public key by folding over all polynomial constant terms, starting from `Point::default()` (the identity element) and summing each signer's `comm.poly[0]` contribution, then storing the result directly without validation: [1](#0-0) 

The codebase demonstrates awareness of identity point validation in other contexts—`PublicNonce::is_valid()` explicitly checks that nonce points are not the identity: [2](#0-1) 

**Root Cause:** The protocol assumes that if all individual polynomial commitments pass Schnorr ID proof verification, the aggregate must be valid. However, Schnorr ID verification only proves each signer knows the discrete logarithm of their commitment—it does not prevent coordinated secret selection.

A malicious signer can create a valid Schnorr ID proof for `secret = 0` (producing the identity point). The verification equation `kca * G == kG + c * A` passes for `A = identity` because `c * identity = identity` (the additive identity), reducing to `k * G == k * G`: [3](#0-2) 

**Why Existing Mitigations Fail:** The coordinator's `gather_dkg_end()` validates individual commitments via `check_public_shares()`: [4](#0-3) 

This function only verifies Schnorr proofs and polynomial degree, but cannot detect coordinated secret selection: [5](#0-4) 

Each colluding signer's commitment passes all individual validations. Similarly, the signer's `compute_secret()` accumulates the group key without checking if the final result is the identity point: [6](#0-5) 

**Attack Execution:**
1. Two or more colluding malicious signers (within threshold-1 Byzantine tolerance) agree on secrets that sum to zero modulo curve order (e.g., Party A chooses `r`, Party B chooses `-r`)
2. Each generates their polynomial with the agreed constant term and creates valid Schnorr ID proofs
3. All individual validations pass (Schnorr proofs verify, shares are consistent)
4. Coordinator computes aggregate: `sum of commitments = identity`
5. DKG completes "successfully" with unusable key, returned as a successful result: [7](#0-6) 

## Impact Explanation

When the aggregate public key is the identity point, the threshold signing protocol becomes fundamentally broken. The FROST signature verification equation degenerates: [8](#0-7) 

With `public_key = identity`, the equation becomes `R = z * G + (-c) * identity = z * G`. Any signature where `R = z * G` would verify without requiring knowledge of private keys, completely breaking cryptographic security.

The DKG round produces an unusable key that cannot securely sign transactions. If the WSTS signing group controls critical blockchain operations (e.g., PoX, cross-chain operations), the network cannot confirm new valid transactions requiring signatures from this group. This maps to **Critical** severity: "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks."

The attack is stealthy—all individual protocol messages are valid, and neither coordinator nor honest signers detect the problem until attempting to use the key.

## Likelihood Explanation

**Required Capabilities:** At least 2 malicious signers in the DKG participant set with ability to coordinate secret selection. This is within the protocol's Byzantine threat model for threshold ≥ 3 (which allows up to threshold-1 malicious signers).

**Attack Complexity:** Straightforward—colluding parties agree on secrets that sum to zero, generate valid proofs, and submit valid protocol messages. No cryptographic breaks or additional resources required beyond DKG participation.

**Probability of Success:** 100% if the prerequisite collusion exists among threshold-1 Byzantine participants.

## Recommendation

Add validation to reject the identity point as an aggregate public key. In `dkg_end_gathered()`, after computing the aggregate key, verify it is not the identity:

```rust
fn dkg_end_gathered(&mut self) -> Result<(), Error> {
    // ... existing polynomial caching code ...
    
    // Calculate the aggregate public key
    let key = self
        .dkg_end_messages
        .keys()
        .flat_map(|signer_id| self.dkg_public_shares[signer_id].comms.clone())
        .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

    // Validate the aggregate key is not the identity point
    if key == Point::identity() {
        return Err(Error::InvalidAggregatePublicKey);
    }

    info!("Aggregate public key: {key}");
    self.aggregate_public_key = Some(key);
    self.move_to(State::Idle)
}
```

Apply the same validation in `compute_secret()` after accumulating the group key.

## Proof of Concept

```rust
#[test]
fn test_identity_aggregate_key_attack() {
    use crate::curve::{point::{Point, G}, scalar::Scalar};
    use crate::common::PolyCommitment;
    use crate::schnorr::ID;
    use crate::util::create_rng;
    use polynomial::Polynomial;
    
    let mut rng = create_rng();
    let ctx = 0u64.to_be_bytes();
    
    // Party A chooses secret r
    let secret_a = Scalar::random(&mut rng);
    let poly_a = Polynomial::new(vec![secret_a]);
    let comm_a = PolyCommitment {
        id: ID::new(&Scalar::from(1u32), &secret_a, &ctx, &mut rng),
        poly: vec![secret_a * G],
    };
    
    // Party B chooses secret -r (negation of Party A's secret)
    let secret_b = -secret_a;
    let poly_b = Polynomial::new(vec![secret_b]);
    let comm_b = PolyCommitment {
        id: ID::new(&Scalar::from(2u32), &secret_b, &ctx, &mut rng),
        poly: vec![secret_b * G],
    };
    
    // Both Schnorr proofs verify
    assert!(comm_a.verify(&ctx));
    assert!(comm_b.verify(&ctx));
    
    // Aggregate is the identity point
    let aggregate = comm_a.poly[0] + comm_b.poly[0];
    assert_eq!(aggregate, Point::identity());
    
    // This identity key breaks signature verification
    // Any R = z * G will satisfy: z * G + (-c) * identity = z * G
}
```

### Citations

**File:** src/state_machine/coordinator/fire.rs (L302-309)
```rust
                        // We are done with the DKG round! Return the operation result
                        return Ok((
                            None,
                            Some(OperationResult::Dkg(
                                self.aggregate_public_key
                                    .ok_or(Error::MissingAggregatePublicKey)?,
                            )),
                        ));
```

**File:** src/state_machine/coordinator/fire.rs (L633-637)
```rust
                                    if !check_public_shares(
                                        comm,
                                        threshold,
                                        &self.current_dkg_id.to_be_bytes(),
                                    ) {
```

**File:** src/state_machine/coordinator/fire.rs (L803-810)
```rust
        let key = self
            .dkg_end_messages
            .keys()
            .flat_map(|signer_id| self.dkg_public_shares[signer_id].comms.clone())
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

        info!("Aggregate public key: {key}");
        self.aggregate_public_key = Some(key);
```

**File:** src/common.rs (L161-163)
```rust
    pub fn is_valid(&self) -> bool {
        self.D != Point::identity() && self.E != Point::identity() && self.D != G && self.E != G
    }
```

**File:** src/common.rs (L245-249)
```rust
    pub fn verify(&self, public_key: &Point, msg: &[u8]) -> bool {
        let c = challenge(public_key, &self.R, msg);
        let R = &self.z * G + (-c) * public_key;

        R == self.R
```

**File:** src/common.rs (L319-321)
```rust
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```

**File:** src/schnorr.rs (L62-65)
```rust
    pub fn verify(&self, A: &Point, ctx: &[u8]) -> bool {
        let c = Self::challenge(&self.id, &self.kG, A, ctx);
        &self.kca * &G == &self.kG + c * A
    }
```

**File:** src/v2.rs (L130-139)
```rust
        self.group_key = Point::zero();

        let threshold: usize = self.threshold.try_into()?;

        let mut bad_ids = Vec::new();
        for (i, comm) in public_shares.iter() {
            if !check_public_shares(comm, threshold, ctx) {
                bad_ids.push(*i);
            } else {
                self.group_key += comm.poly[0];
```
