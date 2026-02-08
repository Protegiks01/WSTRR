# Audit Report

## Title
Schnorr ID Proof Bypassed by Identity Point Allows DKG Threshold Reduction

## Summary
The `ID::verify()` function does not validate that the public key point `A` is not the identity point (point at infinity). An attacker can exploit this by creating a trivial proof with identity point values that always passes verification, allowing malicious DKG participants to be counted as valid contributors without actually contributing to the group key. This effectively reduces the threshold security from T parties to (T-K) parties where K is the number of malicious participants exploiting this vulnerability.

## Finding Description

The vulnerability exists in the Schnorr identity proof verification used during Distributed Key Generation (DKG). The core issue is in the `ID::verify()` function which performs proof verification without validating that the public key point is not the identity element. [1](#0-0) 

This verification equation checks `kca * G == kG + c * A` where `A` is the public key point being proven. When an attacker sets `A = Point::identity()`, `kG = Point::identity()`, and `kca = Scalar::zero()`, the equation becomes:

- Left side: `Scalar::zero() * G = Point::identity()`
- Right side: `Point::identity() + c * Point::identity() = Point::identity()`
- Result: `Point::identity() == Point::identity()` (always true)

This bypasses the proof-of-knowledge requirement entirely.

During DKG, polynomial commitments use this ID proof, passing `poly[0]` (the polynomial's constant term representing the party's public key contribution) as the `A` parameter: [2](#0-1) 

The validation function only checks the Schnorr proof validity and polynomial length, but does not verify that `poly[0]` is not the identity point: [3](#0-2) 

Both v1 and v2 implementations then add the validated `poly[0]` to compute the group key: [4](#0-3) [5](#0-4) 

Since adding the identity point is a no-op in elliptic curve arithmetic, the attacker contributes nothing to the group key while being counted as a valid participant.

While the codebase validates that `PublicNonce` points are not identity points to prevent attacks: [6](#0-5) 

No similar validation exists for `poly[0]` in polynomial commitments.

## Impact Explanation

This vulnerability breaks the fundamental threshold security guarantee of WSTS. If the configured threshold is T out of N parties, and K malicious parties exploit this vulnerability, the actual security threshold is reduced to only (T-K) honest parties, while the system still believes T parties are required for signatures.

In the worst case where K ≥ T malicious parties exploit this, fewer than T honest parties control the group key, completely breaking the threshold assumption. This enables signature forgery with fewer honest parties than the protocol promises.

For Bitcoin/Stacks applications using WSTS for multisig custody, this allows theft of funds by reducing the actual signing threshold below the configured security level. An attacker who can participate in DKG and subsequently compromise (T-K) honest parties can forge signatures and steal funds, when they should need to compromise T honest parties.

This maps to **Critical** severity because it enables:
- "Any confirmation of an invalid transaction" - attackers can forge signatures that should require T parties with only (T-K) honest parties
- "Any causing the direct loss of funds" - in Bitcoin/Stacks multisig applications, this enables theft by breaking the threshold assumption

## Likelihood Explanation

The attack has very high likelihood of success because:

**Required Attacker Capabilities:**
- Must be an authorized DKG participant (have a valid signer_id)
- Can send network messages during the DKG phase
- No cryptographic breaks or special computational resources required

**Attack Complexity:**
Low. The attacker simply constructs a malicious `PolyCommitment` message with:
1. `id.kG = Point::identity()`
2. `id.kca = Scalar::zero()`
3. `id.id = Scalar::from(attacker_signer_id)`
4. `poly = vec![Point::identity(), ...]` (with remaining coefficients set to any valid points)

The p256k1 crate used for elliptic curve operations supports serialization of the identity point, so this message can be constructed and transmitted through normal protocol channels.

**Economic Feasibility:**
Extremely feasible - no additional costs beyond normal DKG participation. The attack is deterministic and succeeds 100% of the time once the malicious commitment is accepted.

**Detection Risk:**
Low. The malicious commitment appears valid to all verification checks. Detection would require manually inspecting polynomial commitments for identity points, which is not currently implemented.

**Estimated Probability:**
Near 100% success rate if the attacker is a DKG participant. The only requirement is being included in the DKG participant set.

## Recommendation

Add identity point validation to the `ID::verify()` function and `check_public_shares()` function:

**In `src/schnorr.rs`, modify `ID::verify()`:**
```rust
pub fn verify(&self, A: &Point, ctx: &[u8]) -> bool {
    // Reject identity point
    if *A == Point::identity() {
        return false;
    }
    let c = Self::challenge(&self.id, &self.kG, A, ctx);
    &self.kca * &G == &self.kG + c * A
}
```

**In `src/common.rs`, modify `check_public_shares()`:**
```rust
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    // Validate that poly[0] is not the identity point
    if poly_comm.poly[0] == Point::identity() {
        return false;
    }
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```

Additionally, consider validating that `self.kG` in the `ID` struct is not the identity point during verification.

## Proof of Concept

```rust
#[test]
fn test_identity_point_bypass() {
    use crate::curve::point::{Point, G};
    use crate::curve::scalar::Scalar;
    use crate::schnorr::ID;
    use crate::common::PolyCommitment;
    
    // Construct malicious ID with identity point values
    let malicious_id = ID {
        id: Scalar::from(1u32),
        kG: Point::identity(),
        kca: Scalar::zero(),
    };
    
    // Create a polynomial commitment with identity point
    let poly = vec![Point::identity()]; // poly[0] = identity
    let malicious_commitment = PolyCommitment {
        id: malicious_id,
        poly,
    };
    
    let ctx = 0u64.to_be_bytes();
    
    // This should fail but currently passes
    assert!(malicious_commitment.verify(&ctx), "Identity point bypass successful");
}
```

## Notes

This vulnerability demonstrates a critical gap in validation between `PublicNonce` (which correctly validates against identity points) and polynomial commitments (which do not). The fix requires adding consistent identity point validation across all cryptographic commitments used in the protocol.

### Citations

**File:** src/schnorr.rs (L62-65)
```rust
    pub fn verify(&self, A: &Point, ctx: &[u8]) -> bool {
        let c = Self::challenge(&self.id, &self.kG, A, ctx);
        &self.kca * &G == &self.kG + c * A
    }
```

**File:** src/common.rs (L36-39)
```rust
    /// Verify the wrapped schnorr ID
    pub fn verify(&self, ctx: &[u8]) -> bool {
        self.id.verify(&self.poly[0], ctx)
    }
```

**File:** src/common.rs (L160-163)
```rust
    /// Check that the nonces are not zero since that can lead to attacks
    pub fn is_valid(&self) -> bool {
        self.D != Point::identity() && self.E != Point::identity() && self.D != G && self.E != G
    }
```

**File:** src/common.rs (L319-321)
```rust
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```

**File:** src/v1.rs (L161-166)
```rust
        for (i, comm) in public_shares.iter() {
            if !check_public_shares(comm, threshold, ctx) {
                bad_ids.push(*i);
            } else {
                self.group_key += comm.poly[0];
            }
```

**File:** src/v2.rs (L135-141)
```rust
        for (i, comm) in public_shares.iter() {
            if !check_public_shares(comm, threshold, ctx) {
                bad_ids.push(*i);
            } else {
                self.group_key += comm.poly[0];
            }
        }
```
