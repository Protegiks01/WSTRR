# Audit Report

## Title
Empty Polynomial in DkgPublicShares Causes Panic-Based Denial of Service

## Summary
A malicious signer can send DkgPublicShares messages containing empty polynomial vectors, causing all participants (signers and coordinators) to panic and crash when attempting to validate the shares. This vulnerability allows a single malicious participant within the threshold to trigger network-wide denial of service, preventing DKG completion and blocking all signature generation operations.

## Finding Description

The vulnerability exists in the interaction between `check_public_shares()` and `PolyCommitment::verify()`. The `PolyCommitment::verify()` method directly accesses the first element of the polynomial vector without performing bounds checking: [1](#0-0) 

The `check_public_shares()` validation function calls this verify method before checking the polynomial length: [2](#0-1) 

Due to Rust's left-to-right short-circuit evaluation of the `&&` operator, `poly_comm.verify(ctx)` executes first. When the polynomial vector is empty, accessing `self.poly[0]` triggers an index out of bounds panic before the length check is ever evaluated.

This validation function is called from multiple critical code paths during DKG completion:

**V1 Implementation:** [3](#0-2) 

**V2 Implementation:** [4](#0-3) 

**Signer State Machine:** [5](#0-4) 

**FIRE Coordinator (during malicious signer detection):** [6](#0-5) 

The attack succeeds because messages are received and stored without polynomial validation. The signer stores DkgPublicShares without validating polynomial commitments: [7](#0-6) 

The coordinator similarly stores messages without validation: [8](#0-7) 

The DkgPublicShares struct itself allows empty polynomial vectors, as demonstrated in the existing test suite: [9](#0-8) 

## Impact Explanation

This vulnerability maps to **Low** severity as defined in the scope: "Any remotely-exploitable denial of service in a node."

A single malicious signer (within the protocol's threat model of up to threshold-1 malicious parties) can crash all honest participants:
- All honest signers panic and crash when calling `dkg_ended()` which invokes `check_public_shares()`
- The coordinator panics when attempting to validate `BadPublicShares` reports from signers
- DKG cannot complete, preventing any threshold signatures from being generated
- The entire protocol remains unavailable until all nodes restart and the malicious signer is excluded from the configuration

While this is a serious availability issue that can completely halt the protocol, it does not:
- Compromise cryptographic security or secret shares
- Cause loss of funds or unauthorized signatures
- Enable consensus failures or chain splits
- Exploit memory safety or enable code execution
- Produce invalid cryptographic material

The attack causes clean process termination through panic rather than memory corruption or other security-critical failures.

## Likelihood Explanation

The likelihood of exploitation is **very high** if a malicious signer participates in DKG:

**Attacker Requirements:**
- Must be an authorized signer (within the protocol's threat model of up to threshold-1 malicious parties)
- Requires only the ability to send network messages via the standard protocol interface
- No cryptographic secrets, special privileges, or protocol-breaking assumptions needed

**Attack Complexity:** Trivial
1. Construct a `PolyCommitment` with an empty polynomial vector: `poly: vec![]`
2. Include it in a `DkgPublicShares` message
3. Send the message during the DKG public share gathering phase
4. All recipients panic immediately when they attempt to validate shares during DKG completion

**Success Rate:** 100% - If the malicious message reaches any honest participant, that participant will panic when executing the standard DKG validation logic.

**Detection:** The panic is immediately visible in crash logs and process termination, but identifying the malicious signer may be difficult if the coordinator crashes before completing its malicious signer detection logic.

## Recommendation

Implement bounds checking before accessing the polynomial vector. The fix is to swap the order of checks in `check_public_shares()` so that the length validation occurs before calling `verify()`:

```rust
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.poly.len() == threshold && poly_comm.verify(ctx)
}
```

Alternatively, add explicit bounds checking in `PolyCommitment::verify()`:

```rust
pub fn verify(&self, ctx: &[u8]) -> bool {
    if self.poly.is_empty() {
        return false;
    }
    self.id.verify(&self.poly[0], ctx)
}
```

The first approach (reordering) is simpler and more efficient since it leverages Rust's short-circuit evaluation to avoid the verify call entirely for invalid-length polynomials. However, the second approach provides defense-in-depth by ensuring `verify()` can be called safely in isolation.

## Proof of Concept

The following test demonstrates the panic when attempting to validate a DkgPublicShares message with an empty polynomial:

```rust
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_empty_polynomial_causes_panic() {
    use crate::common::{check_public_shares, PolyCommitment};
    use crate::schnorr::ID;
    use crate::curve::scalar::Scalar;
    use crate::util::create_rng;
    
    let ctx = 0u64.to_be_bytes();
    let mut rng = create_rng();
    
    // Create a malicious PolyCommitment with empty polynomial
    let malicious_comm = PolyCommitment {
        id: ID::new(&Scalar::new(), &Scalar::new(), &ctx, &mut rng),
        poly: vec![],  // Empty polynomial vector!
    };
    
    // This will panic when verify() tries to access poly[0]
    // The panic occurs before the length check is ever evaluated
    check_public_shares(&malicious_comm, 3, &ctx);
}
```

To reproduce the full attack scenario:
1. Run a DKG round with multiple signers
2. Have one malicious signer send a DkgPublicShares message with an empty polynomial commitment
3. Observe all honest participants panic and crash when they reach the DKG completion phase

### Citations

**File:** src/common.rs (L36-39)
```rust
    /// Verify the wrapped schnorr ID
    pub fn verify(&self, ctx: &[u8]) -> bool {
        self.id.verify(&self.poly[0], ctx)
    }
```

**File:** src/common.rs (L318-321)
```rust
/// Check that the PolyCommitment is properly signed and has the correct degree polynomial
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```

**File:** src/v1.rs (L159-167)
```rust
        let threshold: usize = self.threshold.try_into()?;
        let mut bad_ids = Vec::new(); //: Vec<u32> = polys
        for (i, comm) in public_shares.iter() {
            if !check_public_shares(comm, threshold, ctx) {
                bad_ids.push(*i);
            } else {
                self.group_key += comm.poly[0];
            }
        }
```

**File:** src/v2.rs (L132-141)
```rust
        let threshold: usize = self.threshold.try_into()?;

        let mut bad_ids = Vec::new();
        for (i, comm) in public_shares.iter() {
            if !check_public_shares(comm, threshold, ctx) {
                bad_ids.push(*i);
            } else {
                self.group_key += comm.poly[0];
            }
        }
```

**File:** src/state_machine/signer/mod.rs (L556-562)
```rust
                    for (party_id, comm) in shares.comms.iter() {
                        if !check_public_shares(comm, threshold, &self.dkg_id.to_be_bytes()) {
                            bad_public_shares.insert(*signer_id);
                        } else {
                            self.commitments.insert(*party_id, comm.clone());
                        }
                    }
```

**File:** src/state_machine/signer/mod.rs (L1023-1025)
```rust
        self.dkg_public_shares
            .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
        Ok(vec![])
```

**File:** src/state_machine/coordinator/fire.rs (L505-506)
```rust
            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L631-640)
```rust
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
```

**File:** src/net.rs (L724-730)
```rust
            comms: vec![(
                0,
                PolyCommitment {
                    id: ID::new(&Scalar::new(), &Scalar::new(), &ctx, &mut rng),
                    poly: vec![],
                },
            )],
```
