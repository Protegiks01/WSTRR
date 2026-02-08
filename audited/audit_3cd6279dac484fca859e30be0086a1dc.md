Audit Report

## Title
Remote Denial of Service via Empty Polynomial Commitment in DKG Public Shares

## Summary
A malicious signer can send a `DkgPublicShares` message containing a `PolyCommitment` with an empty `poly` vector, causing all nodes that process this message during DKG validation to panic and crash. This vulnerability enables a single compromised signer to deny service to all participants in a DKG round.

## Finding Description

The vulnerability exists due to an ordering issue in polynomial commitment validation. The `PolyCommitment::verify()` method unconditionally accesses the first element of the `poly` vector without bounds checking: [1](#0-0) 

The `check_public_shares()` function calls `verify()` before checking the polynomial length, meaning the bounds check never executes if `verify()` panics: [2](#0-1) 

**Attack Flow:**

1. A malicious signer constructs a `PolyCommitment` with `poly: Vec::new()` (empty vector)
2. The malicious signer includes this in a `DkgPublicShares` message and signs it with their valid ECDSA key
3. When signers receive this message, they store it without validation: [3](#0-2) 

4. Later, during the DKG end phase, signers validate stored public shares by calling `check_public_shares()`: [4](#0-3) 

5. When `check_public_shares()` calls `verify()` on the malicious commitment, it attempts to access `self.poly[0]` on an empty vector, causing an immediate panic

6. Coordinators are also vulnerable when verifying reported bad shares: [5](#0-4) 

**Why Existing Mitigations Fail:**
- Packet signature verification only authenticates the sender identity, not the validity of polynomial contents
- The check at line 553 in `dkg_ended()` only verifies if the `comms` vector is empty, not if individual `PolyCommitment.poly` vectors are empty
- No validation occurs when the message is first received - it's stored immediately
- The length check in `check_public_shares()` comes after the panic-inducing `verify()` call, so it's unreachable

## Impact Explanation

This vulnerability maps to **Low** severity per the scope definition: "Any remotely-exploitable denial of service in a node."

**Specific Harm:**
- All honest signers that received the malicious message will crash simultaneously when `dkg_ended()` is called
- The coordinator will also crash if it attempts to verify the malicious public shares
- This prevents completion of the DKG round and denial of threshold key generation

**Quantified Impact:**
- Single malicious signer can crash all N-1 honest signers plus the coordinator
- Affects every participant that progresses to the DKG validation phase
- Requires restarting all affected nodes and reinitiating the DKG round
- Attack can be repeated for each subsequent DKG attempt

While this affects multiple nodes simultaneously, the impact is strictly denial of service without consensus failures, fund loss, or persistent state corruption.

## Likelihood Explanation

**Probability: High (100% success rate if executed)**

**Required Attacker Capabilities:**
- Control of one signer with valid ECDSA signing keys for packet authentication (within protocol threat model)
- Ability to craft and send network messages
- No cryptographic breaks required

**Attack Complexity: Low**

The attacker needs to:
1. Create a `PolyCommitment` struct with `poly: Vec::new()` (empty vector)
2. Create a valid `ID` struct (can use any values since `verify()` panics before checking the proof)
3. Include it in a `DkgPublicShares` message
4. Sign the packet with their network private key
5. Broadcast the message to all participants

**Detection:**
High detectability - the panic will be visible in all affected node logs with stack traces pointing to the vector index access, making post-mortem analysis straightforward.

## Recommendation

Validate the polynomial length before calling `verify()`. Modify `check_public_shares()` to check bounds first:

```rust
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.poly.len() == threshold && poly_comm.verify(ctx)
}
```

Alternatively, add bounds checking in `PolyCommitment::verify()`:

```rust
impl PolyCommitment {
    pub fn verify(&self, ctx: &[u8]) -> bool {
        if self.poly.is_empty() {
            return false;
        }
        self.id.verify(&self.poly[0], ctx)
    }
}
```

The first approach is preferred as it maintains the invariant that polynomial length must equal threshold before any verification occurs.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_empty_poly_commitment_panic() {
    use crate::common::{PolyCommitment, check_public_shares};
    use crate::schnorr::ID;
    use crate::curve::scalar::Scalar;
    use crate::curve::point::{Point, G};
    
    // Create a malicious PolyCommitment with empty poly vector
    let id_scalar = Scalar::from(1u64);
    let malicious_commitment = PolyCommitment {
        id: ID {
            id: id_scalar,
            kG: G.clone(),
            kca: Scalar::from(1u64),
        },
        poly: Vec::new(), // Empty vector - this is the malicious input
    };
    
    let ctx = &[0u8; 8];
    let threshold = 3;
    
    // This will panic when verify() tries to access poly[0]
    check_public_shares(&malicious_commitment, threshold, ctx);
}
```

This test demonstrates that calling `check_public_shares()` with an empty `poly` vector causes a panic at the point where `verify()` attempts to access `self.poly[0]`.

### Citations

**File:** src/common.rs (L37-38)
```rust
    pub fn verify(&self, ctx: &[u8]) -> bool {
        self.id.verify(&self.poly[0], ctx)
```

**File:** src/common.rs (L319-320)
```rust
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
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

**File:** src/state_machine/signer/mod.rs (L1023-1024)
```rust
        self.dkg_public_shares
            .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L632-638)
```rust
                                for (party_id, comm) in &dkg_public_shares.comms {
                                    if !check_public_shares(
                                        comm,
                                        threshold,
                                        &self.current_dkg_id.to_be_bytes(),
                                    ) {
                                        bad_party_ids.push(party_id);
```
