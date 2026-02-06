### Title
Remote Denial of Service via Empty Polynomial Commitment in DKG Public Shares

### Summary
A malicious signer can send a `DkgPublicShares` message containing a `PolyCommitment` with an empty `poly` vector, causing all nodes that process this message during DKG validation to panic and crash. This vulnerability enables a single compromised signer to deny service to all participants in a DKG round.

### Finding Description

**Exact Code Locations:**

The vulnerability exists in the `PolyCommitment::verify()` method which accesses `self.poly[0]` without bounds checking: [1](#0-0) 

The `check_public_shares()` function calls `verify()` before checking the polynomial length: [2](#0-1) 

Signers accept and store `DkgPublicShares` messages without validating polynomial contents: [3](#0-2) 

Validation occurs later when signers call `check_public_shares` during `dkg_ended()`: [4](#0-3) 

The coordinator also validates public shares and is vulnerable: [5](#0-4) 

**Root Cause:**
The `PolyCommitment::verify()` method unconditionally accesses the first element of the `poly` vector to verify the Schnorr ID proof. When a malicious actor crafts a `PolyCommitment` with an empty `poly` vector, this causes an index-out-of-bounds panic. The validation logic in `check_public_shares()` checks the polynomial length only after calling `verify()`, so the bounds check never executes.

**Why Existing Mitigations Fail:**
- Packet signature verification only authenticates the sender, not the validity of the polynomial content
- The check at line 553 only verifies if `comms` vector is empty, not if individual `PolyCommitment.poly` vectors are empty
- No validation occurs when the message is first received and stored
- The length check in `check_public_shares` comes after the panic-inducing `verify()` call

### Impact Explanation

**Specific Harm:**
All honest signers and the coordinator that received the malicious `DkgPublicShares` message will crash simultaneously when `dkg_ended()` is called. This prevents completion of the DKG round and denial of threshold key generation.

**Quantified Impact:**
- Single malicious signer can crash all N-1 honest signers plus the coordinator
- Affects every participant that progresses to the DKG validation phase
- Requires restarting all affected nodes and reinitiating the DKG round
- Can be repeated for each subsequent DKG attempt

**Who is Affected:**
All participants in a DKG round where at least one signer is compromised.

**Severity Justification:**
This maps to **Low** severity per the protocol scope: "Any remotely-exploitable denial of service in a node". While it affects multiple nodes simultaneously, the impact is limited to denial of service without consensus failures or fund loss.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control of one signer account with valid ECDSA signing keys for packet authentication
- Ability to craft and send network messages
- No cryptographic breaks required

**Attack Complexity:**
Low. The attacker simply needs to:
1. Create a `PolyCommitment` struct with `poly: Vec::new()` (empty vector)
2. Include it in a `DkgPublicShares` message
3. Sign and broadcast the message

**Economic Feasibility:**
Minimal cost. Requires only network bandwidth and one compromised signer key.

**Detection Risk:**
High detectability. The panic will be visible in all affected node logs with stack traces pointing to the empty vector access.

**Probability of Success:**
100% if executed. The panic is guaranteed when `verify()` attempts to access `poly[0]` on an empty vector.

### Recommendation

**Primary Fix:**
Add bounds checking in `PolyCommitment::verify()` before accessing `self.poly[0]`:

```rust
pub fn verify(&self, ctx: &[u8]) -> bool {
    if self.poly.is_empty() {
        return false;
    }
    self.id.verify(&self.poly[0], ctx)
}
```

**Alternative Mitigation:**
Reorder checks in `check_public_shares()` to validate length before calling verify:

```rust
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.poly.len() == threshold && poly_comm.verify(ctx)
}
```

**Testing Recommendations:**
1. Add unit test with empty `poly` vector to verify graceful failure
2. Add integration test simulating malicious signer sending empty polynomial
3. Verify all panic paths are eliminated in DKG validation code

**Deployment Considerations:**
- Deploy fix before allowing untrusted signers in DKG rounds
- Consider adding similar bounds checks throughout polynomial handling code
- Add defensive validation when receiving network messages

### Proof of Concept

**Exploitation Algorithm:**

1. Attacker controls signer with ID `malicious_signer_id` and private key `attacker_private_key`
2. Attacker constructs malicious DkgPublicShares:
```
let malicious_commitment = PolyCommitment {
    id: ID::new(&Scalar::from(malicious_signer_id), &Scalar::zero(), &dkg_id.to_be_bytes(), rng),
    poly: Vec::new()  // Empty vector
};

let malicious_msg = DkgPublicShares {
    dkg_id: current_dkg_id,
    signer_id: malicious_signer_id,
    comms: vec![(party_id, malicious_commitment)],
    kex_public_key: Point::from(Scalar::random(rng))
};
```

3. Sign and broadcast message (passes signature verification)
4. All honest participants store the message without validation
5. When coordinator sends `DkgEndBegin`, all participants call `dkg_ended()`
6. Each participant calls `check_public_shares()` on the malicious commitment
7. `verify()` attempts to access `self.poly[0]` on empty vector
8. Panic occurs: "index out of bounds: the len is 0 but the index is 0"
9. All affected nodes crash

**Expected vs Actual Behavior:**
- Expected: Invalid polynomial should be rejected gracefully, signer marked as malicious
- Actual: Node crashes with panic, requiring restart

**Reproduction:**
Add this test to demonstrate the vulnerability:
```rust
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_empty_poly_panic() {
    let empty_commitment = PolyCommitment {
        id: ID::new(&Scalar::random(rng), &Scalar::random(rng), &[0u8; 8], rng),
        poly: Vec::new()
    };
    check_public_shares(&empty_commitment, 3, &[0u8; 8]);
}
```

### Citations

**File:** src/common.rs (L36-40)
```rust
    /// Verify the wrapped schnorr ID
    pub fn verify(&self, ctx: &[u8]) -> bool {
        self.id.verify(&self.poly[0], ctx)
    }
}
```

**File:** src/common.rs (L318-321)
```rust
/// Check that the PolyCommitment is properly signed and has the correct degree polynomial
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```

**File:** src/state_machine/signer/mod.rs (L551-563)
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
```

**File:** src/state_machine/signer/mod.rs (L973-1026)
```rust
    /// handle incoming DkgPublicShares
    pub fn dkg_public_share(
        &mut self,
        dkg_public_shares: &DkgPublicShares,
    ) -> Result<Vec<Message>, Error> {
        debug!(
            "received DkgPublicShares from signer {} {}/{}",
            dkg_public_shares.signer_id,
            self.commitments.len(),
            self.signer.get_num_parties(),
        );

        let signer_id = dkg_public_shares.signer_id;

        // check that the signer_id exists in the config
        let Some(_signer_public_key) = self.public_keys.signers.get(&signer_id) else {
            warn!(%signer_id, "No public key configured");
            return Ok(vec![]);
        };

        for (party_id, _) in &dkg_public_shares.comms {
            if !SignerType::validate_party_id(
                signer_id,
                *party_id,
                &self.public_keys.signer_key_ids,
            ) {
                warn!(%signer_id, %party_id, "signer sent polynomial commitment for wrong party");
                return Ok(vec![]);
            }
        }

        let have_shares = self
            .dkg_public_shares
            .contains_key(&dkg_public_shares.signer_id);

        if have_shares {
            info!(signer_id = %dkg_public_shares.signer_id, "received duplicate DkgPublicShares");
            return Ok(vec![]);
        }

        let Some(signer_key_ids) = self.public_keys.signer_key_ids.get(&signer_id) else {
            warn!(%signer_id, "No key_ids configured");
            return Ok(vec![]);
        };

        for key_id in signer_key_ids {
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
        }

        self.dkg_public_shares
            .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
        Ok(vec![])
    }
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
