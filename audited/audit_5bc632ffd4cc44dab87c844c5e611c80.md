### Title
Missing Length Validation in Signature Share Computation Enables Network-Wide Denial of Service

### Summary
The `Party::sign()` and related signing functions do not validate that the `signers` and `nonces` slices have matching lengths. This allows a malicious signer to send a `NonceResponse` with mismatched `key_ids` and `nonces` arrays, which propagates through the coordinator to all signers, causing network-wide signing failure. A single malicious signer can prevent any signing round from completing, blocking block production or transaction signing.

### Finding Description

**Exact Code Location:**

The vulnerability exists in multiple related functions in `src/v1.rs`: [1](#0-0) [2](#0-1) [3](#0-2) 

**Root Cause:**

The signature share computation uses three critical functions from `src/compute.rs`:

1. `compute::intermediate()` which uses `zip()` to pair nonces with party IDs: [4](#0-3) 

The `zip()` operation stops at `min(party_ids.len(), nonces.len())`, so only a subset of data is used if lengths mismatch.

2. `compute::binding()` which iterates over ALL nonces: [5](#0-4) 

3. `compute::lambda()` which iterates over ALL signers: [6](#0-5) 

This creates an inconsistency: the aggregate nonce `R` is computed using only `min(signers.len(), nonces.len())` elements, but the binding value uses ALL nonces and the lambda value uses ALL signers. This violates the critical signing invariant that "Binding values must commit to all public nonces and the exact message."

**Attack Entry Point:**

The vulnerability is exploitable through the network message protocol. The `NonceResponse` structure has separate `key_ids` and `nonces` vectors with no length constraint: [7](#0-6) 

The coordinator's `gather_nonces()` function validates that key IDs match the configuration but does NOT validate that `key_ids.len() == nonces.len()`: [8](#0-7) 

When signers receive the `SignatureShareRequest`, they flatten all nonces and key_ids from multiple `NonceResponse` objects: [9](#0-8) 

The production code path calls `Signer::sign()` which attempts to compute the aggregate nonce: [10](#0-9) 

The `compute::aggregate_nonce()` function creates `scalars` with length `2 * party_ids.len()` and `points` with length `2 * nonces.len()`: [11](#0-10) 

When these lengths don't match, `Point::multimult()` will either fail or produce an incorrect result, causing all signers to either panic or produce invalid signature shares.

**Why Existing Mitigations Fail:**

The Aggregator validates that `nonces.len() == sig_shares.len()` when aggregating: [12](#0-11) 

However, this validation occurs AFTER signers have already computed invalid signature shares or panicked. It does not prevent the denial of service.

### Impact Explanation

**Specific Harm:**
A single malicious signer can cause complete signing failure across the entire network by sending a `NonceResponse` with mismatched `key_ids` and `nonces` lengths. This prevents legitimate signing rounds from completing.

**Quantified Impact:**
- One malicious signer out of N total signers can block 100% of signing rounds
- All honest signers compute invalid signature shares or panic
- Signing coordinator cannot aggregate valid signatures
- In blockchain context: blocks cannot be signed, transactions cannot be confirmed

**Who is Affected:**
All participants in the WSTS network, including honest signers and users depending on threshold signatures for block production or transaction signing.

**Severity Justification:**
This maps to **Low** severity under the provided definitions: "Any remotely-exploitable denial of service in a node" and "Any network denial of service impacting more than 10 percent of miners that does not shut down the network." While severe, it does not cause fund loss, chain splits, or invalid transaction confirmation.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a registered signer in the WSTS network
- Must be able to send network messages to the coordinator
- No cryptographic breaks required
- No access to other signers' private keys required

**Attack Complexity:**
Very low. The attacker simply sends a malformed `NonceResponse` with:
```
key_ids: [attacker_key_1, attacker_key_2, attacker_key_3]
nonces: [nonce_1, nonce_2]  // intentionally mismatched length
```

**Economic Feasibility:**
Trivial. No computational cost beyond normal network participation.

**Detection Risk:**
Moderate. The malformed message is observable in network logs, but distinguishing malicious intent from bugs may be difficult. The coordinator accepts the message without validation.

**Estimated Probability:**
High if any signer is malicious or if there are bugs in signer implementations. The attack is deterministic and requires no special timing or race conditions.

### Recommendation

**Proposed Code Changes:**

1. Add validation in `Party::sign()` and related functions:
```rust
pub fn sign(&self, msg: &[u8], signers: &[u32], nonces: &[PublicNonce]) -> Result<SignatureShare, SignError> {
    if signers.len() != nonces.len() {
        return Err(SignError::LengthMismatch(signers.len(), nonces.len()));
    }
    // ... rest of function
}
```

2. Add validation in coordinator's `gather_nonces()`:
```rust
if nonce_response.key_ids.len() != nonce_response.nonces.len() {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response has mismatched key_ids and nonces lengths");
    return Ok(());
}
```

3. Add validation in `Signer::sign()` before calling `aggregate_nonce()`:
```rust
if key_ids.len() != nonces.len() {
    return Err(SignError::LengthMismatch(key_ids.len(), nonces.len()));
}
```

**Alternative Mitigations:**
- Make `NonceResponse` use a single vector of `(u32, PublicNonce)` tuples to ensure pairing
- Add network-level validation that rejects malformed messages
- Implement reputation system to ban signers sending invalid data

**Testing Recommendations:**
- Add unit tests with mismatched lengths to verify error handling
- Add integration tests simulating malicious signer sending bad NonceResponse
- Verify that honest signers properly reject and report invalid data

**Deployment Considerations:**
- This is a non-breaking change that adds validation
- Existing honest signers already send matching lengths, so no behavioral change
- Should be deployed as a security patch to all nodes simultaneously

### Proof of Concept

**Exploitation Steps:**

1. Malicious Signer 1 is part of a WSTS network with threshold t=3, total signers n=5
2. Coordinator requests nonces for signing round
3. Honest signers (0, 2, 3, 4) send valid NonceResponses:
   - Signer 0: `key_ids=[1]`, `nonces=[N1]` ✓
   - Signer 2: `key_ids=[5]`, `nonces=[N5]` ✓
   - Signer 3: `key_ids=[7]`, `nonces=[N7]` ✓
   - Signer 4: `key_ids=[9]`, `nonces=[N9]` ✓

4. Malicious Signer 1 sends malformed NonceResponse:
   - `key_ids=[2, 3, 4]` (3 keys)
   - `nonces=[N2, N3]` (2 nonces)

5. Coordinator accepts all responses (no validation) and broadcasts SignatureShareRequest

6. All signers extract flattened arrays:
   - `key_ids = [1, 2, 3, 4, 5, 7, 9]` (7 elements)
   - `nonces = [N1, N2, N3, N5, N7, N9]` (6 elements)

7. Each signer calls `compute::aggregate_nonce(msg, key_ids, nonces)`:
   - Creates `scalars` with length `2 * 7 = 14`
   - Creates `points` with length `2 * 6 = 12`
   - `Point::multimult(scalars, points)` fails due to length mismatch

8. **Expected Result:** Signers compute valid signature shares, signing succeeds
9. **Actual Result:** All signers either panic or produce invalid signature shares, signing fails
10. **Impact:** Network cannot produce signatures, blocks cannot be signed

**Reproduction Instructions:**

Run the WSTS network with one malicious signer that sends:
```rust
NonceResponse {
    dkg_id: current_dkg_id,
    sign_id: current_sign_id,
    sign_iter_id: current_sign_iter_id,
    signer_id: malicious_signer_id,
    key_ids: vec![1, 2, 3],  // 3 elements
    nonces: vec![nonce1, nonce2],  // 2 elements - MISMATCH!
    message: message_to_sign,
}
```

Observe that the signing round fails for all participants, demonstrating the denial of service vulnerability.

### Citations

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

**File:** src/v1.rs (L232-240)
```rust
    pub fn sign_precomputed(
        &self,
        msg: &[u8],
        signers: &[u32],
        nonces: &[PublicNonce],
        aggregate_nonce: &Point,
    ) -> SignatureShare {
        self.sign_precomputed_with_tweak(msg, signers, nonces, aggregate_nonce, None)
    }
```

**File:** src/v1.rs (L246-294)
```rust
    pub fn sign_precomputed_with_tweak(
        &self,
        msg: &[u8],
        signers: &[u32],
        nonces: &[PublicNonce],
        aggregate_nonce: &Point,
        tweak: Option<Scalar>,
    ) -> SignatureShare {
        let mut r = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        if tweak.is_some() && !aggregate_nonce.has_even_y() {
            r = -r;
        }

        // When using BIP-340 32-byte public keys, we have to invert the private key if the
        // public key is odd.  But if we're also using BIP-341 tweaked keys, we have to do
        // the same thing if the tweaked public key is odd.  In that case, only invert the
        // public key if exactly one of the internal or tweaked public keys is odd
        let mut cx_sign = Scalar::one();
        let tweaked_public_key = if let Some(t) = tweak {
            if t != Scalar::zero() {
                let key = compute::tweaked_public_key_from_tweak(&self.group_key, t);
                if key.has_even_y() ^ self.group_key.has_even_y() {
                    cx_sign = -cx_sign;
                }

                key
            } else {
                if !self.group_key.has_even_y() {
                    cx_sign = -cx_sign;
                }
                self.group_key
            }
        } else {
            self.group_key
        };

        let c = compute::challenge(&tweaked_public_key, aggregate_nonce, msg);
        let mut cx = c * &self.private_key * compute::lambda(self.id, signers);

        cx = cx_sign * cx;

        let z = r + cx;

        SignatureShare {
            id: self.id,
            z_i: z,
            key_ids: vec![self.id],
        }
    }
```

**File:** src/v1.rs (L321-323)
```rust
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }
```

**File:** src/v1.rs (L707-719)
```rust
    fn sign(
        &self,
        msg: &[u8],
        _signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare> {
        let aggregate_nonce = compute::aggregate_nonce(msg, key_ids, nonces).unwrap();
        self.parties
            .iter()
            .map(|p| p.sign_precomputed(msg, key_ids, nonces, &aggregate_nonce))
            .collect()
    }
```

**File:** src/compute.rs (L17-33)
```rust
pub fn binding(id: &Scalar, B: &[PublicNonce], msg: &[u8]) -> Scalar {
    let prefix = b"WSTS/binding";

    // Serialize all input into a buffer
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_bytes());

    for b in B {
        buf.extend_from_slice(b.D.compress().as_bytes());
        buf.extend_from_slice(b.E.compress().as_bytes());
    }

    buf.extend_from_slice(msg);

    expand_to_scalar(&buf, prefix)
        .expect("FATAL: DST is less than 256 bytes so operation should not fail")
}
```

**File:** src/compute.rs (L70-80)
```rust
pub fn lambda(i: u32, key_ids: &[u32]) -> Scalar {
    let mut lambda = Scalar::one();
    let i_scalar = id(i);
    for j in key_ids {
        if i != *j {
            let j_scalar = id(*j);
            lambda *= j_scalar / (j_scalar - i_scalar);
        }
    }
    lambda
}
```

**File:** src/compute.rs (L85-96)
```rust
pub fn intermediate(msg: &[u8], party_ids: &[u32], nonces: &[PublicNonce]) -> (Vec<Point>, Point) {
    let rhos: Vec<Scalar> = party_ids
        .iter()
        .map(|&i| binding(&id(i), nonces, msg))
        .collect();
    let R_vec: Vec<Point> = zip(nonces, rhos)
        .map(|(nonce, rho)| nonce.D + rho * nonce.E)
        .collect();

    let R = R_vec.iter().fold(Point::zero(), |R, &R_i| R + R_i);
    (R_vec, R)
}
```

**File:** src/compute.rs (L100-121)
```rust
pub fn aggregate_nonce(
    msg: &[u8],
    party_ids: &[u32],
    nonces: &[PublicNonce],
) -> Result<Point, PointError> {
    let compressed_nonces: Vec<(Compressed, Compressed)> = nonces
        .iter()
        .map(|nonce| (nonce.D.compress(), nonce.E.compress()))
        .collect();
    let scalars: Vec<Scalar> = party_ids
        .iter()
        .flat_map(|&i| {
            [
                Scalar::from(1),
                binding_compressed(&id(i), &compressed_nonces, msg),
            ]
        })
        .collect();
    let points: Vec<Point> = nonces.iter().flat_map(|nonce| [nonce.D, nonce.E]).collect();

    Point::multimult(scalars, points)
}
```

**File:** src/net.rs (L311-326)
```rust
pub struct NonceResponse {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// Key IDs
    pub key_ids: Vec<u32>,
    /// Public nonces
    pub nonces: Vec<PublicNonce>,
    /// Bytes being signed
    pub message: Vec<u8>,
}
```

**File:** src/state_machine/coordinator/frost.rs (L473-550)
```rust
    fn gather_nonces(
        &mut self,
        packet: &Packet,
        signature_type: SignatureType,
    ) -> Result<(), Error> {
        if let Message::NonceResponse(nonce_response) = &packet.msg {
            if nonce_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(nonce_response.dkg_id, self.current_dkg_id));
            }
            if nonce_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    nonce_response.sign_id,
                    self.current_sign_id,
                ));
            }
            if nonce_response.sign_iter_id != self.current_sign_iter_id {
                return Err(Error::BadSignIterId(
                    nonce_response.sign_iter_id,
                    self.current_sign_iter_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&nonce_response.signer_id) {
                warn!(signer_id = %nonce_response.signer_id, "No public key in config");
                return Ok(());
            };

            // check that the key_ids match the config
            let Some(signer_key_ids) = self
                .config
                .public_keys
                .signer_key_ids
                .get(&nonce_response.signer_id)
            else {
                warn!(signer_id = %nonce_response.signer_id, "No keys IDs configured");
                return Ok(());
            };

            let nonce_response_key_ids = nonce_response
                .key_ids
                .iter()
                .cloned()
                .collect::<HashSet<u32>>();
            if *signer_key_ids != nonce_response_key_ids {
                warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
                return Ok(());
            }

            for nonce in &nonce_response.nonces {
                if !nonce.is_valid() {
                    warn!(
                        sign_id = %nonce_response.sign_id,
                        sign_iter_id = %nonce_response.sign_iter_id,
                        signer_id = %nonce_response.signer_id,
                        "Received invalid nonce in NonceResponse"
                    );
                    return Ok(());
                }
            }

            let have_nonces = self.public_nonces.contains_key(&nonce_response.signer_id);

            if have_nonces {
                info!(signer_id = %nonce_response.signer_id, "Received duplicate NonceResponse");
                return Ok(());
            }

            self.public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());
            self.ids_to_await.remove(&nonce_response.signer_id);
            debug!(
                sign_id = %nonce_response.sign_id,
                sign_iter_id = %nonce_response.sign_iter_id,
                signer_id = %nonce_response.signer_id,
                waiting = ?self.ids_to_await,
                "NonceResponse received"
```

**File:** src/state_machine/signer/mod.rs (L781-818)
```rust
        let nonces = sign_request
            .nonce_responses
            .iter()
            .flat_map(|nr| nr.nonces.clone())
            .collect::<Vec<PublicNonce>>();

        for nonce in &nonces {
            if !nonce.is_valid() {
                warn!(
                    signer_id = %self.signer_id,
                    "received an SignatureShareRequest with invalid nonce"
                );
                return Err(Error::InvalidNonceResponse);
            }
        }

        debug!(signer_id = %self.signer_id, "received a valid SignatureShareRequest");

        if signer_id_set.contains(&self.signer_id) {
            let key_ids: Vec<u32> = sign_request
                .nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.iter().copied())
                .collect::<Vec<u32>>();

            let signer_ids = signer_id_set.into_iter().collect::<Vec<_>>();
            let msg = &sign_request.message;
            let signature_shares = match sign_request.signature_type {
                SignatureType::Taproot(merkle_root) => {
                    self.signer
                        .sign_taproot(msg, &signer_ids, &key_ids, &nonces, merkle_root)
                }
                SignatureType::Schnorr => {
                    self.signer
                        .sign_schnorr(msg, &signer_ids, &key_ids, &nonces)
                }
                SignatureType::Frost => self.signer.sign(msg, &signer_ids, &key_ids, &nonces),
            };
```
