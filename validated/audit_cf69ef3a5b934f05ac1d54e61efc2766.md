# Audit Report

## Title
Missing DKG Round ID Validation Enables Denial of Service via Message Replay

## Summary
The signer's DKG message handlers do not validate the `dkg_id` field before accepting and storing messages, while the coordinator properly validates this field. This allows an attacker with network access to replay messages from previous DKG rounds, causing honest signers to store mismatched shares that fail validation and abort the DKG round.

## Finding Description

The signer's message handlers accept and store DKG messages without validating that the incoming message's `dkg_id` field matches the signer's current round ID (`self.dkg_id`). Specifically:

The `dkg_public_share()` handler stores public shares without any `dkg_id` validation, checking only signer_id, party_id, and duplicates before storing messages. [1](#0-0) 

The `dkg_private_shares()` handler accepts and stores private shares without checking the round ID, performing similar validations but omitting `dkg_id` verification. [2](#0-1) 

The `dkg_end_begin()` handler also lacks this validation, simply storing the message. [3](#0-2) 

In contrast, the coordinator properly validates `dkg_id` in both public and private share handlers, returning a `BadDkgId` error when mismatches occur. [4](#0-3) [5](#0-4) 

**Attack Mechanism:**

1. An attacker captures legitimate DKG messages from round N (e.g., `DkgPublicShares` with `dkg_id=N`)
2. When round N+1 begins, the signer's state is reset and `self.dkg_id` is updated to N+1. [6](#0-5) 

3. The attacker replays captured messages from round N before legitimate round N+1 messages arrive
4. The signer stores these replayed messages without validating `dkg_id`
5. When legitimate round N+1 messages arrive from the same signer_id, they are rejected as duplicates based on signer_id-only duplicate detection. [7](#0-6) 

6. Eventually, when `dkg_ended()` is called, the stored commitments are validated against the current `self.dkg_id`. [8](#0-7) 

7. The validation fails because the Schnorr proofs in the replayed messages were created with context `dkg_id=N` but are being verified against context `dkg_id=N+1`. The `check_public_shares` function verifies proofs using the context parameter. [9](#0-8) 

The Schnorr proof verification includes the context (dkg_id) in the challenge computation. [10](#0-9) 

8. The signer returns `DkgEnd` with failure status. [11](#0-10) 

The DKG messages include `dkg_id` in their signature hash, preventing modification. [12](#0-11) [13](#0-12) 

This means the attacker cannot modify the `dkg_id` field but can replay the original signed messages, which will pass signature verification but fail the deferred commitment validation.

## Impact Explanation

**Severity: Low**

This vulnerability enables a remotely-exploitable denial of service attack that prevents DKG completion. The impact maps to the defined Low severity scope: "Any remotely-exploitable denial of service in a node" and potentially "Any network denial of service impacting more than 10 percent of miners that does not shut down the network."

**Specific impacts:**
- Individual signers can be forced to abort DKG participation by sending `DkgEnd` with failure status
- If the attacker targets more than `(total_signers - dkg_threshold)` signers, the entire DKG round fails network-wide
- DKG must be restarted, delaying key generation and preventing signing operations until completion
- No compromise of cryptographic material, fund loss, or invalid signature acceptance occurs

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely to succeed because:

**Low Attacker Requirements:**
- Network access to inject/replay messages to signers (e.g., man-in-the-middle position)
- Access to previously broadcast DKG messages (publicly observable on the network)
- No cryptographic secrets or private keys required

**Simple Attack Execution:**
- Capture messages from round N during normal DKG operation
- Replay these messages to target signers during round N+1
- If replayed messages arrive before legitimate ones (controllable via network positioning), they will be stored first and legitimate messages rejected as duplicates

**High Success Probability:**
- No race conditions or cryptographic challenges
- Success depends only on message timing, which an attacker with network access can control
- No computational cost or economic stake required

**Detection Difficulty:**
- DKG failures would be logged but distinguishing between network issues and attacks is difficult
- The attack leaves no cryptographic evidence (signatures are valid for the original messages)

## Recommendation

Add `dkg_id` validation to all signer message handlers before storing messages, consistent with the coordinator's validation approach:

```rust
// In dkg_public_share()
if dkg_public_shares.dkg_id != self.dkg_id {
    warn!("Received DkgPublicShares with mismatched dkg_id");
    return Ok(vec![]);
}

// In dkg_private_shares()
if dkg_private_shares.dkg_id != self.dkg_id {
    warn!("Received DkgPrivateShares with mismatched dkg_id");
    return Ok(vec![]);
}

// In dkg_end_begin()
if dkg_end_begin.dkg_id != self.dkg_id {
    warn!("Received DkgEndBegin with mismatched dkg_id");
    return Ok(vec![]);
}
```

This ensures messages from previous DKG rounds are rejected immediately rather than being stored and causing validation failures later.

## Proof of Concept

The attack can be demonstrated by:
1. Capturing a `DkgPublicShares` message from a completed DKG round N
2. Initiating a new DKG round N+1 where signers reset their state
3. Replaying the captured message to a target signer before the legitimate message arrives
4. Observing that the target signer stores the stale message
5. Confirming that the legitimate message is rejected as a duplicate
6. Verifying that `dkg_ended()` fails with `BadPublicShares` error due to Schnorr proof context mismatch

### Citations

**File:** src/state_machine/signer/mod.rs (L417-432)
```rust
    pub fn reset<T: RngCore + CryptoRng>(&mut self, dkg_id: u64, rng: &mut T) {
        self.dkg_id = dkg_id;
        self.commitments.clear();
        self.decrypted_shares.clear();
        self.decryption_keys.clear();
        self.invalid_private_shares.clear();
        self.public_nonces.clear();
        self.signer.reset_polys(rng);
        self.dkg_public_shares.clear();
        self.dkg_private_shares.clear();
        self.dkg_private_begin_msg = None;
        self.dkg_end_begin_msg = None;
        self.kex_private_key = Scalar::random(rng);
        self.kex_public_keys.clear();
        self.state = State::Idle;
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

**File:** src/state_machine/signer/mod.rs (L593-598)
```rust
        if !bad_public_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadPublicShares(bad_public_shares)),
            }));
```

**File:** src/state_machine/signer/mod.rs (L958-970)
```rust
    /// handle incoming DkgEndBegin
    pub fn dkg_end_begin(&mut self, dkg_end_begin: &DkgEndBegin) -> Result<Vec<Message>, Error> {
        let msgs = vec![];

        self.dkg_end_begin_msg = Some(dkg_end_begin.clone());

        info!(
            signer_id = %self.signer_id,
            dkg_id = %self.dkg_id,
            "received DkgEndBegin"
        );

        Ok(msgs)
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

**File:** src/state_machine/signer/mod.rs (L1028-1064)
```rust
    /// handle incoming DkgPrivateShares
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
```

**File:** src/state_machine/coordinator/fire.rs (L479-483)
```rust
            if dkg_public_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_public_shares.dkg_id,
                    self.current_dkg_id,
                ));
```

**File:** src/state_machine/coordinator/fire.rs (L527-531)
```rust
            if dkg_private_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_private_shares.dkg_id,
                    self.current_dkg_id,
                ));
```

**File:** src/common.rs (L318-321)
```rust
/// Check that the PolyCommitment is properly signed and has the correct degree polynomial
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```

**File:** src/schnorr.rs (L47-65)
```rust
    /// Compute the schnorr challenge
    pub fn challenge(id: &Scalar, K: &Point, A: &Point, ctx: &[u8]) -> Scalar {
        let mut hasher = Sha256::new();
        let tag = "WSTS/polynomial-constant";

        hasher.update(tag.as_bytes());
        hasher.update(id.to_bytes());
        hasher.update(K.compress().as_bytes());
        hasher.update(A.compress().as_bytes());
        hasher.update(ctx);

        hash_to_scalar(&mut hasher)
    }

    /// Verify the proof
    pub fn verify(&self, A: &Point, ctx: &[u8]) -> bool {
        let c = Self::challenge(&self.id, &self.kG, A, ctx);
        &self.kca * &G == &self.kG + c * A
    }
```

**File:** src/net.rs (L152-163)
```rust
impl Signable for DkgPublicShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PUBLIC_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        for (party_id, comm) in &self.comms {
            hasher.update(party_id.to_be_bytes());
            for a in &comm.poly {
                hasher.update(a.compress().as_bytes());
            }
        }
    }
```

**File:** src/net.rs (L201-216)
```rust
impl Signable for DkgPrivateShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PRIVATE_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        // make sure we hash consistently by sorting the keys
        for (src_id, share) in &self.shares {
            hasher.update(src_id.to_be_bytes());
            let mut dst_ids = share.keys().cloned().collect::<Vec<u32>>();
            dst_ids.sort();
            for dst_id in &dst_ids {
                hasher.update(dst_id.to_be_bytes());
                hasher.update(&share[dst_id]);
            }
        }
    }
```
