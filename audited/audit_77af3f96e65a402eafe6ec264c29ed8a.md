Let me examine the `compute::challenge` function to see how it handles the public key:
> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/v1.rs (L474-490)
```rust
    fn sign_schnorr(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        _key_ids: &[u32],
    ) -> Result<SchnorrProof, AggregatorError> {
        let tweak = Scalar::from(0);
        let (key, sig) = self.sign_with_tweak(msg, nonces, sig_shares, Some(tweak))?;
        let proof = SchnorrProof::new(&sig);

        if proof.verify(&key.x(), msg) {
            Ok(proof)
        } else {
            Err(self.check_signature_shares(msg, nonces, sig_shares, Some(tweak)))
        }
    }
```

**File:** src/v2.rs (L465-481)
```rust
    fn sign_schnorr(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
    ) -> Result<SchnorrProof, AggregatorError> {
        let tweak = Scalar::from(0);
        let (key, sig) = self.sign_with_tweak(msg, nonces, sig_shares, key_ids, Some(tweak))?;
        let proof = SchnorrProof::new(&sig);

        if proof.verify(&key.x(), msg) {
            Ok(proof)
        } else {
            Err(self.check_signature_shares(msg, nonces, sig_shares, key_ids, Some(tweak)))
        }
    }
```

**File:** src/compute.rs (L57-67)
```rust
pub fn challenge(publicKey: &Point, R: &Point, msg: &[u8]) -> Scalar {
    let tag = "BIP0340/challenge";

    let mut hasher = tagged_hash(tag);

    hasher.update(R.x().to_bytes());
    hasher.update(publicKey.x().to_bytes());
    hasher.update(msg);

    hash_to_scalar(&mut hasher)
}
```
