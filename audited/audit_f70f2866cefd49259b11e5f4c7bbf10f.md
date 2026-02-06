> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/v1.rs (L457-471)
```rust
    fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        _key_ids: &[u32],
    ) -> Result<Signature, AggregatorError> {
        let (key, sig) = self.sign_with_tweak(msg, nonces, sig_shares, None)?;

        if sig.verify(&key, msg) {
            Ok(sig)
        } else {
            Err(self.check_signature_shares(msg, nonces, sig_shares, None))
        }
    }
```

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

**File:** src/v2.rs (L448-462)
```rust
    fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
    ) -> Result<Signature, AggregatorError> {
        let (key, sig) = self.sign_with_tweak(msg, nonces, sig_shares, key_ids, None)?;

        if sig.verify(&key, msg) {
            Ok(sig)
        } else {
            Err(self.check_signature_shares(msg, nonces, sig_shares, key_ids, None))
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
