> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/errors.rs (L40-59)
```rust
pub enum AggregatorError {
    #[error("bad poly commitments {0:?}")]
    /// The polynomial commitments which failed verification or were the wrong size
    BadPolyCommitments(Vec<Scalar>),
    #[error("bad nonce length (expected {0} got {1}")]
    /// The nonce length was the wrong size
    BadNonceLen(usize, usize),
    #[error("bad party keys from {0:?}")]
    /// The party public keys which failed
    BadPartyKeys(Vec<u32>),
    #[error("bad party sigs from {0:?}")]
    /// The party signatures which failed to verify
    BadPartySigs(Vec<u32>),
    #[error("bad group sig")]
    /// The aggregate group signature failed to verify
    BadGroupSig,
    #[error("integer conversion error")]
    /// An error during integer conversion operations
    TryFromInt,
}
```

**File:** src/v1.rs (L357-426)
```rust
    /// Check the party signatures after a failed group signature. The posible values for tweak are
    /// None    - standard FROST signature
    /// Some(0) - BIP-340 schnorr signature using 32-byte private key adjustments
    /// Some(t) - BIP-340 schnorr signature with BIP-341 tweaked keys, using 32-byte private key adjustments
    pub fn check_signature_shares(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        tweak: Option<Scalar>,
    ) -> AggregatorError {
        if nonces.len() != sig_shares.len() {
            return AggregatorError::BadNonceLen(nonces.len(), sig_shares.len());
        }

        let signers: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (Rs, R) = compute::intermediate(msg, &signers, nonces);
        let mut bad_party_keys = Vec::new();
        let mut bad_party_sigs = Vec::new();
        let aggregate_public_key = self.poly[0];
        let tweaked_public_key = match tweak {
            Some(t) if t != Scalar::zero() => {
                compute::tweaked_public_key_from_tweak(&aggregate_public_key, t)
            }
            _ => aggregate_public_key,
        };
        let c = compute::challenge(&tweaked_public_key, &R, msg);
        let mut r_sign = Scalar::one();
        let mut cx_sign = Scalar::one();
        if let Some(t) = tweak {
            if !R.has_even_y() {
                r_sign = -Scalar::one();
            }
            if t != Scalar::zero() {
                if !tweaked_public_key.has_even_y() ^ !aggregate_public_key.has_even_y() {
                    cx_sign = -Scalar::one();
                }
            } else if !aggregate_public_key.has_even_y() {
                cx_sign = -Scalar::one();
            }
        }

        for i in 0..sig_shares.len() {
            let id = compute::id(sig_shares[i].id);
            let public_key = match compute::poly(&id, &self.poly) {
                Ok(p) => p,
                Err(_) => {
                    bad_party_keys.push(sig_shares[i].id);
                    Point::zero()
                }
            };

            let z_i = sig_shares[i].z_i;

            if z_i * G
                != r_sign * Rs[i]
                    + cx_sign * (compute::lambda(sig_shares[i].id, &signers) * c * public_key)
            {
                bad_party_sigs.push(sig_shares[i].id);
            }
        }

        if !bad_party_keys.is_empty() {
            AggregatorError::BadPartyKeys(bad_party_keys)
        } else if !bad_party_sigs.is_empty() {
            AggregatorError::BadPartySigs(bad_party_sigs)
        } else {
            AggregatorError::BadGroupSig
        }
    }
```

**File:** src/v2.rs (L347-417)
```rust
    pub fn check_signature_shares(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
        tweak: Option<Scalar>,
    ) -> AggregatorError {
        if nonces.len() != sig_shares.len() {
            return AggregatorError::BadNonceLen(nonces.len(), sig_shares.len());
        }

        let party_ids: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (Rs, R) = compute::intermediate(msg, &party_ids, nonces);
        let mut bad_party_keys = Vec::new();
        let mut bad_party_sigs = Vec::new();
        let aggregate_public_key = self.poly[0];
        let tweaked_public_key = if let Some(t) = tweak {
            if t != Scalar::zero() {
                compute::tweaked_public_key_from_tweak(&aggregate_public_key, t)
            } else {
                aggregate_public_key
            }
        } else {
            aggregate_public_key
        };
        let c = compute::challenge(&tweaked_public_key, &R, msg);
        let mut r_sign = Scalar::one();
        let mut cx_sign = Scalar::one();
        if let Some(t) = tweak {
            if !R.has_even_y() {
                r_sign = -Scalar::one();
            }
            if t != Scalar::zero() {
                if !tweaked_public_key.has_even_y() ^ !aggregate_public_key.has_even_y() {
                    cx_sign = -Scalar::one();
                }
            } else if !aggregate_public_key.has_even_y() {
                cx_sign = -Scalar::one();
            }
        }

        for i in 0..sig_shares.len() {
            let z_i = sig_shares[i].z_i;
            let mut cx = Point::zero();

            for key_id in &sig_shares[i].key_ids {
                let kid = compute::id(*key_id);
                let public_key = match compute::poly(&kid, &self.poly) {
                    Ok(p) => p,
                    Err(_) => {
                        bad_party_keys.push(sig_shares[i].id);
                        Point::zero()
                    }
                };

                cx += compute::lambda(*key_id, key_ids) * c * public_key;
            }

            if z_i * G != (r_sign * Rs[i] + cx_sign * cx) {
                bad_party_sigs.push(sig_shares[i].id);
            }
        }
        if !bad_party_keys.is_empty() {
            AggregatorError::BadPartyKeys(bad_party_keys)
        } else if !bad_party_sigs.is_empty() {
            AggregatorError::BadPartySigs(bad_party_sigs)
        } else {
            AggregatorError::BadGroupSig
        }
    }
```
