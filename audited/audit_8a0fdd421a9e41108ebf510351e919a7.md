> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** src/v1.rs (L54-65)
```rust
    pub fn new<RNG: RngCore + CryptoRng>(id: u32, n: u32, t: u32, rng: &mut RNG) -> Self {
        Self {
            id,
            num_keys: n,
            threshold: t,
            f: Some(VSS::random_poly(t - 1, rng)),
            private_key: Scalar::zero(),
            public_key: Point::zero(),
            group_key: Point::zero(),
            nonce: Nonce::zero(),
        }
    }
```

**File:** src/v1.rs (L530-548)
```rust
    pub fn new<RNG: RngCore + CryptoRng>(
        id: u32,
        key_ids: &[u32],
        num_keys: u32,
        threshold: u32,
        rng: &mut RNG,
    ) -> Self {
        let parties = key_ids
            .iter()
            .map(|id| Party::new(*id, num_keys, threshold, rng))
            .collect();
        Signer {
            id,
            num_keys,
            threshold,
            group_key: Point::zero(),
            parties,
        }
    }
```

**File:** src/state_machine/signer/mod.rs (L281-325)
```rust
    pub fn new<R: RngCore + CryptoRng>(
        threshold: u32,
        dkg_threshold: u32,
        total_signers: u32,
        total_keys: u32,
        signer_id: u32,
        key_ids: Vec<u32>,
        network_private_key: Scalar,
        public_keys: PublicKeys,
        rng: &mut R,
    ) -> Result<Self, Error> {
        if total_signers > total_keys {
            return Err(Error::Config(ConfigError::InsufficientKeys));
        }

        if threshold == 0 || threshold > total_keys {
            return Err(Error::Config(ConfigError::InvalidThreshold));
        }

        if dkg_threshold == 0 || dkg_threshold < threshold {
            return Err(Error::Config(ConfigError::InvalidThreshold));
        }

        if !validate_signer_id(signer_id, total_signers) {
            return Err(Error::Config(ConfigError::InvalidSignerId(signer_id)));
        }

        for key_id in &key_ids {
            if !validate_key_id(*key_id, total_keys) {
                return Err(Error::Config(ConfigError::InvalidKeyId(*key_id)));
            }
        }

        public_keys.validate(total_signers, total_keys)?;

        let signer = SignerType::new(
            signer_id,
            &key_ids,
            total_signers,
            total_keys,
            threshold,
            rng,
        );
        debug!("new Signer for signer_id {signer_id} with key_ids {key_ids:?}");
        Ok(Self {
```

**File:** src/state_machine/signer/mod.rs (L1047-1056)
```rust
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
```

**File:** src/common.rs (L314-316)
```rust
pub fn validate_key_id(key_id: u32, num_keys: u32) -> bool {
    key_id > 0 && key_id <= num_keys
}
```

**File:** src/state_machine/mod.rs (L105-136)
```rust
    /// Check that all of the signer_ids and key_ids are valid
    pub fn validate(&self, num_signers: u32, num_keys: u32) -> Result<(), SignerError> {
        for (signer_id, _key) in &self.signers {
            if !validate_signer_id(*signer_id, num_signers) {
                return Err(SignerError::Config(ConfigError::InvalidSignerId(
                    *signer_id,
                )));
            }
        }

        for (key_id, _key) in &self.key_ids {
            if !validate_key_id(*key_id, num_keys) {
                return Err(SignerError::Config(ConfigError::InvalidKeyId(*key_id)));
            }
        }

        for (signer_id, key_ids) in &self.signer_key_ids {
            if !validate_signer_id(*signer_id, num_signers) {
                return Err(SignerError::Config(ConfigError::InvalidSignerId(
                    *signer_id,
                )));
            }

            for key_id in key_ids {
                if !validate_key_id(*key_id, num_keys) {
                    return Err(SignerError::Config(ConfigError::InvalidKeyId(*key_id)));
                }
            }
        }

        Ok(())
    }
```
