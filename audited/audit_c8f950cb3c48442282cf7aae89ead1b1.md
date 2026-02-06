Let me examine the exact semantics of the code to ensure there's no panic:
> Searching codebase... [1](#0-0)

### Citations

**File:** src/state_machine/signer/mod.rs (L1112-1129)
```rust
    fn get_kex_public_key(&self, signer_id: u32) -> Result<Point, Error> {
        let Some(signer_key_ids) = self.public_keys.signer_key_ids.get(&signer_id) else {
            warn!(%signer_id, "No key_ids configured");
            return Err(Error::Config(ConfigError::InvalidSignerId(signer_id)));
        };

        let Some(signer_key_id) = signer_key_ids.iter().next() else {
            warn!(%signer_id, "No key_ids configured");
            return Err(Error::Config(ConfigError::InvalidSignerId(signer_id)));
        };

        let Some(kex_public_key) = self.kex_public_keys.get(signer_key_id) else {
            warn!(%signer_id, %signer_key_id, "No KEX public key configured");
            return Err(Error::MissingKexPublicKey(*signer_key_id));
        };

        Ok(*kex_public_key)
    }
```
