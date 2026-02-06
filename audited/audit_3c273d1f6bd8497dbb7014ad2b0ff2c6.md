### Title
Unauthenticated Key Exchange Public Key Enables Man-in-the-Middle Attack on DKG Private Share Distribution

### Summary
The `kex_public_key` field in `DkgPublicShares` messages is not included in the signature hash, allowing an attacker with network MITM capabilities to replace a legitimate signer's key exchange public key with their own. This enables the attacker to decrypt all private DKG shares sent to the victim, compromising the threshold signature scheme's security even when packet signature verification is enabled.

### Finding Description

**Root Cause:**

The vulnerability exists in the `Signable` trait implementation for `DkgPublicShares` messages. [1](#0-0) 

The hash function only includes the `dkg_id`, `signer_id`, and polynomial commitments (`comms`), but explicitly excludes the `kex_public_key` field from the signature. This means the packet signature does not authenticate the key exchange public key.

**Exploitation Path:**

1. When a signer processes received `DkgPublicShares`, it stores the `kex_public_key` for all of that signer's key IDs: [2](#0-1) 

2. The `get_kex_public_key()` function retrieves this stored key without any additional validation: [3](#0-2) 

3. When encrypting private shares, signers use this unauthenticated key to compute the shared secret: [4](#0-3) 

4. The encryption uses Diffie-Hellman key exchange: [5](#0-4) 

**Why Existing Mitigations Fail:**

Even with packet signature verification enabled, the verification only checks fields included in the hash. The packet verification for `DkgPublicShares` correctly validates the signature against the signer's public key: [6](#0-5) 

However, since `kex_public_key` is not part of the signed content, an attacker can modify it while preserving signature validity.

### Impact Explanation

**Specific Harm:**

An attacker with network MITM position can:
1. Replace the victim signer's `kex_public_key` with an attacker-controlled key
2. Decrypt all private DKG shares encrypted for the victim signer
3. Reconstruct the victim's private key contribution to the group key

**Quantified Impact:**

- If an attacker compromises `t` out of `n` signers (where `t` is the threshold), the attacker can reconstruct the complete group private key
- For a typical 7-of-10 configuration, attacking 7 signers would give complete key control
- Even attacking fewer signers weakens security proportionally

**Who Is Affected:**

All WSTS deployments where:
- The attacker has network access to intercept/modify DKG messages
- Multiple signers are targeted to reach threshold
- The compromised key is used for signing blockchain transactions

**Severity Justification:**

This is **High** severity per the defined scope: it enables key control loss and could lead to confirmation of invalid transactions or direct loss of funds if the attacker gains threshold control. It constitutes "remotely-exploitable" compromise of cryptographic key material that secures blockchain operations.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Network MITM position between coordinator and signers (e.g., compromised router, BGP hijacking, or malicious network infrastructure)
- Ability to intercept and modify packets in real-time during DKG
- No need for cryptographic breaks or access to private keys

**Attack Complexity:**
- Low: Simple packet interception and field replacement
- Works even with signature verification enabled
- No timing constraints beyond DKG round duration

**Economic Feasibility:**
- For high-value targets (e.g., Bitcoin custody), attackers may already have MITM capabilities
- Cloud/datacenter deployments may be vulnerable to infrastructure compromise
- Cost is primarily obtaining network position, not computational

**Detection Risk:**
- Low: The modified packets have valid signatures
- Victim signers will experience decryption failures, but these may be attributed to network issues
- No obvious indicators distinguish attack from network problems

**Probability of Success:**
- High for attackers with network position
- Scales with number of signers targeted
- 100% success rate per attacked signer if MITM is achieved

### Recommendation

**Primary Fix:**

Modify the `DkgPublicShares::hash()` implementation to include the `kex_public_key` in the signature:

```rust
impl Signable for DkgPublicShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PUBLIC_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        hasher.update(self.kex_public_key.compress().as_bytes()); // ADD THIS
        for (party_id, comm) in &self.comms {
            hasher.update(party_id.to_be_bytes());
            for a in &comm.poly {
                hasher.update(a.compress().as_bytes());
            }
        }
    }
}
```

**Alternative Mitigations:**

1. Add explicit validation in `dkg_public_share()` to verify the `kex_public_key` is properly bound to the sender's identity
2. Use authenticated encryption that binds the sender's long-term public key to the ephemeral key
3. Implement out-of-band key verification (e.g., fingerprint comparison)

**Testing Recommendations:**

1. Add unit test that verifies signature changes when `kex_public_key` is modified
2. Add integration test simulating MITM attack with modified `kex_public_key`
3. Verify decryption failures occur when keys don't match
4. Test that legitimate DKG flows still succeed after fix

**Deployment Considerations:**

- This is a breaking change to the message format
- All nodes must upgrade simultaneously
- Existing DKG rounds in progress must be aborted and restarted
- Document the security issue in release notes

### Proof of Concept

**Exploitation Algorithm:**

1. **Setup:**
   - Attacker positions themselves as MITM between coordinator and signers
   - Attacker generates their own key pair: `(m, M=m*G)` where `m` is private, `M` is public

2. **Interception:**
   - Attacker intercepts `DkgPublicShares` from victim Signer A
   - Original message contains: `{signer_id: A, kex_public_key: a*G, comms: [...], sig: S}`

3. **Modification:**
   - Attacker replaces `kex_public_key: a*G` with `kex_public_key: M`
   - Modified message: `{signer_id: A, kex_public_key: M, comms: [...], sig: S}`
   - Signature `S` remains valid because `kex_public_key` is not in the hash

4. **Forwarding:**
   - Attacker forwards modified message to other signers
   - Other signers verify signature successfully (it only covers `dkg_id`, `signer_id`, `comms`)
   - Other signers store `M` as Signer A's key exchange public key

5. **Private Share Interception:**
   - When Signer B sends private shares to Signer A:
     - Signer B retrieves `M` as Signer A's key
     - Signer B computes `shared_secret = b * M = bm*G`
     - Signer B encrypts private share with this secret
   - Attacker intercepts encrypted share
   - Attacker decrypts using: `shared_secret = m * (b*G) = bm*G`

6. **Result:**
   - Attacker obtains all private shares meant for Signer A
   - Signer A cannot decrypt (has key `a`, not `m`)
   - Attacker can reconstruct Signer A's private key contributions

**Expected vs Actual Behavior:**

- **Expected:** Signature should protect all security-critical fields including `kex_public_key`
- **Actual:** Signature omits `kex_public_key`, allowing undetected modification

**Reproduction Instructions:**

1. Set up 3-node WSTS cluster with signature verification enabled
2. Configure network proxy to intercept packets between nodes
3. Intercept `DkgPublicShares` from Signer 0
4. Replace `kex_public_key` field with attacker-controlled key
5. Forward modified packet to other signers
6. Observe: signature validates, key is stored, encryption uses wrong key
7. Intercept `DkgPrivateShares` sent to Signer 0
8. Decrypt using attacker's private key
9. Observe: successful decryption of victim's private shares

### Citations

**File:** src/net.rs (L152-164)
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
}
```

**File:** src/net.rs (L526-539)
```rust
            Message::DkgPublicShares(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a DkgPublicShares message with an invalid signature.");
                        return false;
                    }
                } else {
                    warn!(
                        "Received a DkgPublicShares message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
```

**File:** src/state_machine/signer/mod.rs (L936-943)
```rust
                    debug!("encrypting dkg private share for key_id {dst_key_id}");
                    let Some(kex_public_key) = self.kex_public_keys.get(dst_key_id) else {
                        error!("No KEX public key for key_id {dst_key_id}");
                        return Err(Error::MissingKexPublicKey(*dst_key_id));
                    };
                    let shared_secret = make_shared_secret(&self.kex_private_key, kex_public_key);
                    let encrypted_share = encrypt(&shared_secret, &private_share.to_bytes(), rng)?;

```

**File:** src/state_machine/signer/mod.rs (L1018-1021)
```rust
        for key_id in signer_key_ids {
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
        }
```

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

**File:** src/util.rs (L47-52)
```rust
/// Do a Diffie-Hellman key exchange to create a shared secret from the passed private/public keys
pub fn make_shared_secret(private_key: &Scalar, public_key: &Point) -> [u8; 32] {
    let shared_key = private_key * public_key;

    make_shared_secret_from_key(&shared_key)
}
```
