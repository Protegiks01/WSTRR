# Audit Report

## Title
Missing Validation of DH Public Keys Allows Predictable Encryption Keys in DKG Private Share Distribution

## Summary
The DKG protocol fails to validate ephemeral Diffie-Hellman public keys (`kex_public_key`) in `DkgPublicShares` messages, allowing malicious actors to force the use of predictable encryption keys for private share distribution. When `Point::identity()` is used as `kex_public_key`, all honest signers derive a constant, predictable encryption key, enabling unauthorized decryption of private shares and potential reconstruction of the distributed group key.

## Finding Description

The vulnerability exists in the DKG private share encryption mechanism. The protocol uses ephemeral Diffie-Hellman key exchange to encrypt private polynomial shares, but fails to validate that the exchanged public keys are valid, non-degenerate elliptic curve points.

**Attack Vector 1 - Malicious Signer:**
A registered malicious signer can broadcast `Point::identity()` as their `kex_public_key` in the `DkgPublicShares` message. When honest signers encrypt private shares for this malicious party, they compute the shared secret as `kex_private_key * Point::identity() = Point::identity()`. This results in a predictable encryption key: `SHA256(identity_point_compressed || 0x00000001 || "DH_SHARED_SECRET_KEY/")`, which anyone can compute.

**Attack Vector 2 - Network Man-in-the-Middle:**
More critically, since `kex_public_key` is not included in the message authentication hash [1](#0-0) , a network attacker can modify any honest signer's `kex_public_key` to `Point::identity()` without invalidating the message signature. When other signers encrypt shares for the victim, they use the predictable key. The attacker can decrypt these shares, while the victim cannot (due to key mismatch), causing DKG to fail for the victim but leaking their private shares to the attacker.

**Technical Details:**

1. The `encrypt()` function accepts a 32-byte key without any validation of its entropy or source: [2](#0-1) 

2. The `make_shared_secret()` function performs scalar-point multiplication without validating that the public key is not the identity point or other weak points: [3](#0-2) 

3. When `DkgPublicShares` messages are received, the `kex_public_key` is stored directly without any point validation: [4](#0-3) 

4. This unvalidated key is then used to encrypt private shares: [5](#0-4) 

5. The codebase demonstrates awareness of such attacks by validating `PublicNonce` points against identity: [6](#0-5) 

6. However, no equivalent validation is applied to `kex_public_key` values.

7. The `TupleProof` mechanism cannot prevent this attack. When `B = Point::identity()`, the verification equations `z * G == R + s * A` and `z * identity == identity` both evaluate correctly, allowing the proof to pass: [7](#0-6) 

## Impact Explanation

This vulnerability enables **complete compromise of the distributed key**, mapping to Critical severity under the audit scope for "Any causing the direct loss of funds" and "Any confirmation of an invalid transaction."

**Concrete Attack Scenario:**
In a threshold (t, n) setup, a network attacker can:
1. Use man-in-the-middle position to modify `kex_public_key` for t different honest signers to `Point::identity()`
2. Intercept and decrypt all private shares intended for these t victims using the predictable encryption key
3. Reconstruct each victim's complete share (sum of polynomial evaluations they should receive)
4. With t shares, use Lagrange interpolation to reconstruct the group private key
5. Create unauthorized signatures to steal funds or execute unauthorized transactions

**Why This Breaks Security:**
The FROST DKG protocol's security relies on the confidentiality of private polynomial shares during distribution. By breaking this confidentiality, an external attacker (not even a protocol participant) can reconstruct the distributed key, completely undermining the threshold signature scheme's security guarantees.

## Likelihood Explanation

**Attack Complexity:** Extremely low. For the MitM scenario, the attacker only needs to:
- Position themselves on the network path (standard for blockchain P2P networks)
- Modify a single unprotected field in DKG messages
- Compute the predictable encryption key and decrypt intercepted shares

**Attacker Capabilities Required:**
- Network position to observe/modify messages (realistic for P2P networks)
- No cryptographic breaks needed
- No insider access required (though insider attack is even simpler)

**Detection Difficulty:** Very low. The attack is silent - message signatures remain valid, TupleProof verifications pass, and the attack is only detectable through out-of-band share verification.

**Success Probability:** 100% if the attacker can modify messages before they reach honest signers, which is feasible in decentralized P2P networks.

## Recommendation

Add strict validation of `kex_public_key` when receiving `DkgPublicShares` messages:

```rust
// In dkg_public_share() method, after line 1016:
// Validate kex_public_key is not identity or generator
if dkg_public_shares.kex_public_key == Point::identity() 
    || dkg_public_shares.kex_public_key == G {
    warn!(%signer_id, "Invalid kex_public_key (identity or generator)");
    return Ok(vec![]);
}
```

**Additional Hardening:**
1. Include `kex_public_key` in the `Signable::hash()` implementation for `DkgPublicShares` to prevent MitM modification: [1](#0-0) 

2. Validate the point is on the curve and in the correct subgroup (though the `Point` type from p256k1 likely handles this).

3. Consider adding validation in `make_shared_secret()` as a defense-in-depth measure.

## Proof of Concept

```rust
#[test]
fn test_identity_point_produces_predictable_key() {
    use crate::curve::{point::Point, scalar::Scalar};
    use crate::util::{make_shared_secret, create_rng};
    
    let mut rng = create_rng();
    
    // Any two different private keys
    let key1 = Scalar::random(&mut rng);
    let key2 = Scalar::random(&mut rng);
    
    // Both produce the SAME shared secret with identity point
    let secret1 = make_shared_secret(&key1, &Point::identity());
    let secret2 = make_shared_secret(&key2, &Point::identity());
    
    // Predictable and constant!
    assert_eq!(secret1, secret2);
    
    // This breaks the Diffie-Hellman security assumption
    // where different private keys should produce different shared secrets
}
```

### Citations

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

**File:** src/util.rs (L48-52)
```rust
pub fn make_shared_secret(private_key: &Scalar, public_key: &Point) -> [u8; 32] {
    let shared_key = private_key * public_key;

    make_shared_secret_from_key(&shared_key)
}
```

**File:** src/util.rs (L80-99)
```rust
pub fn encrypt<RNG: RngCore + CryptoRng>(
    key: &[u8; 32],
    data: &[u8],
    rng: &mut RNG,
) -> Result<Vec<u8>, EncryptionError> {
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];

    rng.fill_bytes(&mut nonce_bytes);

    let nonce_vec = nonce_bytes.to_vec();
    let nonce = Nonce::from_slice(&nonce_vec);
    let cipher = Aes256Gcm::new(key.into());
    let cipher_vec = cipher.encrypt(nonce, data.to_vec().as_ref())?;
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&nonce_vec);
    bytes.extend_from_slice(&cipher_vec);

    Ok(bytes)
}
```

**File:** src/state_machine/signer/mod.rs (L937-942)
```rust
                    let Some(kex_public_key) = self.kex_public_keys.get(dst_key_id) else {
                        error!("No KEX public key for key_id {dst_key_id}");
                        return Err(Error::MissingKexPublicKey(*dst_key_id));
                    };
                    let shared_secret = make_shared_secret(&self.kex_private_key, kex_public_key);
                    let encrypted_share = encrypt(&shared_secret, &private_share.to_bytes(), rng)?;
```

**File:** src/state_machine/signer/mod.rs (L1019-1021)
```rust
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
        }
```

**File:** src/common.rs (L160-163)
```rust
    /// Check that the nonces are not zero since that can lead to attacks
    pub fn is_valid(&self) -> bool {
        self.D != Point::identity() && self.E != Point::identity() && self.D != G && self.E != G
    }
```

**File:** src/common.rs (L288-292)
```rust
    pub fn verify(&self, A: &Point, B: &Point, K: &Point) -> bool {
        let s = Self::challenge(A, B, K, &self.R);

        (self.z * G == self.R + s * A) && (self.z * B == self.rB + s * K)
    }
```
