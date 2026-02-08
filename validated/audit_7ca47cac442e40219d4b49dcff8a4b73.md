# Audit Report

## Title
Missing Identity Point Validation in DKG Key Exchange Enables Private Share Decryption and Key Theft

## Summary
The DKG private share distribution phase fails to validate that ephemeral `kex_public_key` values are not the identity point (point at infinity). A malicious signer can broadcast the identity point as their ephemeral public key, causing all private shares encrypted for that signer's key IDs to use a predictable, constant shared secret. Any network observer can decrypt these shares, and if the malicious signer controls threshold-many key IDs (a legitimate configuration in weighted WSTS), the observer can reconstruct all honest signers' private polynomials and steal the complete group signing key.

## Finding Description

**Root Cause - Missing Validation:**

When signers receive `DkgPublicShares` messages, the ephemeral `kex_public_key` field is stored directly in the `kex_public_keys` HashMap without any validation that it is not the identity point: [1](#0-0) 

The coordinator similarly stores `DkgPublicShares` without validating the `kex_public_key`: [2](#0-1) [3](#0-2) 

**Vulnerable Computation:**

When honest signers encrypt private shares during `dkg_private_begin()`, they retrieve the recipient's `kex_public_key` and compute a shared secret without validating the key: [4](#0-3) 

The `make_shared_secret` function performs Diffie-Hellman key exchange: [5](#0-4) 

If `kex_public_key` is the identity point, then `shared_key = private_key * identity = identity` (a fundamental property of elliptic curve groups). The function then derives the shared secret: [6](#0-5) 

Since the identity point has a fixed, well-known serialization, `shared_key.compress().as_bytes()` produces a constant byte array, resulting in a predictable shared secret that any observer can compute independently.

**Contrast with Existing Protections:**

The codebase correctly validates nonce points to prevent identity point usage: [7](#0-6) 

However, no equivalent validation exists for `kex_public_key` in the DKG flow, demonstrating inconsistent application of this critical security check.

**Attack Mechanics:**

1. Malicious signer (within threat model) broadcasts `DkgPublicShares` with `kex_public_key = Point::identity()`
2. All honest signers store this identity point for all of the attacker's key IDs
3. When honest signers encrypt private shares for these key IDs, they compute:
   - `shared_secret = SHA256(identity_bytes || 1 || "DH_SHARED_SECRET_KEY/")`
   - This is a publicly computable constant
4. Encrypted shares are broadcast over the network: [8](#0-7) 

5. Any network observer can decrypt the shares using the constant shared secret
6. In weighted configurations, a single signer legitimately controls multiple key IDs. If the attacker controls `k >= threshold` key IDs, the observer obtains `k` evaluations of each honest signer's polynomial
7. Since polynomials are degree `threshold-1`, having `threshold` or more evaluations allows unique reconstruction via Lagrange interpolation, revealing each `f_i(0)`
8. The group private key equals the sum of all honest signers' `f_i(0)` values plus the attacker's known contribution

## Impact Explanation

**Critical Severity - Direct Loss of Funds:**

This vulnerability maps to the **Critical** severity category: "Any causing the direct loss of funds other than through any form of freezing."

With the stolen group private key, an attacker can:
- Sign arbitrary transactions without authorization from other signers
- Transfer all funds from addresses controlled by the compromised WSTS group
- Create valid Schnorr signatures or BIP-341 taproot spends
- Completely bypass all threshold signature protections

**Affected Deployments:**

The vulnerability is particularly severe in weighted WSTS configurations where a single signer legitimately controls >= threshold key IDs, which is a common pattern for:
- Major stakeholders in multi-signature wallets
- Weighted voting systems where parties have different voting power
- Stacks blockchain validators using WSTS for consensus signing
- Bitcoin layer-2 protocols using WSTS for custody

The attack enables complete compromise of the cryptographic foundation, leading to irreversible theft of all protected assets.

## Likelihood Explanation

**High Likelihood in Weighted Configurations:**

The attack requires:
1. **Control of one legitimate signer** - Explicitly within the WSTS threat model (malicious participants up to threshold-1 are permitted)
2. **Weighted configuration with >= threshold key weight** - A standard legitimate configuration for representing stakeholders with different voting power
3. **Network message capability** - Standard protocol operation

**Low Attack Complexity:**

- The attacker simply sets `kex_public_key = Point::identity()` when constructing their `DkgPublicShares` message
- No cryptographic breaks, timing attacks, or race conditions required
- The identity point is a well-defined mathematical constant in elliptic curve cryptography
- Attack is deterministic once prerequisites are met

**Low Detection Risk:**

- The identity point is a valid `Point` value that passes deserialization checks
- Without explicit validation, malicious keys are indistinguishable from legitimate ones during protocol execution
- Network observers can passively collect encrypted shares without active participation
- The compromise is only discovered when unauthorized transactions appear on-chain

**Economic Incentive:**

In production deployments protecting significant value, compromising a single high-weight signer provides massive financial incentive with minimal technical barrier.

## Recommendation

Add identity point validation for `kex_public_key` in two locations:

1. **Signer validation** - Add check before storing kex_public_key:
```rust
// In dkg_public_share method, before line 1018
if dkg_public_shares.kex_public_key == Point::identity() {
    warn!(%signer_id, "Received identity point as kex_public_key");
    return Ok(vec![]);
}
```

2. **Coordinator validation** - Add check in gather_public_shares:
```rust
// In gather_public_shares, after checking signer_id
if dkg_public_shares.kex_public_key == Point::identity() {
    warn!(signer_id = %dkg_public_shares.signer_id, "Received identity point as kex_public_key");
    return Ok(());
}
```

This validation should mirror the existing pattern used for nonce validation in `PublicNonce::is_valid()`.

## Proof of Concept

```rust
#[test]
fn test_identity_point_breaks_encryption() {
    use crate::curve::point::{Point, G};
    use crate::curve::scalar::Scalar;
    use crate::util::{make_shared_secret, encrypt, decrypt, create_rng};
    
    let mut rng = create_rng();
    
    // Honest signer's ephemeral private key
    let honest_kex_private = Scalar::random(&mut rng);
    
    // Malicious signer broadcasts identity point
    let malicious_kex_public = Point::identity();
    
    // Honest signer computes shared secret for encryption
    let shared_secret_honest = make_shared_secret(&honest_kex_private, &malicious_kex_public);
    
    // Attacker/observer computes the same shared secret without knowing honest_kex_private
    // because identity * any_scalar = identity
    let shared_secret_attacker = make_shared_secret(&Scalar::from(1u32), &malicious_kex_public);
    
    // The shared secrets are identical - attacker can decrypt
    assert_eq!(shared_secret_honest, shared_secret_attacker);
    
    // Demonstrate actual encryption/decryption
    let secret_share = b"secret polynomial evaluation";
    let ciphertext = encrypt(&shared_secret_honest, secret_share, &mut rng).unwrap();
    let decrypted = decrypt(&shared_secret_attacker, &ciphertext).unwrap();
    
    // Attacker successfully decrypts without knowing honest signer's private key
    assert_eq!(secret_share, &decrypted[..]);
}
```

### Citations

**File:** src/state_machine/signer/mod.rs (L937-942)
```rust
                    let Some(kex_public_key) = self.kex_public_keys.get(dst_key_id) else {
                        error!("No KEX public key for key_id {dst_key_id}");
                        return Err(Error::MissingKexPublicKey(*dst_key_id));
                    };
                    let shared_secret = make_shared_secret(&self.kex_private_key, kex_public_key);
                    let encrypted_share = encrypt(&shared_secret, &private_share.to_bytes(), rng)?;
```

**File:** src/state_machine/signer/mod.rs (L951-952)
```rust
        let private_shares = Message::DkgPrivateShares(private_shares);
        msgs.push(private_shares);
```

**File:** src/state_machine/signer/mod.rs (L1018-1021)
```rust
        for key_id in signer_key_ids {
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
        }
```

**File:** src/state_machine/coordinator/frost.rs (L317-318)
```rust
            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L668-668)
```rust
                                let signer_public_key = signer_public_shares.kex_public_key;
```

**File:** src/util.rs (L48-52)
```rust
pub fn make_shared_secret(private_key: &Scalar, public_key: &Point) -> [u8; 32] {
    let shared_key = private_key * public_key;

    make_shared_secret_from_key(&shared_key)
}
```

**File:** src/util.rs (L55-60)
```rust
pub fn make_shared_secret_from_key(shared_key: &Point) -> [u8; 32] {
    ansi_x963_derive_key(
        shared_key.compress().as_bytes(),
        "DH_SHARED_SECRET_KEY/".as_bytes(),
    )
}
```

**File:** src/common.rs (L161-163)
```rust
    pub fn is_valid(&self) -> bool {
        self.D != Point::identity() && self.E != Point::identity() && self.D != G && self.E != G
    }
```
