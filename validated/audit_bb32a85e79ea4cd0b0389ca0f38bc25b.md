# Audit Report

## Title
Missing Identity Point Validation in DKG Key Exchange Enables Private Share Decryption and Key Theft

## Summary
The DKG private share distribution phase fails to validate that ephemeral `kex_public_key` values are not the identity point (point at infinity). An attacker controlling a signer can broadcast the identity point as their ephemeral public key, causing all private shares encrypted for that signer to use a predictable, constant shared secret. Any network observer can decrypt these shares, and if the attacker controls threshold-many key IDs, the observer can reconstruct all honest signers' private polynomials and steal the group signing key.

## Finding Description

**Root Cause - Missing Validation:**

When signers receive `DkgPublicShares` messages, the ephemeral `kex_public_key` field is stored without any point validation. The signer stores these keys directly in the `kex_public_keys` HashMap indexed by key_id: [1](#0-0) 

The coordinator also stores `DkgPublicShares` without validating the `kex_public_key` field: [2](#0-1) 

**Vulnerable Computation:**

When honest signers encrypt private shares for recipients during `dkg_private_begin()`, they retrieve the recipient's `kex_public_key` and compute a shared secret: [3](#0-2) 

Later, when receiving encrypted shares in `dkg_private_shares()`, the same vulnerable computation occurs: [4](#0-3) 

The `make_shared_secret` function performs Diffie-Hellman key exchange: [5](#0-4) 

If `kex_public_key` is the identity point, then `shared_key = private_key * identity = identity`. The function then derives the shared secret from this point: [6](#0-5) 

Since the identity point has a fixed, well-known serialization, `shared_key.compress().as_bytes()` produces a constant byte array, resulting in a predictable shared secret that any observer can compute.

**Contrast with Existing Protections:**

The codebase correctly validates nonce points to prevent identity point usage: [7](#0-6) 

However, no equivalent validation exists for `kex_public_key` in the DKG flow, demonstrating that the developers understood the need for such validation but failed to apply it to key exchange keys.

**Attack Mechanics:**

1. Malicious signer broadcasts `DkgPublicShares` with `kex_public_key = Point::identity()`
2. All signers store this identity point for the attacker's key IDs
3. When honest signers encrypt private shares for these key IDs, they compute:
   - `shared_secret = SHA256(identity_bytes || 1 || "DH_SHARED_SECRET_KEY/")`
   - This is a publicly computable constant
4. Any network observer can decrypt the shares using this constant shared secret
5. If the attacker controls `k >= threshold` key IDs, the observer obtains `k` evaluations of each honest signer's polynomial
6. Using Lagrange interpolation, the observer reconstructs each polynomial `f_i(x)` and learns `f_i(0)`
7. The group private key equals the sum of all `f_i(0)` values

## Impact Explanation

**Critical Severity - Direct Loss of Funds:**

This vulnerability maps to the **Critical** severity category defined in scope: "Any causing the direct loss of funds other than through any form of freezing."

With the stolen group private key, an attacker can:
- Sign arbitrary transactions without authorization
- Transfer all funds from addresses controlled by the compromised WSTS group  
- Create valid Schnorr signatures or BIP-341 taproot spends
- Bypass all threshold signature protections

**Affected Deployments:**

The vulnerability is most severe in weighted WSTS configurations where:
- A single signer legitimately controls >= threshold key IDs (e.g., representing a major stakeholder)
- Multi-signature wallets with high-weight participants
- Stacks blockchain validators using WSTS for consensus signing
- Bitcoin layer-2 protocols using WSTS for custody

The attack enables complete compromise of the cryptographic foundation of these systems, leading to irreversible theft of all protected assets.

## Likelihood Explanation

**High Likelihood in Weighted Configurations:**

The attack requires:
1. **Control of one legitimate signer** - Within the WSTS threat model (malicious participants up to threshold-1 are permitted)
2. **Network message capability** - Standard protocol operation
3. **>= threshold key weight** - Common in weighted configurations where major stakeholders control multiple key IDs

**Low Attack Complexity:**

- The attacker simply sets `kex_public_key` to `Point::identity()` in their `DkgPublicShares` message
- No cryptographic breaks, timing attacks, or race conditions required
- The identity point is a well-defined mathematical constant
- Attack is deterministic once prerequisites are met

**Low Detection Risk:**

- The identity point is a valid `Point` value that passes deserialization
- Without explicit validation, malicious keys are indistinguishable from legitimate ones
- Network observers can passively collect encrypted shares without raising alarms
- The compromise is only discovered when unauthorized transactions appear

**Economic Incentive:**

In production deployments protecting significant value (Stacks consensus, Bitcoin custody), compromising a single high-weight signer provides massive financial incentive with minimal technical barrier.

## Recommendation

Add identity point validation for `kex_public_key` at the point of receipt, mirroring the existing nonce validation pattern:

**For Signers (src/state_machine/signer/mod.rs):**

After line 1016, before storing the key, add:
```rust
// Validate kex_public_key is not identity or generator
if dkg_public_shares.kex_public_key == Point::identity() 
    || dkg_public_shares.kex_public_key == G {
    warn!(%signer_id, "Invalid kex_public_key (identity or generator)");
    return Ok(vec![]);
}
```

**For Coordinator (src/state_machine/coordinator/fire.rs):**

After line 500, add similar validation:
```rust
// Validate kex_public_key is not identity or generator  
if dkg_public_shares.kex_public_key == Point::identity()
    || dkg_public_shares.kex_public_key == G {
    warn!(signer_id = %dkg_public_shares.signer_id, "Invalid kex_public_key");
    return Ok(());
}
```

Apply equivalent validation in the FROST coordinator at `src/state_machine/coordinator/frost.rs`.

## Proof of Concept

```rust
#[test]
fn test_identity_kex_key_attack() {
    use crate::curve::point::Point;
    use crate::util::make_shared_secret;
    use crate::curve::scalar::Scalar;
    
    let mut rng = create_rng();
    
    // Honest signer's private KEX key
    let honest_private = Scalar::random(&mut rng);
    
    // Attacker broadcasts identity as their KEX public key
    let malicious_public = Point::identity();
    
    // Honest signer computes shared secret for encrypting shares to attacker
    let shared_secret = make_shared_secret(&honest_private, &malicious_public);
    
    // Any observer can compute the same constant shared secret
    let observer_private = Scalar::random(&mut rng); // Different key
    let observer_secret = make_shared_secret(&observer_private, &malicious_public);
    
    // Both computations yield identity point, thus same shared secret
    // because any_scalar * identity = identity
    // This demonstrates the shared secret is constant and predictable
    assert_eq!(shared_secret, observer_secret);
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

**File:** src/state_machine/signer/mod.rs (L1018-1021)
```rust
        for key_id in signer_key_ids {
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
        }
```

**File:** src/state_machine/signer/mod.rs (L1069-1070)
```rust
        let shared_key = self.kex_private_key * kex_public_key;
        let shared_secret = make_shared_secret(&self.kex_private_key, &kex_public_key);
```

**File:** src/state_machine/coordinator/fire.rs (L505-506)
```rust
            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
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

**File:** src/common.rs (L159-163)
```rust
impl PublicNonce {
    /// Check that the nonces are not zero since that can lead to attacks
    pub fn is_valid(&self) -> bool {
        self.D != Point::identity() && self.E != Point::identity() && self.D != G && self.E != G
    }
```
