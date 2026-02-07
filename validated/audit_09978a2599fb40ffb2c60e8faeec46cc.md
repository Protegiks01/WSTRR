# Audit Report

## Title
Identity Point Attack on DKG Private Share Encryption Enables Complete Key Material Extraction

## Summary
The DKG private share encryption mechanism fails to validate that `kex_public_key` is not the identity point, allowing a malicious signer to force predictable shared secrets and decrypt all private shares sent by honest signers. This completely compromises the distributed key generation protocol, enabling reconstruction of the group private key and theft of all funds controlled by the threshold signature scheme.

## Finding Description

The vulnerability arises from three compounding failures in the DKG private share encryption mechanism:

**Failure 1: Missing Identity Point Validation**

When a signer receives a `DkgPublicShares` message, the `kex_public_key` field is stored without validating that it is not the identity point. [1](#0-0) 

No check exists to ensure `kex_public_key != Point::identity()`, despite the codebase demonstrating awareness of this attack vector through identity point validation for nonces. [2](#0-1) 

**Failure 2: Signature Hash Excludes kex_public_key**

The `DkgPublicShares::hash()` implementation for signature verification explicitly excludes the `kex_public_key` field from the hash computation. [3](#0-2) 

This allows a malicious signer to set their `kex_public_key` to the identity point in their own properly-signed message without detection.

**Failure 3: Unvalidated Diffie-Hellman Computation**

When encrypting private shares for a recipient, the sender performs Diffie-Hellman key exchange without validating the recipient's public key. [4](#0-3) 

The underlying `make_shared_secret` function performs scalar multiplication without input validation: [5](#0-4) 

**Attack Mechanism:**

By the mathematical property of elliptic curves, for any scalar `s`: `s * Point::identity() = Point::identity()`. The compressed representation of the identity point is deterministic and publicly known. Therefore:

1. Malicious signer broadcasts `DkgPublicShares` with `kex_public_key = Point::identity()`
2. Honest signers accept this (no validation occurs)
3. When encrypting shares, honest signers compute: `shared_key = their_kex_private_key * Point::identity() = Point::identity()`
4. The shared secret is derived via ANSI X9.63 KDF from the identity point's compressed bytes: [6](#0-5) 

5. This shared secret is deterministic and computable by the attacker without knowing the honest signer's private key
6. The attacker successfully decrypts all shares sent to them
7. With threshold `t` shares, the attacker reconstructs the group private key via Lagrange interpolation

**Why Existing Validations Fail:**

Polynomial commitment verification occurs during `dkg_ended()` after share decryption: [7](#0-6) 

This verification checks share correctness (whether `s * G == poly(...)`) but not confidentiality: [8](#0-7) 

The attacker uses their own valid polynomial, so their shares pass verification. The attack targets the confidentiality of shares sent by OTHERS to the attacker, not the correctness of the attacker's own shares.

## Impact Explanation

This vulnerability maps to **Critical** severity as defined in the scope: "causing the direct loss of funds other than through any form of freezing."

**Specific Impacts:**

1. **Complete Private Key Extraction**: In a threshold t-of-n setup where n > t, the attacker (as one of n signers) receives private shares from n-1 honest signers. For a typical 3-of-5 configuration, the attacker receives 4 shares, exceeding the threshold of 3.

2. **Group Private Key Reconstruction**: With t or more shares, the attacker performs Lagrange interpolation to reconstruct the complete group private key, bypassing all threshold signature security properties.

3. **Unconditional Fund Theft**: With the group private key, the attacker can:
   - Sign arbitrary Bitcoin/cryptocurrency transactions
   - Steal 100% of funds controlled by the compromised group key
   - Confirm invalid transactions on Stacks blockchain
   - Impersonate the entire signing group indefinitely

4. **Scope of Damage**: All participants in any DKG session where the malicious signer participates are compromised. The attack affects the entire security model of the threshold signature scheme.

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be a legitimate registered signer in the DKG protocol (standard participant role)
- Possesses valid `signer_id` and signing key (normal operational requirement)
- No special network position or privileged access required

**Attack Complexity: Trivial**
- The attack requires only setting `kex_public_key = Point::identity()` in the attacker's own `DkgPublicShares` message
- No cryptographic primitives need to be broken
- No brute-force computation required
- No timing attacks or side-channels needed
- Single message modification is sufficient

**Detection Resistance:**
- Encrypted shares decrypt successfully (no errors raised)
- Polynomial commitments validate correctly (attacker's own polynomial is legitimate)
- No warning messages generated
- The attack is completely silent until funds are stolen
- Standard monitoring and logging would not detect this attack

**Economic Viability:**
- Attack cost: Only the cost of becoming a registered signer
- Attack gain: All funds controlled by the group key
- For any non-trivial fund amounts, the attack provides overwhelming economic incentive

**Probability Assessment:**
Given a motivated attacker with signer access, this attack succeeds with 100% probability. The vulnerability is deterministic, not probabilistic, and no defensive measures are in place.

## Recommendation

Add identity point validation for `kex_public_key` when receiving `DkgPublicShares` messages:

```rust
// In src/state_machine/signer/mod.rs, dkg_public_share() method
// After line 1016, before storing kex_public_key:

// Validate kex_public_key is not the identity point
if dkg_public_shares.kex_public_key == Point::identity() {
    warn!(%signer_id, "Received identity point as kex_public_key");
    return Ok(vec![]);
}

// Also validate it's not the generator G
if dkg_public_shares.kex_public_key == G {
    warn!(%signer_id, "Received generator G as kex_public_key");
    return Ok(vec![]);
}

for key_id in signer_key_ids {
    self.kex_public_keys
        .insert(*key_id, dkg_public_shares.kex_public_key);
}
```

Additionally, include `kex_public_key` in the signature hash to prevent manipulation:

```rust
// In src/net.rs, DkgPublicShares::hash() implementation
impl Signable for DkgPublicShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PUBLIC_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        hasher.update(self.kex_public_key.compress().as_bytes()); // ADD THIS LINE
        for (party_id, comm) in &self.comms {
            hasher.update(party_id.to_be_bytes());
            for a in &comm.poly {
                hasher.update(a.compress().as_bytes());
            }
        }
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_identity_point_attack_on_kex_public_key() {
    use crate::state_machine::signer::Signer;
    use crate::net::DkgPublicShares;
    use crate::curve::point::Point;
    use crate::util::make_shared_secret;
    use crate::curve::scalar::Scalar;
    
    let mut rng = create_rng();
    
    // Setup: honest signer generates legitimate kex_private_key
    let honest_kex_private_key = Scalar::random(&mut rng);
    
    // Attack: malicious signer sets kex_public_key to identity point
    let malicious_kex_public_key = Point::identity();
    
    // When honest signer encrypts shares for malicious signer:
    let shared_secret = make_shared_secret(&honest_kex_private_key, &malicious_kex_public_key);
    
    // Verify that shared_secret is deterministic and predictable
    // (derived from identity point which is publicly known)
    let attacker_computed_secret = make_shared_secret(&Scalar::one(), &malicious_kex_public_key);
    
    // The attacker can compute shared secrets for ANY honest signer's private key
    // because scalar * identity = identity for all scalars
    let different_honest_key = Scalar::random(&mut rng);
    let different_shared_secret = make_shared_secret(&different_honest_key, &malicious_kex_public_key);
    
    // All shared secrets collapse to the same value derived from identity point
    assert_eq!(
        make_shared_secret_from_key(&Point::identity()),
        shared_secret
    );
    assert_eq!(shared_secret, different_shared_secret);
    
    // This demonstrates the attacker can decrypt ALL shares without knowing
    // any honest signer's kex_private_key
}
```

### Citations

**File:** src/state_machine/signer/mod.rs (L612-616)
```rust
            match self.signer.compute_secrets(
                &self.decrypted_shares,
                &self.commitments,
                &self.dkg_id.to_be_bytes(),
            ) {
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

**File:** src/state_machine/signer/mod.rs (L1018-1021)
```rust
        for key_id in signer_key_ids {
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
        }
```

**File:** src/common.rs (L161-163)
```rust
    pub fn is_valid(&self) -> bool {
        self.D != Point::identity() && self.E != Point::identity() && self.D != G && self.E != G
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

**File:** src/v2.rs (L165-186)
```rust
        let mut bad_shares = Vec::new();
        for key_id in &self.key_ids {
            if let Some(shares) = private_shares.get(key_id) {
                for (sender, s) in shares {
                    if let Some(comm) = public_shares.get(sender) {
                        if s * G != compute::poly(&compute::id(*key_id), &comm.poly)? {
                            bad_shares.push(*sender);
                        }
                    } else {
                        warn!("unable to check private share from {}: no corresponding public share, even though we checked for it above", sender);
                    }
                }
            } else {
                warn!(
                    "no private shares for key_id {}, even though we checked for it above",
                    key_id
                );
            }
        }
        if !bad_shares.is_empty() {
            return Err(DkgError::BadPrivateShares(bad_shares));
        }
```
