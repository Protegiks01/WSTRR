# Audit Report

## Title
Missing Point-at-Infinity Validation in DKG Key Exchange Enables Denial of Service

## Summary
The `make_shared_secret()` function does not validate whether the `public_key` parameter is the point at infinity (identity element), allowing malicious DKG participants to provide `Point::identity()` as their ephemeral key exchange public key. This produces a predictable shared secret that enables attackers to cause DKG round failures through encrypted share manipulation, resulting in denial of service.

## Finding Description

The vulnerability exists in the ECDH key exchange mechanism used during DKG Phase 2 for encrypting private polynomial shares. The `make_shared_secret()` function performs scalar multiplication without validating the public key: [1](#0-0) 

When `public_key` is `Point::identity()`, the multiplication `private_key * public_key` always yields `Point::identity()` regardless of the private key value, creating a predictable shared secret that any party can compute.

**Attack Flow:**

1. Malicious DKG participant broadcasts `DkgPublicShares` with `kex_public_key = Point::identity()`
2. The `kex_public_key` field is not included in the message integrity hash: [2](#0-1) 
3. Honest signers store this value without validation: [3](#0-2) 
4. Coordinator also stores it without validation: [4](#0-3) 
5. When honest signers receive `DkgPrivateShares`, they compute the shared secret using the identity point: [5](#0-4) 
6. The attacker knows this predictable shared secret and sends encrypted shares that fail decryption or VSS validation
7. Honest signers generate `BadPrivateShare` reports: [6](#0-5) 
8. Coordinator validates reports and marks attacker as malicious: [7](#0-6) 
9. DKG fails and must be restarted: [8](#0-7) 

**Evidence of Missing Validation:**

The codebase demonstrates awareness of this vulnerability class through explicit identity point validation in `PublicNonce`: [9](#0-8) 

However, this validation is absent for `kex_public_key` in the DKG flow.

## Impact Explanation

This vulnerability enables a remotely-exploitable denial of service attack against DKG rounds. A single malicious participant can force one DKG round to fail by:

- Causing all honest participants to generate `BadPrivateShare` complaints
- Forcing coordinator validation overhead to process and verify complaints
- Triggering DKG round restart and exclusion of the malicious party
- Creating delays in threshold signature generation

**Severity Justification:** This maps to **Low** severity per the defined scope: "Any remotely-exploitable denial of service in a node." The impact is limited to a single DKG round failure, as the malicious party is identified and excluded during the failure handling process. However, with multiple compromised signer identities or if attackers can re-join, repeated disruptions could impact more than 10% of miners attempting DKG participation.

## Likelihood Explanation

**High Likelihood** - The attack is trivial to execute and requires only:

1. **Attacker Capabilities:** Valid DKG participant with authorized `signer_id` (within threat model of up to threshold-1 malicious signers)
2. **Attack Complexity:** Trivial - simply construct and send `DkgPublicShares` with `kex_public_key = Point::identity()`
3. **No Cryptographic Breaks:** The p256k1 library supports serialization/deserialization of the identity point as a valid curve point
4. **Guaranteed Success:** The attack will succeed in causing at least one DKG round failure before detection and exclusion

**Detection:** The attack is highly detectable through `BadPrivateShare` reports that identify the malicious signer, but detection occurs after the DKG round has already failed.

## Recommendation

Add validation to reject `Point::identity()` as a key exchange public key, mirroring the validation pattern used for `PublicNonce`:

```rust
// In src/util.rs
pub fn make_shared_secret(private_key: &Scalar, public_key: &Point) -> Result<[u8; 32], EncryptionError> {
    // Reject identity point to prevent predictable shared secrets
    if *public_key == Point::identity() {
        return Err(EncryptionError::InvalidPublicKey);
    }
    
    let shared_key = private_key * public_key;
    Ok(make_shared_secret_from_key(&shared_key))
}
```

Additionally, add validation when storing `kex_public_key`:

```rust
// In src/state_machine/signer/mod.rs, dkg_public_share method
if dkg_public_shares.kex_public_key == Point::identity() {
    warn!(%signer_id, "Received invalid kex_public_key (identity point)");
    return Ok(vec![]);
}

for key_id in signer_key_ids {
    self.kex_public_keys
        .insert(*key_id, dkg_public_shares.kex_public_key);
}
```

Consider including `kex_public_key` in the `DkgPublicShares` message hash for signature integrity protection.

## Proof of Concept

```rust
#[test]
fn test_identity_point_causes_predictable_shared_secret() {
    use crate::curve::{point::Point, scalar::Scalar};
    use crate::util::make_shared_secret;
    
    let mut rng = util::create_rng();
    
    // Two different private keys
    let priv_key_1 = Scalar::random(&mut rng);
    let priv_key_2 = Scalar::random(&mut rng);
    
    // Both compute shared secret with Point::identity()
    let identity = Point::identity();
    let secret_1 = make_shared_secret(&priv_key_1, &identity);
    let secret_2 = make_shared_secret(&priv_key_2, &identity);
    
    // Secrets are identical despite different private keys - vulnerability confirmed
    assert_eq!(secret_1, secret_2, "Shared secrets should be predictable with identity point");
    
    // The shared secret is just the encoding of Point::identity()
    let expected_secret = make_shared_secret_from_key(&identity);
    assert_eq!(secret_1, expected_secret);
}
```

This test demonstrates that any participant can compute the same shared secret when `Point::identity()` is used, enabling the denial of service attack described above.

### Citations

**File:** src/util.rs (L48-52)
```rust
pub fn make_shared_secret(private_key: &Scalar, public_key: &Point) -> [u8; 32] {
    let shared_key = private_key * public_key;

    make_shared_secret_from_key(&shared_key)
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

**File:** src/state_machine/signer/mod.rs (L1089-1094)
```rust
                        Err(e) => {
                            warn!("Failed to decrypt dkg private share from src_id {src_id} to dst_id {dst_key_id}: {e:?}");
                            self.invalid_private_shares.insert(
                                src_signer_id,
                                self.make_bad_private_share(src_signer_id, rng)?,
                            );
```

**File:** src/state_machine/coordinator/fire.rs (L505-506)
```rust
            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L681-685)
```rust
                                if bad_private_share.tuple_proof.verify(
                                    &signer_public_key,
                                    &bad_signer_public_key,
                                    &bad_private_share.shared_key,
                                ) {
```

**File:** src/state_machine/coordinator/fire.rs (L785-788)
```rust
                return Err(Error::DkgFailure {
                    reported_failures,
                    malicious_signers,
                });
```

**File:** src/common.rs (L161-163)
```rust
    pub fn is_valid(&self) -> bool {
        self.D != Point::identity() && self.E != Point::identity() && self.D != G && self.E != G
    }
```
