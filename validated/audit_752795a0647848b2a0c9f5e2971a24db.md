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

However, this validation is absent for `kex_public_key` in the DKG flow. No validation exists at message reception in either the signer or coordinator state machines.

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

Add validation to reject `Point::identity()` as a `kex_public_key` value, similar to the existing validation for `PublicNonce`. The validation should be added at the point where `DkgPublicShares` messages are received:

**In `src/state_machine/signer/mod.rs` (around line 1020):**
```rust
// Validate kex_public_key is not identity point
if dkg_public_shares.kex_public_key == Point::identity() {
    warn!(%signer_id, "Invalid kex_public_key: identity point");
    return Ok(vec![]);
}

for key_id in signer_key_ids {
    self.kex_public_keys
        .insert(*key_id, dkg_public_shares.kex_public_key);
}
```

**In `src/state_machine/coordinator/fire.rs` (around line 505):**
```rust
// Validate kex_public_key is not identity point
if dkg_public_shares.kex_public_key == Point::identity() {
    warn!(signer_id = %dkg_public_shares.signer_id, "Invalid kex_public_key: identity point");
    return Ok(());
}

self.dkg_public_shares
    .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
```

Additionally, consider including `kex_public_key` in the `DkgPublicShares` message hash to provide integrity protection.

## Proof of Concept

```rust
#[test]
fn test_identity_kex_public_key_dos() {
    use crate::curve::point::Point;
    use crate::net::DkgPublicShares;
    use crate::util::make_shared_secret;
    use crate::curve::scalar::Scalar;
    use rand_core::OsRng;
    
    // Attacker sends identity point as kex_public_key
    let malicious_kex_public_key = Point::identity();
    
    // Honest signer has a valid private key
    let honest_private_key = Scalar::random(&mut OsRng);
    
    // Compute shared secret using the identity point
    let shared_secret1 = make_shared_secret(&honest_private_key, &malicious_kex_public_key);
    
    // Use a different honest private key
    let another_private_key = Scalar::random(&mut OsRng);
    let shared_secret2 = make_shared_secret(&another_private_key, &malicious_kex_public_key);
    
    // Both shared secrets are identical and predictable
    assert_eq!(shared_secret1, shared_secret2, "Shared secrets should be identical when using identity point");
    
    // The attacker can compute the same shared secret
    let attacker_known_secret = make_shared_secret(&Scalar::from(1u64), &malicious_kex_public_key);
    assert_eq!(shared_secret1, attacker_known_secret, "Attacker can compute the same shared secret");
}
```

## Notes

This vulnerability represents a missing input validation that allows a malicious participant to cause predictable cryptographic state. While the attack is detected and the malicious party is excluded, the DKG round must be restarted, constituting a denial of service. The severity is appropriately assessed as Low because the impact is limited to a single round failure with automatic malicious party identification and exclusion.

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

**File:** src/state_machine/signer/mod.rs (L1019-1020)
```rust
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
```

**File:** src/state_machine/signer/mod.rs (L1070-1070)
```rust
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

**File:** src/state_machine/coordinator/fire.rs (L760-761)
```rust
                                    warn!("Signer {signer_id} reported BadPrivateShare from {bad_signer_id}, mark {bad_signer_id} as malicious");
                                    malicious_signers.insert(*bad_signer_id);
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
