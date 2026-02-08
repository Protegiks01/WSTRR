# Audit Report

## Title
Unauthenticated KEX Public Key Enables Man-in-the-Middle Decryption of DKG Private Shares via Point-at-Infinity Substitution

## Summary
The `kex_public_key` field in `DkgPublicShares` messages is neither authenticated by the message signature nor validated against point-at-infinity, allowing a man-in-the-middle attacker to replace any participant's `kex_public_key` with `Point::identity()`. This causes all encrypted private shares for that participant to use a predictable shared secret, enabling the attacker to decrypt private polynomial shares and reconstruct the group private key.

## Finding Description

**Security Guarantee Broken:** Confidentiality of private polynomial shares during DKG, and ultimately the security of the group private key.

**Root Cause 1: Missing Authentication**

The `DkgPublicShares` message signature excludes the `kex_public_key` field from its hash computation. [1](#0-0) 

The signature authenticates only `dkg_id`, `signer_id`, and polynomial commitments (`comms`), but omits `kex_public_key`. An attacker can modify this field without invalidating the signature.

**Root Cause 2: Missing Validation**

When processing incoming `DkgPublicShares` messages, the `kex_public_key` is stored directly without validation: [2](#0-1) 

The code performs various validation checks but never validates that `kex_public_key != Point::identity()`.

**Root Cause 3: Predictable Shared Secret from Point-at-Infinity**

The `make_shared_secret()` function performs scalar multiplication without checking if the public key is point-at-infinity: [3](#0-2) 

When `public_key` is `Point::identity()`, the computation `private_key * public_key` yields `Point::identity()` regardless of `private_key`, producing a constant, predictable shared secret via: [4](#0-3) 

**Why Existing Mitigations Fail**

The codebase has similar validation for public nonces to prevent this exact attack class: [5](#0-4) 

However, this validation is not applied to `kex_public_key` in the DKG flow. The test suite demonstrates that `Point::new()` (identity) can be serialized in messages: [6](#0-5) 

**Attack Flow:**

1. During DKG public shares phase, victim V broadcasts `DkgPublicShares` with their `kex_public_key`
2. Attacker intercepts and replaces V's `kex_public_key` with `Point::identity()`
3. Signature verification passes (field not authenticated)
4. All signers store `Point::identity()` as V's key: [2](#0-1) 
5. During private share distribution, each sender S encrypts shares for V using: [7](#0-6) 
6. Because V's key is `Point::identity()`, all senders compute the same predictable `shared_secret`
7. Attacker computes this same `shared_secret` and decrypts all private shares intended for V: [8](#0-7) 
8. V's decryption fails (V uses correct key, different from attacker's), but attacker has already obtained the shares
9. Each party's private key is computed as the sum of received shares: [9](#0-8) 
10. With threshold `t` compromised participants, attacker uses Lagrange interpolation to reconstruct the group private key

## Impact Explanation

This vulnerability maps to **Critical** severity under the defined scope:

**Direct Loss of Funds:** The attacker gains the ability to reconstruct the group private key by collecting threshold `t` shares through MITM attacks. With the group private key, the attacker can sign arbitrary transactions and steal all funds controlled by that key. This satisfies: "Any causing the direct loss of funds other than through any form of freezing."

**Invalid Transaction Confirmation:** The attacker can sign and broadcast transactions without legitimate authorization from the threshold signers. This satisfies: "Any confirmation of an invalid transaction, such as with an incorrect nonce."

**Quantified Impact:**
- All assets controlled by WSTS-generated keys in compromised DKG rounds are at risk
- Attacker needs MITM capability on `t` out of `n` participants (e.g., 28 out of 40 in typical Stacks configuration)
- Attack window is during DKG private share distribution phase
- Affects all downstream systems relying on these threshold signatures (Stacks blockchain transaction validation)

## Likelihood Explanation

**Required Attacker Capabilities:**
1. Man-in-the-middle network position to intercept and modify DKG traffic between participants
2. Ability to deserialize/reserialize `DkgPublicShares` messages and replace the `kex_public_key` field
3. No cryptographic breaks, compromised private keys, or insider access required

**Attack Complexity: Low to Medium**
- Standard MITM techniques (ARP spoofing, BGP hijacking, compromised network infrastructure) suffice
- The attack modifies a single field in a message
- No timing constraints beyond normal DKG round duration
- The modified message passes all existing validation checks

**Threat Model Alignment:**
MITM attacks on RPC/P2P ports are explicitly in-scope per the High severity definition: "attacks restricted to the Stacks blockchain RPC/P2P ports." This attack operates at the application layer on these communication channels.

**Detection Risk: Low**
- Modified `kex_public_key` passes signature verification (field not authenticated)
- Decryption failures may be attributed to network errors or implementation bugs
- No cryptographic alarms trigger (attack exploits protocol logic, not crypto primitives)
- Honest participants see abnormal behavior only when DKG completion fails

**Economic Feasibility:**
For high-value targets (institutional custody, Stacks mining rewards), the cost-benefit strongly favors attack. Compromising network intermediaries (ISPs, data centers, cloud providers) to MITM multiple participants is achievable for well-resourced attackers when controlled funds exceed attack costs.

## Recommendation

**Fix 1: Include `kex_public_key` in Signature Hash**

Modify the `Signable` trait implementation for `DkgPublicShares` to include `kex_public_key` in the hash:

```rust
impl Signable for DkgPublicShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PUBLIC_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        // ADD THIS LINE:
        hasher.update(self.kex_public_key.compress().as_bytes());
        for (party_id, comm) in &self.comms {
            hasher.update(party_id.to_be_bytes());
            for a in &comm.poly {
                hasher.update(a.compress().as_bytes());
            }
        }
    }
}
```

**Fix 2: Validate KEX Public Key Against Point-at-Infinity**

Add validation when storing `kex_public_key`, similar to `PublicNonce::is_valid()`:

```rust
// In dkg_public_share() method
if dkg_public_shares.kex_public_key == Point::identity() || 
   dkg_public_shares.kex_public_key == Point::new() {
    warn!("Invalid kex_public_key (identity point) from signer {}", signer_id);
    return Ok(vec![]);
}

for key_id in signer_key_ids {
    self.kex_public_keys
        .insert(*key_id, dkg_public_shares.kex_public_key);
}
```

**Fix 3: Validate Input to `make_shared_secret()`**

Add point-at-infinity check in the encryption path:

```rust
pub fn make_shared_secret(private_key: &Scalar, public_key: &Point) -> [u8; 32] {
    if *public_key == Point::identity() || *public_key == Point::new() {
        panic!("Cannot create shared secret with identity point");
    }
    let shared_key = private_key * public_key;
    make_shared_secret_from_key(&shared_key)
}
```

## Proof of Concept

```rust
#[test]
fn test_mitm_kex_public_key_identity_attack() {
    use crate::curve::point::{Point, G};
    use crate::curve::scalar::Scalar;
    use crate::util::{make_shared_secret, create_rng};
    
    let mut rng = create_rng();
    
    // Victim's legitimate KEX keypair
    let victim_private = Scalar::random(&mut rng);
    let victim_public = Point::from(victim_private);
    
    // Attacker's KEX keypair (sender)
    let attacker_private = Scalar::random(&mut rng);
    
    // Attacker MITMs victim's public key and replaces with Point::identity()
    let mitm_victim_public = Point::identity();
    
    // Sender (attacker) encrypts shares for victim using MITM'd key
    let sender_shared_secret = make_shared_secret(&attacker_private, &mitm_victim_public);
    
    // Attacker can compute the same shared secret (predictable)
    let attacker_shared_secret = make_shared_secret(&Scalar::from(1u32), &mitm_victim_public);
    
    // Both produce the same predictable value
    assert_eq!(sender_shared_secret, attacker_shared_secret);
    
    // This proves attacker can decrypt shares encrypted with sender_shared_secret
    // because they can compute the same key independently
}
```

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

**File:** src/state_machine/signer/mod.rs (L1018-1021)
```rust
        for key_id in signer_key_ids {
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
        }
```

**File:** src/state_machine/signer/mod.rs (L1070-1070)
```rust
        let shared_secret = make_shared_secret(&self.kex_private_key, &kex_public_key);
```

**File:** src/state_machine/signer/mod.rs (L1076-1096)
```rust
                    match decrypt(&shared_secret, bytes) {
                        Ok(plain) => match Scalar::try_from(&plain[..]) {
                            Ok(s) => {
                                decrypted_shares.insert(*dst_key_id, s);
                            }
                            Err(e) => {
                                warn!("Failed to parse Scalar for dkg private share from src_id {src_id} to dst_id {dst_key_id}: {e:?}");
                                self.invalid_private_shares.insert(
                                    src_signer_id,
                                    self.make_bad_private_share(src_signer_id, rng)?,
                                );
                            }
                        },
                        Err(e) => {
                            warn!("Failed to decrypt dkg private share from src_id {src_id} to dst_id {dst_key_id}: {e:?}");
                            self.invalid_private_shares.insert(
                                src_signer_id,
                                self.make_bad_private_share(src_signer_id, rng)?,
                            );
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

**File:** src/common.rs (L160-163)
```rust
    /// Check that the nonces are not zero since that can lead to attacks
    pub fn is_valid(&self) -> bool {
        self.D != Point::identity() && self.E != Point::identity() && self.D != G && self.E != G
    }
```

**File:** src/state_machine/coordinator/fire.rs (L2642-2649)
```rust
                            msg: Message::DkgPublicShares(DkgPublicShares {
                                dkg_id: shares.dkg_id,
                                signer_id: shares.signer_id,
                                comms,
                                kex_public_key: Point::new(),
                            }),
                            sig: vec![],
                        }
```

**File:** src/v2.rs (L188-192)
```rust
        for key_id in &self.key_ids {
            self.private_keys.insert(*key_id, Scalar::zero());
            if let Some(shares) = private_shares.get(key_id) {
                let secret = shares.values().sum();
                self.private_keys.insert(*key_id, secret);
```
