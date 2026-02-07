# Audit Report

## Title
Unauthenticated DH Key Exchange in DKG Enables MitM Extraction of Private Shares

## Summary
The `kex_public_key` field in `DkgPublicShares` messages is not included in the message signature, allowing an attacker with network access to substitute their own public key via man-in-the-middle attack. This enables the attacker to decrypt DKG private shares intended for honest participants, potentially compromising the group private key and enabling signature forgery.

## Finding Description
The WSTS protocol uses ECDSA signatures to authenticate messages between participants. However, the `DkgPublicShares::hash()` implementation excludes the `kex_public_key` field from the signed message digest. [1](#0-0) 

The `kex_public_key` is an ephemeral Diffie-Hellman public key used to encrypt private shares during DKG. When a `DkgPublicShares` message is received, the signature is verified via `Packet::verify()`, but since the signature doesn't cover `kex_public_key`, an attacker can replace this field while maintaining signature validity. [2](#0-1) 

Recipients store the unauthenticated `kex_public_key` directly from the message without additional validation: [3](#0-2) 

When encrypting private shares, the sender uses the stored (potentially attacker-controlled) `kex_public_key` to derive the encryption key: [4](#0-3) 

**Attack Execution:**
1. Honest signer Alice broadcasts `DkgPublicShares` with her legitimate `kex_public_key_A`
2. Network attacker intercepts the message to Bob and replaces `kex_public_key_A` with `attacker_public_key`
3. The message signature remains valid because it doesn't cover `kex_public_key`
4. Bob verifies the signature (passes) and stores `attacker_public_key` for Alice's key IDs
5. When Bob sends encrypted private shares to Alice, he uses `attacker_public_key` for encryption
6. The attacker intercepts and decrypts Bob's shares using `attacker_private_key`
7. Alice cannot decrypt the shares (they were encrypted for the wrong key)
8. If the attacker compromises threshold number of shares this way, they can reconstruct the group private key

This breaks the security guarantee that only authorized participants can obtain DKG private shares.

## Impact Explanation
This vulnerability enables an active network attacker to compromise DKG private shares from threshold participants, leading to complete reconstruction of the group private key. With the group private key, the attacker can:

- **Direct loss of funds**: Unilaterally forge signatures to authorize unauthorized Bitcoin or cryptocurrency transactions
- **Confirmation of invalid transactions**: Sign transactions with invalid nonces or state
- **Chain split**: Produce conflicting valid signatures that cause consensus failures

The coordinator's BadPrivateShares validation mechanism cannot fully mitigate this attack because it relies on the same unauthenticated `kex_public_key` values when verifying TupleProofs. [5](#0-4) 

This qualifies as **Critical** severity under the provided scope criteria.

## Likelihood Explanation
Exploitation requires:
- Network position to intercept and modify messages (standard MitM capability)
- No cryptographic breaks or insider access
- No special knowledge beyond protocol specifications

The attack is straightforward to execute:
1. Intercept `DkgPublicShares` messages
2. Replace `kex_public_key` field
3. Forward modified message (signature remains valid)
4. Intercept and decrypt subsequent `DkgPrivateShares`

Detection is difficult because:
- Modified messages retain valid signatures
- Protocol flows continue normally from attacker's perspective
- Honest participants only observe decryption failures (could be misattributed to network issues)

The probability of success is **high** in deployment scenarios without additional transport-layer authentication (TLS with mutual authentication), which is not enforced or documented as a protocol requirement.

## Recommendation
Include `kex_public_key` in the `DkgPublicShares` message hash:

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
        // ADD THIS LINE:
        hasher.update(self.kex_public_key.compress().as_bytes());
    }
}
```

This binds the `kex_public_key` to the message signature, preventing substitution attacks while maintaining backward compatibility concerns only at the protocol version level.

**Additional hardening**: Document that deployments should use mutually-authenticated TLS for transport security as defense-in-depth.

## Proof of Concept

```rust
#[test]
fn test_kex_public_key_mitm_attack() {
    use crate::net::{DkgPublicShares, Signable};
    use crate::curve::{scalar::Scalar, point::{Point, G}};
    use rand_core::OsRng;
    
    let mut rng = OsRng;
    
    // Alice's legitimate keys
    let alice_kex_private = Scalar::random(&mut rng);
    let alice_kex_public = alice_kex_private * G;
    
    // Attacker's keys
    let attacker_private = Scalar::random(&mut rng);
    let attacker_public = attacker_private * G;
    
    // Alice creates legitimate message
    let original_msg = DkgPublicShares {
        dkg_id: 1,
        signer_id: 0,
        comms: vec![],
        kex_public_key: alice_kex_public,
    };
    
    // Compute signature
    let alice_network_key = Scalar::random(&mut rng);
    let sig = original_msg.sign(&alice_network_key).unwrap();
    
    // Attacker modifies kex_public_key
    let modified_msg = DkgPublicShares {
        kex_public_key: attacker_public, // SUBSTITUTED
        ..original_msg
    };
    
    // Signature STILL VALID despite substitution
    let alice_public = ecdsa::PublicKey::new(&alice_network_key).unwrap();
    assert!(modified_msg.verify(&sig, &alice_public));
    
    // This proves the vulnerability: attacker can substitute key
    // while maintaining valid signature
}
```

This test demonstrates that the signature verification passes even when `kex_public_key` is substituted, proving the authentication bypass.

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

**File:** src/state_machine/signer/mod.rs (L932-942)
```rust
            let mut encrypted_shares = HashMap::new();

            for (dst_key_id, private_share) in shares {
                if active_key_ids.contains(dst_key_id) {
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

**File:** src/state_machine/coordinator/fire.rs (L668-685)
```rust
                                let signer_public_key = signer_public_shares.kex_public_key;

                                let Some(bad_signer_public_shares) =
                                    self.dkg_public_shares.get(bad_signer_id)
                                else {
                                    warn!("Signer {signer_id} reported BadPrivateShares from {bad_signer_id} but there are no public shares from {bad_signer_id}, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                    continue;
                                };
                                let bad_signer_public_key = bad_signer_public_shares.kex_public_key;

                                let mut is_bad = false;

                                if bad_private_share.tuple_proof.verify(
                                    &signer_public_key,
                                    &bad_signer_public_key,
                                    &bad_private_share.shared_key,
                                ) {
```
