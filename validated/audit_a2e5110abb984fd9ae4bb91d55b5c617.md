# Audit Report

## Title
Man-in-the-Middle Attack on DKG Key Exchange Causes Denial of Service Through Unauthenticated kex_public_key Field

## Summary
The `kex_public_key` field in `DkgPublicShares` messages is excluded from the signed message hash, allowing network attackers with man-in-the-middle capability to replace it with attacker-controlled public keys. This causes legitimate private share decryption to fail, triggers false accusations against honest signers, and ultimately causes DKG to abort with `Error::DkgFailure`.

## Finding Description

The DKG protocol uses ephemeral Diffie-Hellman key exchange to encrypt private shares between participants. The protocol explicitly uses digital signatures to authenticate all DKG messages against network adversaries, as documented in the codebase.

**Root Cause - Incomplete Signature Coverage:**

The `DkgPublicShares` struct contains a security-critical `kex_public_key` field used for encrypting private shares. [1](#0-0)  However, the `hash()` implementation that generates the digest for signature verification only includes `dkg_id`, `signer_id`, and polynomial commitments, completely omitting the `kex_public_key` field. [2](#0-1) 

When signature verification occurs via the `Signable::verify()` method, it computes the hash by calling `self.hash()`, which excludes `kex_public_key`. [3](#0-2)  This allows an attacker to modify the `kex_public_key` field without invalidating the ECDSA signature.

Packet verification is enforced by default in production configurations through the `verify_packet_sigs` flag. [4](#0-3)  The coordinator's `process_message()` method correctly checks packet signatures. [5](#0-4)  However, because `kex_public_key` is not in the signed hash, these security checks do not protect against manipulation of this field.

**Attack Propagation:**

When a signer processes an incoming `DkgPublicShares` message, it stores the (potentially manipulated) `kex_public_key` directly into its `kex_public_keys` HashMap without any cryptographic binding to the verified signature. [6](#0-5) 

During the private shares phase, the victim signer retrieves this stored key and uses it to compute the shared secret for decryption. [7](#0-6)  When decryption fails (because the honest sender encrypted with their legitimate key but the victim is using the manipulated key), the victim creates a `BadPrivateShare` report. [8](#0-7) 

The `make_bad_private_share()` method constructs a Chaum-Pedersen tuple proof using the manipulated key retrieved from storage. [9](#0-8) 

The FIRE coordinator validates this report by retrieving the same manipulated `kex_public_key` from its stored `DkgPublicShares` messages. [10](#0-9)  The coordinator verifies the tuple proof (which passes because both parties are using the same manipulated key) and attempts to decrypt the private shares using the manipulated shared secret. [11](#0-10)  When decryption fails, the coordinator incorrectly marks the honest sender as malicious. [12](#0-11) 

The coordinator then returns `Error::DkgFailure`, aborting the DKG process. [13](#0-12) 

**Security Invariant Broken:**

DKG should succeed when all participating signers are honest and messages are authenticated via signatures. The protocol explicitly uses packet signatures to authenticate messages against network adversaries, but this authentication is incomplete because it doesn't cover the `kex_public_key` field that is critical for the confidentiality guarantee of private share encryption.

## Impact Explanation

This vulnerability enables remotely-exploitable denial of service against the DKG protocol, mapping to **Low severity** under "Any remotely-exploitable denial of service in a node."

The attack prevents DKG from completing for the affected round, blocking threshold key generation. While this doesn't directly cause network shutdown or consensus failure, it prevents new threshold keys from being established, which impacts operations requiring key rotation, validator set changes, or initial threshold key setup.

The attack is deterministic - given a network MITM position, it succeeds with 100% probability. The coordinator's malicious signer detection mechanism amplifies the attack by marking honest participants as malicious based on cryptographically-valid but misleading proofs.

## Likelihood Explanation

**Threat Model Alignment:** The protocol's use of digital signatures for message authentication proves that network adversaries with message interception/modification capability are within the threat model. The vulnerability is not about defeating the signature mechanism, but about its incomplete coverage of security-critical fields.

**Attack Requirements:**
- Network MITM position on P2P connections during DKG
- Ability to intercept and modify `DkgPublicShares` messages
- Capability to generate valid secp256k1 key pairs (computationally trivial)

**Attack Complexity:** Low. The attacker only needs to deserialize messages, replace the `kex_public_key` field, and forward them.

**Detection Difficulty:** Very Low. Signature verification passes, making the attack transparent to all participants. Only out-of-band verification of key exchange parameters would reveal the manipulation.

## Recommendation

Include the `kex_public_key` field in the `DkgPublicShares::hash()` implementation to ensure it is authenticated by the signature:

```rust
impl Signable for DkgPublicShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PUBLIC_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        // Add kex_public_key to signed hash
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

This ensures that any modification to the `kex_public_key` field will invalidate the signature, preventing the MITM attack.

## Proof of Concept

```rust
#[test]
fn test_kex_public_key_not_authenticated() {
    use crate::curve::point::Point;
    use crate::net::{DkgPublicShares, Signable};
    use crate::common::PolyCommitment;
    use sha2::{Digest, Sha256};
    
    // Create a DkgPublicShares message
    let original_key = Point::generator();
    let manipulated_key = Point::generator() * Scalar::from(42);
    
    let msg1 = DkgPublicShares {
        dkg_id: 1,
        signer_id: 1,
        comms: vec![],
        kex_public_key: original_key,
    };
    
    let msg2 = DkgPublicShares {
        dkg_id: 1,
        signer_id: 1,
        comms: vec![],
        kex_public_key: manipulated_key,
    };
    
    // Compute hashes
    let mut hasher1 = Sha256::new();
    msg1.hash(&mut hasher1);
    let hash1 = hasher1.finalize();
    
    let mut hasher2 = Sha256::new();
    msg2.hash(&mut hasher2);
    let hash2 = hasher2.finalize();
    
    // Vulnerability: hashes are identical despite different kex_public_key
    assert_eq!(hash1, hash2, "Hash should differ when kex_public_key differs");
}
```

This test demonstrates that two `DkgPublicShares` messages with different `kex_public_key` values produce identical hashes, proving the field is not authenticated by the signature mechanism.

### Citations

**File:** src/net.rs (L32-45)
```rust
    /// Verify a hash of this object using the passed public key
    fn verify(&self, signature: &[u8], public_key: &ecdsa::PublicKey) -> bool {
        let mut hasher = Sha256::new();

        self.hash(&mut hasher);

        let hash = hasher.finalize();
        let sig = match ecdsa::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        sig.verify(hash.as_slice(), public_key)
    }
```

**File:** src/net.rs (L141-150)
```rust
pub struct DkgPublicShares {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// List of (party_id, commitment)
    pub comms: Vec<(u32, PolyCommitment)>,
    /// Ephemeral public key for key exchange
    pub kex_public_key: Point,
}
```

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

**File:** src/state_machine/coordinator/mod.rs (L186-199)
```rust
        Config {
            num_signers,
            num_keys,
            threshold,
            dkg_threshold: num_keys,
            message_private_key,
            dkg_public_timeout: None,
            dkg_private_timeout: None,
            dkg_end_timeout: None,
            nonce_timeout: None,
            sign_timeout: None,
            public_keys: Default::default(),
            verify_packet_sigs: true,
        }
```

**File:** src/state_machine/coordinator/fire.rs (L218-225)
```rust
        if self.config.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.config.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
        }
```

**File:** src/state_machine/coordinator/fire.rs (L662-678)
```rust
                                let Some(signer_public_shares) =
                                    self.dkg_public_shares.get(signer_id)
                                else {
                                    warn!("Signer {signer_id} reported BadPrivateShares from {bad_signer_id} but there are no public shares from {signer_id}");
                                    continue;
                                };
                                let signer_public_key = signer_public_shares.kex_public_key;

                                let Some(bad_signer_public_shares) =
                                    self.dkg_public_shares.get(bad_signer_id)
                                else {
                                    warn!("Signer {signer_id} reported BadPrivateShares from {bad_signer_id} but there are no public shares from {bad_signer_id}, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                    continue;
                                };
                                let bad_signer_public_key = bad_signer_public_shares.kex_public_key;

```

**File:** src/state_machine/coordinator/fire.rs (L681-688)
```rust
                                if bad_private_share.tuple_proof.verify(
                                    &signer_public_key,
                                    &bad_signer_public_key,
                                    &bad_private_share.shared_key,
                                ) {
                                    // verify at least one bad private share for one of signer_id's key_ids
                                    let shared_secret =
                                        make_shared_secret_from_key(&bad_private_share.shared_key);
```

**File:** src/state_machine/coordinator/fire.rs (L742-761)
```rust
                                                Err(e) => {
                                                    warn!("Failed to decrypt dkg private share from signer_id {bad_signer_id} to key_id {key_id}: {e:?}");
                                                    is_bad = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    warn!("TupleProof failed to verify, mark {signer_id} as malicious");
                                    is_bad = false;
                                }

                                // if tuple proof failed or none of the shares were bad sender was malicious
                                if !is_bad {
                                    warn!("Signer {signer_id} reported BadPrivateShare from {bad_signer_id} but the shares were valid, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                } else {
                                    warn!("Signer {signer_id} reported BadPrivateShare from {bad_signer_id}, mark {bad_signer_id} as malicious");
                                    malicious_signers.insert(*bad_signer_id);
```

**File:** src/state_machine/coordinator/fire.rs (L779-788)
```rust
            if reported_failures.is_empty() {
                debug!("no dkg failures");
                self.dkg_end_gathered()?;
            } else {
                // TODO: see if we have sufficient non-malicious signers to continue
                warn!("got dkg failures");
                return Err(Error::DkgFailure {
                    reported_failures,
                    malicious_signers,
                });
```

**File:** src/state_machine/signer/mod.rs (L1018-1021)
```rust
        for key_id in signer_key_ids {
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
        }
```

**File:** src/state_machine/signer/mod.rs (L1043-1070)
```rust
        let Ok(kex_public_key) = self.get_kex_public_key(src_signer_id) else {
            return Ok(vec![]);
        };

        for (party_id, _shares) in &dkg_private_shares.shares {
            if !SignerType::validate_party_id(
                src_signer_id,
                *party_id,
                &self.public_keys.signer_key_ids,
            ) {
                warn!("Signer {src_signer_id} sent a polynomial commitment for party {party_id}");
                return Ok(vec![]);
            }
        }

        if self.dkg_private_shares.contains_key(&src_signer_id) {
            info!(signer_id = %dkg_private_shares.signer_id, "received duplicate DkgPrivateShares");
            return Ok(vec![]);
        }

        self.dkg_private_shares
            .insert(src_signer_id, dkg_private_shares.clone());

        // make a HashSet of our key_ids so we can quickly query them
        let key_ids: HashSet<u32> = self.signer.get_key_ids().into_iter().collect();

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

**File:** src/state_machine/signer/mod.rs (L1132-1147)
```rust
    fn make_bad_private_share<R: RngCore + CryptoRng>(
        &self,
        signer_id: u32,
        rng: &mut R,
    ) -> Result<BadPrivateShare, Error> {
        let a = self.kex_private_key;
        let A = a * G;
        let B = self.get_kex_public_key(signer_id)?;
        let K = a * B;
        let tuple_proof = TupleProof::new(&a, &A, &B, &K, rng);

        Ok(BadPrivateShare {
            shared_key: K,
            tuple_proof,
        })
    }
```
