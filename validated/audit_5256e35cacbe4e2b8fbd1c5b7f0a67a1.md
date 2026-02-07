# Audit Report

## Title
Man-in-the-Middle Attack on DKG Key Exchange Causes Denial of Service Through Unauthenticated kex_public_key Field

## Summary
The `kex_public_key` field in `DkgPublicShares` messages is excluded from the signed message hash, allowing network attackers with man-in-the-middle position to replace it with attacker-controlled public keys. This causes legitimate private share decryption to fail, triggers false accusations against honest signers, and ultimately causes DKG to abort with `Error::DkgFailure`. The vulnerability enables remotely-exploitable denial of service that prevents threshold key generation.

## Finding Description

The DKG protocol uses ephemeral Diffie-Hellman key exchange to encrypt private shares between participants. Each signer includes a `kex_public_key` in their `DkgPublicShares` message, which other participants use to compute shared secrets for encryption/decryption.

**Root Cause:**

The `DkgPublicShares::hash()` implementation only includes `dkg_id`, `signer_id`, and polynomial commitments in the signed digest, but omits the `kex_public_key` field. [1](#0-0) 

When signature verification occurs via `Signable::verify()`, it calls `self.hash()` which excludes `kex_public_key`, allowing this field to be modified without invalidating the signature. [2](#0-1) 

Packet verification is enforced by default and correctly validates signatures, but the signature doesn't cover all security-critical fields. [3](#0-2) 

**Attack Propagation:**

When a signer receives `DkgPublicShares`, it stores the (potentially manipulated) `kex_public_key` directly into its `kex_public_keys` HashMap without any cryptographic binding to the message signature. [4](#0-3) 

During the private shares phase, the victim signer retrieves this stored key and uses it to compute the shared secret for decryption. [5](#0-4) 

When decryption fails (because the honest sender used the legitimate key but the victim is using the manipulated key), the victim creates a `BadPrivateShare` report containing a tuple proof constructed with the manipulated key. [6](#0-5) [7](#0-6) 

The FIRE coordinator validates this report by retrieving the same manipulated `kex_public_key` from its stored `DkgPublicShares`, verifying the tuple proof (which passes because it was correctly constructed with the manipulated key), and attempting to decrypt the private shares using the manipulated shared secret. When decryption fails, the coordinator incorrectly identifies the honest sender as malicious. [8](#0-7) [9](#0-8) [10](#0-9) 

The coordinator returns `Error::DkgFailure`, aborting the DKG process. [11](#0-10) 

**Security Invariant Broken:**

DKG should succeed when all participating signers are honest and messages are authenticated via signatures. This vulnerability breaks that invariant by allowing authenticated messages to contain manipulated key exchange parameters.

## Impact Explanation

This vulnerability enables **remotely-exploitable denial of service** against the DKG protocol, mapping to **Low severity** under "Any remotely-exploitable denial of service in a node."

The attack prevents DKG from completing for the affected round, blocking threshold key generation. While this doesn't directly cause network shutdown or consensus failure, it prevents new threshold keys from being established, which could impact operations that depend on key rotation, validator set changes, or initial threshold key setup.

The attack is transient (each DKG round requires a new attack) but deterministic - given network MITM position, the attack succeeds with 100% probability. The coordinator's malicious signer detection actually makes the attack more effective by marking honest participants as malicious based on the false accusations.

## Likelihood Explanation

**Attacker Requirements:**
- Network man-in-the-middle position on P2P connections between DKG participants
- Ability to intercept and modify DkgPublicShares messages in transit
- Capability to generate valid secp256k1 key pairs (trivial computational requirement)
- No need for cryptographic breaks, key compromise, or insider access

**Attack Complexity:** Low

The attacker only needs to:
1. Intercept DkgPublicShares messages during the public shares phase
2. Deserialize the message structure
3. Replace the `kex_public_key` field with an attacker-generated public key
4. Forward the modified message

**Feasibility:** High for sophisticated attackers

MITM attacks on P2P networks are realistic through BGP hijacking, compromised network infrastructure, ARP spoofing, or malicious routing. The protocol's use of message signatures indicates it's designed to resist network attackers, but the incomplete signature coverage creates an exploitable gap.

**Detection Difficulty:** Very Low

The attack is transparent to all participants because signature verification passes. Only out-of-band verification of key exchange parameters or forensic analysis of DKG failures would reveal the manipulation.

## Recommendation

Include `kex_public_key` in the `DkgPublicShares::hash()` implementation:

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

This binds the key exchange public key to the message signature, preventing modification without detection.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up two honest signers (A and B) and a coordinator
2. Initiating DKG protocol
3. Intercepting Signer A's `DkgPublicShares` message
4. Replacing `kex_public_key` with a randomly generated public key
5. Forwarding the modified message to Signer B and Coordinator
6. Observing that signature verification passes
7. Observing that Signer B fails to decrypt A's private shares
8. Observing that Signer B generates `BadPrivateShare` accusation against A
9. Observing that Coordinator marks honest Signer A as malicious
10. Confirming DKG aborts with `Error::DkgFailure`

The attack succeeds because the signature in step 6 validates successfully despite the key modification, as `kex_public_key` is not part of the signed hash digest.

### Citations

**File:** src/net.rs (L33-45)
```rust
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

**File:** src/state_machine/signer/mod.rs (L1137-1147)
```rust
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

**File:** src/state_machine/coordinator/fire.rs (L668-677)
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
```

**File:** src/state_machine/coordinator/fire.rs (L681-747)
```rust
                                if bad_private_share.tuple_proof.verify(
                                    &signer_public_key,
                                    &bad_signer_public_key,
                                    &bad_private_share.shared_key,
                                ) {
                                    // verify at least one bad private share for one of signer_id's key_ids
                                    let shared_secret =
                                        make_shared_secret_from_key(&bad_private_share.shared_key);

                                    let polys = bad_signer_public_shares
                                        .comms
                                        .iter()
                                        .cloned()
                                        .collect::<HashMap<u32, PolyCommitment>>();
                                    let Some(dkg_private_shares) =
                                        self.dkg_private_shares.get(bad_signer_id)
                                    else {
                                        warn!("Signer {signer_id} reported BadPrivateShare from signer {bad_signer_id} who didn't send public shares, mark {signer_id} as malicious");
                                        malicious_signers.insert(*signer_id);
                                        continue;
                                    };

                                    for (src_party_id, key_shares) in &dkg_private_shares.shares {
                                        let Some(poly) = polys.get(src_party_id) else {
                                            warn!("Signer {signer_id} reported BadPrivateShares from {bad_signer_id} but the private shares from {bad_signer_id} dont have a polynomial for party {src_party_id}");
                                            continue;
                                        };
                                        for key_id in signer_key_ids {
                                            let Some(bytes) = key_shares.get(key_id) else {
                                                warn!("DkgPrivateShares from party_id {src_party_id} did not include a share for key_id {key_id}");
                                                continue;
                                            };
                                            match decrypt(&shared_secret, bytes) {
                                                Ok(plain) => match Scalar::try_from(&plain[..]) {
                                                    Ok(private_eval) => {
                                                        let poly_eval = match compute::poly(
                                                            &compute::id(*key_id),
                                                            &poly.poly,
                                                        ) {
                                                            Ok(p) => p,
                                                            Err(e) => {
                                                                warn!("Failed to evaluate public poly from signer_id {bad_signer_id} to key_id {key_id}: {e:?}");
                                                                is_bad = true;
                                                                break;
                                                            }
                                                        };

                                                        if private_eval * G != poly_eval {
                                                            warn!("Invalid dkg private share from signer_id {bad_signer_id} to key_id {key_id}");

                                                            is_bad = true;
                                                            break;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!("Failed to parse Scalar for dkg private share from signer_id {bad_signer_id} to key_id {key_id}: {e:?}");

                                                        is_bad = true;
                                                        break;
                                                    }
                                                },
                                                Err(e) => {
                                                    warn!("Failed to decrypt dkg private share from signer_id {bad_signer_id} to key_id {key_id}: {e:?}");
                                                    is_bad = true;
                                                    break;
                                                }
                                            }
```

**File:** src/state_machine/coordinator/fire.rs (L759-761)
```rust
                                } else {
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
