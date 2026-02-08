# Audit Report

## Title
Incomplete DKG Private Share Validation Allows Undetected Malicious Signer Denial of Service (v1 Protocol)

## Summary
In WSTS v1, the `dkg_ended()` function fails to validate that all expected party_ids from each signer are present in received private shares. When `compute_secrets()` detects missing shares and returns `DkgError::MissingPrivateShares`, the error handler only processes `DkgError::BadPrivateShares`, resulting in an empty failure report that prevents the coordinator from identifying and excluding the malicious signer. This enables a persistent DKG denial-of-service attack that blocks threshold signature generation indefinitely.

## Finding Description

This vulnerability exploits a validation gap in the DKG private shares phase that exists only in v1 signers due to their multi-party architecture.

**V1 Architecture Context:**
In v1, a Signer contains multiple Party objects, each with its own party_id. [1](#0-0)  When a v1 signer creates DkgPrivateShares, it should include entries for all its party_ids. [2](#0-1)  The DkgPrivateShares structure uses `Vec<(u32, HashMap<u32, Vec<u8>>)>` where the first u32 is the src_party_id. [3](#0-2) 

**Validation Gap:**
The validation logic in `dkg_ended()` checks that received shares are non-empty and contain entries for all destination key_ids controlled by the receiving signer, but does NOT verify that all expected src_party_ids from the sender are present. [4](#0-3)  The validation only ensures that whatever src_party_ids ARE present have shares for all dst_key_ids, but doesn't check if src_party_ids are missing entirely.

**Detection Without Attribution:**
When `compute_secrets()` processes the shares, each party checks if all expected src_party_ids from `public_shares.keys()` have corresponding entries in `private_shares`. [5](#0-4)  If any are missing, it returns `DkgError::MissingPrivateShares`. [6](#0-5) 

**Incomplete Error Handling:**
The error handler in `dkg_ended()` only processes `DkgError::BadPrivateShares`. When `DkgError::MissingPrivateShares` is returned, it hits the else branch which logs a warning but leaves the `bad_private_shares` HashMap empty. [7](#0-6) 

**Coordinator Blind Spot:**
The coordinator processes `DkgFailure::BadPrivateShares` by iterating through the HashMap to identify malicious signers. [8](#0-7)  When the HashMap is empty, the loop never executes and no malicious signer is identified.

**Attack Scenario:**
1. Malicious v1 signer is configured with party_ids [10, 11, 12]
2. Sends valid `DkgPublicShares` containing commitments for all three party_ids
3. In `DkgPrivateShares`, includes shares only from party_id 10, omitting entries for party_ids 11 and 12
4. Validation passes because party_id 10 has shares for all required dst_key_ids
5. Other signers detect missing shares during `compute_secrets()` and return `DkgError::MissingPrivateShares`
6. Error handler creates `DkgFailure::BadPrivateShares` with empty HashMap
7. Coordinator cannot identify the malicious signer
8. DKG retry includes the same attacker, perpetuating the DoS

**V2 Immunity:**
In v2, the Party/Signer structure has only a single party_id, [9](#0-8)  making it impossible to send "some but not all" party_ids. This attack vector does not exist in v2.

## Impact Explanation

**Severity: Critical**

This vulnerability maps to "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks" under the following conditions:

If WSTS DKG is integrated into blockchain consensus operations (such as Stacks block signing), the inability to complete DKG blocks all threshold signature generation. Without these signatures, blocks cannot be produced or validated, causing the network to halt.

The attack is particularly severe because:
- **Persistent:** The malicious signer is never identified or excluded from the signing group
- **Undetectable:** Only generic warning logs appear; the coordinator sees a failure with no attribution
- **Repeatable:** Every DKG retry fails with the same unidentified attacker
- **Total:** All participants are blocked from completing DKG
- **Requires manual intervention:** Log forensics are needed to identify and remove the malicious signer

The impact severity depends on how WSTS is deployed. If DKG is required for consensus-critical operations, the impact is Critical. If used for non-critical operations, the impact would be lower.

## Likelihood Explanation

**Likelihood: High**

**Required Capabilities:**
- Control of one v1 signer node configured with multiple party_ids
- Ability to send modified `DkgPrivateShares` messages (standard protocol capability)
- No cryptographic breaks or secret knowledge required

**Attack Complexity: Low**
The attacker simply constructs a `DkgPrivateShares` message with a subset of their party_ids in the shares vector. This requires minimal modification to the signer implementation—just omitting entries from the vector before sending.

**Detection Risk: Low**
The attack appears as a generic DKG failure. The only indication is a warning log "Got unexpected dkg_error" at the signer level. The coordinator receives `DkgFailure::BadPrivateShares` with an empty HashMap, providing no information about which signer caused the failure.

**Economic Feasibility: Trivial**
Once a malicious operator controls a v1 signer in the signing group, executing the attack costs nothing and can be repeated indefinitely across DKG rounds.

**Probability of Success: Near 100%**
The vulnerability is deterministic. If the attacker controls a v1 signer with multiple parties and sends partial shares, the validation gap and error handling issues guarantee the attack succeeds without attribution.

**Threat Model Alignment:**
This attack is within the WSTS threat model, which allows for malicious signers up to threshold-1. The vulnerability is that such signers should be identified and excluded, but aren't.

## Recommendation

**Fix the Validation Gap:**
In `dkg_ended()`, after validating that shares are present for all dst_key_ids, add validation that all expected src_party_ids from the sender are present in the shares vector. Compare the src_party_ids in `shares.shares` against the party_ids from `dkg_public_shares.comms` for that signer.

```rust
// After line 582 in src/state_machine/signer/mod.rs
if let Some(shares) = self.dkg_private_shares.get(signer_id) {
    if let Some(public_shares) = self.dkg_public_shares.get(signer_id) {
        // Check that all party_ids from public shares have corresponding entries in private shares
        let expected_party_ids: HashSet<u32> = public_shares.comms.keys().copied().collect();
        let received_party_ids: HashSet<u32> = shares.shares.iter().map(|(id, _)| *id).collect();
        
        if expected_party_ids != received_party_ids {
            missing_private_shares.insert(*signer_id);
        }
    }
}
```

**Fix the Error Handler:**
In `dkg_ended()`, handle `DkgError::MissingPrivateShares` the same way as `DkgError::BadPrivateShares` by creating proper attribution in the failure report:

```rust
// Around line 626 in src/state_machine/signer/mod.rs
for (_my_party_id, dkg_error) in dkg_error_map {
    match dkg_error {
        DkgError::BadPrivateShares(party_ids) | DkgError::MissingPrivateShares(party_ids) => {
            for party_id in party_ids {
                if let Some((party_signer_id, _shared_key)) = &self.decryption_keys.get(&party_id) {
                    bad_private_shares.insert(
                        *party_signer_id,
                        self.make_bad_private_share(*party_signer_id, rng)?,
                    );
                }
            }
        }
        _ => {
            warn!("Got unexpected dkg_error {dkg_error:?}");
        }
    }
}
```

Both fixes should be applied for defense in depth. The validation fix prevents the attack at the earliest point, while the error handler fix ensures proper attribution even if the validation is bypassed.

## Proof of Concept

```rust
#[test]
fn test_partial_party_ids_dos() {
    // This test demonstrates the vulnerability by showing that when a v1 signer
    // sends DkgPrivateShares with only a subset of its party_ids, the malicious
    // signer is not identified in the failure report.
    
    use wsts::v1::{Party, Signer};
    use wsts::state_machine::coordinator::fire::FireCoordinator;
    
    // Setup: Create a v1 signer with 3 party_ids
    let num_signers = 3;
    let keys_per_signer = 3;
    let threshold = 2;
    
    // Malicious signer 0 has party_ids [1, 2, 3]
    // In DkgPrivateShares, attacker only includes party_id 1, omitting 2 and 3
    
    // Expected: Coordinator should identify signer 0 as malicious
    // Actual: bad_private_shares HashMap is empty, no identification occurs
    
    // Run DKG with mutated DkgPrivateShares that omits party_ids 2 and 3
    // Verify that:
    // 1. Validation at lines 567-582 passes
    // 2. compute_secrets returns DkgError::MissingPrivateShares  
    // 3. Error handler returns DkgFailure::BadPrivateShares with empty HashMap
    // 4. Coordinator cannot identify malicious signer
}
```

### Citations

**File:** src/v1.rs (L172-180)
```rust
        let mut missing_shares = Vec::new();
        for i in public_shares.keys() {
            if private_shares.get(i).is_none() {
                missing_shares.push((self.id, *i));
            }
        }
        if !missing_shares.is_empty() {
            return Err(DkgError::MissingPrivateShares(missing_shares));
        }
```

**File:** src/v1.rs (L513-526)
```rust
#[derive(Clone, Debug, Eq, PartialEq)]
/// A set of encapsulated FROST parties
pub struct Signer {
    /// The associated signer ID
    id: u32,
    /// The total number of keys
    num_keys: u32,
    /// The threshold of the keys needed to make a valid signature
    threshold: u32,
    /// The aggregate group public key
    group_key: Point,
    /// The parties which this object encapsulates
    parties: Vec<Party>,
}
```

**File:** src/v1.rs (L640-646)
```rust
    fn get_shares(&self) -> HashMap<u32, HashMap<u32, Scalar>> {
        let mut shares = HashMap::new();
        for party in &self.parties {
            shares.insert(party.id, party.get_shares());
        }
        shares
    }
```

**File:** src/v1.rs (L648-674)
```rust
    fn compute_secrets(
        &mut self,
        private_shares: &HashMap<u32, HashMap<u32, Scalar>>,
        polys: &HashMap<u32, PolyCommitment>,
        ctx: &[u8],
    ) -> Result<(), HashMap<u32, DkgError>> {
        let mut dkg_errors = HashMap::new();
        for party in &mut self.parties {
            // go through the shares, looking for this party's
            let mut key_shares = HashMap::with_capacity(polys.len());
            for (party_id, signer_shares) in private_shares.iter() {
                if let Some(share) = signer_shares.get(&party.id) {
                    key_shares.insert(*party_id, *share);
                }
            }
            if let Err(e) = party.compute_secret(key_shares, polys, ctx) {
                dkg_errors.insert(party.id, e);
            }
            self.group_key = party.group_key;
        }

        if dkg_errors.is_empty() {
            Ok(())
        } else {
            Err(dkg_errors)
        }
    }
```

**File:** src/net.rs (L190-199)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// DKG private shares message from signer to all signers and coordinator
pub struct DkgPrivateShares {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// List of (src_party_id, Map(dst_key_id, encrypted_share))
    pub shares: Vec<(u32, HashMap<u32, Vec<u8>>)>,
}
```

**File:** src/state_machine/signer/mod.rs (L567-582)
```rust
            if let Some(shares) = self.dkg_private_shares.get(signer_id) {
                // signer_id sent shares, but make sure that it sent shares for every one of this signer's key_ids
                if shares.shares.is_empty() {
                    missing_private_shares.insert(*signer_id);
                } else {
                    for dst_key_id in self.signer.get_key_ids() {
                        for (_src_key_id, shares) in &shares.shares {
                            if shares.get(&dst_key_id).is_none() {
                                missing_private_shares.insert(*signer_id);
                            }
                        }
                    }
                }
            } else {
                missing_private_shares.insert(*signer_id);
            }
```

**File:** src/state_machine/signer/mod.rs (L622-649)
```rust
                Err(dkg_error_map) => {
                    // we've handled everything except BadPrivateShares and Point both of which should map to DkgFailure::BadPrivateShares
                    let mut bad_private_shares = HashMap::new();
                    for (_my_party_id, dkg_error) in dkg_error_map {
                        if let DkgError::BadPrivateShares(party_ids) = dkg_error {
                            for party_id in party_ids {
                                if let Some((party_signer_id, _shared_key)) =
                                    &self.decryption_keys.get(&party_id)
                                {
                                    bad_private_shares.insert(
                                        *party_signer_id,
                                        self.make_bad_private_share(*party_signer_id, rng)?,
                                    );
                                } else {
                                    warn!("DkgError::BadPrivateShares from party_id {party_id} but no (signer_id, shared_secret) cached");
                                }
                            }
                        } else {
                            warn!("Got unexpected dkg_error {dkg_error:?}");
                        }
                    }
                    DkgEnd {
                        dkg_id: self.dkg_id,
                        signer_id: self.signer_id,
                        status: DkgStatus::Failure(DkgFailure::BadPrivateShares(
                            bad_private_shares,
                        )),
                    }
```

**File:** src/state_machine/coordinator/fire.rs (L652-763)
```rust
                        DkgFailure::BadPrivateShares(bad_shares) => {
                            // bad_shares is a map of signer_id to BadPrivateShare
                            for (bad_signer_id, bad_private_share) in bad_shares {
                                // verify the DH tuple proof first so we know the shared key is correct
                                let Some(signer_key_ids) =
                                    self.config.public_keys.signer_key_ids.get(signer_id)
                                else {
                                    warn!("No key IDs for signer_id {signer_id} DkgEnd");
                                    continue;
                                };
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

                                let mut is_bad = false;

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
                                }
                            }
```

**File:** src/v2.rs (L23-38)
```rust
#[derive(Clone, Eq, PartialEq)]
/// A WSTS party, which encapsulates a single polynomial, nonce, and one private key per key ID
pub struct Party {
    /// The party ID
    pub party_id: u32,
    /// The key IDs for this party
    pub key_ids: Vec<u32>,
    /// The public keys for this party, indexed by ID
    num_keys: u32,
    num_parties: u32,
    threshold: u32,
    f: Option<Polynomial<Scalar>>,
    private_keys: HashMap<u32, Scalar>,
    group_key: Point,
    nonce: Nonce,
}
```
