# Audit Report

## Title
Incomplete Private Share Validation Allows DKG Denial of Service with Accountability Evasion

## Summary
The `dkg_ended()` method in the Signer state machine fails to validate that all party IDs declared in a signer's `DkgPublicShares` are present in their `DkgPrivateShares`. When `compute_secrets()` detects missing shares and returns `DkgError::MissingPrivateShares`, the error handling only processes `DkgError::BadPrivateShares`, resulting in no accountability information. This allows a malicious signer to repeatedly cause DKG failures without being identified or excluded.

## Finding Description

The vulnerability exists in two parts:

**1. Missing Validation Logic**

During DKG, each signer declares their party IDs in `DkgPublicShares.comms` which are stored in `self.commitments`. [1](#0-0) 

However, the validation logic that checks `DkgPrivateShares` only iterates over the party IDs that ARE present in `shares.shares` and validates their completeness per destination key. [2](#0-1) 

This validation never checks that the set of `src_party_id` values in `DkgPrivateShares.shares` matches the complete set of party IDs declared in `DkgPublicShares.comms`. A malicious signer can declare party IDs [1, 2, 3] in their public shares but only send private shares for [1, 2], and this validation will pass.

**2. Inadequate Error Handling**

When `compute_secrets()` is called, it properly detects missing party IDs by iterating over all party IDs in the commitments (public shares) and checking if corresponding private shares exist. [3](#0-2) [4](#0-3) 

When missing shares are detected, `compute_secret()` returns `DkgError::MissingPrivateShares`. [5](#0-4) 

However, the error handling in `dkg_ended()` only processes `DkgError::BadPrivateShares`. When `MissingPrivateShares` is returned, it falls into the else branch which merely logs a warning without populating the `bad_private_shares` HashMap. [6](#0-5) 

This results in `DkgFailure::BadPrivateShares({})` with an empty accountability map, providing no forensic information about which signer caused the failure.

**Attack Execution:**

1. Malicious signer sends `DkgPublicShares` with `comms: Vec<(u32, PolyCommitment)>` declaring party IDs [1, 2, 3]
2. These commitments pass validation and are stored in `self.commitments`
3. Malicious signer sends `DkgPrivateShares` with `shares: Vec<(u32, HashMap<u32, Vec<u8>>)>` containing only party IDs [1, 2], omitting party 3
4. The `dkg_private_shares()` handler accepts this, only validating party_id ownership, not completeness [7](#0-6) 
5. The validation at lines 567-582 passes because it only checks the shares that ARE present
6. `compute_secrets()` detects missing party 3 and returns `DkgError::MissingPrivateShares`
7. Error handling fails to attribute fault, returning empty accountability map
8. DKG fails with no way to identify the malicious signer

## Impact Explanation

**Severity: Low** - "Any remotely-exploitable denial of service in a node"

This vulnerability enables persistent denial of service against DKG initialization:

- **DKG Failure Rate:** 100% when attacked - missing shares cause `compute_secret()` to fail deterministically
- **Scope of Impact:** All signers participating in the DKG are affected, as DKG requires successful completion by all honest participants
- **Persistence:** The attacker is not identified in the `DkgEnd` message, preventing automatic exclusion mechanisms from working
- **Recovery:** Requires manual intervention to identify and exclude the malicious signer through out-of-band analysis of message patterns

In WSTS-based threshold signature systems, DKG is a prerequisite for all signing operations. Blocking DKG completion prevents establishment of the threshold signing group, which in systems like Stacks/sBTC would block peg-in/peg-out operations and multi-signature transaction capabilities. While this does not cause direct fund loss, it constitutes a critical availability attack on the signing infrastructure.

## Likelihood Explanation

**Likelihood: High**

- **Attacker Capabilities:** Must be a designated signer in the DKG protocol - no additional privileges required beyond normal participation
- **Attack Complexity:** Trivial - the attacker constructs `DkgPrivateShares` with a subset of their declared party IDs (omitting one or more)
- **Detection Difficulty:** High - the empty `bad_private_shares` map provides no forensic information about which signer caused the failure
- **Economic Cost:** Negligible - requires only normal DKG participation rights
- **Success Rate:** Near 100% - the validation bypass is deterministic and the error handling consistently fails to attribute fault

The threat model explicitly allows for malicious signers up to threshold-1, making this attack realistic within the protocol's security assumptions.

## Recommendation

**Fix 1: Add validation in `dkg_ended()` to ensure completeness of private shares**

Before calling `compute_secrets()`, validate that for each signer, the set of party IDs in their `DkgPrivateShares.shares` matches the set of party IDs in their `DkgPublicShares.comms`:

```rust
// After line 566, add validation that all party_ids from comms are present in shares
if let Some(public_shares) = self.dkg_public_shares.get(signer_id) {
    if let Some(private_shares) = self.dkg_private_shares.get(signer_id) {
        let public_party_ids: HashSet<u32> = public_shares.comms.iter()
            .map(|(party_id, _)| *party_id)
            .collect();
        let private_party_ids: HashSet<u32> = private_shares.shares.iter()
            .map(|(party_id, _)| *party_id)
            .collect();
        
        if public_party_ids != private_party_ids {
            missing_private_shares.insert(*signer_id);
        }
    }
}
```

**Fix 2: Handle `DkgError::MissingPrivateShares` in error processing**

Modify the error handling at lines 622-650 to also process `MissingPrivateShares` errors:

```rust
for (_my_party_id, dkg_error) in dkg_error_map {
    match dkg_error {
        DkgError::BadPrivateShares(party_ids) | DkgError::MissingPrivateShares(party_ids_tuples) => {
            // Extract party_ids and create accountability proofs
            let party_ids = match dkg_error {
                DkgError::BadPrivateShares(ids) => ids,
                DkgError::MissingPrivateShares(tuples) => {
                    tuples.iter().map(|(_, party_id)| *party_id).collect()
                }
                _ => vec![]
            };
            
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

## Proof of Concept

```rust
#[test]
fn test_missing_party_ids_in_private_shares() {
    use crate::v2::Signer as V2Signer;
    
    let mut rng = create_rng();
    let num_signers = 3;
    let num_keys = 3;
    let threshold = 2;
    
    // Create signer state machine
    let mut signer = Signer::<V2Signer>::new(
        threshold,
        1, // signer_id
        num_signers,
        num_keys,
        1, // dkg_id
        vec![1], // key_ids
        Default::default(),
        Default::default(),
        &mut rng,
    ).unwrap();
    
    // Simulate malicious signer 2 sending DkgPublicShares with 3 party IDs
    let malicious_public_shares = DkgPublicShares {
        dkg_id: 1,
        signer_id: 2,
        comms: vec![
            (1, create_dummy_commitment()),
            (2, create_dummy_commitment()),
            (3, create_dummy_commitment()), // Declares party 3
        ],
        kex_public_key: Point::generator(),
    };
    
    // But DkgPrivateShares only includes party IDs 1 and 2 (missing 3)
    let malicious_private_shares = DkgPrivateShares {
        dkg_id: 1,
        signer_id: 2,
        shares: vec![
            (1, create_dummy_encrypted_shares()),
            (2, create_dummy_encrypted_shares()),
            // Party 3 OMITTED
        ],
    };
    
    // Process messages
    signer.dkg_public_shares(&malicious_public_shares);
    signer.dkg_private_shares(&malicious_private_shares, &mut rng);
    
    // Trigger DKG end - should fail but with empty accountability
    let dkg_end_begin = create_dkg_end_begin();
    let result = signer.dkg_ended(&dkg_end_begin, &mut rng).unwrap();
    
    // Verify DKG fails
    if let Message::DkgEnd(dkg_end) = result {
        match dkg_end.status {
            DkgStatus::Failure(DkgFailure::BadPrivateShares(bad_shares)) => {
                // VULNERABILITY: bad_shares should contain signer 2, but is empty
                assert!(bad_shares.is_empty(), "Accountability evasion: attacker not identified");
            }
            _ => panic!("Expected BadPrivateShares failure"),
        }
    }
}
```

### Citations

**File:** src/state_machine/signer/mod.rs (L556-562)
```rust
                    for (party_id, comm) in shares.comms.iter() {
                        if !check_public_shares(comm, threshold, &self.dkg_id.to_be_bytes()) {
                            bad_public_shares.insert(*signer_id);
                        } else {
                            self.commitments.insert(*party_id, comm.clone());
                        }
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

**File:** src/state_machine/signer/mod.rs (L622-650)
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
                }
```

**File:** src/state_machine/signer/mod.rs (L1047-1056)
```rust
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
```

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

**File:** src/v2.rs (L146-163)
```rust
        let mut missing_shares = Vec::new();
        for dst_key_id in &self.key_ids {
            for src_key_id in public_shares.keys() {
                match private_shares.get(dst_key_id) {
                    Some(shares) => {
                        if shares.get(src_key_id).is_none() {
                            missing_shares.push((*dst_key_id, *src_key_id));
                        }
                    }
                    None => {
                        missing_shares.push((*dst_key_id, *src_key_id));
                    }
                }
            }
        }
        if !missing_shares.is_empty() {
            return Err(DkgError::MissingPrivateShares(missing_shares));
        }
```

**File:** src/errors.rs (L15-17)
```rust
    #[error("missing private shares for/from {0:?}")]
    /// The private shares which were missing
    MissingPrivateShares(Vec<(u32, u32)>),
```
