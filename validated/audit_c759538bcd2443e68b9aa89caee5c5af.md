# Audit Report

## Title
Unvalidated Private Shares Corruption in DKG Secret Computation

## Summary
The `Party::compute_secret()` function in both v1 and v2 implementations sums ALL private shares into the private key without validating shares that lack corresponding public polynomial commitments. A malicious signer can inject arbitrary unvalidated scalar values into victims' private keys by selectively sending `DkgPrivateShares` messages while being excluded from the final DKG participant set, causing all subsequent signatures to fail verification.

## Finding Description

**Core Vulnerability:**

The DKG protocol requires that private shares be validated against public polynomial commitments before being incorporated into the final secret key. However, `compute_secret()` in both implementations has an asymmetric validation flaw.

In v2, the function correctly validates that all public shares have corresponding private shares (forward direction validation) [1](#0-0) , but fails to validate the reverse direction. The validation loop only checks private shares that have corresponding public commitments [2](#0-1) . When a private share has no corresponding public commitment, it merely logs a warning and continues [3](#0-2) .

Critically, the final private key computation sums ALL values from `private_shares` using `shares.values().sum()` [4](#0-3) , which includes these unvalidated shares. The same vulnerability exists in v1 [5](#0-4) .

**Why State Machine Protections Fail:**

The state machine's `dkg_ended` method builds `self.commitments` only from signers in the coordinator's `DkgEndBegin.signer_ids` list [6](#0-5) . However, `self.decrypted_shares` is populated independently by the `dkg_private_shares` handler, which accepts and decrypts shares from any configured signer [7](#0-6)  without verifying they will be in the final participant set.

The coordinator determines the final participant list based on who sent messages to the coordinator [8](#0-7) . A malicious signer can exploit this by selectively broadcasting `DkgPrivateShares` to victim signers while omitting the coordinator, or being excluded for other reasons (e.g., late message arrival, failed public share validation).

**Attack Execution:**

1. Malicious Signer A broadcasts `DkgPrivateShares` to victim signers
2. Victims receive and decrypt A's shares, storing them in `self.decrypted_shares[A.party_id]` [9](#0-8) 
3. Coordinator doesn't receive A's messages (selective sending/network partition/timing)
4. Coordinator creates `DkgEndBegin` without A in `signer_ids`
5. Victims build `self.commitments` only from `signer_ids`, excluding A [10](#0-9) 
6. `compute_secrets` is called with mismatched inputs [11](#0-10) 
7. A's unvalidated shares are summed into victims' private keys [12](#0-11) 

The DKG appears to succeed (returns `Ok(())`), but produces corrupted keys where `private_key * G ≠ group_key`.

## Impact Explanation

**Cryptographic Invariant Violation:**

The fundamental DKG security property is: `Σ(private_keys) * G = group_public_key`. This vulnerability breaks that invariant because:
- `group_key` is computed correctly from validated public commitments only
- `private_key` includes arbitrary attacker-controlled scalars
- `private_key * G ≠ group_key`

**Concrete Harms:**

1. **Signature Verification Failures:** All signatures produced with the corrupted keys will fail verification, as they won't match the group public key
2. **Silent DKG Failure:** The DKG protocol completes successfully, making the corruption undetectable until signing fails
3. **Consensus Impact:** If different nodes receive different sets of malicious shares (due to selective sending), they will have different corrupted keys and produce incompatible signatures for the same message, leading to consensus failures
4. **Network-Wide DoS:** An attacker with minimal resources can render an entire DKG round unusable, forcing re-execution

**Severity Justification:**

This maps to **Medium** severity under "Any transient consensus failures" as corrupted DKG keys prevent valid signature creation. It escalates to **High** severity ("Any chain split caused by different nodes processing the same block or transaction and yielding different results") when different nodes have different corruption patterns, causing them to produce and accept divergent signatures.

## Likelihood Explanation

**Attacker Requirements:**
- Valid signer configuration (exists in `public_keys.signers`)
- Network access to broadcast P2P messages
- Ability to selectively send messages (standard network capability)

**Attack Complexity:** Low

The attack requires only:
1. Monitoring DKG protocol initiation
2. Sending `DkgPrivateShares` with arbitrary scalar values to victim signers
3. Omitting the coordinator from recipients OR waiting to be excluded from final participants
4. No cryptographic breaks, no special resources, no timing attacks

**Economic Feasibility:** High

Any configured signer can execute this attack with zero cost beyond normal network participation.

**Detection Difficulty:** High

The attack is logged only as a warning [13](#0-12)  and doesn't cause DKG failure. The corruption is detected only when signatures fail to verify, making post-mortem analysis difficult.

**Estimated Probability:** High

This vulnerability is easily exploitable by any malicious signer with network access, making it a realistic threat within the protocol's threat model.

## Recommendation

Add reverse-direction validation to reject private shares that have no corresponding public commitments:

```rust
// In compute_secret(), after line 186, before summing shares:

// Validate reverse direction: all private shares must have corresponding public shares
for key_id in &self.key_ids {
    if let Some(shares) = private_shares.get(key_id) {
        for sender in shares.keys() {
            if !public_shares.contains_key(sender) {
                return Err(DkgError::BadPrivateShares(vec![*sender]));
            }
        }
    }
}
```

Additionally, in `dkg_ended`, validate that `self.decrypted_shares` contains only entries from `signer_ids_set` before calling `compute_secrets`:

```rust
// After line 609, before line 611:

// Remove decrypted shares from signers not in final participant set
self.decrypted_shares.retain(|party_id, _| {
    self.commitments.contains_key(party_id)
});
```

## Proof of Concept

```rust
#[test]
fn test_unvalidated_shares_corruption() {
    use hashbrown::HashMap;
    use crate::v2::Party;
    use crate::common::PolyCommitment;
    use crate::curve::scalar::Scalar;
    use crate::util::create_rng;
    
    let mut rng = create_rng();
    let key_ids = vec![1u32];
    let mut party = Party::new(0, &key_ids, 1, 3, 2, &mut rng);
    
    // Setup: one valid participant (party_id 1) with public commitment
    let mut public_shares = HashMap::new();
    public_shares.insert(1u32, PolyCommitment { /* valid commitment */ });
    
    // Attack: private_shares contains party_id 1 (valid) AND party_id 2 (no public commitment)
    let mut private_shares = HashMap::new();
    let mut shares_for_key1 = HashMap::new();
    shares_for_key1.insert(1u32, Scalar::from(100u32)); // Valid share
    shares_for_key1.insert(2u32, Scalar::from(999u32)); // Unvalidated attacker share
    private_shares.insert(1u32, shares_for_key1);
    
    // Execute: compute_secret should reject but actually succeeds
    let result = party.compute_secret(&private_shares, &public_shares, &[0u8; 8]);
    
    // Vulnerability: function returns Ok despite unvalidated share
    assert!(result.is_ok()); // This passes but shouldn't
    
    // Verification: private key is corrupted (100 + 999 = 1099)
    // but should only be 100
    let expected_valid_key = Scalar::from(100u32);
    let actual_corrupted_key = party.private_keys.get(&1u32).unwrap();
    assert_ne!(actual_corrupted_key, &expected_valid_key); // Keys are corrupted
}
```

### Citations

**File:** src/v2.rs (L147-163)
```rust
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

**File:** src/v2.rs (L188-199)
```rust
        for key_id in &self.key_ids {
            self.private_keys.insert(*key_id, Scalar::zero());
            if let Some(shares) = private_shares.get(key_id) {
                let secret = shares.values().sum();
                self.private_keys.insert(*key_id, secret);
            } else {
                warn!(
                    "no private shares for key_id {}, even though we checked for it above",
                    key_id
                );
            }
        }
```

**File:** src/v1.rs (L191-208)
```rust
        for (i, s) in private_shares.iter() {
            if let Some(comm) = public_shares.get(i) {
                if s * G != compute::poly(&self.id(), &comm.poly)? {
                    bad_shares.push(*i);
                }
            } else {
                warn!("unable to check private share from {}: no corresponding public share, even though we checked for it above", i);
            }
        }

        if !bad_shares.is_empty() {
            return Err(DkgError::BadPrivateShares(bad_shares));
        }

        self.private_key = private_shares.values().sum();
        self.public_key = self.private_key * G;

        Ok(())
```

**File:** src/state_machine/signer/mod.rs (L529-563)
```rust
        let signer_ids_set: HashSet<u32> = dkg_end_begin
            .signer_ids
            .iter()
            .filter(|&&id| id < self.total_signers)
            .copied()
            .collect::<HashSet<u32>>();
        let mut num_dkg_keys = 0u32;
        for id in &signer_ids_set {
            if let Some(key_ids) = self.public_keys.signer_key_ids.get(id) {
                let len: u32 = key_ids.len().try_into()?;
                num_dkg_keys = num_dkg_keys.saturating_add(len);
            }
        }

        if num_dkg_keys < self.dkg_threshold {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::Threshold),
            }));
        }

        for signer_id in &signer_ids_set {
            if let Some(shares) = self.dkg_public_shares.get(signer_id) {
                if shares.comms.is_empty() {
                    missing_public_shares.insert(*signer_id);
                } else {
                    for (party_id, comm) in shares.comms.iter() {
                        if !check_public_shares(comm, threshold, &self.dkg_id.to_be_bytes()) {
                            bad_public_shares.insert(*signer_id);
                        } else {
                            self.commitments.insert(*party_id, comm.clone());
                        }
                    }
                }
```

**File:** src/state_machine/signer/mod.rs (L612-616)
```rust
            match self.signer.compute_secrets(
                &self.decrypted_shares,
                &self.commitments,
                &self.dkg_id.to_be_bytes(),
            ) {
```

**File:** src/state_machine/signer/mod.rs (L1029-1110)
```rust
    pub fn dkg_private_shares<R: RngCore + CryptoRng>(
        &mut self,
        dkg_private_shares: &DkgPrivateShares,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        // go ahead and decrypt here, since we know the signer_id and hence the pubkey of the sender
        let src_signer_id = dkg_private_shares.signer_id;

        // check that the signer_id exists in the config
        let Some(_signer_public_key) = self.public_keys.signers.get(&src_signer_id) else {
            warn!(%src_signer_id, "No public key configured");
            return Ok(vec![]);
        };

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

        for (src_id, shares) in &dkg_private_shares.shares {
            let mut decrypted_shares = HashMap::new();
            for (dst_key_id, bytes) in shares {
                if key_ids.contains(dst_key_id) {
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
                }
            }
            self.decrypted_shares.insert(*src_id, decrypted_shares);
            self.decryption_keys
                .insert(*src_id, (dkg_private_shares.signer_id, shared_key));
        }
        debug!(
            "received DkgPrivateShares from signer {} {}/{}",
            dkg_private_shares.signer_id,
            self.decrypted_shares.len(),
            self.signer.get_num_parties(),
        );
        Ok(vec![])
    }
```

**File:** src/state_machine/coordinator/fire.rs (L461-465)
```rust
        let dkg_end_begin = DkgEndBegin {
            dkg_id: self.current_dkg_id,
            signer_ids: self.dkg_private_shares.keys().cloned().collect(),
            key_ids: vec![],
        };
```
