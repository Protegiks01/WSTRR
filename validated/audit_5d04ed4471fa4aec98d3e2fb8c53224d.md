# Audit Report

## Title
Aggregate Public Key Mismatch Due to Missing Party ID Uniqueness Validation in DKG

## Summary
The FIRE coordinator fails to validate that party IDs are unique when receiving DkgPublicShares messages during DKG. This allows a malicious signer to send duplicate party IDs, causing a mismatch between the aggregate public key (which includes duplicates) and the aggregator's polynomial (which deduplicates via HashMap). This breaks protocol correctness, causing all subsequent signature verifications to fail.

## Finding Description

The vulnerability exists in the DKG completion flow within the FIRE coordinator. During DKG, the coordinator processes DkgPublicShares messages but performs no validation of party ID uniqueness.

**Attack Flow:**

In v1 (weighted FROST), a malicious signer can exploit this by:

1. Constructing a Signer with duplicate key_ids (e.g., `[1, 1, 2]`), which creates multiple Party objects sharing the same party_id [1](#0-0) 

2. When `get_poly_commitments()` is called, it returns polynomial commitments for each Party, including duplicates [2](#0-1) 

3. The malicious DkgPublicShares message contains duplicate party_ids in its comms vector [3](#0-2) 

4. Other signers validate received DkgPublicShares using `validate_party_id()`, which only checks if the party_id exists in the configured key_ids set - NOT uniqueness [4](#0-3) [5](#0-4) 

5. The coordinator's `gather_public_shares()` performs no party_id validation at all [6](#0-5) 

6. When DKG completes, `dkg_end_gathered()` creates a critical mismatch:
   - Lines 795-800 store party_polynomials in a HashMap, where duplicate party_ids cause overwrites (last value wins) [7](#0-6) 
   - Lines 803-807 calculate aggregate_public_key by flat_mapping over ALL comms, including duplicates [8](#0-7) 

7. During signing, the aggregator is initialized with the deduplicated `party_polynomials` HashMap [9](#0-8) 

8. The `Aggregator::init()` sums only the deduplicated polynomials into `self.poly` [10](#0-9) 

9. Signature verification uses `self.poly[0]` as the public key, which doesn't match the true aggregate key [11](#0-10) 

The invariant `aggregate_public_key = sum of all party polynomials' first coefficients` is broken because the aggregate key includes duplicates while the aggregator's polynomial does not.

Notably, the `set_key_and_party_polynomials()` function DOES detect duplicates, but it's only used when manually loading state, not during the normal DKG flow [12](#0-11) 

## Impact Explanation

This vulnerability causes **transient consensus failures** (Medium severity per the defined scope). When duplicate party IDs are present in a DKG round:

1. The coordinator calculates an incorrect aggregate public key that includes duplicate contributions
2. The aggregator stores only deduplicated party polynomials  
3. All subsequent signature verification attempts fail because the verification key (`aggregator.poly[0]`) doesn't match the key against which signatures were actually created
4. The threshold signature protocol cannot produce valid signatures, breaking its fundamental correctness guarantee
5. Dependent systems relying on WSTS signatures experience verification failures and consensus disruption

The impact is **Medium** rather than Critical/High because:
- It causes transient protocol failures rather than permanent security breaks
- No funds are directly lost (though dependent systems may be affected)
- The issue manifests as denial of correct operation rather than acceptance of invalid operations
- Recovery requires restarting DKG with proper validation

## Likelihood Explanation

The likelihood is **Medium-High** because:

**Required Attacker Capabilities:**
- Control of at least one signer participant (within the threshold-1 threat model)
- Ability to construct a Signer with duplicate key_ids (trivial in v1)
- No cryptographic breaks or special resources required

**Attack Complexity:**
- Low for v1: The malicious signer simply passes duplicate values in the key_ids array during Signer construction
- Higher for v2: Would require multiple malicious signers to coordinate using the same party_id, and honest signers would reject such messages

**Detection Risk:**
- Low: The coordinator performs no validation of party_id uniqueness
- Other signers' `validate_party_id` checks only verify membership, not uniqueness, so duplicate party_ids from a single signer are not detected

**Economic Feasibility:**
- Highly feasible: Requires only standard protocol participation

## Recommendation

Add party ID uniqueness validation to the coordinator's DKG flow:

1. **In `gather_public_shares()`**: Validate that all party_ids in the received DkgPublicShares match the configured key_ids for that signer, and that no party_id appears more than once within a single message.

2. **In `dkg_end_gathered()`**: Before calculating the aggregate public key, validate that all party_ids across all accepted DkgPublicShares are globally unique.

3. **Apply the existing validation logic**: The `set_key_and_party_polynomials()` duplicate detection logic should be reused or extracted into a common validation function that runs during normal DKG flow.

Recommended code structure:
```rust
// In gather_public_shares(), after line 491:
let party_ids: HashSet<u32> = dkg_public_shares.comms.iter()
    .map(|(id, _)| *id)
    .collect();
if party_ids.len() != dkg_public_shares.comms.len() {
    warn!(signer_id = %dkg_public_shares.signer_id, "Duplicate party_ids in DkgPublicShares");
    return Ok(());
}

// In dkg_end_gathered(), after line 800:
let total_comms = self.dkg_public_shares.values()
    .map(|shares| shares.comms.len())
    .sum::<usize>();
if self.party_polynomials.len() != total_comms {
    return Err(Error::DuplicatePartyId);
}
```

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_duplicate_party_id_mismatch() {
    use wsts::v1::Signer;
    use rand_core::OsRng;
    
    // Malicious signer creates duplicate party_ids
    let duplicate_key_ids = vec![1u32, 1u32, 2u32]; // duplicate party_id=1
    let signer = Signer::new(0, &duplicate_key_ids, 3, 2, &mut OsRng);
    
    // Get polynomial commitments - will include duplicates
    let comms = signer.get_poly_commitments(&[0u8; 8], &mut OsRng);
    assert_eq!(comms.len(), 3); // 3 commitments
    
    // Extract party_ids from commitments
    let party_ids: Vec<u32> = comms.iter()
        .map(|c| c.id.id.get_u32())
        .collect();
    
    // Verify duplicates exist
    assert_eq!(party_ids[0], 1);
    assert_eq!(party_ids[1], 1); // duplicate!
    assert_eq!(party_ids[2], 2);
    
    // Simulate coordinator's dkg_end_gathered logic
    let mut party_polynomials = HashMap::new();
    let mut aggregate_sum = Point::default();
    
    // Store in HashMap (deduplicates)
    for (i, comm) in comms.iter().enumerate() {
        party_polynomials.insert(party_ids[i], comm.clone());
        aggregate_sum = aggregate_sum + comm.poly[0]; // sum all including duplicates
    }
    
    // Calculate what aggregator would compute
    let aggregator_sum = party_polynomials.values()
        .fold(Point::default(), |s, c| s + c.poly[0]);
    
    // Verify the mismatch
    assert_ne!(aggregate_sum, aggregator_sum, 
        "Aggregate key mismatch due to duplicate party_ids");
    assert_eq!(party_polynomials.len(), 2); // only 2 unique party_ids stored
}
```

### Citations

**File:** src/v1.rs (L329-329)
```rust
        let aggregate_public_key = self.poly[0];
```

**File:** src/v1.rs (L440-454)
```rust
    fn init(&mut self, comms: &HashMap<u32, PolyCommitment>) -> Result<(), AggregatorError> {
        let threshold = self.threshold.try_into()?;
        let mut poly = Vec::with_capacity(threshold);

        for i in 0..poly.capacity() {
            poly.push(Point::zero());
            for (_, p) in comms {
                poly[i] += &p.poly[i];
            }
        }

        self.poly = poly;

        Ok(())
    }
```

**File:** src/v1.rs (L537-540)
```rust
        let parties = key_ids
            .iter()
            .map(|id| Party::new(*id, num_keys, threshold, rng))
            .collect();
```

**File:** src/v1.rs (L613-626)
```rust
    fn get_poly_commitments<RNG: RngCore + CryptoRng>(
        &self,
        ctx: &[u8],
        rng: &mut RNG,
    ) -> Vec<PolyCommitment> {
        let mut polys = Vec::new();
        for party in &self.parties {
            let comm = party.get_poly_commitment(ctx, rng);
            if let Some(poly) = &comm {
                polys.push(poly.clone());
            }
        }
        polys
    }
```

**File:** src/v1.rs (L696-705)
```rust
    fn validate_party_id(
        signer_id: u32,
        party_id: u32,
        signer_key_ids: &HashMap<u32, HashSet<u32>>,
    ) -> bool {
        match signer_key_ids.get(&signer_id) {
            Some(key_ids) => key_ids.contains(&party_id),
            None => false,
        }
    }
```

**File:** src/state_machine/signer/mod.rs (L879-883)
```rust
        for poly in &comms {
            public_share
                .comms
                .push((poly.id.id.get_u32(), poly.clone()));
        }
```

**File:** src/state_machine/signer/mod.rs (L993-1002)
```rust
        for (party_id, _) in &dkg_public_shares.comms {
            if !SignerType::validate_party_id(
                signer_id,
                *party_id,
                &self.public_keys.signer_key_ids,
            ) {
                warn!(%signer_id, %party_id, "signer sent polynomial commitment for wrong party");
                return Ok(vec![]);
            }
        }
```

**File:** src/state_machine/coordinator/fire.rs (L477-518)
```rust
    fn gather_public_shares(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Message::DkgPublicShares(dkg_public_shares) = &packet.msg {
            if dkg_public_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_public_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&dkg_public_shares.signer_id) {
                warn!(signer_id = %dkg_public_shares.signer_id, "No public key in config");
                return Ok(());
            };

            let have_shares = self
                .dkg_public_shares
                .contains_key(&dkg_public_shares.signer_id);

            if have_shares {
                info!(signer_id = %dkg_public_shares.signer_id, "received duplicate DkgPublicShares");
                return Ok(());
            }

            self.dkg_wait_signer_ids
                .remove(&dkg_public_shares.signer_id);

            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            debug!(
                dkg_id = %dkg_public_shares.dkg_id,
                signer_id = %dkg_public_shares.signer_id,
                "DkgPublicShares received"
            );
        }

        if self.dkg_wait_signer_ids.is_empty() {
            self.public_shares_gathered()?;
        }
        Ok(())
    }
```

**File:** src/state_machine/coordinator/fire.rs (L795-800)
```rust
        // Cache the polynomials used in DKG for the aggregator
        for signer_id in self.dkg_private_shares.keys() {
            for (party_id, comm) in &self.dkg_public_shares[signer_id].comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
        }
```

**File:** src/state_machine/coordinator/fire.rs (L803-807)
```rust
        let key = self
            .dkg_end_messages
            .keys()
            .flat_map(|signer_id| self.dkg_public_shares[signer_id].comms.clone())
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);
```

**File:** src/state_machine/coordinator/fire.rs (L1145-1145)
```rust
            self.aggregator.init(&self.party_polynomials)?;
```

**File:** src/state_machine/coordinator/fire.rs (L1398-1402)
```rust
        let party_polynomials_len = party_polynomials.len();
        let party_polynomials = HashMap::from_iter(party_polynomials);
        if party_polynomials.len() != party_polynomials_len {
            return Err(Error::DuplicatePartyId);
        }
```
