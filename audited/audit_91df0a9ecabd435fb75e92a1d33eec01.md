### Title
Duplicate Party IDs Cause DKG Inconsistencies Leading to Signature Verification Failures or Silent Key Takeover

### Summary
The protocol fails to enforce uniqueness of party IDs across different signers during distributed key generation (DKG). When multiple signers use the same party ID, the coordinator's HashMap-based storage silently overwrites polynomial commitments, creating critical inconsistencies between stored commitments and the aggregate public key. This causes all signatures to fail verification in the Fire coordinator (denial of service) or allows one signer to silently control another's key share in the Frost coordinator (loss of distributed trust).

### Finding Description

**Exact Code Locations:**

The vulnerability exists in multiple locations:

1. **Configuration Validation** [1](#0-0) 
   The `PublicKeys::validate()` method validates that signer_ids and key_ids are within range but does NOT check that key_ids are unique across different signers in the `signer_key_ids` HashMap.

2. **Fire Coordinator DKG** [2](#0-1) 
   The `dkg_end_gathered()` method uses `HashMap::insert()` to store polynomial commitments by party_id, which silently overwrites duplicates. However, the aggregate public key calculation uses `flat_map` over all commitments, including duplicates from all signers.

3. **Frost Coordinator DKG** [3](#0-2) 
   The `dkg_end_gathered()` method also uses `HashMap::insert()` causing silent overwrites, but calculates the aggregate key from the deduplicated HashMap, causing one signer's contribution to be completely dropped.

4. **No Duplicate Detection in gather_public_shares** [4](#0-3) 
   The coordinator only validates that each signer sends one DkgPublicShares message and that the signer exists in config, but does not validate party_id uniqueness across different signers.

**Root Cause:**

The `ID` struct contains a `Scalar` field representing the party identifier. [5](#0-4)  During DKG, each party creates polynomial commitments with these ID values. [6](#0-5) 

The DkgPublicShares message contains a vector of (party_id, PolyCommitment) tuples. [7](#0-6)  When the coordinator processes these shares, party_ids extracted from different signers are not checked for uniqueness before being stored in the `party_polynomials` HashMap.

The traits module shows this pattern when collecting polynomial commitments into a HashMap, where duplicates are silently dropped: [8](#0-7) 

**Why Existing Mitigations Fail:**

The `set_key_and_party_polynomials()` method does check for duplicates [9](#0-8)  but this method is not called during the normal DKG flow. The actual DKG path uses `dkg_end_gathered()` which lacks this validation.

### Impact Explanation

**Fire Coordinator Impact:**

When duplicate party_ids exist, the Fire coordinator creates a critical inconsistency:
- The `party_polynomials` HashMap stores only the last signer's commitment for each party_id (HashMap overwrites)
- The `aggregate_public_key` includes contributions from ALL signers, including duplicates (flat_map sums all poly[0] values)

During signature verification: [10](#0-9) 
- The aggregator uses the deduplicated `party_polynomials` to evaluate commitments
- But signatures must verify against the `aggregate_public_key` that includes duplicate contributions
- This mismatch causes ALL signature verification attempts to fail

**Concrete Example:**
- Config: Signer A controls party_id=5, Signer B also controls party_id=5 (2 of 3 threshold)
- DKG: Both contribute polynomial commitments P_A and P_B
- Result: aggregate_public_key = ... + P_A[0] + P_B[0] + ..., but party_polynomials[5] = P_B only
- Signing: All signatures fail verification due to key mismatch
- **Severity: Medium** - Complete denial of service for signing operations (transient consensus failure)

**Frost Coordinator Impact:**

The Frost coordinator's `dkg_end_gathered` calculates the aggregate key from the deduplicated `party_polynomials`: [11](#0-10) 

This causes Signer A's contribution to be completely lost:
- Only Signer B's polynomial remains in storage and aggregate key
- Signer A cannot produce valid signature shares (their key is not in the aggregate)
- Signer B effectively controls the key share that should have been distributed
- **Severity: Medium** - Loss of distributed trust model, potential threshold compromise if multiple signers are affected

**Who is Affected:**
Any deployment using WSTS where the configuration allows duplicate key_ids across signers, either through misconfiguration or malicious coordinator setup.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Ability to configure or influence the `PublicKeys` configuration with overlapping `signer_key_ids`
- No cryptographic breaks required
- No network position required beyond normal coordinator/signer roles

**Attack Complexity:**
1. Create a `PublicKeys` configuration where `signer_key_ids[signer_A]` and `signer_key_ids[signer_B]` both contain the same key_id
2. Run DKG normally - the vulnerability triggers automatically
3. For Fire: All subsequent signing attempts fail
4. For Frost: One signer silently takes over the other's contribution

**Economic Feasibility:**
Very low cost - simply requires control over configuration. No computational resources needed.

**Detection Risk:**
- Fire variant: Immediate detection when signatures fail to verify
- Frost variant: Silent and difficult to detect unless all signers verify their contributions are included in the final aggregate key

**Probability of Success:**
High if configuration is not properly validated. The current codebase has no safeguards against this scenario.

### Recommendation

**Primary Fix - Add Configuration Validation:**

Modify `PublicKeys::validate()` to check for duplicate key_ids across signers:

```rust
// In src/state_machine/mod.rs, add to validate() method after line 133:
let mut all_key_ids = HashSet::new();
for (signer_id, key_ids) in &self.signer_key_ids {
    for key_id in key_ids {
        if !all_key_ids.insert(*key_id) {
            return Err(SignerError::Config(ConfigError::DuplicateKeyId(*key_id)));
        }
    }
}
```

**Secondary Fix - Add Runtime Validation:**

Add duplicate detection in `dkg_end_gathered()` before storing commitments:

```rust
// Track all seen party_ids across all signers
let mut seen_party_ids = HashSet::new();
for signer_id in self.dkg_private_shares.keys() {
    for (party_id, comm) in &self.dkg_public_shares[signer_id].comms {
        if !seen_party_ids.insert(*party_id) {
            return Err(Error::DuplicatePartyId);
        }
        self.party_polynomials.insert(*party_id, comm.clone());
    }
}
```

**Testing Recommendations:**
1. Add unit tests creating configs with duplicate key_ids and verify rejection
2. Add integration tests for DKG with duplicate party_ids
3. Verify error propagation through state machine
4. Test both Fire and Frost coordinator variants

**Deployment Considerations:**
- This is a breaking change that will reject previously "valid" configurations
- Audit all existing configurations before deploying the fix
- Add migration path for any systems with duplicate key_ids

### Proof of Concept

**Exploitation Steps:**

1. **Create Malicious Configuration:**
```
num_signers = 3
num_keys = 5
threshold = 2

signer_key_ids = {
    0: {1, 2},  // Signer 0 controls keys 1, 2
    1: {2, 3},  // Signer 1 ALSO controls key 2 (DUPLICATE)
    2: {4, 5}   // Signer 2 controls keys 4, 5
}
```

2. **Run DKG:** [12](#0-11) 
Each signer creates PolyCommitments where `party_id = poly.id.id.get_u32()` for their key_ids.

3. **Observe Fire Coordinator Behavior:**
   - Signer 0 sends commitment for party_id=2
   - Signer 1 sends commitment for party_id=2 (overwrites in HashMap)
   - `aggregate_public_key` includes both commitments
   - `party_polynomials[2]` only has Signer 1's commitment
   - All subsequent signatures fail verification

4. **Observe Frost Coordinator Behavior:**
   - Same overwrite occurs
   - `aggregate_public_key` calculated from deduplicated HashMap
   - Signer 0's contribution to key_id=2 is completely lost
   - Only Signer 1 can produce valid shares for party_id=2

**Expected vs Actual Behavior:**

Expected: Configuration validation rejects duplicate key_ids, or DKG process detects and rejects duplicate party_ids.

Actual: 
- Configuration validation passes [13](#0-12) 
- DKG silently accepts duplicates
- Fire: DoS on all signing operations
- Frost: Silent key takeover

**Reproduction:**
Use the test configuration structure and run DKG through either coordinator variant. Observe signature verification failures (Fire) or check aggregate key composition (Frost).

## Notes

This vulnerability violates the stated security invariant: "Threshold and key ID bounds must be enforced; no duplicates or out-of-range IDs." The duplicate check for party IDs across different signers is missing from both configuration validation and runtime DKG processing.

### Citations

**File:** src/state_machine/mod.rs (L106-136)
```rust
    pub fn validate(&self, num_signers: u32, num_keys: u32) -> Result<(), SignerError> {
        for (signer_id, _key) in &self.signers {
            if !validate_signer_id(*signer_id, num_signers) {
                return Err(SignerError::Config(ConfigError::InvalidSignerId(
                    *signer_id,
                )));
            }
        }

        for (key_id, _key) in &self.key_ids {
            if !validate_key_id(*key_id, num_keys) {
                return Err(SignerError::Config(ConfigError::InvalidKeyId(*key_id)));
            }
        }

        for (signer_id, key_ids) in &self.signer_key_ids {
            if !validate_signer_id(*signer_id, num_signers) {
                return Err(SignerError::Config(ConfigError::InvalidSignerId(
                    *signer_id,
                )));
            }

            for key_id in key_ids {
                if !validate_key_id(*key_id, num_keys) {
                    return Err(SignerError::Config(ConfigError::InvalidKeyId(*key_id)));
                }
            }
        }

        Ok(())
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

**File:** src/state_machine/coordinator/fire.rs (L794-812)
```rust
    fn dkg_end_gathered(&mut self) -> Result<(), Error> {
        // Cache the polynomials used in DKG for the aggregator
        for signer_id in self.dkg_private_shares.keys() {
            for (party_id, comm) in &self.dkg_public_shares[signer_id].comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
        }

        // Calculate the aggregate public key
        let key = self
            .dkg_end_messages
            .keys()
            .flat_map(|signer_id| self.dkg_public_shares[signer_id].comms.clone())
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

        info!("Aggregate public key: {key}");
        self.aggregate_public_key = Some(key);
        self.move_to(State::Idle)
    }
```

**File:** src/state_machine/coordinator/frost.rs (L422-445)
```rust
    fn dkg_end_gathered(&mut self) -> Result<(), Error> {
        // Cache the polynomials used in DKG for the aggregator
        for signer_id in self.dkg_private_shares.keys() {
            let Some(dkg_public_shares) = self.dkg_public_shares.get(signer_id) else {
                warn!(%signer_id, "no DkgPublicShares");
                return Err(Error::BadStateChange(format!("Should not have transitioned to DkgEndGather since we were missing DkgPublicShares from signer {signer_id}")));
            };
            for (party_id, comm) in &dkg_public_shares.comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
        }

        // Calculate the aggregate public key
        let key = self
            .party_polynomials
            .iter()
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

        info!(
            %key,
            "Aggregate public key"
        );
        self.aggregate_public_key = Some(key);
        self.move_to(State::Idle)
```

**File:** src/state_machine/coordinator/frost.rs (L918-922)
```rust
        let party_polynomials_len = party_polynomials.len();
        let party_polynomials = HashMap::from_iter(party_polynomials);
        if party_polynomials.len() != party_polynomials_len {
            return Err(Error::DuplicatePartyId);
        }
```

**File:** src/schnorr.rs (L14-23)
```rust
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
/// ID type which encapsulates the ID and a schnorr proof of ownership of the polynomial
pub struct ID {
    /// The ID
    pub id: Scalar,
    /// The public schnorr response
    pub kG: Point,
    /// The aggregate of the schnorr committed values
    pub kca: Scalar,
}
```

**File:** src/common.rs (L26-40)
```rust
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
/// A commitment to a polynonial, with a Schnorr proof of ownership bound to the ID
pub struct PolyCommitment {
    /// The party ID with a schnorr proof
    pub id: ID,
    /// The public polynomial which commits to the secret polynomial
    pub poly: Vec<Point>,
}

impl PolyCommitment {
    /// Verify the wrapped schnorr ID
    pub fn verify(&self, ctx: &[u8]) -> bool {
        self.id.verify(&self.poly[0], ctx)
    }
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

**File:** src/traits.rs (L206-210)
```rust
        let public_shares: HashMap<u32, PolyCommitment> = signers
            .iter()
            .flat_map(|s| s.get_poly_commitments(&ctx, rng))
            .map(|comm| (comm.id.id.get_u32(), comm))
            .collect();
```

**File:** src/v2.rs (L395-404)
```rust
                let public_key = match compute::poly(&kid, &self.poly) {
                    Ok(p) => p,
                    Err(_) => {
                        bad_party_keys.push(sig_shares[i].id);
                        Point::zero()
                    }
                };

                cx += compute::lambda(*key_id, key_ids) * c * public_key;
            }
```

**File:** src/state_machine/signer/mod.rs (L882-882)
```rust
                .push((poly.id.id.get_u32(), poly.clone()));
```
