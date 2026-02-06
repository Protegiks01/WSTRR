### Title
Insufficient Validation of Polynomial Commitments Against Claimed Key IDs Enables DKG Threshold Bypass

### Summary
The protocol fails to validate that signers provide polynomial commitments for all key IDs they claim to control in the `signer_key_ids` mapping. A malicious signer can claim control of N keys but only initialize with M keys (where M < N), causing DKG to succeed based on claimed keys while later signing operations fail. This violates the DKG invariant requiring all expected shares to be present and enables resource exhaustion attacks.

### Finding Description

**Code Locations:**

The vulnerability spans multiple validation points that fail to enforce completeness:

1. **DKG public share validation** - signers only validate that provided party_ids are valid, not that all claimed keys have commitments: [1](#0-0) 

2. **DKG threshold calculation** - counts claimed keys from `signer_key_ids` rather than actual commitments received: [2](#0-1) 

3. **DKG end validation** - only checks that commitments aren't empty, not that count matches claimed keys: [3](#0-2) 

4. **Coordinator validation** - uses claimed key count rather than validating commitment completeness: [4](#0-3) 

5. **Signing validation** - this is where the mismatch is finally detected: [5](#0-4) 

**Root Cause:**

The `PublicKeys` struct contains a `signer_key_ids` mapping that declares which key IDs each signer controls: [6](#0-5) 

This mapping is external configuration with only range validation, no cryptographic binding: [7](#0-6) 

During DKG, the v1 `validate_party_id` only checks if a party_id is IN the claimed set, not whether ALL claimed keys are present: [8](#0-7) 

When signers generate polynomial commitments, they create one per initialized party: [9](#0-8) 

If a signer initializes with fewer keys than claimed, they send fewer commitments, but no validation catches this discrepancy during DKG.

**Why Existing Mitigations Fail:**

The security model assumes "PKI established before protocol execution," but the code doesn't cryptographically enforce consistency between the claimed mapping and actual signer initialization. The protocol treats `signer_key_ids` as authoritative during threshold checks but never validates that polynomial commitments exist for all claimed keys.

### Impact Explanation

**Specific Harm:**
A malicious signer can cause DKG to appear successful while rendering the system unable to complete signing operations, creating a denial of service condition.

**Attack Scenario:**
1. Malicious Signer A manipulates configuration so `signer_key_ids[A] = {1,2,3,4}` (claims 4 keys)
2. Signer A initializes their actual Signer with only `key_ids = [1,2]` (has 2 keys)
3. DKG public phase: Signer A sends commitments only for parties 1 and 2
4. DKG threshold check counts 4 claimed keys toward threshold (not 2 actual)
5. If threshold is 7 and would be 6 with only 2 keys, DKG incorrectly succeeds
6. DKG completes with Status::Success but signer has insufficient key shares
7. Later signing: Signer A can only provide signature shares for keys [1,2]
8. Coordinator detects mismatch and rejects with `BadKeyIDsForSigner`
9. All signing operations fail permanently for this DKG round

**Quantified Impact:**
- Wasted DKG round (typically minutes to complete with network delays)
- All subsequent signing operations fail
- Resources consumed: bandwidth, computation, coordinator time
- In blockchain context: transaction signing delays, potential block production failures

**Affected Parties:**
- All honest participants who completed DKG in good faith
- Coordinator resources wasted
- Dependent systems waiting for signatures

**Severity Justification:**
Maps to **Low severity** per protocol scope: "Any remotely-exploitable denial of service in a node." While not causing direct fund loss or chain splits, this enables targeted DoS by forcing wasted DKG rounds and preventing valid signing operations.

### Likelihood Explanation

**Required Attacker Capabilities:**
1. **Position:** Must be registered participant signer in the DKG protocol
2. **Access:** Ability to initialize their Signer instance with arbitrary `key_ids` parameter (standard protocol capability)
3. **Influence:** Either ability to manipulate `PublicKeys` configuration OR exploit gap between configuration and enforcement

**Attack Complexity:**
- **Low complexity** - requires only standard signer participation plus dishonest initialization
- No cryptographic breaks required
- No privileged access needed beyond being a protocol participant
- Attacker controls their own Signer initialization parameters

**Exploitation Path:**
```
1. Attacker registers as legitimate signer in protocol
2. During setup, ensure signer_key_ids[attacker] lists N keys
3. When creating Signer instance, pass only M keys where M < N
4. Participate normally in DKG (will succeed if threshold met with claimed keys)
5. DKG completes successfully
6. On any signing attempt, provide only M signature shares
7. Coordinator rejects, signing fails
8. Repeat for each signing round to maintain DoS
```

**Economic Feasibility:**
- Minimal cost: just participant registration and normal DKG participation
- High impact: blocks all signing for affected DKG group
- Detectable only after DKG completion when signing attempted

**Detection Risk:**
- Not detected during DKG phase
- Only detected when first signing operation attempted
- By then, DKG resources already wasted
- Can repeat attack in subsequent DKG rounds

**Estimated Success Probability:**
- 100% if attacker controls their own Signer initialization
- Depends on whether deployment enforces consistent initialization with configuration
- No defense in protocol layer itself

### Recommendation

**Primary Fix - Add Completeness Validation:**

Add validation in DKG end phase to verify polynomial commitments exist for all claimed key IDs:

```rust
// In src/state_machine/signer/mod.rs, dkg_ended() function, after line 563
for signer_id in &signer_ids_set {
    if let Some(shares) = self.dkg_public_shares.get(signer_id) {
        if let Some(expected_key_ids) = self.public_keys.signer_key_ids.get(signer_id) {
            // Collect actual party_ids from commitments
            let provided_party_ids: HashSet<u32> = shares.comms.iter()
                .map(|(party_id, _)| *party_id)
                .collect();
            
            // Verify all expected keys have commitments
            if *expected_key_ids != provided_party_ids {
                return Ok(Message::DkgEnd(DkgEnd {
                    dkg_id: self.dkg_id,
                    signer_id: self.signer_id,
                    status: DkgStatus::Failure(DkgFailure::BadPublicShares(
                        hashset![*signer_id]
                    )),
                }));
            }
        }
    }
}
```

**Alternative Mitigation - Coordinator Early Validation:**

Add validation in coordinator's `gather_public_shares`:

```rust
// In src/state_machine/coordinator/fire.rs, after receiving DkgPublicShares
let expected_count = self.config.public_keys.signer_key_ids
    .get(&dkg_public_shares.signer_id)
    .map(|s| s.len())
    .unwrap_or(0);

if dkg_public_shares.comms.len() != expected_count {
    warn!("Signer {} provided {} commitments but claims {} keys",
          dkg_public_shares.signer_id, 
          dkg_public_shares.comms.len(),
          expected_count);
    return Ok(()); // Reject this signer
}
```

**Configuration Authentication:**

Add cryptographic binding of `PublicKeys` configuration:
1. Hash the entire PublicKeys structure (including signer_key_ids)
2. Include hash in DkgBegin message
3. All signers verify they have identical configuration before proceeding
4. Mismatch causes immediate DKG failure

**Testing Recommendations:**
1. Add test case where signer claims N keys but initializes with M < N keys
2. Verify DKG fails with appropriate error
3. Test threshold boundary: DKG should fail if actual keys < threshold even if claimed keys >= threshold
4. Test legitimate case: signer providing all claimed commitments succeeds

**Deployment Considerations:**
- Requires coordination to update all nodes simultaneously
- Existing DKG rounds in progress may need restart
- Update configuration validation in deployment scripts
- Add monitoring for commitment count mismatches

### Proof of Concept

**Exploitation Algorithm:**

```rust
// Setup: Configure system with signer claiming 4 keys
let mut public_keys = PublicKeys::default();
let signer_id = 0u32;
let attacker_pubkey = ecdsa::PublicKey::new(&attacker_privkey).unwrap();

// Attacker manipulates signer_key_ids to claim 4 keys
let claimed_keys = hashset![1u32, 2u32, 3u32, 4u32];
public_keys.signer_key_ids.insert(signer_id, claimed_keys);
public_keys.signers.insert(signer_id, attacker_pubkey);

// But initialize Signer with only 2 keys
let actual_keys = vec![1u32, 2u32]; // Only 2 keys!
let mut attacker_signer = Signer::<v1::Signer>::new(
    threshold,
    dkg_threshold,
    total_signers,
    total_keys,
    signer_id,
    actual_keys, // Mismatch: claims 4, has 2
    network_private_key,
    public_keys.clone(),
    &mut rng,
)?;

// Participate in DKG normally
// DkgBegin -> attacker sends DkgPublicShares with only 2 commitments
// Other signers validate using validate_party_id - PASSES (keys 1,2 are valid)
// No validation checks that keys 3,4 are missing

// DKG threshold check in dkg_ended():
// num_dkg_keys += 4  (counts CLAIMED keys from signer_key_ids)
// If this meets threshold, DKG succeeds

// Later, during signing:
let nonce_response = attacker_signer.nonce_request(&nonce_req, &mut rng)?;
// nonce_response.key_ids = [1, 2] (only actual keys)

// Coordinator validation in gather_nonces():
// Expected: signer_key_ids[0] = {1,2,3,4}
// Received: [1,2]
// Comparison fails: {1,2,3,4} != {1,2}
// Returns Error::BadKeyIDsForSigner(0)
// Signing FAILS
```

**Expected vs Actual Behavior:**

**Expected (with fix):**
- DKG end validation detects commitment count mismatch
- Returns `DkgFailure::BadPublicShares([signer_id])`
- DKG fails immediately
- No resources wasted on subsequent signing attempts

**Actual (current vulnerable behavior):**
- DKG end validation passes (only checks commitments non-empty)
- DKG completes with Status::Success
- Threshold met based on claimed keys (4) not actual commitments (2)
- Signing attempts all fail with BadKeyIDsForSigner error
- Resources wasted: DKG round completion time, network bandwidth, coordinator processing

**Reproduction Steps:**

1. Set up WSTS with threshold=7, total_keys=10, total_signers=3
2. Configure Signer 0 with `signer_key_ids[0] = {1,2,3,4}` (4 keys)
3. Initialize Signer 0 with `key_ids = vec![1,2]` (2 keys only)
4. Configure other signers legitimately to meet threshold with claimed keys
5. Execute DKG protocol - observe success despite insufficient actual commitments
6. Attempt signing operation - observe immediate failure with BadKeyIDsForSigner
7. Verify DKG resources were wasted (time, bandwidth, computation)

## Notes

The vulnerability violates the stated DKG invariant: "All expected private shares must be present and verify against commitments." While the private shares that ARE present do verify against their commitments, the protocol fails to enforce that shares exist for ALL expected key IDs claimed in the `signer_key_ids` mapping. This gap between claimed and actual key ownership enables the DoS attack.

### Citations

**File:** src/state_machine/signer/mod.rs (L535-541)
```rust
        let mut num_dkg_keys = 0u32;
        for id in &signer_ids_set {
            if let Some(key_ids) = self.public_keys.signer_key_ids.get(id) {
                let len: u32 = key_ids.len().try_into()?;
                num_dkg_keys = num_dkg_keys.saturating_add(len);
            }
        }
```

**File:** src/state_machine/signer/mod.rs (L552-563)
```rust
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

**File:** src/state_machine/coordinator/fire.rs (L1066-1076)
```rust
        let mut sig_share_response_key_ids = HashSet::new();
        for sig_share in &sig_share_response.signature_shares {
            for key_id in &sig_share.key_ids {
                sig_share_response_key_ids.insert(*key_id);
            }
        }

        if *signer_key_ids != sig_share_response_key_ids {
            warn!(signer_id = %sig_share_response.signer_id, "SignatureShareResponse key_ids didn't match config");
            return Err(Error::BadKeyIDsForSigner(sig_share_response.signer_id));
        }
```

**File:** src/state_machine/coordinator/fire.rs (L1200-1221)
```rust
    fn compute_num_key_ids<'a, I>(&self, signer_ids: I) -> Result<u32, Error>
    where
        I: Iterator<Item = &'a u32>,
    {
        signer_ids
            .map(
                |signer_id| match self.config.public_keys.signer_key_ids.get(signer_id) {
                    Some(key_ids) => key_ids.len(),
                    None => {
                        error!("No key_ids for signer {signer_id}");
                        0usize
                    }
                },
            )
            .sum::<usize>()
            .try_into()
            .map_err(Error::TryFromInt)
    }

    fn compute_dkg_public_size(&self) -> Result<u32, Error> {
        self.compute_num_key_ids(self.dkg_public_shares.keys())
    }
```

**File:** src/state_machine/mod.rs (L93-102)
```rust
#[derive(Clone, Default, PartialEq, Eq)]
/// Map of signer_id and key_id to the relevant ecdsa public keys
pub struct PublicKeys {
    /// signer_id -> public key
    pub signers: HashMap<u32, ecdsa::PublicKey>,
    /// key_id -> public key
    pub key_ids: HashMap<u32, ecdsa::PublicKey>,
    /// map of signer_id to controlled key_ids
    pub signer_key_ids: HashMap<u32, HashSet<u32>>,
}
```

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
