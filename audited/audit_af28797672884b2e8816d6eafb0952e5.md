### Title
Duplicate Party IDs Within Single DkgPrivateShares Message Bypass Duplicate Check

### Summary
The duplicate check at lines 1058-1061 prevents multiple DkgPrivateShares messages from the same signer but does not prevent duplicate party_ids within a single message. A malicious signer can exploit this by including the same party_id multiple times in one message, causing the second occurrence to overwrite the first and enabling denial-of-service attacks on the DKG process.

### Finding Description

**Code Location:** [1](#0-0) 

**Root Cause:**

The duplicate check only validates that a signer hasn't sent multiple messages by checking if `self.dkg_private_shares` already contains the `src_signer_id`. However, it does not validate that party_ids are unique within the `DkgPrivateShares.shares` vector. [2](#0-1) 

The `shares` field is a `Vec<(u32, HashMap<u32, Vec<u8>>)>`, allowing duplicate party_ids (the first element of each tuple) to appear multiple times.

**Processing Loop with Overwrite Issue:** [3](#0-2) 

The processing loop iterates through all entries in `dkg_private_shares.shares` and uses `HashMap::insert()` at line 1099, which overwrites any existing entry with the same key. If the message contains duplicate `src_id` values, the last occurrence wins.

**Validation Gap:** [4](#0-3) 

The validation loop only checks that each party_id belongs to the sender but does not detect duplicates within the message.

### Impact Explanation

**Denial of Service Attack:**
A malicious signer can cause DKG to fail by sending a single message containing duplicate party_ids with invalid shares in the second occurrence. When `compute_secrets` validates the shares against polynomial commitments, the invalid shares will be detected as `BadPrivateShares`, causing DKG failure. [5](#0-4) 

**Specific Harm:**
- DKG process fails to complete
- Threshold signature setup cannot proceed
- System cannot sign transactions until a successful DKG round
- All participating signers are blocked from establishing the group key

**Affected Parties:**
All participants in the DKG round are affected, as a single malicious signer can prevent the entire group from completing key generation.

**Severity:** Medium - Maps to "Any transient consensus failures" in the protocol scope. While DKG can be retried, this prevents threshold signature setup and could cause transaction signing delays in dependent systems.

### Likelihood Explanation

**Attacker Prerequisites:**
- Attacker must be a legitimate participating signer in the DKG
- Attacker needs their signing key to authenticate messages (if `verify_packet_sigs` is enabled)
- No cryptographic breaks required [6](#0-5) 

**Attack Complexity:** Low
- Attacker simply crafts a DkgPrivateShares message with duplicate party_ids
- No timing constraints or race conditions required
- Single malicious message causes the attack

**Detection:**
The attack is detectable when DKG fails with `BadPrivateShares` error, and the malicious signer is identified in the error response. However, the root cause (duplicate party_ids in message) may not be immediately obvious.

**Probability of Success:** High (100% if executed correctly)

### Recommendation

**Primary Fix:**
Add validation to detect duplicate party_ids within a single DkgPrivateShares message before processing:

```rust
// After line 1056, before the duplicate message check
let mut seen_party_ids = HashSet::new();
for (party_id, _shares) in &dkg_private_shares.shares {
    if !seen_party_ids.insert(*party_id) {
        warn!("Signer {src_signer_id} sent duplicate party_id {party_id} in shares");
        return Ok(vec![]);
    }
}
```

**Alternative Mitigation:**
Change the `DkgPrivateShares.shares` field from a `Vec` to a `HashMap` to prevent duplicates at the data structure level:

```rust
pub struct DkgPrivateShares {
    pub dkg_id: u64,
    pub signer_id: u32,
    pub shares: HashMap<u32, HashMap<u32, Vec<u8>>>,  // Changed from Vec
}
```

**Testing Recommendations:**
1. Add unit test that sends DkgPrivateShares with duplicate party_ids
2. Verify the duplicate is detected and rejected
3. Test with both v1 and v2 signer implementations
4. Verify error handling and signer identification

**Deployment Considerations:**
- This is a validation fix with no breaking changes to valid messages
- Can be deployed immediately without protocol version change
- Existing valid messages will be unaffected

### Proof of Concept

**Exploitation Algorithm:**

1. Malicious signer (signer_id=1) controls parties 1, 2, 3
2. Generate valid polynomial commitments and send DkgPublicShares
3. Create DkgPrivateShares message with structure:
   ```
   DkgPrivateShares {
       signer_id: 1,
       shares: vec![
           (1, valid_encrypted_shares),    // Valid shares from party 1
           (2, valid_encrypted_shares),    // Valid shares from party 2
           (1, invalid_encrypted_shares),  // Duplicate party 1 with modified shares
       ]
   }
   ```
4. Send the crafted message

**Expected Behavior:**
- Validation at lines 1047-1056 passes (all party_ids belong to signer 1)
- Duplicate check at lines 1058-1061 passes (first message from this signer)
- Processing loop processes all three entries:
  - First: `decrypted_shares[1] = valid_shares`
  - Second: `decrypted_shares[2] = valid_shares`
  - Third: `decrypted_shares[1] = invalid_shares` (OVERWRITES first entry)

**Actual Behavior:**
- `compute_secrets` validation detects that shares from party 1 don't match commitments
- DKG fails with `DkgStatus::Failure(DkgFailure::BadPrivateShares({1: ...}))`
- Signer 1 is identified as sending bad shares
- DKG round must be restarted

**Reproduction:**
Create a test case that constructs a DkgPrivateShares message with duplicate party_ids and verifies it passes validation but causes DKG failure during secret computation.

### Citations

**File:** src/state_machine/signer/mod.rs (L458-470)
```rust
    pub fn process<R: RngCore + CryptoRng>(
        &mut self,
        packet: &Packet,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        if self.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
        }
```

**File:** src/state_machine/signer/mod.rs (L611-650)
```rust
        let dkg_end = if self.invalid_private_shares.is_empty() {
            match self.signer.compute_secrets(
                &self.decrypted_shares,
                &self.commitments,
                &self.dkg_id.to_be_bytes(),
            ) {
                Ok(()) => DkgEnd {
                    dkg_id: self.dkg_id,
                    signer_id: self.signer_id,
                    status: DkgStatus::Success,
                },
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

**File:** src/state_machine/signer/mod.rs (L1058-1061)
```rust
        if self.dkg_private_shares.contains_key(&src_signer_id) {
            info!(signer_id = %dkg_private_shares.signer_id, "received duplicate DkgPrivateShares");
            return Ok(vec![]);
        }
```

**File:** src/state_machine/signer/mod.rs (L1072-1102)
```rust
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
```

**File:** src/net.rs (L192-199)
```rust
pub struct DkgPrivateShares {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// List of (src_party_id, Map(dst_key_id, encrypted_share))
    pub shares: Vec<(u32, HashMap<u32, Vec<u8>>)>,
}
```
