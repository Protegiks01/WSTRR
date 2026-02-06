### Title
Missing DKG Round ID Validation Before Duplicate Check Enables Denial of Service

### Summary
The `dkg_private_shares()` function in the Signer state machine lacks validation that incoming shares match the current DKG round ID (`dkg_id`) before performing the duplicate check and storing shares. This allows an attacker to inject or replay shares from wrong DKG rounds, which pass the duplicate check and block legitimate shares, causing DKG failure and preventing transaction signing.

### Finding Description

**Exact Code Location:**
- File: `src/state_machine/signer/mod.rs`
- Function: `dkg_private_shares()`
- Lines: 1028-1110, specifically the duplicate check at lines 1058-1061 [1](#0-0) 

**Root Cause:**
The function performs validation checks in this order:
1. Validates `signer_id` exists in config [2](#0-1) 

2. Validates party IDs [3](#0-2) 

3. Performs duplicate check keyed only by `signer_id` [1](#0-0) 

4. Stores shares before cryptographic validation [4](#0-3) 

**Critically missing:** No validation that `dkg_private_shares.dkg_id` matches `self.dkg_id`. The `DkgPrivateShares` message contains a `dkg_id` field that is included in the message signature, but this field is never checked against the current round. [5](#0-4) 

**Why Existing Mitigations Fail:**

The Coordinator state machines (both FIRE and FROST) correctly validate `dkg_id` BEFORE the duplicate check: [6](#0-5) [7](#0-6) 

However, the Signer state machine does not perform this validation. Message authentication (when enabled) verifies the signature but does not validate round ID correctness: [8](#0-7) 

The signature verification confirms the message was signed by the claimed signer but allows any `dkg_id` value: [9](#0-8) 

### Impact Explanation

**Specific Harm:**
An attacker can cause DKG failure by injecting shares with incorrect `dkg_id` values, preventing legitimate shares from being processed. Since DKG must complete successfully before the group can sign transactions, this blocks transaction signing capability.

**Attack Scenario:**
1. Attacker obtains a validly-signed `DkgPrivateShares` message from a previous DKG round (round N-1) or forges one if authentication is disabled
2. During current DKG round N, attacker replays/sends the old message before legitimate shares arrive
3. The message has `dkg_id = N-1` but `signer_id = X` 
4. No `dkg_id` validation occurs, duplicate check passes (first message from signer X)
5. Wrong-round shares are stored and associated with signer X
6. Legitimate shares with correct `dkg_id = N` arrive from signer X
7. Duplicate check rejects them (already have shares from signer X)
8. DKG proceeds with wrong-round shares which fail cryptographic validation
9. DKG fails with `BadPrivateShares` error
10. Manual restart required, no automatic recovery [10](#0-9) 

**Who is Affected:**
All participants in the DKG round. The entire signing group cannot complete DKG and therefore cannot sign transactions.

**Severity Justification:**
This maps to **Medium severity** ("transient consensus failures") or **Low severity** ("remotely-exploitable denial of service in a node") depending on recovery time and impact scope. If DKG failure prevents transaction confirmation for extended periods, it could approach Critical severity. The coordinator does not automatically restart failed DKG rounds - manual intervention is required.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Network-level access to inject or intercept messages between signers
- Ability to replay previously captured messages OR
- If `verify_packet_sigs = false`: ability to forge messages from any signer

**Attack Complexity:**
- Low complexity: Simply replay a captured `DkgPrivateShares` message from any previous DKG round
- Messages remain validly signed (signature includes `dkg_id`) so authentication checks pass
- Default configuration has `verify_packet_sigs = true`, but this can be disabled [11](#0-10) 

**Economic Feasibility:**
- Minimal cost: requires only network positioning to replay messages
- No cryptographic breaks needed
- No need to compromise signing keys (if using replayed messages)

**Detection Risk:**
- Low detection risk: appears as legitimate protocol message
- Only detected when DKG validation fails, at which point damage is done

**Estimated Probability:**
- Moderate to High if attacker has network access
- Guaranteed success with single malicious signer or network attacker position

### Recommendation

**Primary Fix:**
Add `dkg_id` validation before the duplicate check in `dkg_private_shares()`, matching the coordinator implementations:

```rust
// After line 1056, before line 1058:
if dkg_private_shares.dkg_id != self.dkg_id {
    warn!(
        "Received DkgPrivateShares with dkg_id {} but expected {}",
        dkg_private_shares.dkg_id,
        self.dkg_id
    );
    return Ok(vec![]);
}
```

**Alternative Mitigations:**
1. Make `dkg_private_shares` keyed by `(signer_id, dkg_id)` tuple instead of just `signer_id`
2. Clear `dkg_private_shares` immediately when `dkg_id` changes
3. Reject all messages if current state doesn't match expected DKG phase

**Testing Recommendations:**
1. Add test case: send shares with `dkg_id = current_dkg_id - 1`, verify rejection
2. Add test case: send shares with `dkg_id = current_dkg_id + 1`, verify rejection  
3. Add test case: send valid shares followed by replay, verify second message rejected with appropriate error
4. Verify DKG completes successfully when all shares have correct `dkg_id`

**Deployment Considerations:**
- This is a protocol-level fix that should be deployed to all signers
- Backward compatible: only adds validation, doesn't change message format
- No state migration needed

### Proof of Concept

**Exploitation Steps:**

1. **Setup**: Start DKG round with `dkg_id = 5`
2. **Capture**: Record a `DkgPrivateShares` message from signer A during DKG round 4 (has `dkg_id = 4`, signed by signer A's key)
3. **Start Round 5**: Coordinator initiates DKG round 5
4. **Attack**: Replay the captured message (with `dkg_id = 4`) before signer A's legitimate message arrives
5. **Expected behavior**: Message should be rejected due to `dkg_id` mismatch
6. **Actual behavior**: Message is accepted and stored because:
   - Signature verification passes (valid signature from signer A)
   - `signer_id` validation passes (signer A exists in config)
   - Party ID validation passes
   - No `dkg_id` validation occurs
   - Duplicate check passes (first message from signer A)
7. **Result**: Legitimate shares from signer A (with `dkg_id = 5`) are rejected by duplicate check
8. **Final state**: DKG fails when attempting to validate wrong-round shares against current commitments

**Reproduction:**
```rust
// In test environment:
let mut signer = create_test_signer(dkg_id: 5);
let old_shares = create_dkg_private_shares(dkg_id: 4, signer_id: 1);
let valid_shares = create_dkg_private_shares(dkg_id: 5, signer_id: 1);

// Send old shares first
signer.dkg_private_shares(&old_shares, &mut rng); // Accepted
assert!(signer.dkg_private_shares.contains_key(&1));

// Try to send valid shares
signer.dkg_private_shares(&valid_shares, &mut rng); // Rejected by duplicate check
// DKG will fail in validation phase
```

**Notes:**
The vulnerability exists because the duplicate check prevents ANY second message from the same `signer_id`, regardless of `dkg_id`. While this correctly prevents adaptive attacks within the same round (where a signer tries to modify shares after seeing commitments), the lack of `dkg_id` validation before the duplicate check creates a cross-round replay vulnerability.

### Citations

**File:** src/state_machine/signer/mod.rs (L347-347)
```rust
            verify_packet_sigs: true,
```

**File:** src/state_machine/signer/mod.rs (L463-470)
```rust
        if self.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
        }
```

**File:** src/state_machine/signer/mod.rs (L504-620)
```rust
    pub fn dkg_ended<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<Message, Error> {
        if !self.can_dkg_end() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadState),
            }));
        }

        // only use the public shares from the DkgEndBegin signers
        let mut missing_public_shares = HashSet::new();
        let mut missing_private_shares = HashSet::new();
        let mut bad_public_shares = HashSet::new();
        let threshold: usize = self.threshold.try_into().unwrap();

        let Some(dkg_end_begin) = &self.dkg_end_begin_msg else {
            // no cached DkgEndBegin message
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadState),
            }));
        };

        // fist check to see if dkg_threshold has been met
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
            } else {
                missing_public_shares.insert(*signer_id);
            }
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
        }

        if !missing_public_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::MissingPublicShares(missing_public_shares)),
            }));
        }

        if !bad_public_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadPublicShares(bad_public_shares)),
            }));
        }

        if !missing_private_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::MissingPrivateShares(
                    missing_private_shares,
                )),
            }));
        }

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
```

**File:** src/state_machine/signer/mod.rs (L1037-1041)
```rust
        // check that the signer_id exists in the config
        let Some(_signer_public_key) = self.public_keys.signers.get(&src_signer_id) else {
            warn!(%src_signer_id, "No public key configured");
            return Ok(vec![]);
        };
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

**File:** src/state_machine/signer/mod.rs (L1063-1064)
```rust
        self.dkg_private_shares
            .insert(src_signer_id, dkg_private_shares.clone());
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

**File:** src/net.rs (L540-556)
```rust
            Message::DkgPrivateShares(msg) => {
                // Private shares have key IDs from [0, N) to reference IDs from [1, N]
                // in Frost V4 to enable easy indexing hence ID + 1
                // TODO: Once Frost V5 is released, this off by one adjustment will no longer be required
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a DkgPrivateShares message with an invalid signature from signer_id {} key {}", msg.signer_id, &public_key);
                        return false;
                    }
                } else {
                    warn!(
                        "Received a DkgPrivateShares message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
```

**File:** src/state_machine/coordinator/fire.rs (L527-532)
```rust
            if dkg_private_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_private_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }
```

**File:** src/state_machine/coordinator/frost.rs (L338-343)
```rust
            if dkg_private_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_private_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }
```
