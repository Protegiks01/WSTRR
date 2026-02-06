### Title
Coordinator Can Force Premature DKG Completion With Arbitrary Signer Exclusion

### Summary
The coordinator can unilaterally exclude signers from DKG completion by sending `DkgEndBegin` with an incomplete signer list, as long as the threshold is met. Signers do not validate that the signer set matches the originally configured participants, allowing the coordinator to arbitrarily choose which signers receive key shares. This breaks the security assumption that all configured signers participate in DKG and can lead to consensus failures in dependent blockchain systems.

### Finding Description

The vulnerability exists in the coordinator's DKG finalization logic and the signer's validation of the `DkgEndBegin` message.

**Coordinator Side (src/state_machine/coordinator/fire.rs):** [1](#0-0) 

At line 463, the coordinator populates `DkgEndBegin.signer_ids` with only the signers who have sent private shares (`self.dkg_private_shares.keys()`). This list can be arbitrarily smaller than the total configured signers. [2](#0-1) 

Similarly, at line 434, `DkgPrivateBegin.signer_ids` is populated with only signers who sent public shares, progressively narrowing the participant set. [3](#0-2) 

At line 399, the initial `dkg_wait_signer_ids` is set to all configured signers `(0..self.config.num_signers)`, but this gets progressively narrowed at each phase. [4](#0-3) 

The timeout handler at lines 112-126 shows that if the threshold is met, the coordinator proceeds with DKG finalization even with fewer signers than originally configured.

**Signer Side (src/state_machine/signer/mod.rs):** [5](#0-4) 

The signer's `dkg_end_begin` handler simply stores the message without validation of the signer list. [6](#0-5) 

In `can_dkg_end()`, the signer only checks for shares from signers listed in the `DkgEndBegin` message (lines 705-709), not from all originally configured signers. [7](#0-6) 

The signer validates that the threshold is met (line 543) but does not validate that all expected signers are included in the `signer_ids` list. At line 532, it filters invalid IDs but doesn't check for completeness.

**Root Cause:**

The protocol allows the coordinator to progressively narrow the signer set at each DKG phase without requiring signers to validate that all originally configured participants are included. Signers have knowledge of `total_signers` but never check that the `signer_ids` list in `DkgEndBegin` includes all expected signers.

### Impact Explanation

**Specific Harm:**

1. **Arbitrary Signer Exclusion**: A malicious coordinator can exclude honest signers from receiving key shares while including only cooperative/malicious signers (as long as threshold is met).

2. **Security Model Degradation**: If a system is configured with N signers for security redundancy, but only threshold T signers actually receive shares, the security assumptions are violated. For example, with 10 configured signers but only 6 receiving shares, 4 signers are unexpectedly excluded.

3. **Consensus Failures**: In a blockchain context where different nodes expect different sets of signers to be active, this causes:
   - Invalid signature acceptance if excluded signers believe they should validate
   - Chain splits if nodes disagree on which signers control the threshold key
   - Transaction validation failures when the actual signer set doesn't match expectations

4. **Undetectable Exclusion**: Excluded signers have no way to know they should have been included, as they never receive `DkgPrivateBegin` or `DkgEndBegin` messages with the full participant list.

**Quantification:**

Consider a deployment with 10 signers and threshold 6:
- Coordinator excludes 4 honest signers
- Completes DKG with 6 cooperative signers
- The 4 excluded signers cannot participate in future signing operations
- Blockchain validation logic expecting 10 active signers will fail
- This maps to **High severity**: unintended chain split or network partition

### Likelihood Explanation

**Attacker Capabilities Required:**
- Control of the coordinator (either malicious coordinator or compromised coordinator key)
- No cryptographic breaks required
- No need to compromise individual signer keys

**Attack Complexity:**
The attack is straightforward:
1. Coordinator initiates DKG with `DkgBegin` to all signers
2. All signers respond with `DkgPublicShares`
3. Coordinator sends `DkgPrivateBegin` to only a subset of signers (≥ threshold)
4. Only that subset sends `DkgPrivateShares`
5. Coordinator sends `DkgEndBegin` listing only those signers
6. DKG completes with excluded signers unaware

**Economic Feasibility:**
- Low cost: requires only coordinator access
- High impact: allows control over which signers participate
- No detection: excluded signers cannot detect the exclusion

**Detection Risk:**
- Low: The protocol considers this normal timeout/non-response behavior
- Excluded signers appear to have simply not responded
- No cryptographic evidence of malicious behavior

**Estimated Probability:**
High - any coordinator (intentionally malicious or compromised) can execute this attack trivially.

### Recommendation

**Primary Fix:**

Add validation in the signer's `dkg_end_begin` handler to ensure all expected signers are included:

```rust
// In src/state_machine/signer/mod.rs, dkg_end_begin function
pub fn dkg_end_begin(&mut self, dkg_end_begin: &DkgEndBegin) -> Result<Vec<Message>, Error> {
    // Validate that all configured signers are included
    let expected_signers: HashSet<u32> = (0..self.total_signers).collect();
    let provided_signers: HashSet<u32> = dkg_end_begin.signer_ids.iter().copied().collect();
    
    if expected_signers != provided_signers {
        warn!(
            "DkgEndBegin missing signers. Expected: {:?}, Got: {:?}",
            expected_signers, provided_signers
        );
        return Err(Error::InvalidDkgPublicShares);
    }
    
    self.dkg_end_begin_msg = Some(dkg_end_begin.clone());
    Ok(vec![])
}
```

**Alternative Mitigation:**

If timeout-based exclusion is intended, require explicit consensus among signers about which participants to exclude, rather than allowing unilateral coordinator decision.

**Testing Recommendations:**
1. Add test case where coordinator sends `DkgEndBegin` with incomplete signer list
2. Verify signers reject the message
3. Test timeout scenarios to ensure legitimate exclusion still works with explicit agreement
4. Add integration tests with blockchain validation logic

**Deployment Considerations:**
- This is a breaking change requiring coordinated upgrade of all signers
- Existing deployments should audit historical DKG rounds to verify all expected signers participated
- Consider adding configuration option for "strict mode" vs "timeout-tolerant mode"

### Proof of Concept

**Exploitation Steps:**

1. **System Configuration:**
   - 10 signers (IDs 0-9)
   - Threshold: 6 key IDs
   - Each signer has 1 key ID
   - Coordinator controls message routing

2. **Attack Execution:**

   a. Coordinator sends `DkgBegin{dkg_id: 1}` to all 10 signers
   
   b. All 10 signers send `DkgPublicShares` to coordinator
   
   c. Coordinator sends `DkgPrivateBegin{dkg_id: 1, signer_ids: [0,1,2,3,4,5]}` to only 6 signers
      - Signers 6-9 never receive this message
   
   d. Signers 0-5 send `DkgPrivateShares` to each other
   
   e. Coordinator sends `DkgEndBegin{dkg_id: 1, signer_ids: [0,1,2,3,4,5], key_ids: []}` to signers 0-5
   
   f. Signers 0-5 validate:
      - Check threshold: 6 key IDs ≥ 6 threshold ✓
      - Check shares from [0,1,2,3,4,5]: all present ✓
      - No check that signers 6-9 should be included ✗
   
   g. Signers 0-5 send `DkgEnd{status: Success}` to coordinator
   
   h. DKG completes with only 6 signers instead of 10

3. **Expected vs Actual Behavior:**

   **Expected:** DKG should fail or wait for all 10 configured signers
   
   **Actual:** DKG succeeds with only 6 signers; signers 6-9 are excluded without notification

4. **Verification:**
   - Signers 6-9 never receive key shares
   - Future signing operations only involve signers 0-5
   - Blockchain nodes expecting 10 signers will reject signatures
   - System security reduced from 10-of-10 participation to 6-of-10

### Citations

**File:** src/state_machine/coordinator/fire.rs (L105-131)
```rust
            State::DkgPrivateGather => {
                if let Some(start) = self.dkg_private_start {
                    if let Some(timeout) = self.config.dkg_private_timeout {
                        if now.duration_since(start) > timeout {
                            // check dkg_threshold to determine if we can continue
                            let dkg_size = self.compute_dkg_private_size()?;

                            if self.config.dkg_threshold > dkg_size {
                                error!("Timeout gathering DkgPrivateShares for dkg round {} signing round {} iteration {}, dkg_threshold not met ({dkg_size}/{}), unable to continue", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, self.config.dkg_threshold);
                                let wait = self.dkg_wait_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::DkgError(DkgError::DkgPrivateTimeout(
                                        wait,
                                    ))),
                                ));
                            } else {
                                // we hit the timeout but met the threshold, continue
                                warn!("Timeout gathering DkgPrivateShares for dkg round {} signing round {} iteration {}, dkg_threshold was met ({dkg_size}/{}), ", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, self.config.dkg_threshold);
                                self.private_shares_gathered()?;
                                let packet = self.start_dkg_end()?;
                                return Ok((Some(packet), None));
                            }
                        }
                    }
                }
            }
```

**File:** src/state_machine/coordinator/fire.rs (L395-417)
```rust
    /// Ask signers to send DKG public shares
    pub fn start_public_shares(&mut self) -> Result<Packet, Error> {
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        self.dkg_wait_signer_ids = (0..self.config.num_signers).collect();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting Public Share Distribution"
        );
        let dkg_begin = DkgBegin {
            dkg_id: self.current_dkg_id,
        };
        let dkg_begin_packet = Packet {
            sig: dkg_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgBegin"),
            msg: Message::DkgBegin(dkg_begin),
        };

        self.move_to(State::DkgPublicGather)?;
        self.dkg_public_start = Some(Instant::now());
        Ok(dkg_begin_packet)
    }
```

**File:** src/state_machine/coordinator/fire.rs (L420-446)
```rust
    pub fn start_private_shares(&mut self) -> Result<Packet, Error> {
        // only wait for signers that returned DkgPublicShares
        self.dkg_wait_signer_ids = self
            .dkg_public_shares
            .keys()
            .cloned()
            .collect::<HashSet<u32>>();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting Private Share Distribution"
        );

        let dkg_begin = DkgPrivateBegin {
            dkg_id: self.current_dkg_id,
            signer_ids: self.dkg_public_shares.keys().cloned().collect(),
            key_ids: vec![],
        };
        let dkg_private_begin_msg = Packet {
            sig: dkg_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgPrivateBegin"),
            msg: Message::DkgPrivateBegin(dkg_begin),
        };
        self.move_to(State::DkgPrivateGather)?;
        self.dkg_private_start = Some(Instant::now());
        Ok(dkg_private_begin_msg)
    }
```

**File:** src/state_machine/coordinator/fire.rs (L448-475)
```rust
    /// Ask signers to compute shares and send DKG end
    pub fn start_dkg_end(&mut self) -> Result<Packet, Error> {
        // only wait for signers that returned DkgPublicShares
        self.dkg_wait_signer_ids = self
            .dkg_private_shares
            .keys()
            .cloned()
            .collect::<HashSet<u32>>();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting DkgEnd Distribution"
        );

        let dkg_end_begin = DkgEndBegin {
            dkg_id: self.current_dkg_id,
            signer_ids: self.dkg_private_shares.keys().cloned().collect(),
            key_ids: vec![],
        };
        let dkg_end_begin_msg = Packet {
            sig: dkg_end_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgPrivateBegin"),
            msg: Message::DkgEndBegin(dkg_end_begin),
        };
        self.move_to(State::DkgEndGather)?;
        self.dkg_end_start = Some(Instant::now());
        Ok(dkg_end_begin_msg)
    }
```

**File:** src/state_machine/signer/mod.rs (L528-549)
```rust
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
```

**File:** src/state_machine/signer/mod.rs (L685-721)
```rust
    pub fn can_dkg_end(&self) -> bool {
        debug!(
            "can_dkg_end: state {:?} DkgPrivateBegin {} DkgEndBegin {}",
            self.state,
            self.dkg_private_begin_msg.is_some(),
            self.dkg_end_begin_msg.is_some(),
        );

        if self.state == State::DkgPrivateGather {
            if let Some(dkg_private_begin) = &self.dkg_private_begin_msg {
                // need public shares from active signers
                for signer_id in &dkg_private_begin.signer_ids {
                    if !self.dkg_public_shares.contains_key(signer_id) {
                        debug!("can_dkg_end: false, missing public shares from signer {signer_id}");
                        return false;
                    }
                }

                if let Some(dkg_end_begin) = &self.dkg_end_begin_msg {
                    // need private shares from active signers
                    for signer_id in &dkg_end_begin.signer_ids {
                        if !self.dkg_private_shares.contains_key(signer_id) {
                            debug!("can_dkg_end: false, missing private shares from signer {signer_id}");
                            return false;
                        }
                    }
                    debug!("can_dkg_end: true");

                    return true;
                }
            }
        } else {
            debug!("can_dkg_end: false, bad state {:?}", self.state);
            return false;
        }
        false
    }
```

**File:** src/state_machine/signer/mod.rs (L958-971)
```rust
    /// handle incoming DkgEndBegin
    pub fn dkg_end_begin(&mut self, dkg_end_begin: &DkgEndBegin) -> Result<Vec<Message>, Error> {
        let msgs = vec![];

        self.dkg_end_begin_msg = Some(dkg_end_begin.clone());

        info!(
            signer_id = %self.signer_id,
            dkg_id = %self.dkg_id,
            "received DkgEndBegin"
        );

        Ok(msgs)
    }
```
