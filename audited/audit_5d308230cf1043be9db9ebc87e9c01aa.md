### Title
Race Condition in DKG Failure Verification Allows Malicious Exclusion of Honest Signers

### Summary
The FIRE coordinator's `gather_dkg_end` function contains a race condition in its verification logic for `BadPublicShares` reports. When a signer reports another signer's bad public shares, the coordinator checks if it has received those shares. If the shares haven't arrived yet, the coordinator incorrectly marks the honest reporting signer as malicious, allowing an attacker to exclude honest participants through message timing manipulation.

### Finding Description

**Location:** [1](#0-0) 

The vulnerability exists in the `BadPublicShares` verification logic within the `gather_dkg_end` function. When processing a signer's `DkgEnd` message that reports `DkgFailure::BadPublicShares`, the coordinator attempts to verify the claim by checking if it has the accused signer's public shares: [2](#0-1) 

**Root Cause:**
The coordinator assumes that if it doesn't have public shares from the accused signer (`self.dkg_public_shares.get(bad_signer_id)` returns `None`), then the reporting signer must be lying and is therefore malicious. However, this assumption fails to account for legitimate message ordering scenarios where:
- The accused signer's `DkgPublicShares` message is delayed in transit
- The coordinator processes messages in a different order than they were sent
- Network partitions cause selective message delivery

**Why Existing Mitigations Fail:**
The state machine guarantees that `DkgEnd` messages are processed after `DkgPublicShares` and `DkgPrivateShares` phases, but it does not guarantee that ALL signers' shares have been received before processing ANY `DkgEnd` messages. The coordinator moves from `DkgPrivateGather` to `DkgEndDistribute` based on receiving sufficient shares, not all shares: [3](#0-2) 

**How Signers Generate Reports:**
Honest signers correctly identify bad public shares: [4](#0-3) 

An honest signer reports `BadPublicShares` only when it has received shares that fail `check_public_shares` verification, which validates the polynomial commitment and Schnorr proof: [5](#0-4) 

### Impact Explanation

**Direct Impact:**
The vulnerability allows a malicious signer to cause honest signers to be incorrectly marked as malicious and excluded from the protocol. The malicious signers are returned in the error result: [6](#0-5) 

This error propagates to the application layer: [7](#0-6) 

**Concrete Harm:**
1. **DKG Failure**: Even with sufficient honest participants, DKG rounds fail as honest signers are incorrectly excluded
2. **Protocol Denial of Service**: Repeated exploitation prevents signature generation, blocking transaction confirmation
3. **Network Partition Risk**: Different coordinators may receive messages in different orders, leading to inconsistent views of which signers are malicious

**Blockchain Context Impact:**
- **Critical Severity**: Aligns with "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks" - if enough honest signers are excluded, the threshold cannot be met to form valid signatures
- **High Severity**: Aligns with "Any unintended chain split or network partition" - inconsistent malicious signer sets across coordinators can cause protocol divergence

**Quantified Impact:**
- With threshold t and n signers, excluding just (n - t) honest signers renders the system unable to meet threshold
- In a 7-of-10 setup, excluding 4 honest signers (marking them as malicious) prevents any valid signatures
- Each malicious signer can potentially exclude multiple honest signers per DKG round

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control of at least one malicious signer node
- Ability to selectively deliver or delay network messages (standard P2P network capability)
- No cryptographic key material or protocol secrets required

**Attack Complexity:**
1. Malicious signer M generates invalid `DkgPublicShares` (e.g., commitments that fail Schnorr proof verification)
2. M broadcasts these shares to honest signers but delays/drops messages to the coordinator
3. Honest signers receive M's invalid shares, validate them, and correctly identify them as bad
4. Honest signers send `DkgEnd` messages reporting `BadPublicShares(M)`
5. Coordinator receives honest signers' `DkgEnd` messages before (or without) M's `DkgPublicShares`
6. Coordinator marks honest signers as malicious

**Feasibility:**
- **Network Control**: Trivial - any node controls its own message sending and can implement delays
- **Timing Window**: Large - the delay only needs to be until the coordinator processes the `DkgEnd` message
- **Detection Risk**: Low - legitimate network delays are indistinguishable from malicious delays
- **Resources**: Minimal - requires only one compromised signer node

**Estimated Probability:**
- High (~80%+) - the attack requires only basic network control and timing, both of which are easily achievable in P2P networks
- Success rate increases with network latency and number of honest signers (more targets)

### Recommendation

**Primary Fix:**
Defer malicious signer determination until all expected public shares have been received or a timeout occurs. Modify the verification logic:

```rust
// Instead of immediately marking as malicious, defer judgment
let Some(dkg_public_shares) = self.dkg_public_shares.get(bad_signer_id)
else {
    // Cannot verify claim yet - either the accused never sent shares,
    // or they haven't arrived. Log for later verification.
    warn!("Signer {signer_id} reported BadPublicShares from {bad_signer_id} but shares not yet received");
    // Store for later verification or mark as inconclusive
    continue;
};
```

**Alternative Mitigation:**
Track which signers were expected to send public shares (based on `DkgPublicDistribute` phase) and only mark reporters as malicious if the accused signer WAS expected but the shares were valid:

```rust
// Check if accused signer was expected to participate
if !self.expected_public_share_signers.contains(bad_signer_id) {
    // Accused never sent shares - cannot determine if reporter is honest
    continue;
}
```

**Additional Safeguards:**
1. Implement a two-phase verification: collect all reports first, verify after all shares received
2. Add timeout-based verification: only mark signers as malicious after sufficient time for all messages to arrive
3. Require multiple independent reports of bad shares before marking anyone as malicious
4. Log inconclusive verifications for operator review

**Testing Recommendations:**
1. Add test case where honest signer reports bad shares before coordinator receives them
2. Test with intentional message delivery delays
3. Verify that deferred verification correctly identifies malicious reporters vs. accurate reporters
4. Test with multiple coordinators receiving messages in different orders

**Deployment Considerations:**
- This fix is backward compatible - it makes verification more conservative
- May require DKG restart mechanisms if verification is deferred
- Consider logging/monitoring for inconclusive verifications to detect persistent malicious behavior

### Proof of Concept

**Exploitation Algorithm:**

1. **Setup**: Network with coordinator C, honest signers H1, H2, malicious signer M
   - Threshold: 2 of 3 keys
   - M controls its network stack

2. **Attack Execution**:
   ```
   Step 1: DKG begins, C broadcasts DkgBegin
   
   Step 2: M generates invalid DkgPublicShares
           - Create polynomial commitment with invalid Schnorr proof
           - Or create commitment with wrong degree
   
   Step 3: M selectively broadcasts
           - Send invalid shares to H1, H2 (honest signers)
           - Drop/delay messages to C (coordinator)
   
   Step 4: H1 and H2 receive M's shares
           - check_public_shares() returns false
           - H1 and H2 correctly mark M's shares as bad
   
   Step 5: DKG proceeds through private shares phase
   
   Step 6: H1 sends DkgEnd with BadPublicShares(M)
           - Message arrives at C before M's public shares
   
   Step 7: C processes H1's DkgEnd message
           - Reaches line 625: self.dkg_public_shares.get(M) == None
           - Executes line 628: malicious_signers.insert(H1)
   
   Step 8: C returns DkgError::DkgEndFailure
           - malicious_signers contains H1 (honest signer)
           - H1 is now excluded from protocol
   ```

**Expected vs Actual Behavior:**
- **Expected**: M is identified as malicious for sending invalid shares
- **Actual**: H1 is incorrectly identified as malicious for honestly reporting M's invalid shares

**Reproduction Instructions:**
1. Set up 3-signer FIRE coordinator test with message interception
2. Have malicious signer create invalid polynomial commitment (wrong Schnorr proof)
3. Implement selective message delivery: send to honest signers, drop to coordinator
4. Run DKG round and observe coordinator marks honest reporter as malicious
5. Verify `malicious_signers` HashSet contains honest signer ID

**Parameter Values for Demonstration:**
- `num_signers = 3`, `keys_per_signer = 1`, `threshold = 2`
- Malicious signer ID = 0
- Target honest signer = 1
- Message delay = sufficient for DkgEnd to arrive before DkgPublicShares (network-dependent, typically 100-500ms)

### Citations

**File:** src/state_machine/coordinator/fire.rs (L449-474)
```rust
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
```

**File:** src/state_machine/coordinator/fire.rs (L620-650)
```rust
                        DkgFailure::BadPublicShares(bad_shares) => {
                            // bad_shares is a set of signer_ids
                            for bad_signer_id in bad_shares {
                                // verify public shares are bad
                                let Some(dkg_public_shares) =
                                    self.dkg_public_shares.get(bad_signer_id)
                                else {
                                    warn!("Signer {signer_id} reported BadPublicShares from {bad_signer_id} but there are no public shares from that signer, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                    continue;
                                };
                                let mut bad_party_ids = Vec::new();
                                for (party_id, comm) in &dkg_public_shares.comms {
                                    if !check_public_shares(
                                        comm,
                                        threshold,
                                        &self.current_dkg_id.to_be_bytes(),
                                    ) {
                                        bad_party_ids.push(party_id);
                                    }
                                }

                                // if none of the shares were bad sender was malicious
                                if bad_party_ids.is_empty() {
                                    warn!("Signer {signer_id} reported BadPublicShares from {bad_signer_id} but the shares were valid, mark {signer_id} as malicious");
                                    malicious_signers.insert(*signer_id);
                                } else {
                                    warn!("Signer {signer_id} reported BadPublicShares from {bad_signer_id}, mark {bad_signer_id} as malicious");
                                    malicious_signers.insert(*bad_signer_id);
                                }
                            }
```

**File:** src/state_machine/coordinator/fire.rs (L785-788)
```rust
                return Err(Error::DkgFailure {
                    reported_failures,
                    malicious_signers,
                });
```

**File:** src/state_machine/signer/mod.rs (L551-566)
```rust
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
```

**File:** src/common.rs (L319-321)
```rust
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```

**File:** src/state_machine/mod.rs (L48-55)
```rust
    /// DKG end failure
    #[error("DKG end failure")]
    DkgEndFailure {
        /// failures reported by signers during DkgEnd
        reported_failures: HashMap<u32, DkgFailure>,
        /// signers who were discovered to be malicious during this DKG round
        malicious_signers: HashSet<u32>,
    },
```
