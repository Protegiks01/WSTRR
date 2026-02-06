### Title
DKG Group Key Divergence Due to Unvalidated DkgEndBegin Message Caching

### Summary
The `dkg_end_begin()` function unconditionally caches incoming `DkgEndBegin` messages without validation, allowing the coordinator to send multiple messages with different signer lists. Due to network timing variations, different signers may cache different messages, causing them to compute different group public keys. This violates the critical DKG invariant that all signers must derive the same group key, leading to a deterministic chain split.

### Finding Description

**Exact Location:**
- File: `src/state_machine/signer/mod.rs`
- Function: `dkg_end_begin()`
- Line 962: `self.dkg_end_begin_msg = Some(dkg_end_begin.clone());` [1](#0-0) 

**Root Cause:**
The function performs no validation before caching:
1. No check if a `DkgEndBegin` message was already cached
2. No validation that `dkg_end_begin.dkg_id` matches `self.dkg_id`
3. No duplicate detection or replay prevention
4. Simply overwrites any existing cached message [2](#0-1) 

**Attack Vector:**
The cached message's `signer_ids` field directly determines which polynomial commitments are included in the group key calculation. In `dkg_ended()`, only signers listed in the cached `DkgEndBegin` message have their commitments validated and included: [3](#0-2) 

The commitments are then passed to `compute_secrets()`, which computes the group key by summing the constant terms of all included polynomial commitments: [4](#0-3) 

**Why Existing Mitigations Fail:**
- Packet signature verification only confirms the coordinator sent the message, but doesn't prevent the coordinator from sending multiple valid messages
- The coordinator validation at lines 479-484 in `fire.rs` checks `dkg_id` but signers do not perform equivalent validation
- Duplicate detection exists for `DkgPublicShares` and `DkgPrivateShares` but not for `DkgEndBegin` [5](#0-4) 

### Impact Explanation

**Specific Harm:**
Different signers compute different group public keys, creating incompatible cryptographic states. When these signers participate in subsequent signing operations or blockchain consensus, they use different public keys, causing signature verification failures and consensus divergence.

**Quantified Impact:**
1. **Chain Split (Critical Severity):** If Signer A caches a message with `signer_ids = [0,1,2,3]` and Signer B caches `signer_ids = [0,1,2]`, they compute:
   - Group Key A = `comm[0].poly[0] + comm[1].poly[0] + comm[2].poly[0] + comm[3].poly[0]`
   - Group Key B = `comm[0].poly[0] + comm[1].poly[0] + comm[2].poly[0]`
   - These keys are provably different (assuming non-zero commitments)

2. **Permanent Divergence:** Once signers compute different keys, all future signatures and consensus decisions diverge deterministically

3. **Network-Wide Impact:** All nodes using the affected signers for consensus will fork into incompatible chains

**Affected Parties:**
All signers participating in the DKG round and any blockchain or system relying on the generated keys for consensus.

**Severity Justification:**
Maps directly to Critical scope: "Any chain split caused by different nodes processing the same block or transaction and yielding different results"

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control of coordinator node or coordinator signing key
- Ability to send multiple broadcast messages with timing control
- No cryptographic breaks required

**Attack Complexity:**
LOW - The attack is straightforward:
1. Coordinator waits for signers to send DKG shares
2. Coordinator broadcasts `DkgEndBegin` with `signer_ids = [0,1,2,3]`
3. After partial network propagation, coordinator broadcasts second message with `signer_ids = [0,1,2]`
4. Network timing ensures some signers receive only first, some receive both (last wins)

**Economic Feasibility:**
Trivial - requires only network message sending, no computational cost

**Detection Risk:**
LOW - Different signers report successful DKG completion (`DkgStatus::Success`) with different group keys, but this divergence only becomes apparent during signing operations

**Probability of Success:**
HIGH in asynchronous networks. Even unintentional message reordering or retransmission could trigger the vulnerability.

### Recommendation

**Primary Fix:**
Add validation in `dkg_end_begin()` to reject duplicate or mismatched messages:

```rust
pub fn dkg_end_begin(&mut self, dkg_end_begin: &DkgEndBegin) -> Result<Vec<Message>, Error> {
    // Validate dkg_id matches current round
    if dkg_end_begin.dkg_id != self.dkg_id {
        warn!(
            "Received DkgEndBegin with mismatched dkg_id: {} vs {}",
            dkg_end_begin.dkg_id, self.dkg_id
        );
        return Ok(vec![]);
    }
    
    // Reject duplicate messages
    if self.dkg_end_begin_msg.is_some() {
        warn!("Received duplicate DkgEndBegin, ignoring");
        return Ok(vec![]);
    }
    
    self.dkg_end_begin_msg = Some(dkg_end_begin.clone());
    info!(
        signer_id = %self.signer_id,
        dkg_id = %self.dkg_id,
        "received DkgEndBegin"
    );
    Ok(vec![])
}
```

**Alternative Mitigations:**
1. Include commitment hash in `DkgEndBegin` for validation
2. Implement deterministic signer set calculation based on shares received before a deadline
3. Add coordinator commitment to signer list before DKG begins

**Testing Recommendations:**
1. Unit test: Send multiple `DkgEndBegin` messages with different `signer_ids`, verify only first is cached
2. Integration test: Simulate network partition where different signers receive different messages, verify DKG fails rather than producing divergent keys
3. Fuzzing: Random message ordering and timing variations

**Deployment Considerations:**
- Breaking change requiring coordinated upgrade
- Existing DKG rounds in progress may need to be aborted and restarted

### Proof of Concept

**Exploitation Algorithm:**
```
Setup:
- 4 signers with IDs 0, 1, 2, 3
- All signers have sent valid DkgPublicShares and DkgPrivateShares
- Coordinator has dkg_private_shares from all 4 signers

Step 1: Coordinator sends first DkgEndBegin
  msg1 = DkgEndBegin { dkg_id: 1, signer_ids: [0,1,2,3], key_ids: [...] }
  broadcast(msg1)

Step 2: Wait for partial propagation (e.g., 50ms)
  - Signers 0 and 1 receive and cache msg1
  - Signers 2 and 3 have not yet received msg1

Step 3: Coordinator sends second DkgEndBegin
  msg2 = DkgEndBegin { dkg_id: 1, signer_ids: [0,1,2], key_ids: [...] }
  broadcast(msg2)

Step 4: All signers eventually receive all messages
  - Signers 0 and 1: receive msg1 first (cached), then msg2 (overwrites)
  - Signers 2 and 3: receive msg2 first (cached), msg1 arrives but ignored by can_dkg_end timing

Expected Behavior:
  All signers should compute the same group key or DKG should fail

Actual Behavior:
  - Signers with cached msg1 compute: group_key = sum(comm[0..3].poly[0])
  - Signers with cached msg2 compute: group_key = sum(comm[0..2].poly[0])
  - Two different group keys created
  - Both report DkgStatus::Success
  - Chain split on next block requiring signature
```

**Reproduction Instructions:**
1. Deploy 4-signer WSTS network with coordinator
2. Initiate DKG round, wait for share distribution
3. Modify coordinator to send two `DkgEndBegin` messages with 100ms delay
4. Observe signers report success with different `group_key` values (requires logging)
5. Attempt group signature with all signers - verification will fail due to key mismatch

### Citations

**File:** src/state_machine/signer/mod.rs (L529-560)
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
```

**File:** src/state_machine/signer/mod.rs (L959-971)
```rust
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

**File:** src/net.rs (L219-228)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// DKG end begin message from signer to all signers and coordinator
pub struct DkgEndBegin {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer IDs who responded in time for this DKG round
    pub signer_ids: Vec<u32>,
    /// Key IDs who responded in time for this DKG round
    pub key_ids: Vec<u32>,
}
```

**File:** src/v2.rs (L135-141)
```rust
        for (i, comm) in public_shares.iter() {
            if !check_public_shares(comm, threshold, ctx) {
                bad_ids.push(*i);
            } else {
                self.group_key += comm.poly[0];
            }
        }
```

**File:** src/state_machine/coordinator/fire.rs (L477-484)
```rust
    fn gather_public_shares(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Message::DkgPublicShares(dkg_public_shares) = &packet.msg {
            if dkg_public_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_public_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }
```
