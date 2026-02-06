### Title
Unbounded Vector Deserialization in DkgPublicShares Enables Memory Exhaustion DoS

### Summary
The `DkgPublicShares` message contains two unbounded vectors (`comms` and nested `poly`) that are deserialized and stored in memory without size validation. A malicious or compromised signer can send oversized messages causing memory exhaustion and denial of service on receiving nodes (signers and coordinators). Validation only occurs later in the DKG process, after the memory has already been allocated.

### Finding Description

**Exact Code Locations:**

The `DkgPublicShares` struct defines an unbounded `comms` vector: [1](#0-0) 

Each `PolyCommitment` within `comms` contains an unbounded `poly` vector: [2](#0-1) 

When signers receive `DkgPublicShares`, the entire message is cloned and stored without bounds checking: [3](#0-2) 

When coordinators receive `DkgPublicShares`, the same unbounded storage occurs: [4](#0-3) 

**Root Cause:**

The vulnerability exists because bounds validation happens too late in the DKG lifecycle. The `check_public_shares` function validates that `poly.len() == threshold`: [5](#0-4) 

However, this validation is only called in the `dkg_ended` function after receiving `DkgEndBegin`: [6](#0-5) 

By this time, the oversized message has already been deserialized and stored in memory during the earlier `dkg_public_share` processing.

**Why Existing Mitigations Fail:**

Packet signature verification prevents unsigned messages but does not prevent oversized messages from legitimate (or compromised) signers: [7](#0-6) 

The signature check ensures the message came from the claimed signer but does not validate message size.

### Impact Explanation

**Specific Harm:**
An attacker can cause memory exhaustion and crash individual signer or coordinator nodes by sending oversized `DkgPublicShares` messages.

**Quantified Impact:**
- Expected legitimate size: ~10 parties × ~10 Points (threshold) = 100 Points
- Attack payload: 10,000 `comms` entries × 10,000 Points each = 100 million Points
- Memory consumption: 100M Points × ~100 bytes per Point = ~10 GB per message
- Multiple such messages can quickly exhaust available memory

**Who is Affected:**
All signers and coordinators receiving DKG messages from malicious or compromised participants.

**Severity Justification:**
This is **LOW** severity according to the protocol scope definition: "Any remotely-exploitable denial of service in a node." The attack causes individual node DoS but does not:
- Shut down the entire network (requires >10% miner impact)
- Cause chain splits or consensus failures
- Enable invalid signature acceptance
- Result in loss of funds

### Likelihood Explanation

**Required Attacker Capabilities:**
- Option 1: Compromise a signer's private network key to sign malicious packets
- Option 2: Exploit nodes with `verify_packet_sigs = false` (testing/misconfiguration)

**Attack Complexity:**
- Low: Attacker simply crafts a `DkgPublicShares` message with oversized vectors
- Serialization libraries (serde) will deserialize arbitrarily large vectors by default
- No cryptographic operations need to be broken

**Economic Feasibility:**
- Very low cost: Single malicious message can DoS a node
- Can be repeated to target multiple nodes
- No significant computational resources required

**Detection Risk:**
- Moderate: Large network packets may be detected by monitoring
- However, attack succeeds before detection can prevent memory allocation

**Estimated Probability:**
- High if packet verification is disabled
- Medium if a signer key is compromised (realistic threat model)
- Attack is practical and does not require sophisticated techniques

### Recommendation

**Primary Fix:**
Add bounds validation immediately upon receiving `DkgPublicShares`, before cloning and storing:

1. In `src/state_machine/signer/mod.rs` at the start of `dkg_public_share`:
   - Validate `dkg_public_shares.comms.len() <= expected_num_parties`
   - For each `PolyCommitment` in `comms`, validate `poly.len() <= threshold`
   - Reject oversized messages before storage

2. In `src/state_machine/coordinator/fire.rs` at the start of `gather_public_shares`:
   - Apply the same validation as above
   - Reject and log oversized messages

**Specific Code Changes:**
```rust
// Early in dkg_public_share() and gather_public_shares()
if dkg_public_shares.comms.len() > max_expected_parties {
    warn!("Received oversized comms vector, rejecting");
    return Ok(vec![]);
}

for (_, comm) in &dkg_public_shares.comms {
    if comm.poly.len() > max_threshold {
        warn!("Received oversized poly vector, rejecting");
        return Ok(vec![]);
    }
}
```

**Alternative Mitigations:**
- Set serde max depth/size limits on deserialization
- Implement rate limiting for DKG messages per signer
- Add memory usage monitoring with automatic rejection of large messages

**Testing Recommendations:**
- Unit tests with oversized `comms` and `poly` vectors
- Integration tests measuring memory consumption
- Fuzz testing with randomized vector sizes

**Deployment Considerations:**
- Deploy with conservative bounds (2-3x expected maximum)
- Monitor for legitimate cases that might exceed bounds
- Add metrics for rejected oversized messages

### Proof of Concept

**Exploitation Steps:**

1. Attacker obtains or compromises a signer's network private key
2. Crafts malicious `DkgPublicShares` message:
   - `comms` vector with 10,000 entries
   - Each `PolyCommitment` with `poly` vector of 10,000 Points
   - Valid signatures using compromised key

3. Sends message during DKG public share gathering phase
4. Victim node (signer or coordinator) receives message
5. Message passes signature verification
6. Deserialization allocates ~10 GB memory
7. Node stores cloned message without validation
8. Node crashes or becomes unresponsive due to memory exhaustion

**Parameter Values:**
```
comms.len() = 10,000
poly.len() = 10,000 (for each PolyCommitment)
Total Points = 10,000 × 10,000 = 100,000,000
Memory per Point ≈ 100 bytes (uncompressed in-memory representation)
Total Memory ≈ 100,000,000 × 100 = 10 GB
```

**Expected vs Actual Behavior:**
- Expected: Message with ~10 comms entries, each with ~10 Points (100 Points total, ~10 KB)
- Actual: Message accepted with 100M Points (~10 GB), causing memory exhaustion
- No bounds check prevents the attack before memory allocation

**Reproduction:**
1. Set up WSTS test environment with 2+ signers and 1 coordinator
2. Modify a signer to send oversized `DkgPublicShares` during DKG
3. Monitor memory usage on receiving nodes
4. Observe memory spike and potential OOM crash
5. Verify that validation only occurs in later `dkg_ended` call, after storage

### Citations

**File:** src/net.rs (L139-150)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// DKG public shares message from signer to all signers and coordinator
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

**File:** src/net.rs (L526-539)
```rust
            Message::DkgPublicShares(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a DkgPublicShares message with an invalid signature.");
                        return false;
                    }
                } else {
                    warn!(
                        "Received a DkgPublicShares message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
            }
```

**File:** src/common.rs (L26-33)
```rust
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
/// A commitment to a polynonial, with a Schnorr proof of ownership bound to the ID
pub struct PolyCommitment {
    /// The party ID with a schnorr proof
    pub id: ID,
    /// The public polynomial which commits to the secret polynomial
    pub poly: Vec<Point>,
}
```

**File:** src/common.rs (L319-321)
```rust
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```

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

**File:** src/state_machine/signer/mod.rs (L1023-1024)
```rust
        self.dkg_public_shares
            .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L505-506)
```rust
            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
```
