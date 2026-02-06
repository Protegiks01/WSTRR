### Title
Unbounded ID Proof Verification Enables Computational DoS During DKG

### Summary
The `ID::verify()` function performs expensive elliptic curve point operations without any limit on how many times it can be invoked per message. A malicious signer can send a `DkgPublicShares` message containing an arbitrarily large number of polynomial commitments, each requiring cryptographic verification. When other nodes process reported failures, they synchronously verify all commitments, causing CPU exhaustion that can prevent DKG completion and block signature generation.

### Finding Description

**Exact Code Location:**
- Vulnerable function: [1](#0-0) 
- Called from: [2](#0-1) 
- Attack trigger in coordinator: [3](#0-2) 
- Attack trigger in signer: [4](#0-3) 

**Root Cause:**
The `ID::verify()` function performs two scalar multiplications and one point addition - expensive cryptographic operations. The `DkgPublicShares` message structure contains an unbounded `Vec<(u32, PolyCommitment)>` field called `comms` [5](#0-4) , with no validation on its size when messages are received [6](#0-5) .

When the coordinator or signers process `DkgEnd` messages reporting `BadPublicShares` failures, they iterate through every commitment in the malicious message and call `check_public_shares()` for each one, which internally calls `ID::verify()`. There is no size limit, early termination, or rate limiting.

**Why Existing Mitigations Fail:**
- **Duplicate message rejection** [7](#0-6) : Only prevents multiple messages from the same `signer_id`, but doesn't limit the number of commitments within a single message
- **Packet signature verification** [8](#0-7) : Requires authentication to send messages, but a malicious legitimate signer can still exploit this, and can be disabled via configuration
- **Timeouts** [9](#0-8) : Only apply to message gathering phases, not to the synchronous processing of individual messages

### Impact Explanation

**Specific Harm:**
A malicious signer can cause all honest signers and the coordinator to spend excessive CPU time verifying fake ID proofs. With 100,000 fake commitments at approximately 0.5ms per `ID::verify()` operation, this results in ~50 seconds of CPU exhaustion per node. With 1 million commitments, this extends to 8+ minutes of blocked processing.

**Quantified Impact:**
- All honest signers become unresponsive during verification
- DKG cannot complete within timeout windows, causing the round to fail
- Signature generation is blocked until DKG succeeds
- In systems using WSTS for Bitcoin transaction signing (e.g., Stacks), this prevents transaction confirmations

**Who is Affected:**
All coordinator and signer nodes participating in the DKG round when a malicious participant is present.

**Severity Justification:**
This maps to **Medium severity** under "Any transient consensus failures" - the DKG will fail and need to retry, causing temporary loss of signing capability. It could also be classified as **Low severity** under "Any remotely-exploitable denial of service in a node" for the CPU exhaustion aspect. It does not cause permanent fund loss or chain splits, so it is not Critical or High.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Must be a legitimate signer in the WSTS system (possess valid signing credentials), OR
- Configuration must have `verify_packet_sigs` set to `false` (allowing unauthenticated messages)

**Attack Complexity:**
Low. The attacker simply needs to:
1. Construct a `DkgPublicShares` message with a large `comms` vector
2. Populate it with fake `PolyCommitment` structures
3. Send the message during the DKG public shares phase

**Economic Feasibility:**
Extremely low cost. Creating fake commitments is computationally cheap (just random data). The attacker only needs to send one malicious message per DKG round to cause significant disruption.

**Detection Risk:**
Medium. The attack leaves evidence in logs and network traffic (large message sizes), and the malicious signer can be identified from the `signer_id` field. However, by the time detection occurs, the CPU exhaustion has already happened.

**Estimated Probability:**
High if any signer is compromised or acts maliciously. The attack is trivial to execute and guaranteed to succeed in causing CPU exhaustion.

### Recommendation

**Primary Fix:**
Enforce a maximum size on the `comms` vector in `DkgPublicShares` messages. Add validation when messages are received:

```rust
// In gather_public_shares function, after line 491:
let max_comms_per_signer = self.config.public_keys
    .signer_key_ids
    .get(&dkg_public_shares.signer_id)
    .map(|ids| ids.len())
    .unwrap_or(0);

if dkg_public_shares.comms.len() > max_comms_per_signer {
    warn!(
        signer_id = %dkg_public_shares.signer_id,
        comms_count = dkg_public_shares.comms.len(),
        expected = max_comms_per_signer,
        "DkgPublicShares has too many commitments"
    );
    return Ok(());
}
```

Apply the same validation in the signer's message processing code.

**Alternative Mitigations:**
1. Add a processing timeout for verification loops to prevent unbounded execution
2. Implement early termination after detecting a threshold number of invalid commitments
3. Rate-limit DKG messages per signer per time window

**Testing Recommendations:**
1. Create integration tests that send oversized `comms` vectors and verify rejection
2. Test that legitimate messages with correct commitment counts are accepted
3. Benchmark verification performance with maximum expected commitment counts

**Deployment Considerations:**
- This is a breaking protocol change if messages are already in flight
- Requires coordinated upgrade across all nodes
- Consider implementing as a soft limit first (warn but accept) before enforcing as a hard limit

### Proof of Concept

**Exploitation Algorithm:**

1. Attacker (malicious signer with ID `M`) creates a malicious `DkgPublicShares` message:
```
msg = DkgPublicShares {
    dkg_id: current_dkg_id,
    signer_id: M,
    comms: vec![(fake_party_id, fake_commitment); 100_000],
    kex_public_key: random_point
}
```

2. For each fake commitment, create invalid ID proofs:
```
fake_commitment = PolyCommitment {
    id: ID {
        id: random_scalar(),
        kG: random_point(),
        kca: random_scalar()
    },
    poly: vec![random_point(); threshold]
}
```

3. Send the message during DKG public shares phase

4. Honest signers receive and store the message (no size validation)

5. During DKG end phase, honest signers call `compute_secret()` which validates all public shares

6. Each node iterates through all 100,000 commitments, calling `check_public_shares()` → `ID::verify()` for each

7. Each `ID::verify()` performs:
   - Challenge computation (hash)
   - `self.kca * G` (scalar multiplication, ~0.2-0.5ms)
   - `c * A` (scalar multiplication, ~0.2-0.5ms)
   - Point addition and comparison

**Expected Behavior:**
Message should be rejected due to excessive commitment count.

**Actual Behavior:**
Message is accepted and stored. During verification, nodes spend 50-100 seconds processing fake commitments, causing DKG failure and preventing signature generation.

**Reproduction Steps:**
1. Set up a WSTS system with 3 signers
2. Modify one signer to send a `DkgPublicShares` message with 100,000 fake commitments
3. Observe that coordinator and other signers hang during DKG end processing
4. Monitor CPU usage showing sustained 100% on verification operations
5. Observe DKG timeout and failure

### Notes

This vulnerability is particularly concerning because:
- It affects both the coordinator and all honest signers simultaneously
- The attack is repeatable across multiple DKG rounds
- Normal expected commitment counts are very small (1-10 per signer), so a 100x or 1000x multiplier is clearly malicious but currently undetected
- The fix is straightforward but requires protocol-level changes to message validation

### Citations

**File:** src/schnorr.rs (L62-65)
```rust
    pub fn verify(&self, A: &Point, ctx: &[u8]) -> bool {
        let c = Self::challenge(&self.id, &self.kG, A, ctx);
        &self.kca * &G == &self.kG + c * A
    }
```

**File:** src/common.rs (L319-321)
```rust
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```

**File:** src/state_machine/coordinator/fire.rs (L218-224)
```rust
        if self.config.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.config.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
```

**File:** src/state_machine/coordinator/fire.rs (L497-500)
```rust
            if have_shares {
                info!(signer_id = %dkg_public_shares.signer_id, "received duplicate DkgPublicShares");
                return Ok(());
            }
```

**File:** src/state_machine/coordinator/fire.rs (L505-506)
```rust
            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L632-640)
```rust
                                for (party_id, comm) in &dkg_public_shares.comms {
                                    if !check_public_shares(
                                        comm,
                                        threshold,
                                        &self.current_dkg_id.to_be_bytes(),
                                    ) {
                                        bad_party_ids.push(party_id);
                                    }
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

**File:** src/net.rs (L147-147)
```rust
    pub comms: Vec<(u32, PolyCommitment)>,
```

**File:** src/state_machine/coordinator/mod.rs (L145-149)
```rust
    pub dkg_public_timeout: Option<Duration>,
    /// timeout to gather DkgPrivateShares messages
    pub dkg_private_timeout: Option<Duration>,
    /// timeout to gather DkgEnd messages
    pub dkg_end_timeout: Option<Duration>,
```
