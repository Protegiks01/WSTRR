### Title
FIRE Coordinator Aggregate Key Double-Counting via Duplicate Party IDs in DkgPublicShares

### Summary
The FIRE coordinator's `dkg_end_gathered()` function computes the aggregate public key by directly iterating over `DkgPublicShares.comms` vectors without deduplication, allowing malicious signers to include duplicate `party_id` values that get counted multiple times. This causes the coordinator to compute a different aggregate public key than the signers, breaking signature verification and causing denial of service for all signing operations after DKG completion.

### Finding Description

**Exact Code Location:**

The vulnerability exists in the FIRE coordinator's aggregate key computation: [1](#0-0) 

This code uses `flat_map` to iterate over all `comms` vectors from all signers and sums the first coefficient of each polynomial commitment without checking for duplicate `party_id` values.

**Root Cause:**

The `DkgPublicShares` struct defines `comms` as a `Vec<(u32, PolyCommitment)>`: [2](#0-1) 

There is **no validation** to prevent duplicate `party_id` values within this vector. The only validation checks that each `party_id` belongs to the sending signer: [3](#0-2) 

This validation confirms ownership but does not check for duplicates within the vector.

**Why Existing Mitigations Fail:**

1. The `set_key_and_party_polynomials()` function DOES check for duplicates, but it's only used when loading saved state, not during normal DKG flow: [4](#0-3) 

2. The FROST coordinator is NOT vulnerable because it computes the aggregate key from `party_polynomials` HashMap (which automatically deduplicates): [5](#0-4) 

3. Signers compute their group key using a `commitments` HashMap, also deduplicating: [6](#0-5) 

**Critical Inconsistency:**

The FIRE coordinator stores commitments in `party_polynomials` HashMap (deduplicated) but computes the aggregate key from raw `comms` vectors (non-deduplicated): [7](#0-6) 

### Impact Explanation

**Specific Harm:**

A malicious signer can send `DkgPublicShares` with duplicate `party_id` values such as:
```
comms: [(1, comm_A), (2, comm_B), (1, comm_C)]
```

This causes:
1. **FIRE Coordinator** computes: `Y_coord = comm_A.poly[0] + comm_B.poly[0] + comm_C.poly[0]` (party_id 1 counted twice)
2. **Signers** compute: `Y_signer = comm_C.poly[0] + comm_B.poly[0]` (HashMap keeps last entry for party_id 1)
3. **Result**: `Y_coord ≠ Y_signer`

**Who is Affected:**

All participants in any DKG round where a single malicious signer sends duplicates. The entire signing group becomes unable to produce valid signatures.

**Severity Justification:**

This maps to **High** severity per the protocol scope:
- **"Any remotely-exploitable denial of service"** - Any registered signer can exploit this
- The DKG appears to succeed, but all subsequent signing operations fail
- Affects protocol availability and could impact dependent systems (Stacks blockchain)
- Could be interpreted as **"network denial of service impacting more than 10 percent of miners"** if multiple signing groups are affected

While not directly causing fund loss, it prevents the threshold signature scheme from functioning, potentially blocking critical blockchain operations.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Must be a registered signer with valid credentials
- No cryptographic breaks required
- No special network position needed
- Simple message construction

**Attack Complexity:**
- Trivial: Attacker constructs a single `DkgPublicShares` message with duplicate `party_id` values
- Example: If attacker controls party_ids [5, 6], they send `comms: [(5, C5), (6, C6), (5, C5')]`
- The packet signature validation passes (attacker is legitimate signer)
- No timing attacks or race conditions required

**Economic Feasibility:**
- Zero cost beyond normal signer participation
- No additional computational resources needed
- Can be repeated across multiple DKG rounds

**Detection Risk:**
- Low: The DKG phase completes successfully with no errors
- The issue only manifests during signing when verification fails
- Difficult to attribute to specific malicious signer without detailed logging
- Appears as signature verification failure rather than malicious input

**Estimated Probability of Success:**
- 100% if attacker is a registered signer
- No defenses in place to prevent or detect this attack
- Guaranteed to cause signing failures after DKG completion

### Recommendation

**Primary Fix:**

Add duplicate detection in the FIRE coordinator's `gather_public_shares()` function:

```rust
// In gather_public_shares, after line 506
let mut seen_party_ids = HashSet::new();
for (party_id, _) in &dkg_public_shares.comms {
    if !seen_party_ids.insert(*party_id) {
        warn!(signer_id = %dkg_public_shares.signer_id, party_id = %party_id, 
              "Duplicate party_id in DkgPublicShares");
        return Ok(()); // Reject the message
    }
}
```

**Alternative Fix:**

Modify `dkg_end_gathered()` to use `party_polynomials` HashMap (like FROST):

```rust
// Replace lines 803-807 with:
let key = self
    .party_polynomials
    .iter()
    .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);
```

This ensures consistency with the cached `party_polynomials` computed at lines 797-799.

**Additional Validation:**

Add the same duplicate check that exists in `set_key_and_party_polynomials()` to the normal DKG flow: [4](#0-3) 

**Testing Recommendations:**
1. Unit test: Signer sends `DkgPublicShares` with duplicate `party_id` values
2. Integration test: Verify DKG fails or aggregate keys match between coordinator and signers
3. Test with FIRE coordinator specifically (FROST is already safe)

**Deployment Considerations:**
- This is a breaking change that will reject previously accepted messages
- Coordinate deployment across all nodes to avoid incompatibility
- Consider logging duplicate detections for forensic analysis

### Proof of Concept

**Exploitation Steps:**

1. **Setup**: Attacker is registered as signer_id=10 controlling party_ids [20, 21]

2. **Craft Malicious Message**: Create `DkgPublicShares` with duplicate party_id 20:
   ```
   DkgPublicShares {
       dkg_id: 1,
       signer_id: 10,
       comms: [
           (20, PolyCommitment { poly: [P1, ...] }),  // First commitment for party 20
           (21, PolyCommitment { poly: [P2, ...] }),  // Commitment for party 21
           (20, PolyCommitment { poly: [P3, ...] })   // Duplicate for party 20
       ],
       kex_public_key: Point { ... }
   }
   ```

3. **Send Message**: Attacker signs and broadcasts this message during DKG public share phase

4. **Validation Passes**: The message passes all existing validations:
   - Each party_id (20, 21) belongs to signer_id 10 ✓
   - Packet signature is valid ✓
   - No duplicate detection exists ✗

5. **Coordinator Processing**:
   - Stores message in `dkg_public_shares[10]`
   - In `dkg_end_gathered()`, computes: `aggregate_key = P1 + P2 + P3` (party 20 counted twice)

6. **Signer Processing**:
   - Each signer inserts into `commitments` HashMap: `{20: P3, 21: P2}` (P1 overwritten by P3)
   - Computes: `group_key = P3 + P2` (party 20 counted once)

7. **Result**: 
   - Coordinator: `aggregate_key = P1 + P2 + P3`
   - Signers: `group_key = P2 + P3`
   - **Keys mismatch**: `aggregate_key ≠ group_key`

8. **Signing Failure**: When signing begins:
   - Signers generate shares based on their `group_key`
   - Coordinator verifies against its `aggregate_key`
   - Verification always fails → **Denial of Service**

**Expected vs Actual Behavior:**

- **Expected**: DKG should reject messages with duplicate party_ids, or at minimum, ensure coordinator and signers compute identical aggregate keys
- **Actual**: FIRE coordinator counts duplicates multiple times, creating key mismatch and permanent signing failure

**Reproduction Instructions:**

Run with FIRE coordinator, register test signers, and inject a `DkgPublicShares` message with duplicate party_ids during DKG. Observe that DKG completes but all subsequent signature verifications fail.

---

## Notes

This vulnerability affects **only the FIRE coordinator implementation**. The FROST coordinator is not vulnerable because it computes the aggregate key from the `party_polynomials` HashMap, which automatically deduplicates entries. Signers also use HashMap storage, so they compute the correct (deduplicated) group key. The inconsistency between coordinator and signer aggregate key computations is the root cause of the denial of service.

### Citations

**File:** src/state_machine/coordinator/fire.rs (L797-807)
```rust
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
```

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

**File:** src/state_machine/coordinator/frost.rs (L435-438)
```rust
        let key = self
            .party_polynomials
            .iter()
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);
```

**File:** src/state_machine/coordinator/frost.rs (L918-922)
```rust
        let party_polynomials_len = party_polynomials.len();
        let party_polynomials = HashMap::from_iter(party_polynomials);
        if party_polynomials.len() != party_polynomials_len {
            return Err(Error::DuplicatePartyId);
        }
```
