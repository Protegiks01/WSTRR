# Audit Report

## Title
Unbounded Message Serialization Sizes Enable Memory Exhaustion DoS

## Summary
The WSTS library stores and processes DKG messages without validating vector sizes, allowing malicious signers to cause denial of service through memory and CPU exhaustion. Messages with excessive polynomial commitments are accepted, hashed for signature verification, and stored in coordinator state before size validation occurs in later protocol phases.

## Finding Description

The `DkgPublicShares` message structure contains unbounded vectors that are processed without size validation before storage. [1](#0-0) 

The `comms` field is defined as `Vec<(u32, PolyCommitment)>` with no maximum size constraint, and each `PolyCommitment` contains an unbounded `poly: Vec<Point>` field. [2](#0-1) 

During signature verification (if enabled), the `DkgPublicShares::hash` method iterates through all entries in `comms` and all Points in each polynomial, compressing each Point (33 bytes). This occurs before any size validation. [3](#0-2) 

In the coordinator's `gather_public_shares` function, messages are cloned and stored immediately in state without checking vector bounds or polynomial sizes. [4](#0-3)  The same pattern exists in the FireCoordinator implementation. [5](#0-4) 

The `check_public_shares` validation function only verifies that the polynomial length equals the configured threshold, not that it's within reasonable absolute bounds. [6](#0-5) 

This validation occurs much later during the DkgEnd phase, after resources have already been consumed. [7](#0-6) [8](#0-7) 

A malicious signer can construct messages with arbitrary vector sizes (e.g., 10,000 comms entries with 10,000 Points each) and sign them with their valid private key. These messages will be accepted, signature-verified (consuming CPU), and stored (consuming memory) before eventual rejection during DkgEnd validation.

## Impact Explanation

This vulnerability enables remotely-exploitable denial of service against coordinator and signer nodes. A malicious signer can craft `DkgPublicShares` messages with excessive polynomial commitments (e.g., 10,000 entries × 10,000 Points = 3.3 GB after decompression). When received, the coordinator must:

1. Hash the entire message during signature verification, iterating through millions of Points and performing point compression operations (CPU exhaustion)
2. Clone and store the entire message structure in state (memory exhaustion)

Since DKG completion is required before any threshold signatures can be generated, preventing DKG through DoS prevents the entire signing functionality. This maps to **"Low: Any remotely-exploitable denial of service in a node"** in the protocol scope, as it renders nodes unresponsive and prevents signature generation without completely shutting down the network.

Multiple concurrent malicious messages from different registered signers could compound the impact, especially in resource-constrained environments.

## Likelihood Explanation

**High Likelihood** - The attack is trivially exploitable:

**Required Attacker Capabilities:**
- Must be a registered signer with valid credentials (within protocol threat model)
- Ability to send network messages to coordinators

**Attack Complexity:** Very Low
- Simply construct oversized message by populating vectors with excessive elements
- Sign with valid private key (no cryptographic bypasses needed)
- Executable with basic script modifications

**Economic Feasibility:** High
- Minimal computational cost (just memory allocation)
- Single message impacts multiple nodes simultaneously
- No ongoing costs or resource requirements

**Detection Risk:** Low
- No size limits exist to reject messages before processing
- Messages pass initial validation checks (signature verification succeeds)
- Only fail validation after resource consumption

**Success Probability:** High
- Works immediately upon message receipt
- No race conditions or timing dependencies
- Affects all coordinator/signer implementations
- Repeatable across DKG rounds

## Recommendation

Implement size validation before message processing and storage:

1. **Add bounds checking in `gather_public_shares`:**
   - Validate that `comms.len()` matches expected key_ids for the signer (from configuration)
   - Validate that each `comm.poly.len() == threshold` BEFORE storage
   - Reject messages that exceed reasonable bounds

2. **Add early validation in packet processing:**
   - Before calling `packet.verify()`, check message sizes
   - Define maximum acceptable sizes based on configuration parameters (num_keys, threshold)
   - Return error for oversized messages without processing

3. **Add configuration limits:**
   - Add `max_poly_commitments_per_message` to Config
   - Add `max_polynomial_degree` to Config
   - Enforce these limits at message receipt

Example fix for `gather_public_shares`:

```rust
// Validate comms size matches expected key_ids for this signer
let expected_key_ids = self.config.public_keys.signer_key_ids.get(&dkg_public_shares.signer_id);
if let Some(key_ids) = expected_key_ids {
    if dkg_public_shares.comms.len() != key_ids.len() {
        warn!("Invalid comms size from signer {}", dkg_public_shares.signer_id);
        return Ok(());
    }
    
    // Validate polynomial sizes BEFORE storage
    let threshold: usize = self.config.threshold.try_into().unwrap();
    for (party_id, comm) in &dkg_public_shares.comms {
        if comm.poly.len() != threshold {
            warn!("Invalid polynomial length from signer {}", dkg_public_shares.signer_id);
            return Ok(());
        }
    }
}

// Only store after validation passes
self.dkg_public_shares.insert(...);
```

## Proof of Concept

A test demonstrating this vulnerability would construct an oversized `DkgPublicShares` message, sign it with a valid signer key, and verify that the coordinator consumes excessive resources during `process_message` before eventually rejecting it in the DkgEnd phase. The test would measure memory allocation and processing time to confirm resource exhaustion occurs before validation.

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

**File:** src/net.rs (L152-163)
```rust
impl Signable for DkgPublicShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PUBLIC_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        for (party_id, comm) in &self.comms {
            hasher.update(party_id.to_be_bytes());
            for a in &comm.poly {
                hasher.update(a.compress().as_bytes());
            }
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

**File:** src/state_machine/coordinator/frost.rs (L317-321)
```rust
            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            for (party_id, comm) in &dkg_public_shares.comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
```

**File:** src/state_machine/coordinator/fire.rs (L505-506)
```rust
            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L632-637)
```rust
                                for (party_id, comm) in &dkg_public_shares.comms {
                                    if !check_public_shares(
                                        comm,
                                        threshold,
                                        &self.current_dkg_id.to_be_bytes(),
                                    ) {
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
