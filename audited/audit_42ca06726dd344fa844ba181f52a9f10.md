### Title
Unbounded Vector Size in DkgPrivateBegin Enables Memory and CPU Exhaustion DoS

### Summary
A malicious coordinator can create a `DkgPrivateBegin` message with arbitrarily large `signer_ids` and `key_ids` vectors (up to u32::MAX elements each, totaling ~34 GB), causing memory exhaustion and CPU-intensive hash computation on all signer nodes. This denial-of-service attack prevents DKG completion and blocks threshold signature operations.

### Finding Description

**Exact Code Location:**
- Vulnerable hash function: [1](#0-0) 
- Message structure definition: [2](#0-1) 
- Coordinator message creation (FROST): [3](#0-2) 
- Signer signature verification entry point: [4](#0-3) 

**Root Cause:**
The `Config` struct allows unbounded `num_signers` and `num_keys` values with no validation in its constructors [5](#0-4) . When the coordinator creates a `DkgPrivateBegin` message, it populates vectors by collecting ranges based on these unconstrained configuration values [6](#0-5) . The hash function then iterates through every element in both vectors [7](#0-6) .

**Why Existing Mitigations Fail:**
There are no size limits on:
1. `num_signers` and `num_keys` during Config initialization
2. Vector lengths during `DkgPrivateBegin` deserialization (uses `#[derive(Deserialize)]` without custom validation)
3. Hash computation in `DkgPrivateBegin::hash()`
4. Processing loops in `dkg_private_begin()` [8](#0-7) 

### Impact Explanation

**Specific Harm:**
When a malicious coordinator sets `num_signers` and `num_keys` to very large values (e.g., 100 million each):

1. **Memory Exhaustion**: Each vector requires num_elements × 4 bytes. At 100M elements per vector, this totals ~800 MB per message. At u32::MAX (4.3 billion), this reaches ~34 GB, causing immediate memory exhaustion.

2. **CPU Exhaustion**: During signature verification [9](#0-8) , signers must hash all vector elements. With 200M total elements (100M key_ids + 100M signer_ids), this requires ~2-3 seconds of pure hashing time per signer, blocking all other operations.

3. **Network Congestion**: Broadcasting an 800 MB to 34 GB message to all signers saturates network bandwidth.

4. **Amplification**: The message is cloned for storage [10](#0-9) , doubling memory consumption.

**Who is Affected:**
All signer nodes in the WSTS deployment are simultaneously DoS'd, preventing DKG completion and blocking any threshold signature operations.

**Severity Justification:**
This maps to **Low** severity per the protocol scope: "Any remotely-exploitable denial of service in a node." While severe for WSTS operations, it does not directly cause blockchain consensus failures, chain splits, or fund loss.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control over coordinator configuration (ability to set `num_signers` and `num_keys`)
- Possession of valid coordinator private key for message signing [11](#0-10) 
- No cryptographic breaks required

**Attack Complexity:**
Low. The attack requires only:
1. Creating a `Config` with large `num_signers` and `num_keys` values
2. Calling `start_private_shares()` to generate the malicious message
3. Broadcasting the signed message to signers

**Economic Feasibility:**
The coordinator must have sufficient memory to create the vectors (400 MB to 17 GB per vector), which is feasible on modern hardware. The attack cost is minimal.

**Detection Risk:**
Low. The message appears valid (properly signed by coordinator) and only becomes apparent when signers experience resource exhaustion.

**Estimated Probability:**
High, given a malicious or compromised coordinator. The coordinator role is typically trusted, but if compromised, exploitation is trivial.

### Recommendation

**Primary Fix - Add Configuration Bounds:**
Add reasonable upper bounds in `Config::new()` and `Config::with_timeouts()`:

```rust
const MAX_SIGNERS: u32 = 10_000;
const MAX_KEYS: u32 = 10_000;

pub fn new(...) -> Result<Self, Error> {
    if num_signers > MAX_SIGNERS {
        return Err(Error::InvalidConfig("num_signers exceeds maximum"));
    }
    if num_keys > MAX_KEYS {
        return Err(Error::InvalidConfig("num_keys exceeds maximum"));
    }
    // ... existing code
}
```

**Secondary Fix - Add Deserialization Validation:**
Implement custom deserialization for `DkgPrivateBegin` that validates vector lengths against expected configuration values before allocating memory.

**Tertiary Fix - Add Message Size Limits:**
Implement a maximum message size check at the network layer before deserialization to reject oversized packets early.

**Testing Recommendations:**
1. Add unit tests with `num_signers` and `num_keys` at boundary values (MAX_SIGNERS, MAX_SIGNERS+1)
2. Add integration tests measuring memory usage with large vector sizes
3. Add fuzzing tests for `DkgPrivateBegin` deserialization with random vector sizes

### Proof of Concept

**Exploitation Steps:**

1. **Setup malicious coordinator:**
```rust
let config = Config::new(
    100_000_000,  // num_signers: 100 million
    100_000_000,  // num_keys: 100 million
    1,            // threshold
    coordinator_private_key
);
let mut coordinator = Coordinator::new(config);
```

2. **Generate malicious message:**
```rust
// This creates DkgPrivateBegin with:
// - key_ids: Vec with 100M elements (~400 MB)
// - signer_ids: Vec with 100M elements (~400 MB)
let malicious_packet = coordinator.start_private_shares()?;
```

3. **Broadcast to signers:**
When each signer receives the packet and calls `process()`, it must:
    - Deserialize ~800 MB of vector data
    - Verify signature by hashing 200M vector elements (~2-3 seconds)
    - Clone the message for storage (another ~800 MB)
    - Loop through 100M signer_ids for processing

**Expected Behavior:**
Coordinator and signers operate with reasonable memory and CPU usage.

**Actual Behavior:**
- Coordinator allocates ~800 MB for message creation
- Each signer allocates ~1.6 GB (800 MB message + 800 MB clone)
- Each signer spends 2-3 seconds in signature verification, blocking all other operations
- DKG cannot complete due to signer resource exhaustion

**Reproduction:**
1. Create test with `num_signers = num_keys = 10_000_000` (10 million)
2. Measure memory usage during `start_private_shares()` and signer `process()`
3. Observe ~80 MB memory allocation and ~200ms verification time
4. Scale to 100M to observe proportional impact

**Notes**

This vulnerability exists because WSTS was designed with the assumption that coordinators are trusted and will configure reasonable parameters. However, a compromised coordinator or misconfigured deployment can exploit this to deny service to all signers. The fix is straightforward: enforce reasonable bounds on configuration parameters that constrain message sizes.

### Citations

**File:** src/net.rs (L33-44)
```rust
    fn verify(&self, signature: &[u8], public_key: &ecdsa::PublicKey) -> bool {
        let mut hasher = Sha256::new();

        self.hash(&mut hasher);

        let hash = hasher.finalize();
        let sig = match ecdsa::Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        sig.verify(hash.as_slice(), public_key)
```

**File:** src/net.rs (L166-175)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// DKG private begin message from signer to all signers and coordinator
pub struct DkgPrivateBegin {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer IDs who responded in time for this DKG round
    pub signer_ids: Vec<u32>,
    /// Key IDs who responded in time for this DKG round
    pub key_ids: Vec<u32>,
}
```

**File:** src/net.rs (L177-188)
```rust
impl Signable for DkgPrivateBegin {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PRIVATE_BEGIN".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        for key_id in &self.key_ids {
            hasher.update(key_id.to_be_bytes());
        }
        for signer_id in &self.signer_ids {
            hasher.update(signer_id.to_be_bytes());
        }
    }
}
```

**File:** src/net.rs (L500-504)
```rust
            Message::DkgPrivateBegin(msg) => {
                if !msg.verify(&self.sig, coordinator_public_key) {
                    warn!("Received a DkgPrivateBegin message with an invalid signature.");
                    return false;
                }
```

**File:** src/state_machine/coordinator/frost.rs (L255-259)
```rust
        let dkg_begin = DkgPrivateBegin {
            dkg_id: self.current_dkg_id,
            key_ids: (1..self.config.num_keys + 1).collect(),
            signer_ids: (0..self.config.num_signers).collect(),
        };
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

**File:** src/state_machine/signer/mod.rs (L904-910)
```rust
        for signer_id in &dkg_private_begin.signer_ids {
            if let Some(key_ids) = self.public_keys.signer_key_ids.get(signer_id) {
                for key_id in key_ids {
                    active_key_ids.insert(*key_id);
                }
            }
        }
```

**File:** src/state_machine/signer/mod.rs (L912-912)
```rust
        self.dkg_private_begin_msg = Some(dkg_private_begin.clone());
```

**File:** src/state_machine/coordinator/mod.rs (L180-200)
```rust
    pub fn new(
        num_signers: u32,
        num_keys: u32,
        threshold: u32,
        message_private_key: Scalar,
    ) -> Self {
        Config {
            num_signers,
            num_keys,
            threshold,
            dkg_threshold: num_keys,
            message_private_key,
            dkg_public_timeout: None,
            dkg_private_timeout: None,
            dkg_end_timeout: None,
            nonce_timeout: None,
            sign_timeout: None,
            public_keys: Default::default(),
            verify_packet_sigs: true,
        }
    }
```
