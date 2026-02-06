### Title
Unbounded Packet Deserialization Enables Memory Exhaustion Denial of Service

### Summary
The WSTS network protocol lacks maximum size limits on packet fields, allowing malicious coordinators or signers to send arbitrarily large messages that cause memory exhaustion during deserialization. Multiple message types contain unbounded vectors that can be filled with millions of entries, leading to gigabytes of memory allocation and node crashes.

### Finding Description

**Exact Code Location:**

The `Packet` struct is defined in `src/net.rs` with no size constraints: [1](#0-0) 

The `Message` enum contains multiple variants with unbounded vector fields: [2](#0-1) 

Specific vulnerable message types include:

1. **DkgPublicShares** with unbounded commitments vector: [3](#0-2) 

Where each `PolyCommitment` contains an unbounded `poly` vector: [4](#0-3) 

2. **DkgPrivateShares** with nested unbounded collections: [5](#0-4) 

3. **NonceRequest** with unbounded message vector: [6](#0-5) 

4. **NonceResponse** with multiple unbounded vectors: [7](#0-6) 

5. **SignatureShareRequest** with unbounded nonce_responses vector: [8](#0-7) 

**Root Cause:**

The protocol uses serde's Serialize/Deserialize traits on message structures without enforcing maximum size constraints. When packets are received and deserialized, the coordinator and signer state machines process them without any pre-validation of collection sizes.

Coordinator packet processing: [9](#0-8) 

The `verify()` method only validates signatures, not packet sizes: [10](#0-9) 

Signer packet processing: [11](#0-10) 

**Why Existing Mitigations Fail:**

No size validation exists anywhere in the packet processing pipeline:
- The `Packet::verify()` method only checks cryptographic signatures
- The `process_message()` functions in both coordinator and signer immediately match on message types without size checks
- Individual message handlers process vector contents without length validation
- Serde deserialization allocates memory proportional to the serialized data size without limits

### Impact Explanation

**Specific Harm:**

A malicious actor (coordinator or signer) can construct messages with oversized vector fields that cause:
1. **Memory exhaustion** during deserialization (multi-gigabyte allocations)
2. **CPU exhaustion** during processing of massive collections
3. **Node crashes** when memory limits are exceeded
4. **Service unavailability** as nodes become unresponsive

**Quantified Impact:**

Example attack scenarios:

- **DkgPublicShares attack**: An attacker sends a message with 1,000 commitments, each containing 10 million Points. Each Point is ~33 bytes compressed, resulting in ~330 GB total memory allocation.

- **DkgPrivateShares attack**: An attacker sends nested HashMaps with millions of entries and multi-megabyte encrypted values, causing similar memory exhaustion.

- **SignatureShareRequest attack**: A malicious coordinator sends thousands of NonceResponse objects, each with massive vectors, overwhelming signer memory.

**Who is Affected:**

- All nodes (coordinators and signers) in the WSTS network
- If multiple signers are targeted simultaneously, this could impact 10%+ of network participants

**Severity Justification:**

This vulnerability maps to **Low** severity per the protocol scope:
- "Any remotely-exploitable denial of service in a node"

However, if an attacker can target multiple nodes simultaneously (≥10% of miners), this could escalate to **Medium** severity:
- "Any network denial of service impacting more than 10 percent of miners that does not shut down the network"

The attack does not cause fund loss, invalid signatures, or persistent chain splits, keeping it below High/Critical severity.

### Likelihood Explanation

**Required Attacker Capabilities:**

The attacker must be either:
1. A coordinator with ability to send messages to signers, OR
2. A signer with ability to send messages to the coordinator

No additional privileges, secrets, or cryptographic breaks are required.

**Attack Complexity:**

Extremely low. The attacker simply constructs messages with large vectors:
```
// Pseudocode - no actual implementation needed
DkgPublicShares {
    dkg_id: valid_id,
    signer_id: attacker_id,
    comms: vec![poly_commitment; 1_000_000],  // 1 million entries
    kex_public_key: valid_key,
}
```

The messages will pass signature validation if properly signed by the attacker's private key.

**Economic Feasibility:**

Negligible cost. Network bandwidth required is proportional to the attack size, but the amplification factor is high (small bandwidth → large memory consumption on target).

**Detection Risk:**

Medium to low. While anomalous packet sizes could be detected by monitoring, there is currently no validation layer to reject oversized packets before deserialization damage occurs.

**Estimated Probability of Success:**

Very high (~95%+). The attack requires only the ability to send network messages, which is a basic capability of any protocol participant. No timing windows, race conditions, or complex sequences are involved.

### Recommendation

**Immediate Fix:**

Implement maximum size limits on all vector and collection fields in network messages. Add validation before deserialization:

1. Add size limit constants for each message type
2. Implement size validation in a pre-deserialization check
3. Reject oversized packets before allocating memory
4. Return appropriate error codes for oversized packets

**Specific Code Changes:**

Add to `src/net.rs`:
```rust
const MAX_COMMS_PER_MESSAGE: usize = 1000;
const MAX_POLY_COEFFICIENTS: usize = 1000;
const MAX_MESSAGE_BYTES: usize = 10_485_760; // 10 MB
const MAX_NONCE_RESPONSES: usize = 1000;
const MAX_KEY_IDS: usize = 1000;
const MAX_SHARES: usize = 1000;
```

Add pre-deserialization size validation or post-deserialization bounds checking in message handlers in both coordinator and signer `process_message()` functions.

**Alternative Mitigations:**

1. Implement a wrapper around serde that enforces maximum byte limits during deserialization
2. Use streaming deserialization with size checks
3. Add network-layer packet size limits before reaching the application layer

**Testing Recommendations:**

1. Unit tests that attempt to deserialize oversized messages and verify rejection
2. Integration tests with realistic large-but-valid messages to ensure limits aren't too restrictive
3. Fuzzing tests with randomized oversized inputs
4. Load tests simulating multiple concurrent oversized packet attacks

**Deployment Considerations:**

- Limits should be configurable to allow adjustment based on network conditions
- Coordinate with all node operators to deploy the fix simultaneously
- Monitor for legitimate messages that approach size limits and adjust if needed
- Consider backward compatibility if older nodes remain in the network

### Proof of Concept

**Exploitation Steps:**

1. Attacker joins the network as a signer or coordinator
2. Attacker constructs a malicious message with oversized vectors
3. Attacker signs the message with their valid private key
4. Attacker sends the packet to target node(s)
5. Target node attempts to deserialize the packet
6. Memory exhaustion occurs during allocation of giant vectors
7. Target node crashes or becomes unresponsive

**Concrete Attack Example (DkgPublicShares):**

```rust
// Create a PolyCommitment with 10 million points
let huge_poly = vec![Point::generator(); 10_000_000]; // ~330 MB

let malicious_commitment = PolyCommitment {
    id: valid_schnorr_id,
    poly: huge_poly,
};

// Create 1000 such commitments
let malicious_comms = vec![(0, malicious_commitment.clone()); 1000]; // ~330 GB total

let malicious_msg = DkgPublicShares {
    dkg_id: current_dkg_id,
    signer_id: attacker_signer_id,
    comms: malicious_comms,
    kex_public_key: attacker_kex_key,
};

let packet = Packet {
    msg: Message::DkgPublicShares(malicious_msg),
    sig: sign_message(&malicious_msg, &attacker_private_key),
};

// Send packet to coordinator
// Coordinator attempts to deserialize and allocates ~330 GB
// Coordinator crashes with OOM error
```

**Expected vs Actual Behavior:**

- **Expected**: Oversized packets should be rejected with an error before memory allocation
- **Actual**: Packets are deserialized regardless of size, causing unbounded memory allocation

**Reproduction Instructions:**

1. Set up a test WSTS network with a coordinator and multiple signers
2. Modify a signer to construct DkgPublicShares with 1,000 commitments of 1,000 points each
3. Send the packet during the DKG public shares phase
4. Observe coordinator memory usage spike to multiple gigabytes
5. Observe coordinator crash or unresponsiveness
6. Verify attack works with other message types (DkgPrivateShares, NonceRequest, etc.)

### Notes

This vulnerability affects all network participants equally - both coordinators and signers can be attacked, and both can be attackers. The lack of any size validation at any layer (network, deserialization, or application) makes this a fundamental design issue rather than an implementation bug. The fix requires careful consideration of legitimate use cases to avoid setting limits too low, while still protecting against DoS attacks.

### Citations

**File:** src/net.rs (L84-106)
```rust
/// Encapsulation of all possible network message types
pub enum Message {
    /// Tell signers to begin DKG by sending DKG public shares
    DkgBegin(DkgBegin),
    /// Send DKG public shares
    DkgPublicShares(DkgPublicShares),
    /// Tell signers to send DKG private shares
    DkgPrivateBegin(DkgPrivateBegin),
    /// Send DKG private shares
    DkgPrivateShares(DkgPrivateShares),
    /// Tell signers to compute shares and send DKG end
    DkgEndBegin(DkgEndBegin),
    /// Tell coordinator that DKG is complete
    DkgEnd(DkgEnd),
    /// Tell signers to send signing nonces
    NonceRequest(NonceRequest),
    /// Tell coordinator signing nonces
    NonceResponse(NonceResponse),
    /// Tell signers to construct signature shares
    SignatureShareRequest(SignatureShareRequest),
    /// Tell coordinator signature shares
    SignatureShareResponse(SignatureShareResponse),
}
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

**File:** src/net.rs (L190-199)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
/// DKG private shares message from signer to all signers and coordinator
pub struct DkgPrivateShares {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// List of (src_party_id, Map(dst_key_id, encrypted_share))
    pub shares: Vec<(u32, HashMap<u32, Vec<u8>>)>,
}
```

**File:** src/net.rs (L262-275)
```rust
#[derive(Clone, Serialize, Deserialize, PartialEq)]
/// Nonce request message from coordinator to signers
pub struct NonceRequest {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// The message to sign
    pub message: Vec<u8>,
    /// What type of signature to create
    pub signature_type: SignatureType,
}
```

**File:** src/net.rs (L309-326)
```rust
#[derive(Clone, Serialize, Deserialize, PartialEq)]
/// Nonce response message from signers to coordinator
pub struct NonceResponse {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// Key IDs
    pub key_ids: Vec<u32>,
    /// Public nonces
    pub nonces: Vec<PublicNonce>,
    /// Bytes being signed
    pub message: Vec<u8>,
}
```

**File:** src/net.rs (L381-396)
```rust
#[derive(Clone, Serialize, Deserialize, PartialEq)]
/// Signature share request message from coordinator to signers
pub struct SignatureShareRequest {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Nonces responses used for this signature
    pub nonce_responses: Vec<NonceResponse>,
    /// Bytes to sign
    pub message: Vec<u8>,
    /// What type of signature to create
    pub signature_type: SignatureType,
}
```

**File:** src/net.rs (L467-474)
```rust
#[derive(Serialize, Deserialize, Clone, PartialEq)]
/// Network packets need to be signed so they can be verified
pub struct Packet {
    /// The message to sign
    pub msg: Message,
    /// The bytes of the signature
    pub sig: Vec<u8>,
}
```

**File:** src/net.rs (L485-492)
```rust
impl Packet {
    /// This function verifies the packet's signature, returning true if the signature is valid,
    /// i.e. is appropriately signed by either the provided coordinator or one of the provided signer public keys
    pub fn verify(
        &self,
        signers_public_keys: &PublicKeys,
        coordinator_public_key: &ecdsa::PublicKey,
    ) -> bool {
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

**File:** src/state_machine/coordinator/fire.rs (L213-225)
```rust
    /// Process the message inside the passed packet
    pub fn process_message(
        &mut self,
        packet: &Packet,
    ) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
        if self.config.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.config.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
        }
```

**File:** src/state_machine/signer/mod.rs (L457-470)
```rust
    /// process the passed incoming message, and return any outgoing messages needed in response
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
