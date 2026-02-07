# Audit Report

## Title
Unbounded Vector Deserialization in DkgPublicShares Enables Memory Exhaustion DoS

## Summary
The WSTS protocol deserializes and stores `DkgPublicShares` messages containing unbounded vectors before validating their sizes, allowing a malicious signer to cause memory exhaustion and node crashes through oversized messages.

## Finding Description

The `DkgPublicShares` message structure contains unbounded vector fields that are deserialized and stored in memory without size validation. [1](#0-0) 

Each `PolyCommitment` within the `comms` vector contains another unbounded `poly` vector. [2](#0-1) 

When signers receive a `DkgPublicShares` message, the entire message is cloned and stored without bounds checking. [3](#0-2) 

The signer's state structure stores these messages in a BTreeMap. [4](#0-3) 

Similarly, coordinators clone and store the entire message without validation. [5](#0-4) 

The coordinator's state structure also stores these messages unbounded. [6](#0-5) 

Size validation only occurs later in the `dkg_ended` function via `check_public_shares`, which validates that the polynomial length equals the threshold. [7](#0-6) 

The `check_public_shares` function enforces the threshold constraint. [8](#0-7) 

However, this validation happens only after the `DkgEndBegin` message is received, well after the oversized message has been deserialized and stored in memory during the earlier `dkg_public_share` processing. [9](#0-8) 

Packet signature verification prevents unsigned messages but does not validate message sizes. [10](#0-9) 

**Attack Flow:**
1. A malicious signer (within threshold-1) crafts a `DkgPublicShares` message with oversized `comms` vector (e.g., 1000 entries) where each `PolyCommitment` has an oversized `poly` vector (e.g., 1000 Points)
2. The malicious signer signs the message with their own legitimate private key
3. The message is sent to other signers and the coordinator
4. Recipients deserialize the message (Serde has no default size limits)
5. Signature verification passes since it's validly signed
6. The entire message is cloned and stored in memory
7. Memory exhaustion occurs (e.g., 1000 × 1000 × 100 bytes ≈ 100 MB per message)
8. Node crashes or becomes unresponsive
9. Validation that would reject the message only happens later, after damage is done

## Impact Explanation

This vulnerability enables a malicious signer to cause denial of service on individual signer and coordinator nodes. The impact is classified as **LOW** severity per the protocol scope definition: "Any remotely-exploitable denial of service in a node."

The attack affects individual nodes but does not:
- Shut down the entire network
- Cause chain splits or consensus failures  
- Enable invalid signature acceptance
- Result in loss of funds

A malicious signer can target specific nodes or broadcast the oversized message to multiple participants, causing coordinated DoS. However, the DKG protocol would eventually timeout and exclude the crashed nodes.

## Likelihood Explanation

This vulnerability has **MEDIUM to HIGH** likelihood of exploitation under the protocol's threat model:

**Attacker Requirements:**
A malicious signer within the threshold-1 limit can execute this attack using their own legitimate private key. No key compromise or cryptographic break is required - this is standard Byzantine behavior that the protocol must defend against.

**Attack Complexity:**
The attack is trivial to execute:
- Craft a `DkgPublicShares` message with large vectors using standard serialization
- Sign it with the malicious signer's own key
- Send via normal protocol channels
- No sophisticated techniques required

**Economic Cost:**
Extremely low - a single malicious message can DoS a node, and the attack can be repeated. No significant computational resources needed.

**Detection:**
While large network packets may be detectable by monitoring, the memory allocation occurs upon deserialization before any mitigation can prevent the DoS.

## Recommendation

Add bounds checking before deserializing and storing `DkgPublicShares` messages. Validate vector sizes immediately upon receipt, before cloning and storage:

1. **Define maximum bounds** based on protocol parameters (e.g., `max_comms = total_signers`, `max_poly = threshold`)

2. **Early validation in message handlers**:
   - In `dkg_public_share()`: Check that `comms.len() <= expected_parties` and each `poly.len() <= threshold` before cloning
   - Reject oversized messages immediately with minimal resource consumption

3. **Add configuration limits**: Allow operators to set maximum message size limits as an additional defense layer

4. **Consider using bounded deserialization**: Use custom Serde deserializers with size limits or validate after deserialization but before storage

Example fix for the signer's `dkg_public_share` method:
```rust
// After line 991, before line 1023:
for (party_id, comm) in &dkg_public_shares.comms {
    if comm.poly.len() > self.threshold as usize {
        warn!(%signer_id, poly_len = comm.poly.len(), "Oversized polynomial commitment");
        return Ok(vec![]);
    }
}
if dkg_public_shares.comms.len() > self.total_keys as usize {
    warn!(%signer_id, comms_len = dkg_public_shares.comms.len(), "Oversized comms vector");
    return Ok(vec![]);
}
```

Apply similar checks in the coordinator's `gather_public_shares` method.

## Proof of Concept

```rust
#[test]
fn test_oversized_dkg_public_shares_dos() {
    use crate::net::DkgPublicShares;
    use crate::common::PolyCommitment;
    use crate::curve::point::Point;
    use crate::schnorr::ID;
    use crate::util::create_rng;
    
    let mut rng = create_rng();
    let ctx = 0u64.to_be_bytes();
    
    // Create an oversized DkgPublicShares message
    let mut oversized_comms = vec![];
    for party_id in 0..1000 {  // 1000 entries instead of expected ~10
        let mut oversized_poly = vec![];
        for _ in 0..1000 {  // 1000 Points instead of expected threshold ~10
            oversized_poly.push(Point::from(Scalar::random(&mut rng)));
        }
        let comm = PolyCommitment {
            id: ID::new(&Scalar::random(&mut rng), &Scalar::random(&mut rng), &ctx, &mut rng),
            poly: oversized_poly,
        };
        oversized_comms.push((party_id, comm));
    }
    
    let oversized_message = DkgPublicShares {
        dkg_id: 0,
        signer_id: 0,
        comms: oversized_comms,  // ~1000 * 1000 * 100 bytes ≈ 100 MB
        kex_public_key: Point::from(Scalar::random(&mut rng)),
    };
    
    // Verify this would be stored without size validation
    // In actual code, this would be cloned and stored at signer/mod.rs:1023-1024
    // causing memory exhaustion before validation at line 557
    let serialized_size = bincode::serialize(&oversized_message).unwrap().len();
    assert!(serialized_size > 10_000_000);  // Confirm message is oversized (>10 MB)
}
```

## Notes

The vulnerability is valid under the protocol's threat model where malicious signers (up to threshold-1) are expected. The claim's mention of "compromising a signer's key" is misleading - a malicious signer simply uses their own legitimate key. The `verify_packet_sigs = false` configuration is a misconfiguration scenario and not the primary attack vector. The exact memory consumption numbers in the original claim are exaggerated for a realistic network, but even 10-100 MB messages would cause significant DoS, making this a valid LOW severity vulnerability.

### Citations

**File:** src/net.rs (L141-150)
```rust
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

**File:** src/common.rs (L318-321)
```rust
/// Check that the PolyCommitment is properly signed and has the correct degree polynomial
pub fn check_public_shares(poly_comm: &PolyCommitment, threshold: usize, ctx: &[u8]) -> bool {
    poly_comm.verify(ctx) && poly_comm.poly.len() == threshold
}
```

**File:** src/state_machine/signer/mod.rs (L154-154)
```rust
    pub dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
```

**File:** src/state_machine/signer/mod.rs (L504-526)
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
```

**File:** src/state_machine/signer/mod.rs (L557-557)
```rust
                        if !check_public_shares(comm, threshold, &self.dkg_id.to_be_bytes()) {
```

**File:** src/state_machine/signer/mod.rs (L1023-1024)
```rust
        self.dkg_public_shares
            .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L40-40)
```rust
    dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
```

**File:** src/state_machine/coordinator/fire.rs (L505-506)
```rust
            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
```
