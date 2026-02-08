Audit Report

## Title
DoS via Duplicate DkgPublicShares Messages Through Pre-Verification CPU Exhaustion

## Summary
The WSTS coordinator performs expensive cryptographic signature verification before checking for duplicate messages, allowing an attacker to exhaust coordinator CPU resources by repeatedly replaying captured DkgPublicShares messages. Each duplicate undergoes full SHA256 hashing and ECDSA verification before being rejected, creating a remotely-exploitable denial of service vulnerability.

## Finding Description

**Architecture Flaw:**

Both the FROST and FIRE coordinator implementations verify packet signatures before performing duplicate detection. This architectural flaw places expensive cryptographic operations (O(n) hashing + ECDSA verification) before cheap state lookups (O(1) HashMap check).

**Execution Flow:**

In the FROST coordinator, the `process_message()` method checks the `verify_packet_sigs` configuration flag and calls `packet.verify()` at the very beginning of message processing, before any state-specific handling occurs. [1](#0-0) 

The duplicate detection occurs much later in the execution flow, inside the `gather_public_shares()` method where it checks if the HashMap already contains the signer_id. [2](#0-1) 

The FIRE coordinator exhibits identical behavior, verifying signatures at the entry point of `process_message()`. [3](#0-2) 

The FIRE coordinator's duplicate detection also occurs later inside `gather_public_shares()`. [4](#0-3) 

**Signature Verification Cost:**

The `Packet::verify()` method performs full ECDSA signature verification for DkgPublicShares messages by retrieving the appropriate signer's public key and calling the message's `verify()` method. [5](#0-4) 

This calls the `Signable::verify()` implementation which hashes the entire message structure using SHA256 and then verifies the ECDSA signature. [6](#0-5) 

For DkgPublicShares, the hash implementation iterates through all polynomial commitments in the `comms` field, hashing each party_id and all Points in each commitment's polynomial. Each Point is compressed to 33 bytes during this process. [7](#0-6) 

**Configuration Default:**

The `verify_packet_sigs` flag defaults to `true` in both the `Config::new()` and `Config::with_timeouts()` constructors, enabling this vulnerability by default. [8](#0-7) [9](#0-8) 

**Why Mitigations Fail:**

The `dkg_id` validation occurs inside `gather_public_shares()` and prevents replay across different DKG rounds, but it provides no protection against replay attacks within the same round. [10](#0-9) 

There is no packet-level caching, rate limiting, or replay protection within a single DKG round. Every duplicate message undergoes full cryptographic verification before the cheap HashMap duplicate check rejects it.

## Impact Explanation

**Direct Impact:**

An attacker can exhaust the coordinator's CPU resources by replaying captured DkgPublicShares messages, causing denial of service that prevents or delays DKG completion. The coordinator will process each duplicate through full signature verification (SHA256 hashing of all polynomial commitments plus ECDSA verification) before rejecting it.

**Quantified Cost:**

The DkgPublicShares message contains a vector of polynomial commitments, where each commitment's `poly` field is a vector of elliptic curve Points. [11](#0-10)  For large threshold configurations, this represents substantial data that must be hashed during each verification attempt.

**Attack Amplification:**

A single captured legitimate message enables unlimited replays during the DKG round. If an attacker sends thousands of duplicates per second, the coordinator's CPU will be saturated with signature verification, delaying or preventing legitimate message processing.

**Consequence:**

DKG timeouts will trigger, causing the DKG round to fail. This prevents generation of the aggregate public key needed for signature operations, resulting in denial of service for the entire protocol operation.

**Severity:** Low - This maps to "Any remotely-exploitable denial of service in a node" in the severity definitions. The attack causes coordinator node DoS without requiring cryptographic breaks, insider access, or causing fund loss.

## Likelihood Explanation

**Attacker Requirements:**

- Network access to send packets to the coordinator (standard network connectivity)
- Ability to capture one legitimate DkgPublicShares message (passive network observation)
- No cryptographic secrets or private keys required

**Attack Simplicity:**

1. Wait for coordinator to enter DkgPublicGather state (observable through timing)
2. Capture any legitimate DkgPublicShares message from any signer
3. Replay the captured message repeatedly to the coordinator
4. Each duplicate triggers full signature verification before being rejected
5. Coordinator CPU saturates, causing DKG timeout

**Economic Feasibility:**

The attack cost is minimal - only network bandwidth to replay packets. The attacker doesn't perform any cryptographic operations; they simply replay a legitimately-signed message. The coordinator bears all the computational cost.

**Attack Window:**

The attack window is bounded by the DKG round duration (configured via `dkg_public_timeout`), but the attack is repeatable across all DKG rounds, enabling sustained denial of service.

**Estimated Probability:** High in distributed deployments using the default configuration where the coordinator is network-accessible and `verify_packet_sigs=true`.

## Recommendation

Perform duplicate detection before signature verification to prevent CPU exhaustion from replayed messages. Implement packet-level deduplication using a cache of recently seen (dkg_id, signer_id, message_hash) tuples.

**Recommended Fix:**

1. Add a packet deduplication cache to the Coordinator struct that tracks (dkg_id, signer_id) pairs already processed in the current round
2. In `process_message()`, check this cache before calling `packet.verify()`
3. Only perform signature verification for packets that haven't been seen before
4. Clear the cache when transitioning to a new DKG round

Example approach:
```rust
// In process_message(), before signature verification:
if self.config.verify_packet_sigs {
    // Extract key for deduplication
    let dedup_key = match &packet.msg {
        Message::DkgPublicShares(msg) => Some((self.current_dkg_id, msg.signer_id)),
        // ... other message types
        _ => None,
    };
    
    // Check if we've already processed this packet
    if let Some(key) = dedup_key {
        if self.processed_packets.contains(&key) {
            return Ok((None, None)); // Already processed
        }
    }
    
    // Only verify signature for new packets
    let Some(coordinator_public_key) = self.coordinator_public_key else {
        return Err(Error::MissingCoordinatorPublicKey);
    };
    if !packet.verify(&self.config.public_keys, &coordinator_public_key) {
        return Err(Error::InvalidPacketSignature);
    }
    
    // Mark as processed after successful verification
    if let Some(key) = dedup_key {
        self.processed_packets.insert(key);
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_duplicate_message_verification_dos() {
    use std::time::Instant;
    
    // Setup coordinator with verify_packet_sigs=true (default)
    let mut coordinator = setup_coordinator_with_default_config();
    coordinator.start_dkg_round(None).unwrap();
    
    // Create a legitimate DkgPublicShares message with large polynomial
    let public_shares = create_dkg_public_shares_with_large_poly(
        coordinator.current_dkg_id,
        0, // signer_id
        100 // threshold - creates 100 Points to hash
    );
    
    let packet = sign_packet(public_shares, &signer_private_key);
    
    // First message processes normally
    let start = Instant::now();
    coordinator.process_message(&packet).unwrap();
    let first_duration = start.elapsed();
    
    // Send 1000 duplicate messages
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = coordinator.process_message(&packet);
    }
    let duplicate_duration = start.elapsed();
    
    // Each duplicate should be rejected quickly if properly optimized
    // But in current implementation, each undergoes full signature verification
    // Demonstrates CPU cost amplification: 1000x verification cost vs 1x HashMap lookup
    assert!(duplicate_duration > first_duration * 500, 
        "Duplicate processing took significant CPU time due to repeated verification");
}
```

### Citations

**File:** src/state_machine/coordinator/frost.rs (L63-70)
```rust
        if self.config.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.config.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
        }
```

**File:** src/state_machine/coordinator/frost.rs (L292-297)
```rust
            if dkg_public_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_public_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }
```

**File:** src/state_machine/coordinator/frost.rs (L306-313)
```rust
            let have_shares = self
                .dkg_public_shares
                .contains_key(&dkg_public_shares.signer_id);

            if have_shares {
                info!(signer_id = %dkg_public_shares.signer_id, "received duplicate DkgPublicShares");
                return Ok(());
            }
```

**File:** src/state_machine/coordinator/fire.rs (L218-225)
```rust
        if self.config.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.config.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
        }
```

**File:** src/state_machine/coordinator/fire.rs (L493-500)
```rust
            let have_shares = self
                .dkg_public_shares
                .contains_key(&dkg_public_shares.signer_id);

            if have_shares {
                info!(signer_id = %dkg_public_shares.signer_id, "received duplicate DkgPublicShares");
                return Ok(());
            }
```

**File:** src/net.rs (L33-45)
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
    }
```

**File:** src/net.rs (L152-164)
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

**File:** src/state_machine/coordinator/mod.rs (L186-200)
```rust
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

**File:** src/state_machine/coordinator/mod.rs (L217-231)
```rust
        Config {
            num_signers,
            num_keys,
            threshold,
            dkg_threshold,
            message_private_key,
            dkg_public_timeout,
            dkg_private_timeout,
            dkg_end_timeout,
            nonce_timeout,
            sign_timeout,
            public_keys,
            verify_packet_sigs: true,
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
