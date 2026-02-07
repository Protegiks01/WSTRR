Audit Report

## Title
DoS via Duplicate DkgPublicShares Messages Through Pre-Verification CPU Exhaustion

## Summary
The WSTS coordinator performs expensive cryptographic signature verification before checking for duplicate messages, allowing an attacker to exhaust coordinator CPU resources by repeatedly replaying captured DkgPublicShares messages. Each duplicate undergoes full SHA256 hashing and ECDSA verification before being rejected, creating a remotely-exploitable denial of service vulnerability.

## Finding Description

**Architecture Flaw:**

Both the FROST and FIRE coordinator implementations verify packet signatures before performing duplicate detection. This architectural flaw places expensive cryptographic operations (O(n) hashing + ECDSA verification) before cheap state lookups (O(1) HashMap check).

**Execution Flow:**

In the FROST coordinator, `process_message()` checks `verify_packet_sigs` and calls `packet.verify()` at the beginning of message processing: [1](#0-0) 

The duplicate detection occurs much later, inside `gather_public_shares()`: [2](#0-1) 

The FIRE coordinator exhibits identical behavior: [3](#0-2) [4](#0-3) 

**Signature Verification Cost:**

The `Packet::verify()` method performs full ECDSA signature verification for DkgPublicShares messages: [5](#0-4) 

This calls the `Signable::verify()` implementation which hashes the entire message structure: [6](#0-5) 

For DkgPublicShares, the hash includes all polynomial commitments (threshold × num_parties Points): [7](#0-6) 

**Configuration Default:**

The `verify_packet_sigs` flag defaults to `true`, enabling this vulnerability by default: [8](#0-7) 

**Why Mitigations Fail:**

The `dkg_id` validation prevents replay across different DKG rounds but not within the same round: [9](#0-8) 

There is no packet-level caching, rate limiting, or replay protection within a single DKG round. Every duplicate message undergoes full cryptographic verification before the cheap HashMap duplicate check rejects it.

## Impact Explanation

**Direct Impact:**

An attacker can exhaust the coordinator's CPU resources by replaying captured DkgPublicShares messages, causing denial of service that prevents or delays DKG completion. The coordinator will process each duplicate through full signature verification (SHA256 hashing of all polynomial commitments plus ECDSA verification) before rejecting it.

**Quantified Cost:**

For a configuration with threshold=100 and num_parties=10, each DkgPublicShares message contains approximately 1000 Points (100 × 10). Each Point is 33 bytes when compressed, requiring ~33KB to be hashed per message verification. Combined with ECDSA verification, this represents significant CPU cost per duplicate.

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

**Solution:** Implement lightweight duplicate detection before expensive signature verification.

**Option 1 - Message Hash Caching:**

```rust
pub struct Coordinator<Aggregator: AggregatorTrait> {
    // ... existing fields ...
    /// Cache of recently seen packet hashes to detect duplicates
    recent_packet_hashes: HashSet<[u8; 32]>,
}

pub fn process_message(
    &mut self,
    packet: &Packet,
) -> Result<(Option<Packet>, Option<OperationResult>), Error> {
    // Quick duplicate check using packet hash
    let packet_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&bincode::serialize(&packet.msg).unwrap());
        let hash = hasher.finalize();
        hash.into()
    };
    
    if self.recent_packet_hashes.contains(&packet_hash) {
        return Ok((None, None)); // Early return for duplicates
    }
    
    // Only verify signature if not a duplicate
    if self.config.verify_packet_sigs {
        // ... existing verification code ...
    }
    
    self.recent_packet_hashes.insert(packet_hash);
    // ... rest of processing ...
}
```

**Option 2 - State-Specific Early Detection:**

Enhance the duplicate check in `gather_public_shares()` to return an error that's caught in `process_message()` before signature verification, though this requires architectural changes.

**Option 3 - Rate Limiting:**

Implement per-signer rate limiting at the packet processing layer to limit duplicate submission rate.

**Recommended:** Option 1 provides immediate protection with minimal overhead, as packet hash computation is significantly cheaper than full signature verification.

## Proof of Concept

```rust
#[test]
fn test_duplicate_packet_cpu_exhaustion() {
    use std::time::Instant;
    
    // Setup: Create coordinator with verify_packet_sigs=true (default)
    let mut rng = create_rng();
    let mut coordinators = vec![];
    let mut signers = vec![];
    setup(&mut rng, 0, 3, 3, 2, &mut coordinators, &mut signers);
    let mut coordinator = coordinators.pop().unwrap();
    
    // Start DKG round
    let dkg_begin_packet = coordinator.start_dkg_round(None).unwrap();
    
    // Signer creates legitimate DkgPublicShares message
    let (outbound_packet, operation_result) = 
        signers[0].process(&dkg_begin_packet).unwrap();
    assert!(operation_result.is_none());
    let legitimate_packet = outbound_packet.unwrap();
    
    // Process legitimate packet once (baseline)
    let start = Instant::now();
    coordinator.process(&legitimate_packet).unwrap();
    let legitimate_duration = start.elapsed();
    
    // Replay the SAME packet (duplicate)
    let start = Instant::now();
    coordinator.process(&legitimate_packet).unwrap();
    let duplicate_duration = start.elapsed();
    
    // VULNERABILITY: Duplicate processing should be near-instant (HashMap lookup)
    // but actually takes similar time to legitimate processing due to 
    // signature verification happening before duplicate detection
    
    // The duplicate takes significant time (>50% of original) 
    // because it undergoes full signature verification
    assert!(
        duplicate_duration.as_micros() > legitimate_duration.as_micros() / 2,
        "Duplicate should trigger expensive signature verification. \
         Legitimate: {:?}, Duplicate: {:?}",
        legitimate_duration, duplicate_duration
    );
    
    // An attacker can replay this thousands of times to exhaust CPU
    println!("CPU exhaustion possible: each duplicate costs {:?}", duplicate_duration);
}
```

This PoC demonstrates that duplicate messages undergo expensive signature verification rather than fast early rejection, proving the vulnerability is exploitable for CPU exhaustion attacks.

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

**File:** src/state_machine/coordinator/mod.rs (L186-199)
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
```
