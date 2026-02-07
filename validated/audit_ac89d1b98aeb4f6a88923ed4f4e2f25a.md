After performing comprehensive validation against the WSTS security framework, I have determined this claim is **VALID**.

---

# Audit Report

## Title
Coordinator Memory Exhaustion via Unbounded NonceResponse Message Creation

## Summary
The coordinator's `gather_nonces()` function accepts NonceResponse messages with arbitrary message values without validating they match the requested message. A malicious signer can exhaust coordinator memory by sending multiple NonceResponse messages with different large message payloads during a single signing round, causing denial of service.

## Finding Description

The vulnerability exists in the nonce gathering phase of the FIRE coordinator state machine. When the coordinator requests nonces for a specific message, it creates entries in the `message_nonces` BTreeMap keyed by the message value received in NonceResponse packets, without validating that this message matches the originally requested message. [1](#0-0) 

The coordinator validates dkg_id, sign_id, sign_iter_id, signer_id, and key_ids from incoming NonceResponse messages, but never checks the message field: [2](#0-1) 

The duplicate detection mechanism only prevents the same signer from sending multiple responses for the **same** message value, not from sending responses with different message values: [3](#0-2) 

The NonceResponse message field is defined as an unbounded `Vec<u8>`: [4](#0-3) 

**Attack Execution Path:**
1. Coordinator sends NonceRequest with legitimate message during `request_nonces()`: [5](#0-4) 

2. Malicious signer sends NonceResponse #1 with message payload `[0; 1MB]`
3. Line 919 creates entry: `message_nonces[vec![0; 1MB]] = SignRoundInfo::default()`
4. Malicious signer sends NonceResponse #2 with message payload `[1; 1MB]`  
5. Line 919 creates entry: `message_nonces[vec![1; 1MB]] = SignRoundInfo::default()`
6. Repeat N times within nonce timeout window

Each SignRoundInfo contains additional data structures: [6](#0-5) 

The `message_nonces.clear()` only occurs when starting a new signing iteration, not during nonce gathering: [7](#0-6) 

Packet signature verification only authenticates the sender, not the message content: [8](#0-7) 

## Impact Explanation

This vulnerability enables denial of service against the coordinator node through memory exhaustion. The coordinator orchestrates the entire signing protocol, so its failure prevents signature generation for all participants.

**Quantified Impact:**
- With 1 malicious signer sending 1,000 NonceResponse messages with 1MB payloads: ~1GB memory consumption
- Each SignRoundInfo adds overhead (BTreeMap + 3 HashSets)  
- Attack completes within nonce timeout window (configurable, typically seconds to minutes)
- Coordinator becomes unresponsive or crashes with OOM

This maps to **Low** severity: "Any remotely-exploitable denial of service in a node." The coordinator node can be DoS'd remotely, preventing completion of signing operations.

## Likelihood Explanation

**Required Attacker Capabilities:**
- Control of at least one valid signer's private key (if `verify_packet_sigs` enabled)
- If signature verification disabled, no authentication required
- Ability to send messages during NonceGather state

**Attack Complexity:** Low
- Wait for coordinator to enter NonceGather state
- Send multiple properly-signed NonceResponse messages with different message values  
- Each passes all validation checks except the missing message equality check

**Economic Feasibility:** Very high
- Minimal cost to generate and sign messages
- No computational barriers beyond message signing

**Detection:** The attack would be visible in logs but may initially appear as legitimate protocol activity. Memory exhaustion becomes obvious when it occurs.

**Estimated Probability:** High if adversary controls a signer key. The attack requires no special conditions beyond network access during a signing round.

## Recommendation

Add validation in `gather_nonces()` to ensure the received message matches the coordinator's expected message:

```rust
fn gather_nonces(
    &mut self,
    packet: &Packet,
    signature_type: SignatureType,
) -> Result<(), Error> {
    if let Message::NonceResponse(nonce_response) = &packet.msg {
        // Existing validations...
        
        // ADD: Validate message matches coordinator's expected message
        if nonce_response.message != self.message {
            warn!(
                signer_id = %nonce_response.signer_id,
                "NonceResponse message does not match expected message"
            );
            return Ok(());
        }
        
        // Continue with existing logic...
        let nonce_info = self
            .message_nonces
            .entry(self.message.clone())  // Use self.message instead
            .or_default();
```

Additionally, consider implementing:
- Maximum message size validation
- Per-signer rate limiting during nonce gathering
- Global limit on total `message_nonces` entries

## Proof of Concept

```rust
#[test]
fn test_memory_exhaustion_via_different_messages() {
    let mut rng = create_rng();
    let (coordinators, _) = setup::<FireCoordinator<v2::Aggregator>, v2::Signer>(2, 1);
    let mut coordinator = coordinators[0].clone();
    let signature_type = SignatureType::Frost;
    
    // Coordinator expects this message
    coordinator.message = vec![0u8; 32];
    coordinator.state = State::NonceGather(signature_type);
    
    // Malicious signer sends responses with different message values
    for i in 0..100 {
        let malicious_message = vec![i as u8; 1024 * 1024]; // 1MB each
        let nonce_response = NonceResponse {
            dkg_id: 0,
            sign_id: 0,
            sign_iter_id: 0,
            signer_id: 0,
            key_ids: vec![1u32],
            nonces: vec![PublicNonce {
                D: Point::from(Scalar::random(&mut rng)),
                E: Point::from(Scalar::random(&mut rng)),
            }],
            message: malicious_message.clone(),
        };
        let packet = Packet {
            msg: Message::NonceResponse(nonce_response),
            sig: Default::default(),
        };
        coordinator.gather_nonces(&packet, signature_type).unwrap();
        
        // Each creates a new entry - memory grows unbounded
        assert!(coordinator.message_nonces.contains_key(&malicious_message));
    }
    
    // Verify 100 different message entries were created
    assert_eq!(coordinator.message_nonces.len(), 100);
    // Original expected message was never added
    assert!(!coordinator.message_nonces.contains_key(&coordinator.message));
}
```

### Citations

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

**File:** src/state_machine/coordinator/fire.rs (L815-816)
```rust
        self.message_nonces.clear();
        self.current_sign_iter_id = self.current_sign_iter_id.wrapping_add(1);
```

**File:** src/state_machine/coordinator/fire.rs (L822-828)
```rust
        let nonce_request = NonceRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            message: self.message.clone(),
            signature_type,
        };
```

**File:** src/state_machine/coordinator/fire.rs (L847-889)
```rust
            if nonce_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(nonce_response.dkg_id, self.current_dkg_id));
            }
            if nonce_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    nonce_response.sign_id,
                    self.current_sign_id,
                ));
            }
            if nonce_response.sign_iter_id != self.current_sign_iter_id {
                return Err(Error::BadSignIterId(
                    nonce_response.sign_iter_id,
                    self.current_sign_iter_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&nonce_response.signer_id) {
                warn!(signer_id = %nonce_response.signer_id, "No public key in config");
                return Ok(());
            };

            // check that the key_ids match the config
            let Some(signer_key_ids) = self
                .config
                .public_keys
                .signer_key_ids
                .get(&nonce_response.signer_id)
            else {
                warn!(signer_id = %nonce_response.signer_id, "No keys IDs configured");
                return Ok(());
            };

            let nonce_response_key_ids = nonce_response
                .key_ids
                .iter()
                .cloned()
                .collect::<HashSet<u32>>();
            if *signer_key_ids != nonce_response_key_ids {
                warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
                return Ok(());
            }
```

**File:** src/state_machine/coordinator/fire.rs (L917-920)
```rust
            let nonce_info = self
                .message_nonces
                .entry(nonce_response.message.clone())
                .or_default();
```

**File:** src/state_machine/coordinator/fire.rs (L922-929)
```rust
            let have_nonces = nonce_info
                .public_nonces
                .contains_key(&nonce_response.signer_id);

            if have_nonces {
                info!(signer_id = %nonce_response.signer_id, "Received duplicate NonceResponse");
                return Ok(());
            }
```

**File:** src/net.rs (L311-326)
```rust
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

**File:** src/state_machine/coordinator/mod.rs (L236-245)
```rust
pub struct SignRoundInfo {
    /// the nonce response of a signer id
    pub public_nonces: BTreeMap<u32, NonceResponse>,
    /// which key_ids we've received nonces for this iteration
    pub nonce_recv_key_ids: HashSet<u32>,
    /// which key_ids we're received sig shares for this iteration
    pub sign_recv_key_ids: HashSet<u32>,
    /// which signer_ids we're expecting sig shares from this iteration
    pub sign_wait_signer_ids: HashSet<u32>,
}
```
