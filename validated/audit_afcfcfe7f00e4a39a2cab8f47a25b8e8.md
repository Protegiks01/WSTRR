# Audit Report

## Title
Coordinator Memory Exhaustion via Unbounded NonceResponse Message Creation in FIRE Coordinator

## Summary
The FIRE coordinator's `gather_nonces()` function accepts `NonceResponse` messages with arbitrary message values without validating they match the coordinator's requested message. A malicious signer can exploit this to create unlimited entries in the `message_nonces` BTreeMap by sending multiple `NonceResponse` messages with different large message payloads, exhausting coordinator memory and causing denial of service.

## Finding Description

The FIRE coordinator uses a BTreeMap keyed by message bytes to organize incoming nonce responses. [1](#0-0) 

When the coordinator requests nonces, it sends a `NonceRequest` containing the message it wants signers to provide nonces for. [2](#0-1) 

However, when processing incoming `NonceResponse` messages in `gather_nonces()`, the coordinator validates dkg_id, sign_id, sign_iter_id, signer_id, key_ids, and nonce validity, [3](#0-2)  but critically **never validates that `nonce_response.message` matches `self.message`** (the requested message stored at [4](#0-3) ).

Instead, the coordinator blindly creates a new BTreeMap entry for every unique message value: [5](#0-4) 

The duplicate check only prevents the same signer from sending multiple responses for the **same** message value: [6](#0-5) 

This check operates on `nonce_info` which is specific to the message key obtained via `entry()`, so a signer can bypass it by sending responses with different message values.

**Attack Vector:**
1. Coordinator enters `NonceGather` state and sends `NonceRequest` with message M1
2. Malicious signer sends `NonceResponse` with message M2 (different from M1) - creates entry for M2
3. Malicious signer sends `NonceResponse` with message M3 - creates entry for M3
4. Repeat with M4, M5, M6... each with potentially large (multi-MB) payloads
5. Each unique message creates a new `SignRoundInfo` entry containing BTreeMaps, HashSets, and a cloned `NonceResponse` [7](#0-6)  (which itself contains another copy of the message)
6. Coordinator memory grows unbounded until OOM

The message field is a `Vec<u8>` with no size restrictions: [8](#0-7) 

**Why Mitigations Fail:**

The `message_nonces.clear()` only executes when starting a new signing iteration, not during the NonceGather phase: [9](#0-8) 

Packet signature verification only authenticates the sender identity, not the message content: [10](#0-9) [11](#0-10) 

The nonce timeout limits the attack window but doesn't prevent rapid memory exhaustion within that window.

## Impact Explanation

This vulnerability enables a remotely-exploitable denial of service attack on the FIRE coordinator node. A malicious signer can exhaust coordinator memory, causing it to crash or become unresponsive. Since the coordinator orchestrates the threshold signing protocol, its failure blocks all signing operations for that instance.

**Quantified Impact:**
- With 1 malicious signer sending 1,000 NonceResponse messages with 1MB payloads: ~1GB+ memory consumption
- With 10 malicious signers: ~10GB+ (each signer can send unlimited unique messages)
- Each `SignRoundInfo` entry adds overhead: BTreeMap of NonceResponses, HashSet of key_ids, HashSet of signer_ids
- Attack completes within the nonce timeout window (typically seconds to minutes)

This maps to **Low** severity per the provided scope: "Any remotely-exploitable denial of service in a node." The coordinator node can be DoS'd remotely by exhausting its memory, preventing completion of signing operations.

## Likelihood Explanation

**Required Attacker Capabilities:**
- Must control at least one valid signer's private key if `verify_packet_sigs` is enabled [12](#0-11) 
- If `verify_packet_sigs` is disabled, no authentication required (unauthenticated remote attack)
- Must be able to send messages to the coordinator during NonceGather state
- No special privileges beyond being a registered signer

**Attack Complexity:** Low. The attacker simply:
1. Waits for coordinator to enter NonceGather state
2. Sends multiple properly-signed NonceResponse messages with different message values
3. Each message passes all validation checks except the missing message equality check

**Economic Feasibility:** Very high. Minimal cost to generate and sign messages. No computational barriers beyond ECDSA signing, which is trivial.

**Detection Risk:** Medium. The attack would be visible in logs as multiple NonceResponse messages, but may initially appear as legitimate protocol activity. Memory exhaustion would be obvious once it occurs.

**Estimated Probability:** High if an adversary controls a signer key. The attack is straightforward with no special conditions required.

## Recommendation

Add validation in `gather_nonces()` to ensure the `NonceResponse` message matches the coordinator's requested message:

```rust
if nonce_response.message != self.message {
    warn!(
        signer_id = %nonce_response.signer_id,
        "NonceResponse message does not match requested message"
    );
    return Ok(());
}
```

This check should be added after line 901 in `src/state_machine/coordinator/fire.rs`, before the `message_nonces.entry()` call at line 917. This ensures only nonces for the requested message are accepted, preventing the memory exhaustion attack.

Additionally, consider adding a size limit on the message field to prevent excessively large payloads, though this is a defense-in-depth measure rather than a complete fix.

## Proof of Concept

```rust
#[test]
fn test_memory_exhaustion_via_multiple_messages() {
    use crate::v2;
    let (mut coordinators, mut signers) = setup::<FireCoordinator<v2::Aggregator>, v2::Signer>(3, 1);
    
    // Run DKG first
    let message = coordinators.first_mut().unwrap().start_dkg_round(None).unwrap();
    let (messages, _) = feedback_messages(&mut coordinators, &mut signers, &[message]);
    let (messages, _) = feedback_messages(&mut coordinators, &mut signers, &messages);
    let (_, results) = feedback_messages(&mut coordinators, &mut signers, &messages);
    assert_eq!(results.len(), 1);
    
    // Start signing round
    let msg = b"original_message".to_vec();
    let nonce_request = coordinators.first_mut().unwrap()
        .start_signing_round(&msg, SignatureType::Schnorr, None).unwrap();
    
    // Malicious signer sends multiple NonceResponses with different messages
    let mut malicious_responses = vec![];
    for i in 0..100 {
        let fake_msg = format!("fake_message_{}", i).into_bytes();
        let mut fake_response = signers[0].process_inbound_messages(&[nonce_request.clone()], &mut create_rng()).unwrap();
        if let Message::NonceResponse(ref mut nr) = &mut fake_response[0].msg {
            nr.message = fake_msg; // Replace with different message
        }
        malicious_responses.push(fake_response[0].clone());
    }
    
    // Send all malicious responses to coordinator
    for response in &malicious_responses {
        let _ = coordinators[0].process(response);
    }
    
    // Verify memory_nonces has 100+ entries (one per unique message)
    assert!(coordinators[0].save().message_nonces.len() >= 100);
}
```

### Citations

**File:** src/state_machine/coordinator/fire.rs (L46-46)
```rust
    message_nonces: BTreeMap<Vec<u8>, SignRoundInfo>,
```

**File:** src/state_machine/coordinator/fire.rs (L54-54)
```rust
    pub message: Vec<u8>,
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

**File:** src/state_machine/coordinator/fire.rs (L815-815)
```rust
        self.message_nonces.clear();
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

**File:** src/state_machine/coordinator/fire.rs (L847-901)
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

            for nonce in &nonce_response.nonces {
                if !nonce.is_valid() {
                    warn!(
                        sign_id = %nonce_response.sign_id,
                        sign_iter_id = %nonce_response.sign_iter_id,
                        signer_id = %nonce_response.signer_id,
                        "Received invalid nonce in NonceResponse"
                    );
                    return Ok(());
                }
            }
```

**File:** src/state_machine/coordinator/fire.rs (L917-920)
```rust
            let nonce_info = self
                .message_nonces
                .entry(nonce_response.message.clone())
                .or_default();
```

**File:** src/state_machine/coordinator/fire.rs (L922-928)
```rust
            let have_nonces = nonce_info
                .public_nonces
                .contains_key(&nonce_response.signer_id);

            if have_nonces {
                info!(signer_id = %nonce_response.signer_id, "Received duplicate NonceResponse");
                return Ok(());
```

**File:** src/state_machine/coordinator/mod.rs (L157-157)
```rust
    pub verify_packet_sigs: bool,
```

**File:** src/state_machine/coordinator/mod.rs (L234-245)
```rust
#[derive(Clone, Debug, Default, PartialEq)]
/// The info for a sign round over specific message bytes
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

**File:** src/net.rs (L325-325)
```rust
    pub message: Vec<u8>,
```

**File:** src/net.rs (L349-367)
```rust
impl Signable for NonceResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("NONCE_RESPONSE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.sign_iter_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());

        for key_id in &self.key_ids {
            hasher.update(key_id.to_be_bytes());
        }

        for nonce in &self.nonces {
            hasher.update(nonce.D.compress().as_bytes());
            hasher.update(nonce.E.compress().as_bytes());
        }

        hasher.update(self.message.as_slice());
    }
```
