# Audit Report

## Title
Unbounded Message Size Allows Memory Exhaustion in Coordinator

## Summary
The FIRE coordinator accepts `NonceResponse` messages without validating that the `message` field matches the originally requested message, allowing malicious authorized signers to inject arbitrarily large messages that cause memory exhaustion and denial of service.

## Finding Description

The WSTS coordinator implements a signing protocol where it sends `NonceRequest` messages to signers and collects `NonceResponse` messages. However, the coordinator fails to validate that the message content in received `NonceResponse` messages matches the message it originally sent.

**Attack Flow:**

1. The coordinator initiates signing by calling `start_signing_round()` which stores the message to be signed in `self.message`. [1](#0-0) 

2. The coordinator sends a `NonceRequest` containing this message to all signers. [2](#0-1) 

3. A malicious authorized signer receives the `NonceRequest` but instead of echoing back the same message, constructs a `NonceResponse` with an arbitrarily large message field (e.g., 1 GB).

4. The malicious signer signs this crafted `NonceResponse` with their own private key (legitimate since they control it). The message is included in the signature hash, so any message content is valid. [3](#0-2) 

5. The coordinator receives the malicious `NonceResponse` and verifies the signature, which passes authentication because the signer legitimately signed it.

6. **Critical vulnerability:** The coordinator's `gather_nonces()` function performs extensive validation checks (dkg_id, sign_id, sign_iter_id, signer_id, key_ids, nonce validity, malicious signer list) [4](#0-3)  but **never validates that `nonce_response.message` matches `self.message`**.

7. The coordinator stores the malicious message as a key in the `message_nonces` BTreeMap via `.clone()`, immediately allocating memory for the large message. [5](#0-4) 

8. When threshold is reached, the coordinator even replaces its own message with the attacker's message. [6](#0-5) 

**Why This is Exploitable:**

The `NonceResponse` structure contains an unbounded `message: Vec<u8>` field with no size constraints. [7](#0-6) 

Multiple malicious signers can send different large messages, each creating a separate entry in the `message_nonces` BTreeMap, multiplying the memory consumption. [8](#0-7) 

There are no message size limits enforced anywhere in the codebase (verified via comprehensive search).

## Impact Explanation

**Severity: Low** - Maps to "Any remotely-exploitable denial of service in a node" per the audit scope.

**Specific Harm:**
- A single malicious signer can send a 1 GB message causing immediate 1 GB memory allocation on the coordinator when the message is cloned as a BTreeMap key
- With multiple malicious signers (up to threshold-1, which is within the WSTS threat model), each sending different large messages, memory consumption multiplies as each unique message creates a new BTreeMap entry
- Coordinator process exhausts available memory and crashes or becomes unresponsive
- All pending signing rounds fail
- Dependent systems (e.g., blockchain transaction signing) cannot proceed until coordinator restarts

**Limitations:** This vulnerability does not compromise cryptographic security, enable fund theft, break threshold guarantees, or cause permanent consensus failures. It only causes temporary service disruption requiring coordinator restart.

## Likelihood Explanation

**Likelihood: High** when a malicious authorized signer is present (which is within the WSTS threat model for Byzantine fault tolerance).

**Required Capabilities:**
- Control of at least one authorized signer's private key (within threat model)
- Network access to send messages to the coordinator
- Ability to construct and sign `NonceResponse` messages (standard WSTS protocol capability)

**Attack Complexity: Low**
- Requires only crafting one malicious `NonceResponse` with a large byte array for the message field
- Signing with the controlled signer key (legitimate operation)
- Sending one network packet
- No sophisticated cryptographic attacks or timing requirements

**Within Threat Model:** The WSTS protocol explicitly tracks `malicious_signer_ids`, demonstrating that Byzantine faults from authorized signers are an expected threat scenario. [9](#0-8)  However, the protocol assumes malicious signers will send valid but adversarial protocol messages, not that they can inject unbounded data.

## Recommendation

Add message validation in the `gather_nonces()` function to verify that `nonce_response.message` matches `self.message`:

```rust
fn gather_nonces(
    &mut self,
    packet: &Packet,
    signature_type: SignatureType,
) -> Result<(), Error> {
    if let Message::NonceResponse(nonce_response) = &packet.msg {
        // ... existing validation ...
        
        // ADD THIS CHECK:
        if nonce_response.message != self.message {
            warn!(
                signer_id = %nonce_response.signer_id,
                "NonceResponse message does not match expected message"
            );
            return Ok(());
        }
        
        // ... rest of function ...
    }
    Ok(())
}
```

Additionally, consider adding a maximum message size constant to prevent excessively large messages from being processed:

```rust
const MAX_MESSAGE_SIZE: usize = 10_000_000; // 10 MB

if nonce_response.message.len() > MAX_MESSAGE_SIZE {
    warn!("NonceResponse message exceeds maximum size");
    return Ok(());
}
```

## Proof of Concept

```rust
#[test]
fn test_unbounded_message_memory_exhaustion() {
    use crate::state_machine::coordinator::{fire::Coordinator as FireCoordinator, Config};
    use crate::v2::Aggregator;
    use crate::net::{NonceResponse, Message, Packet, PublicNonce};
    
    // Setup coordinator with minimal config
    let mut coordinator = FireCoordinator::<Aggregator>::new(
        Config::default(),
        /* ... */
    );
    
    // Complete DKG to enable signing
    // coordinator.aggregate_public_key = Some(test_key);
    
    // Start a signing round with a small message
    let small_message = vec![0u8; 32];
    coordinator.start_signing_round(&small_message, SignatureType::Frost, None).unwrap();
    
    // Malicious signer creates NonceResponse with 100 MB message (different from original)
    let large_message = vec![0u8; 100_000_000]; // 100 MB
    let malicious_response = NonceResponse {
        dkg_id: coordinator.current_dkg_id,
        sign_id: coordinator.current_sign_id,
        sign_iter_id: coordinator.current_sign_iter_id,
        signer_id: 1,
        key_ids: vec![1],
        nonces: vec![PublicNonce::default()],
        message: large_message.clone(),
    };
    
    let packet = Packet {
        sig: malicious_response.sign(&test_key).unwrap(),
        msg: Message::NonceResponse(malicious_response),
    };
    
    // Coordinator accepts the large message without validation
    coordinator.gather_nonces(&packet, SignatureType::Frost).unwrap();
    
    // Verify the large message was stored in message_nonces (consuming 100 MB)
    assert!(coordinator.message_nonces.contains_key(&large_message));
    assert_eq!(coordinator.message_nonces.len(), 1);
    
    // With multiple malicious signers, memory consumption multiplies
    // Each unique message creates a new BTreeMap entry
}
```

### Citations

**File:** src/state_machine/coordinator/fire.rs (L46-46)
```rust
    message_nonces: BTreeMap<Vec<u8>, SignRoundInfo>,
```

**File:** src/state_machine/coordinator/fire.rs (L64-64)
```rust
    malicious_signer_ids: HashSet<u32>,
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

**File:** src/state_machine/coordinator/fire.rs (L847-915)
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

            if self
                .malicious_signer_ids
                .contains(&nonce_response.signer_id)
            {
                warn!(
                    sign_id = %nonce_response.sign_id,
                    sign_iter_id = %nonce_response.sign_iter_id,
                    signer_id = %nonce_response.signer_id,
                    "Received malicious NonceResponse"
                );
                //return Err(Error::MaliciousSigner(nonce_response.signer_id));
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

**File:** src/state_machine/coordinator/fire.rs (L952-954)
```rust
            if nonce_info.nonce_recv_key_ids.len() >= self.config.threshold as usize {
                // We have a winning message!
                self.message.clone_from(&nonce_response.message);
```

**File:** src/state_machine/coordinator/fire.rs (L1467-1467)
```rust
        self.message = message.to_vec();
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
