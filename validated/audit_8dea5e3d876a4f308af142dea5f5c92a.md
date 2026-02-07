# Audit Report

## Title
Unbounded Message Size Allows Memory Exhaustion in Coordinator

## Summary
The coordinator accepts `NonceResponse` messages without validating that the `message` field matches the originally requested message, allowing malicious authorized signers to inject arbitrarily large messages that cause memory exhaustion and denial of service.

## Finding Description

The WSTS coordinator implements a signing protocol where it sends `NonceRequest` messages to signers and collects `NonceResponse` messages. However, the coordinator fails to validate that the message content in received `NonceResponse` messages matches the message it originally sent.

**Attack Flow:**

1. The coordinator initiates signing by calling `start_signing_round()` which stores the message to be signed [1](#0-0) 

2. The coordinator sends a `NonceRequest` containing this message to all signers

3. A malicious authorized signer receives the `NonceRequest` but instead of echoing back the same message, constructs a `NonceResponse` with an arbitrarily large message field (e.g., 1 GB)

4. The malicious signer signs this crafted `NonceResponse` with their own private key (legitimate since they control it)

5. The coordinator receives the malicious `NonceResponse` and verifies the signature, which passes authentication [2](#0-1) 

6. **Critical vulnerability:** The coordinator's `gather_nonces()` function performs extensive validation checks (sign_id, sign_iter_id, signer_id, key_ids, nonce validity, malicious signer list) [3](#0-2)  but **never validates that `nonce_response.message` matches `self.message`**

7. The coordinator stores the malicious message as a key in the `message_nonces` BTreeMap via `.clone()` [4](#0-3) 

8. When threshold is reached, the coordinator even replaces its own message with the attacker's message [5](#0-4) 

**Why This is Exploitable:**

The `NonceResponse` structure contains an unbounded `message: Vec<u8>` field [6](#0-5)  with no size constraints. The message is included in the signature hash [7](#0-6)  which means signature verification passes for any message the malicious signer chooses to sign.

Multiple malicious signers can send different large messages, each creating a separate entry in the `message_nonces` BTreeMap [8](#0-7) , multiplying the memory consumption.

## Impact Explanation

**Severity: Low** - Maps to "Any remotely-exploitable denial of service in a node" per the audit scope.

**Specific Harm:**
- A single malicious signer can send a 1 GB message causing immediate 1 GB memory allocation on the coordinator
- With multiple malicious signers (up to threshold-1), each sending different large messages, memory consumption multiplies as each unique message creates a new BTreeMap entry
- Coordinator process exhausts available memory and crashes or becomes unresponsive
- All pending signing rounds fail
- Dependent systems (e.g., blockchain transaction signing) cannot proceed until coordinator restarts

**Limitations:** This vulnerability does not compromise cryptographic security, enable fund theft, break threshold guarantees, or cause permanent consensus failures. It only causes temporary service disruption.

## Likelihood Explanation

**Likelihood: High** when a malicious authorized signer is present (which is within the WSTS threat model for Byzantine fault tolerance).

**Required Capabilities:**
- Control of at least one authorized signer's private key
- Network access to send messages to the coordinator
- Ability to construct and sign `NonceResponse` messages (standard WSTS protocol capability)

**Attack Complexity: Low**
- Requires only crafting one malicious `NonceResponse` with a large byte array for the message field
- Signing with the controlled signer key (legitimate operation)
- Sending one network packet
- No sophisticated cryptographic attacks or timing requirements

**Within Threat Model:** The WSTS protocol explicitly tracks `malicious_signer_ids` [9](#0-8) , demonstrating that Byzantine faults from authorized signers are an expected threat scenario. However, the protocol assumes malicious signers will send *valid but adversarial* protocol messages, not that they can inject unbounded data.

## Recommendation

Add message validation in the `gather_nonces()` function to verify that `nonce_response.message` matches the expected `self.message`:

```rust
// After line 861 in gather_nonces(), add:
if nonce_response.message != self.message {
    warn!(
        signer_id = %nonce_response.signer_id, 
        "NonceResponse message does not match expected message"
    );
    return Ok(());
}
```

**Additional hardening:**
1. Add a configurable maximum message size constant (e.g., `MAX_MESSAGE_SIZE = 1MB`)
2. Validate message size in `start_signing_round()` before storing
3. Validate message size when deserializing `NonceResponse` messages
4. Document expected message size limits for integrators

## Proof of Concept

```rust
#[test]
fn test_malicious_large_message_dos() {
    use crate::state_machine::coordinator::fire::Coordinator;
    use crate::net::{NonceResponse, PublicNonce, Message, Packet};
    use crate::curve::point::Point;
    
    // Setup coordinator with normal configuration
    let mut coordinator = /* initialize coordinator */;
    
    // Start signing round with normal 32-byte message
    let normal_message = vec![0u8; 32];
    coordinator.start_signing_round(&normal_message, SignatureType::Frost, None).unwrap();
    
    // Malicious signer creates NonceResponse with 100MB message
    let malicious_message = vec![0u8; 100_000_000]; // 100 MB
    let malicious_response = NonceResponse {
        dkg_id: coordinator.current_dkg_id,
        sign_id: coordinator.current_sign_id,
        sign_iter_id: coordinator.current_sign_iter_id,
        signer_id: 1, // Authorized signer ID
        key_ids: vec![0],
        nonces: vec![/* valid nonces */],
        message: malicious_message, // MALICIOUS: different from normal_message
    };
    
    // Coordinator processes this and stores 100MB in memory
    let packet = Packet {
        sig: /* valid signature from signer 1 */,
        msg: Message::NonceResponse(malicious_response),
    };
    
    coordinator.process(packet).unwrap();
    
    // Verify: message_nonces now contains 100MB entry
    // Verify: No error was returned despite message mismatch
    // Memory profiling would show 100MB+ allocation
}
```

**Notes:**
- The codebase contains no constants for `MAX_MESSAGE_SIZE` or similar limits (verified via grep)
- Honest signers echo the received message [10](#0-9)  but malicious signers can deviate
- The protocol's Byzantine fault tolerance assumes signers may be malicious but does not account for resource exhaustion attacks through unbounded data injection

### Citations

**File:** src/state_machine/coordinator/fire.rs (L46-46)
```rust
    message_nonces: BTreeMap<Vec<u8>, SignRoundInfo>,
```

**File:** src/state_machine/coordinator/fire.rs (L850-915)
```rust
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

**File:** src/state_machine/coordinator/fire.rs (L954-954)
```rust
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

**File:** src/net.rs (L366-366)
```rust
        hasher.update(self.message.as_slice());
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

**File:** src/state_machine/signer/mod.rs (L740-740)
```rust
            message: nonce_request.message.clone(),
```
