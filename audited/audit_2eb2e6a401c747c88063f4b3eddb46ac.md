### Title
Coordinator Memory Exhaustion via Unbounded NonceResponse Message Creation

### Summary
The `gather_nonces()` function in the coordinator accepts NonceResponse messages with arbitrary message values without validating they match the requested message, allowing attackers to create unlimited entries in the `message_nonces` map. A malicious signer can exhaust coordinator memory by sending many NonceResponse messages with different large message payloads during a signing round, causing denial of service.

### Finding Description

**Exact Code Location:**
File: `src/state_machine/coordinator/fire.rs`, Function: `gather_nonces()`, Lines: 917-920 [1](#0-0) 

**Root Cause:**
The coordinator uses `entry().or_default()` to create map entries keyed by `nonce_response.message` without validating that the message matches `self.message` (the message the coordinator actually requested nonces for). The coordinator validates dkg_id, sign_id, sign_iter_id, signer_id, and key_ids, but never checks the message field. [2](#0-1) 

The NonceRequest sent by the coordinator contains the expected message: [3](#0-2) 

However, incoming NonceResponse messages are accepted with any message value, and each unique message creates a new `SignRoundInfo` entry in the BTreeMap: [4](#0-3) [5](#0-4) 

**Why Existing Mitigations Fail:**

The duplicate check only prevents the same signer from sending multiple responses for the *same* message: [6](#0-5) 

This check occurs *after* the entry is created via `or_default()`, and only checks within the `nonce_info` for that specific message. A signer can send unlimited NonceResponse messages with *different* message values, bypassing this protection.

The `message_nonces.clear()` call only happens when starting a new signing iteration: [7](#0-6) 

This does not prevent accumulation during a single NonceGather phase.

Packet signature verification (if enabled) only authenticates that the message comes from a valid signer, but does not restrict message content: [8](#0-7) [9](#0-8) 

### Impact Explanation

**Specific Harm:**
A malicious signer can cause the coordinator to run out of memory (OOM) and crash or become unresponsive, preventing signature generation. Since the coordinator orchestrates the signing protocol, its failure blocks all signing operations for that instance.

**Quantified Impact:**
- Message field is `Vec<u8>` with no size restrictions
- With 10 malicious signers each sending 1,000 NonceResponse messages with 1MB payloads: 10 × 1,000 × 1MB = ~10GB memory consumption
- Each `SignRoundInfo` adds additional overhead with its BTreeMaps and HashSets
- Attack completes within the nonce timeout window (configurable, typically seconds to minutes)

**Who Is Affected:**
- Coordinator nodes become unresponsive
- Dependent signing operations fail
- If coordinator is critical for transaction confirmation, transactions cannot be signed

**Severity Justification:**
This maps to **Low** severity per the provided definitions: "Any remotely-exploitable denial of service in a node." The coordinator node can be DoS'd remotely by exhausting its memory, preventing it from completing signing operations.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Must control at least one valid signer (possess their private key) if `verify_packet_sigs` is enabled
- If `verify_packet_sigs` is disabled, no authentication is required (unauthenticated remote attack)
- Must be able to send messages to the coordinator during NonceGather state
- No special privileges beyond being a registered signer

**Attack Complexity:**
Low. The attacker simply needs to:
1. Wait for coordinator to enter NonceGather state
2. Send multiple properly-signed NonceResponse messages with different message values
3. Each message passes all validation checks except the missing message equality check

**Economic Feasibility:**
Very high. Minimal cost to generate messages and sign them. No computational barriers beyond message signing, which is trivial for valid signers.

**Detection Risk:**
Medium. The attack would be visible in logs as the coordinator receives many NonceResponse messages, but may be confused with legitimate protocol activity initially. Memory exhaustion would be obvious once it occurs.

**Estimated Probability:**
High if an adversary controls a signer key. The attack is straightforward to execute with no special conditions required beyond accessing the network during a signing round.

### Recommendation

**Proposed Code Change:**
Add validation in `gather_nonces()` to ensure the nonce response message matches the coordinator's expected message:

```rust
// After line 915, before line 917, add:
if nonce_response.message != self.message {
    warn!(
        signer_id = %nonce_response.signer_id,
        "NonceResponse message does not match coordinator's expected message"
    );
    return Ok(());
}
```

**Alternative Mitigations:**
1. Implement per-signer rate limiting on NonceResponse messages per signing iteration
2. Add maximum message size validation to reject oversized payloads
3. Limit the total number of entries in `message_nonces` map
4. Add memory consumption monitoring with automatic cleanup

**Testing Recommendations:**
1. Unit test: Send NonceResponse with message != coordinator's expected message, verify rejection
2. Integration test: Send multiple NonceResponse messages with different message values from same signer, verify only the matching message is accepted
3. Load test: Simulate attack with many large messages, verify coordinator remains stable

**Deployment Considerations:**
- This is a breaking change that will reject previously-accepted (though invalid) messages
- Deploy with coordinator restart to ensure clean state
- Monitor for legitimate signers accidentally sending wrong messages
- Consider graceful degradation if detection occurs

### Proof of Concept

**Exploitation Algorithm:**

1. Setup: Attacker controls valid signer with ID=1, has private key
2. Wait for coordinator to send NonceRequest (coordinator enters NonceGather state)
3. For i = 1 to 1000:
   - Create NonceResponse with:
     - dkg_id, sign_id, sign_iter_id matching coordinator's values
     - signer_id = 1
     - key_ids matching config
     - Valid nonces
     - message = large_payload(i) // e.g., 1MB of data with counter i
   - Sign the NonceResponse with signer private key
   - Send to coordinator
4. Each message creates new entry in `message_nonces`
5. Continue until coordinator OOMs

**Expected vs Actual Behavior:**

*Expected:* Coordinator should reject NonceResponse messages where `nonce_response.message != self.message`

*Actual:* Coordinator accepts all NonceResponse messages with valid signatures and matching round IDs, creating map entries for arbitrary message values

**Reproduction Steps:**
1. Configure coordinator with `num_signers = 10`, `threshold = 5`
2. Start signing round for legitimate message M
3. From compromised signer, send 1000 NonceResponse messages with messages M1, M2, ..., M1000 (each 1MB)
4. Observe `message_nonces` map grows unbounded
5. Coordinator eventually crashes with OOM or becomes unresponsive
6. Signing for legitimate message M fails

### Citations

**File:** src/state_machine/coordinator/fire.rs (L46-46)
```rust
    message_nonces: BTreeMap<Vec<u8>, SignRoundInfo>,
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

**File:** src/state_machine/coordinator/fire.rs (L822-827)
```rust
        let nonce_request = NonceRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            message: self.message.clone(),
            signature_type,
```

**File:** src/state_machine/coordinator/fire.rs (L847-920)
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
