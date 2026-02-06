### Title
Remotely Exploitable Memory Exhaustion in Coordinator via Unlimited Message Maps during Nonce Gathering

### Summary
An authorized signer can cause the coordinator to exhaust memory during the NonceGather phase by sending many large or arbitrary unique messages in NonceResponse packets, creating unbounded entries in the `message_nonces` map. This can lead to denial-of-service, remotely, from any signer, and may also open the door for message substitution if an attacker holds sufficient signing weight.

### Finding Description
The affected code is in `src/state_machine/coordinator/fire.rs` in `Coordinator::gather_nonces()` (lines 917-920). The code uses `.entry(nonce_response.message.clone()).or_default()` to ensure that every unique message received in a NonceResponse creates a new entry in the `message_nonces` map. There are no explicit limits on the size or number of messages accepted, and the only requirement is that the signer is valid and the message is unique. As a result, any signer can send many large NonceResponses with different `message` fields, causing the coordinator to allocate memory for each one. The map is only cleared at the start of the next signing round, so memory is not reclaimed until the round completes. Existing mitigations (message size or count limits, or abuse detection) are **absent**. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
The attacker can cause full denial of service on the coordinator node by exhausting its memory resources. For example, 1,000 messages of size 1MB each would consume around 1GB of RAM. The protocol does not enforce message uniqueness, size, or a cap on concurrent messages. In an extended attack window (before timeout triggers), the attacker can continually increase memory usage, leading to a crash or serious instability in the node. This is classified as a **High Severity** issue per scope: "Any remotely-exploitable memory access... (attacks restricted to the Stacks blockchain RPC/P2P ports)" and "Any network DoS impacting more than 10 percent of miners". [4](#0-3) 

### Likelihood Explanation
- **Attacker Capabilities:** Must be an authorized signer (has key/weight in group).
- **Complexity:** Very low; send many distinct NonceResponse messages with large/unique message fields.
- **Economic Feasibility:** Cheap; only requires network access and valid signing key.
- **Probability:** Very high; mitigations are absent, and there's no message size/count cap, so the attack can be performed by any group participant.
- **Detection:** The node may log warning-level events, but those are insufficient to prevent attack or provide immediate remediation.

### Recommendation
- Impose a strict upper bound on both the number of concurrent entries in `message_nonces` and the size of the `message` field in NonceResponse.
- Reject or ignore NonceResponse packets with abnormally large messages or when total concurrent messages exceeds a protocol-defined threshold (e.g., 8-16).
- Consider rate-limiting or marking as malicious any signer exceeding reasonable signing rates or message diversity.
- Apply the same control in all relevant coordinator algorithms (FIRE, FROST).
- Add well-defined logging and operator alerting for such abuse cases.
- Add test cases for malicious nonce flooding.

### Proof of Concept
**Exploit Algorithm:**
1. Attacker joins the protocol as a valid signer.
2. During NonceGather phase send 1,000 NonceResponse packets, each with a unique random or large `message` (e.g., 1MB payload).
3. Each will pass the `.entry().or_default()` check and create a new entry in `message_nonces`, allocating memory for the message and SignRoundInfo. Repeat as needed.
4. Observe the node's memory usage increase until it is unable to process further messages or crashes.

**Parameters:**
- Number of NonceResponse packets: 1,000
- Message size: 1MB
- Total memory consumed: ≥1GB per 1,000 messages

**Expected vs Actual:**
- **Expected:** Coordinator drops or rejects excessive messages.
- **Actual:** Coordinator allocates memory per message with no limit, resulting in DoS.

**Reproduction:**
- Start a testnet with the FIRE coordinator.
- Have one signer send the above exploit messages during a signing round.
- Observe node memory and behavior. [4](#0-3) [2](#0-1) [3](#0-2) [5](#0-4)

### Citations

**File:** src/state_machine/coordinator/fire.rs (L814-840)
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
    }

```

**File:** src/state_machine/coordinator/fire.rs (L917-961)
```rust
            let nonce_info = self
                .message_nonces
                .entry(nonce_response.message.clone())
                .or_default();

            let have_nonces = nonce_info
                .public_nonces
                .contains_key(&nonce_response.signer_id);

            if have_nonces {
                info!(signer_id = %nonce_response.signer_id, "Received duplicate NonceResponse");
                return Ok(());
            }

            nonce_info
                .public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());

            // ignore the passed key_ids
            for key_id in signer_key_ids {
                nonce_info.nonce_recv_key_ids.insert(*key_id);
            }

            nonce_info
                .sign_wait_signer_ids
                .insert(nonce_response.signer_id);
            // Because of entry call, it is safe to unwrap here
            info!(
                sign_id = %nonce_response.sign_id,
                sign_iter_id = %nonce_response.sign_iter_id,
                signer_id = %nonce_response.signer_id,
                recv_keys = %nonce_info.nonce_recv_key_ids.len(),
                threshold = %self.config.threshold,
                "Received NonceResponse"
            );
            if nonce_info.nonce_recv_key_ids.len() >= self.config.threshold as usize {
                // We have a winning message!
                self.message.clone_from(&nonce_response.message);
                let aggregate_nonce = self.compute_aggregate_nonce();
                info!("Aggregate nonce: {aggregate_nonce}");

                self.move_to(State::SigShareRequest(signature_type))?;
            }
        }
        Ok(())
```

**File:** src/state_machine/coordinator/mod.rs (L46-46)
```rust
    SigShareGather(SignatureType),
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
