### Title
FIRE Coordinator Message Substitution via Unvalidated NonceResponse.message Field

### Summary
The FIRE coordinator in `src/state_machine/coordinator/fire.rs` does not validate that `NonceResponse.message` matches the original `NonceRequest.message`. Instead, it groups nonces by the unvalidated message field and overwrites its intended signing message when threshold is reached, allowing colluding malicious signers to force the coordinator to produce a valid group signature for an attacker-controlled message rather than the intended message.

### Finding Description

**Exact Code Location:** [1](#0-0) 

**Root Cause:**
The `gather_nonces` function performs comprehensive validation of `NonceResponse` fields including `dkg_id`, `sign_id`, `sign_iter_id`, `signer_id`, `key_ids`, and nonces themselves, but completely omits validation of the `message` field. The coordinator groups nonces by message and overwrites its signing message when threshold is reached: [2](#0-1) [3](#0-2) 

The coordinator stores its intended message during `start_signing_round`: [4](#0-3) 

And sends it in `NonceRequest`: [5](#0-4) 

Honest signers copy the message from `NonceRequest` into `NonceResponse`: [6](#0-5) 

**Why Existing Mitigations Fail:**
The code validates all other `NonceResponse` fields (dkg_id, sign_id, sign_iter_id, signer_id, key_ids, nonces) but has no check comparing `nonce_response.message` against `self.message`. The message is used later to compute binding values which are fundamental to signature security: [7](#0-6) 

### Impact Explanation

**Specific Harm:**
A colluding group of threshold malicious signers can force the coordinator to produce a valid group signature for message B when the coordinator intended to sign message A. This completely breaks the signature scheme's core security property that signatures should only be created for intended messages.

**Quantified Impact:**
- With threshold T signers colluding, they can substitute ANY message
- The coordinator produces a cryptographically valid signature under the group public key for the attacker's message
- No errors or warnings occur; the attack is completely transparent to the coordinator
- The signature can be used to authorize transactions, operations, or state transitions for the wrong message

**Who Is Affected:**
Any system using WSTS FIRE coordinator for threshold signatures where signers could collude (e.g., byzantine fault scenarios, compromised signers, or economically motivated adversaries).

**Severity Justification:**
CRITICAL - Maps directly to "Any confirmation of an invalid transaction, such as with an incorrect nonce" in the protocol scope. The coordinator signs a completely different message than intended, which would authorize invalid transactions or operations in dependent systems like Stacks blockchain.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control of at least threshold (T) signers to collude
- Ability to respond to `NonceRequest` with modified message field
- No cryptographic breaks required

**Attack Complexity:**
Trivial. The attack is a simple message field substitution in `NonceResponse`:
1. Wait for coordinator to send `NonceRequest(message=A)`
2. Colluding signers respond with `NonceResponse(message=B)` 
3. Coordinator automatically accepts and signs message B

**Economic Feasibility:**
If threshold signers are compromised or economically motivated to attack, this is trivial to execute with no additional resources needed.

**Detection Risk:**
Zero. The coordinator logs no errors or warnings. From the coordinator's perspective, everything appears normal.

**Estimated Probability:**
HIGH in scenarios with compromised or colluding threshold signers. The attack is deterministic and requires no complex timing or race conditions.

### Recommendation

**Primary Fix:**
Add strict message validation in `gather_nonces` before processing the `NonceResponse`:

```rust
// In gather_nonces function, add after line 861:
if nonce_response.message != self.message {
    warn!(
        signer_id = %nonce_response.signer_id,
        "NonceResponse message does not match NonceRequest message"
    );
    return Ok(());
}
```

Remove the message substitution logic at line 954 and instead verify all collected nonces are for the same message as `self.message`.

**Alternative Mitigation:**
Remove the `message_nonces` HashMap keyed by message entirely. Since the coordinator should only be signing one message at a time per signing round, store nonce responses directly without grouping by message.

**Testing Recommendations:**
1. Add unit test where malicious signer sends different message in `NonceResponse`
2. Verify coordinator rejects the response with warning log
3. Add integration test with threshold colluding signers attempting message substitution
4. Verify final signature fails or is rejected

**Deployment Considerations:**
This is a critical security fix that should be deployed immediately. The fix is backward compatible (honest signers already send matching messages) and only adds validation that should have been present.

### Proof of Concept

**Exploitation Algorithm:**

1. **Setup**: Coordinator configured with threshold T=2, num_signers=3
2. **Attack Initiation**: Coordinator calls `start_signing_round(message_A, SignatureType::Frost, None)`
3. **Coordinator Action**: Sends `NonceRequest(message=message_A)` to all signers
4. **Attacker Response**: Two colluding malicious signers respond with:
   - `NonceResponse(message=message_B, ...)` where `message_B ≠ message_A`
   - Both use same `message_B` to reach threshold
5. **Coordinator Behavior**: 
   - Groups nonces by `message_B` in `message_nonces` HashMap
   - At line 954: executes `self.message = message_B`
   - Reaches threshold with 2 signers (meets T=2)
6. **Result**: Coordinator proceeds to `request_sig_shares` with `message=message_B`
7. **Final Outcome**: Valid group signature produced for `message_B` instead of intended `message_A`

**Expected vs Actual Behavior:**
- **Expected**: Coordinator should reject `NonceResponse` with mismatched message, log warning, and not count it toward threshold
- **Actual**: Coordinator accepts mismatched message, overwrites its signing target, and produces signature for attacker's message

**Reproduction:**
1. Deploy test with 3 signers, threshold 2
2. Modify 2 signers to respond with different message in `NonceResponse`
3. Observe coordinator logs - no errors or warnings
4. Observe final signature verifies against the substituted message, not original

**Notes**

The FROST coordinator implementation also lacks message validation in `NonceResponse` but does not exhibit the message substitution behavior since it doesn't overwrite `self.message`. However, it should still validate that `nonce_response.message == self.message` to ensure nonces were generated for the correct message, as nonces in threshold signatures must be committed to the specific message being signed.

The vulnerability exists because the FIRE coordinator was designed to support "winning message" semantics where multiple messages could compete, but this creates a critical security flaw when malicious signers can inject arbitrary messages.

### Citations

**File:** src/state_machine/coordinator/fire.rs (L814-839)
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

**File:** src/state_machine/coordinator/fire.rs (L841-962)
```rust
    fn gather_nonces(
        &mut self,
        packet: &Packet,
        signature_type: SignatureType,
    ) -> Result<(), Error> {
        if let Message::NonceResponse(nonce_response) = &packet.msg {
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
    }
```

**File:** src/state_machine/coordinator/fire.rs (L964-996)
```rust
    fn request_sig_shares(&mut self, signature_type: SignatureType) -> Result<Packet, Error> {
        self.signature_shares.clear();
        info!(
            sign_id = %self.current_sign_id,
            "Requesting Signature Shares"
        );
        let nonce_responses = self
            .message_nonces
            .get(&self.message)
            .ok_or(Error::MissingMessageNonceInfo)?
            .public_nonces
            .values()
            .cloned()
            .collect::<Vec<NonceResponse>>();
        let sig_share_request = SignatureShareRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            nonce_responses,
            message: self.message.clone(),
            signature_type,
        };
        let sig_share_request_msg = Packet {
            sig: sig_share_request
                .sign(&self.config.message_private_key)
                .expect("Failed to sign SignatureShareRequest"),
            msg: Message::SignatureShareRequest(sig_share_request),
        };
        self.move_to(State::SigShareGather(signature_type))?;
        self.sign_start = Some(Instant::now());

        Ok(sig_share_request_msg)
    }
```

**File:** src/state_machine/coordinator/fire.rs (L1457-1476)
```rust
    fn start_signing_round(
        &mut self,
        message: &[u8],
        signature_type: SignatureType,
        sign_id: Option<u64>,
    ) -> Result<Packet, Error> {
        // We cannot sign if we haven't first set DKG (either manually or via DKG round).
        if self.aggregate_public_key.is_none() {
            return Err(Error::MissingAggregatePublicKey);
        }
        self.message = message.to_vec();
        if let Some(id) = sign_id {
            self.current_sign_id = id;
        } else {
            self.current_sign_id = self.current_sign_id.wrapping_add(1);
        }
        info!("Starting signing round {}", self.current_sign_id);
        self.move_to(State::NonceRequest(signature_type))?;
        self.request_nonces(signature_type)
    }
```

**File:** src/state_machine/signer/mod.rs (L723-755)
```rust
    fn nonce_request<R: RngCore + CryptoRng>(
        &mut self,
        nonce_request: &NonceRequest,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let mut msgs = vec![];
        let signer_id = self.signer_id;
        let key_ids = self.signer.get_key_ids();
        let nonces = self.signer.gen_nonces(&self.network_private_key, rng);

        let response = NonceResponse {
            dkg_id: nonce_request.dkg_id,
            sign_id: nonce_request.sign_id,
            sign_iter_id: nonce_request.sign_iter_id,
            signer_id,
            key_ids,
            nonces,
            message: nonce_request.message.clone(),
        };

        let response = Message::NonceResponse(response);

        info!(
            %signer_id,
            dkg_id = %nonce_request.dkg_id,
            sign_id = %nonce_request.sign_id,
            sign_iter_id = %nonce_request.sign_iter_id,
            "sending NonceResponse"
        );
        msgs.push(response);

        Ok(msgs)
    }
```
