### Title
Missing `sign_iter_id` Validation Allows Signature Share Replay Attack Causing Persistent Denial of Service

### Summary
The coordinator's `gather_sig_shares` function fails to validate the `sign_iter_id` field of incoming `SignatureShareResponse` messages, and this field is not included in the message signature hash. An attacker can replay valid signature share responses from old signing iterations by modifying the `sign_iter_id` field, causing signature aggregation to fail repeatedly and preventing the protocol from producing signatures indefinitely.

### Finding Description

**Root Cause 1: Missing `sign_iter_id` Validation**

The coordinator's `gather_sig_shares` function in `src/state_machine/coordinator/fire.rs` only validates `dkg_id` and `sign_id` but does NOT validate `sign_iter_id`: [1](#0-0) 

Compare this to the `gather_nonces` function in the same file, which correctly validates all three round IDs including `sign_iter_id`: [2](#0-1) 

**Root Cause 2: Missing `sign_iter_id` in Message Hash**

The `Signable` implementation for `SignatureShareResponse` does not include `sign_iter_id` in the hash computation, only including `dkg_id`, `sign_id`, and `signer_id`: [3](#0-2) 

This means an attacker can modify the `sign_iter_id` field from value N to N+1 without invalidating the message signature, since the signature only covers the hash which doesn't include this field.

**Attack Flow:**

When a signature share timeout occurs, the coordinator increments `sign_iter_id` and requests new nonces: [4](#0-3) 

1. **Iteration N**: Coordinator requests signature shares. Signer A responds with `SignatureShareResponse(sign_iter_id=N)` containing signature shares computed with nonces from iteration N.

2. **Timeout occurs**: Coordinator times out waiting for other signers, increments `sign_iter_id` to N+1, and clears old state: [5](#0-4) 

3. **Iteration N+1**: Coordinator requests new nonces with `sign_iter_id=N+1`. Signers respond with fresh nonces.

4. **Attack**: Attacker intercepts the old `SignatureShareResponse` from iteration N, modifies `sign_iter_id` from N to N+1, and replays it. The coordinator accepts it because:
   - No validation check for `sign_iter_id` in `gather_sig_shares`
   - Message signature remains valid (field not in hash)

5. **Impact**: The coordinator attempts aggregation using:
   - Fresh nonces from iteration N+1
   - Replayed signature shares from iteration N (computed with different nonces)
   
   The aggregated signature fails verification: [6](#0-5) 

6. **Result**: Signing round fails with error returned to caller: [7](#0-6) 

The attacker can repeat this attack for every signing iteration, preventing signature generation indefinitely.

### Impact Explanation

**Specific Harm:**
- The protocol cannot produce valid signatures while under attack
- Signing rounds fail repeatedly with aggregation errors
- All signers are affected - legitimate signature shares are rejected when mixed with replayed old shares

**Quantified Impact:**
- An attacker controlling network position to intercept messages from even a single signer can block all signature generation
- Each signing iteration will fail, requiring timeout and retry (typically seconds to minutes per iteration)
- The attack can be sustained indefinitely as long as the attacker maintains network position
- In blockchain context: blocks cannot be signed, transactions cannot be confirmed

**Severity Justification:**
This maps to **Medium** severity per the scope definition: "Any transient consensus failures". The attack causes repeated signing failures, preventing block production and transaction confirmation. While it's a denial of service rather than permanent state corruption, it can be sustained indefinitely and affects the entire network's ability to function.

Could potentially escalate to **Low** for "Any network denial of service impacting more than 10 percent of miners" depending on deployment, but the primary classification is Medium due to consensus impact.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Network position to intercept `SignatureShareResponse` messages (MitM, malicious network node, or compromised infrastructure)
- Ability to modify and replay network packets
- No cryptographic breaks required
- No access to private keys needed

**Attack Complexity:**
- Low: Simple packet capture and replay with one field modification
- The `sign_iter_id` is not encrypted or authenticated separately
- Standard network interception tools sufficient

**Economic Feasibility:**
- High: Minimal resources required once network position is obtained
- Can be automated to replay messages continuously
- Single compromised signer's messages can be reused indefinitely

**Detection Risk:**
- Medium: Appears as legitimate signature share messages
- Only detectable through correlation analysis of signing failures
- No immediate cryptographic failure indication

**Estimated Probability:**
- High likelihood if attacker has network position (routing infrastructure, malicious peer, etc.)
- Medium likelihood in production networks with standard security (requires some level of access)

### Recommendation

**Fix 1: Add `sign_iter_id` Validation**

In `src/state_machine/coordinator/fire.rs`, add validation in the `gather_sig_shares` function immediately after the existing `sign_id` check:

```rust
if sig_share_response.sign_id != self.current_sign_id {
    return Err(Error::BadSignId(
        sig_share_response.sign_id,
        self.current_sign_id,
    ));
}
// ADD THIS:
if sig_share_response.sign_iter_id != self.current_sign_iter_id {
    return Err(Error::BadSignIterId(
        sig_share_response.sign_iter_id,
        self.current_sign_iter_id,
    ));
}
```

**Fix 2: Include `sign_iter_id` in Message Hash**

In `src/net.rs`, update the `Signable` implementation for `SignatureShareResponse` to include `sign_iter_id`:

```rust
impl Signable for SignatureShareResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("SIGNATURE_SHARE_RESPONSE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.sign_iter_id.to_be_bytes()); // ADD THIS LINE
        hasher.update(self.signer_id.to_be_bytes());
        // ... rest of function
    }
}
```

**Testing Recommendations:**
1. Add test case similar to `old_round_ids_are_ignored` that verifies `SignatureShareResponse` messages with old `sign_iter_id` values are rejected
2. Test that modified `sign_iter_id` invalidates message signature after Fix 2
3. Integration test that simulates timeout-retry scenario and verifies old responses are rejected

**Deployment Considerations:**
- Both fixes required for complete protection
- Fix 2 changes message format - requires coordinated upgrade across all nodes
- Backward compatibility: old signed messages will become invalid after Fix 2

### Proof of Concept

**Attack Algorithm:**

```
1. Setup:
   - Position attacker to intercept network traffic between signers and coordinator
   - Wait for a signing round to begin

2. Capture Phase (Iteration N):
   - Coordinator sends NonceRequest(sign_iter_id=N)
   - Signers respond with NonceResponse(sign_iter_id=N)
   - Coordinator sends SignatureShareRequest(sign_iter_id=N)
   - Signer A responds with SignatureShareResponse(sign_iter_id=N)
   - Attacker captures this response: MSG_N

3. Attack Phase (Iteration N+1):
   - Wait for timeout or cause packet loss to trigger iteration N+1
   - Coordinator increments sign_iter_id to N+1
   - Coordinator sends NonceRequest(sign_iter_id=N+1)
   - Legitimate signers respond with new nonces
   - Coordinator sends SignatureShareRequest(sign_iter_id=N+1)
   
4. Replay:
   - Modify captured MSG_N:
     * Change sign_iter_id field from N to N+1
     * Keep signature unchanged (it remains valid)
   - Send modified message to coordinator
   
5. Expected Behavior:
   - Coordinator accepts replayed message (no sign_iter_id validation)
   - Coordinator attempts aggregation with:
     * New nonces from iteration N+1
     * Old signature shares from iteration N
   - Aggregation produces invalid signature
   - Signature verification fails at aggregator.sign()
   - Error returned: OperationResult::SignError

6. Result:
   - Signing round fails
   - Coordinator retries (iteration N+2)
   - Repeat attack indefinitely
```

**Reproduction Steps:**

1. Set up WSTS test environment with 3 signers and coordinator
2. Configure signature timeout to trigger quickly (e.g., 5 seconds)
3. Start signing round for message M
4. Inject network delay for one signer to cause timeout
5. Capture `SignatureShareResponse` from first iteration
6. When coordinator moves to iteration 2, replay captured response with modified `sign_iter_id`
7. Observe: Coordinator accepts message, aggregation fails, signing round fails
8. Verify: No `Error::BadSignIterId` is returned (because validation is missing)

**Parameter Values:**
- dkg_id: any (e.g., 1)
- sign_id: any (e.g., 1)  
- sign_iter_id: increment from N to N+1 in replayed message
- Message: any 32-byte value
- Signature type: any (Frost, Schnorr, or Taproot)

### Citations

**File:** src/state_machine/coordinator/fire.rs (L173-204)
```rust
            State::SigShareGather(signature_type) => {
                if let Some(start) = self.sign_start {
                    if let Some(timeout) = self.config.sign_timeout {
                        if now.duration_since(start) > timeout {
                            warn!("Timeout gathering signature shares for signing round {} iteration {}", self.current_sign_id, self.current_sign_iter_id);
                            for signer_id in &self
                                .message_nonces
                                .get(&self.message)
                                .ok_or(Error::MissingMessageNonceInfo)?
                                .sign_wait_signer_ids
                            {
                                warn!("Mark signer {signer_id} as malicious");
                                self.malicious_signer_ids.insert(*signer_id);
                            }

                            let num_malicious_keys: u32 =
                                self.compute_num_key_ids(self.malicious_signer_ids.iter())?;

                            if self.config.num_keys - num_malicious_keys < self.config.threshold {
                                error!("Insufficient non-malicious signers, unable to continue");
                                let mal = self.malicious_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::SignError(
                                        SignError::InsufficientSigners(mal),
                                    )),
                                ));
                            }

                            self.move_to(State::NonceRequest(signature_type))?;
                            let packet = self.request_nonces(signature_type)?;
                            return Ok((Some(packet), None));
```

**File:** src/state_machine/coordinator/fire.rs (L327-332)
```rust
                State::SigShareGather(signature_type) => {
                    if let Err(e) = self.gather_sig_shares(packet, signature_type) {
                        return Ok((
                            None,
                            Some(OperationResult::SignError(SignError::Coordinator(e))),
                        ));
```

**File:** src/state_machine/coordinator/fire.rs (L814-816)
```rust
    fn request_nonces(&mut self, signature_type: SignatureType) -> Result<Packet, Error> {
        self.message_nonces.clear();
        self.current_sign_iter_id = self.current_sign_iter_id.wrapping_add(1);
```

**File:** src/state_machine/coordinator/fire.rs (L846-861)
```rust
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
```

**File:** src/state_machine/coordinator/fire.rs (L1027-1038)
```rust
        if sig_share_response.dkg_id != self.current_dkg_id {
            return Err(Error::BadDkgId(
                sig_share_response.dkg_id,
                self.current_dkg_id,
            ));
        }
        if sig_share_response.sign_id != self.current_sign_id {
            return Err(Error::BadSignId(
                sig_share_response.sign_id,
                self.current_sign_id,
            ));
        }
```

**File:** src/net.rs (L450-465)
```rust
impl Signable for SignatureShareResponse {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("SIGNATURE_SHARE_RESPONSE".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.sign_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());

        for signature_share in &self.signature_shares {
            hasher.update(signature_share.id.to_be_bytes());
            hasher.update(signature_share.z_i.to_bytes());
            for key_id in &signature_share.key_ids {
                hasher.update(key_id.to_be_bytes());
            }
        }
    }
}
```

**File:** src/v2.rs (L448-461)
```rust
    fn sign(
        &mut self,
        msg: &[u8],
        nonces: &[PublicNonce],
        sig_shares: &[SignatureShare],
        key_ids: &[u32],
    ) -> Result<Signature, AggregatorError> {
        let (key, sig) = self.sign_with_tweak(msg, nonces, sig_shares, key_ids, None)?;

        if sig.verify(&key, msg) {
            Ok(sig)
        } else {
            Err(self.check_signature_shares(msg, nonces, sig_shares, key_ids, None))
        }
```
