### Title
Missing Message Validation in SignatureShareRequest Allows Coordinator to Switch Messages After Nonce Commitment

### Summary
Signers do not validate that the message field in NonceResponse matches the message field in SignatureShareRequest, allowing a malicious coordinator to collect nonces for one message and then request signatures for a different message using those same nonces. This breaks the authenticated commitment model where signers cryptographically commit to sign a specific message via their signed NonceResponse, enabling unauthorized transaction signing.

### Finding Description

**Exact Code Location:** [1](#0-0) 

The vulnerability exists in the `sign_share_request` function where signers process `SignatureShareRequest` messages from the coordinator. The function performs several validations:

1. Validates signer IDs are unique and in valid range [2](#0-1) 

2. Validates nonces are valid points [3](#0-2) 

3. Extracts nonces from nonce_responses [4](#0-3) 

4. Signs the message from SignatureShareRequest [5](#0-4) 

**Root Cause:**
The function never validates that `nonce_response.message` matches `sign_request.message`. Each `NonceResponse` contains a `message` field that represents the message the signer committed to sign when generating those nonces: [6](#0-5) 

When signers send `NonceResponse`, they include the message from the `NonceRequest`: [7](#0-6) 

Furthermore, `NonceResponse` is signed/authenticated and includes the message in its hash: [8](#0-7) 

This creates an authenticated commitment - the signer cryptographically binds their nonces to a specific message. However, when processing `SignatureShareRequest`, signers never verify this commitment is honored.

**Why Existing Mitigations Fail:**
- Packet signature verification validates the NonceResponse was authentically sent by the signer, but doesn't prevent message substitution
- The binding value computation uses the correct message, but this doesn't prevent protocol violation
- No sign_id-to-message binding exists in signer state

### Impact Explanation

**Specific Harm:**
A malicious or compromised coordinator can trick signers into signing arbitrary messages by:
1. Collecting authenticated NonceResponse messages for approved message A
2. Sending SignatureShareRequest with unapproved message B, including the NonceResponse messages from step 1
3. Signers will create valid signature shares for message B using nonces they committed to use only for message A

**Quantified Impact:**
- In blockchain context: Signers could authorize transactions they never approved
- Breaks the security model where NonceResponse is an authenticated commitment
- Affects all signers participating in the signing round
- Every signing round is vulnerable to message substitution

**Severity Justification:**
This maps to **Critical** severity under the protocol scope: **"Any confirmation of an invalid transaction"**. The vulnerability allows confirmation of transactions (messages) that signers never agreed to sign, as their authenticated nonce commitments are violated. While signers technically create valid cryptographic signatures, they do so for messages they never authorized, which is equivalent to confirming invalid transactions in the trust model.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Position: Malicious or compromised coordinator
- Access: Ability to send NonceRequest and SignatureShareRequest messages (standard coordinator role)
- No cryptographic breaks required
- No access to private keys needed

**Attack Complexity:**
- Simple message substitution attack
- Requires only standard coordinator message-sending privileges
- No timing constraints beyond normal protocol flow
- No complex exploitation technique required

**Economic Feasibility:**
- Zero additional cost beyond coordinator operation
- High value if used to authorize unauthorized blockchain transactions
- Detection risk is low as signatures are cryptographically valid

**Estimated Probability:**
If the coordinator is malicious or compromised, success probability is near 100% as there is no validation to prevent this attack.

### Recommendation

Add validation in the `sign_share_request` function to ensure all NonceResponse messages have a message field matching the SignatureShareRequest message:

```rust
fn sign_share_request<R: RngCore + CryptoRng>(
    &mut self,
    sign_request: &SignatureShareRequest,
    rng: &mut R,
) -> Result<Vec<Message>, Error> {
    // ... existing validations ...
    
    // NEW VALIDATION: Verify message consistency
    for nonce_response in &sign_request.nonce_responses {
        if nonce_response.message != sign_request.message {
            warn!(
                "NonceResponse message mismatch: expected {:?}, got {:?}",
                hex::encode(&sign_request.message),
                hex::encode(&nonce_response.message)
            );
            return Err(Error::InvalidNonceResponse);
        }
    }
    
    // ... rest of function ...
}
```

**Testing Recommendations:**
1. Add unit test where coordinator sends SignatureShareRequest with mismatched message
2. Verify signers reject the request with Error::InvalidNonceResponse
3. Add integration test ensuring full signing round fails if message is switched
4. Test with all signature types (Frost, Schnorr, Taproot)

### Proof of Concept

**Exploitation Algorithm:**

1. **Setup:** Coordinator has DKG completed with N signers, threshold T

2. **Collect Nonces for Approved Message:**
   ```
   approved_message = "transfer 10 BTC to Alice"
   NonceRequest {
       dkg_id: 1,
       sign_id: 1,
       sign_iter_id: 1,
       message: approved_message,
       signature_type: Schnorr
   }
   ```
   Signers respond with authenticated NonceResponse including approved_message

3. **Switch Message:**
   ```
   malicious_message = "transfer 100 BTC to Attacker"
   SignatureShareRequest {
       dkg_id: 1,
       sign_id: 1,
       sign_iter_id: 1,
       nonce_responses: [/* responses from step 2 with approved_message */],
       message: malicious_message,  // DIFFERENT MESSAGE
       signature_type: Schnorr
   }
   ```

4. **Expected Behavior:**
   Signers should reject due to message mismatch

5. **Actual Behavior:**
   Signers create valid signature shares for malicious_message, allowing coordinator to aggregate a complete signature for the unauthorized transaction

**Reproduction:**
The vulnerability can be demonstrated by modifying existing tests in `src/state_machine/coordinator/mod.rs` to send a SignatureShareRequest with a different message than the NonceRequest, then verifying that signers produce signature shares without error.

### Citations

**File:** src/state_machine/signer/mod.rs (L733-741)
```rust
        let response = NonceResponse {
            dkg_id: nonce_request.dkg_id,
            sign_id: nonce_request.sign_id,
            sign_iter_id: nonce_request.sign_iter_id,
            signer_id,
            key_ids,
            nonces,
            message: nonce_request.message.clone(),
        };
```

**File:** src/state_machine/signer/mod.rs (L757-842)
```rust
    fn sign_share_request<R: RngCore + CryptoRng>(
        &mut self,
        sign_request: &SignatureShareRequest,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let signer_id_set = sign_request
            .nonce_responses
            .iter()
            .map(|nr| nr.signer_id)
            .collect::<BTreeSet<u32>>();

        // The expected usage is that Signer IDs start at zero and
        // increment by one until self.total_signers - 1. So the checks
        // here should be sufficient for catching empty signer ID sets,
        // duplicate signer IDs, or unknown signer IDs.
        let is_invalid_request = sign_request.nonce_responses.len() != signer_id_set.len()
            || signer_id_set.is_empty()
            || signer_id_set.last() >= Some(&self.total_signers);

        if is_invalid_request {
            warn!("received an invalid SignatureShareRequest");
            return Err(Error::InvalidNonceResponse);
        }

        let nonces = sign_request
            .nonce_responses
            .iter()
            .flat_map(|nr| nr.nonces.clone())
            .collect::<Vec<PublicNonce>>();

        for nonce in &nonces {
            if !nonce.is_valid() {
                warn!(
                    signer_id = %self.signer_id,
                    "received an SignatureShareRequest with invalid nonce"
                );
                return Err(Error::InvalidNonceResponse);
            }
        }

        debug!(signer_id = %self.signer_id, "received a valid SignatureShareRequest");

        if signer_id_set.contains(&self.signer_id) {
            let key_ids: Vec<u32> = sign_request
                .nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.iter().copied())
                .collect::<Vec<u32>>();

            let signer_ids = signer_id_set.into_iter().collect::<Vec<_>>();
            let msg = &sign_request.message;
            let signature_shares = match sign_request.signature_type {
                SignatureType::Taproot(merkle_root) => {
                    self.signer
                        .sign_taproot(msg, &signer_ids, &key_ids, &nonces, merkle_root)
                }
                SignatureType::Schnorr => {
                    self.signer
                        .sign_schnorr(msg, &signer_ids, &key_ids, &nonces)
                }
                SignatureType::Frost => self.signer.sign(msg, &signer_ids, &key_ids, &nonces),
            };

            self.signer.gen_nonces(&self.network_private_key, rng);

            let response = SignatureShareResponse {
                dkg_id: sign_request.dkg_id,
                sign_id: sign_request.sign_id,
                sign_iter_id: sign_request.sign_iter_id,
                signer_id: self.signer_id,
                signature_shares,
            };
            info!(
                signer_id = %self.signer_id,
                dkg_id = %sign_request.dkg_id,
                sign_id = %sign_request.sign_id,
                sign_iter_id = %sign_request.sign_iter_id,
                "sending SignatureShareResponse"
            );

            Ok(vec![Message::SignatureShareResponse(response)])
        } else {
            debug!(signer_id = %self.signer_id, "signer not included in SignatureShareRequest");
            Ok(Vec::new())
        }
    }
```

**File:** src/net.rs (L310-326)
```rust
/// Nonce response message from signers to coordinator
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

**File:** src/net.rs (L349-368)
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
}
```
