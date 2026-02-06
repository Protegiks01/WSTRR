### Title
Nonce Mismatch Vulnerability via Duplicate NonceRequest Processing

### Summary
The signer's `nonce_request()` handler processes duplicate `NonceRequest` messages without deduplication, causing `Party::gen_nonce()` to overwrite previously generated nonces. Since the coordinator rejects duplicate `NonceResponse` messages, this creates a mismatch between the signer's stored nonce and the public nonce the coordinator expects, causing signature verification to fail and resulting in a denial of service.

### Finding Description

**Exact Code Location:**
- Nonce generation and storage: [1](#0-0) 
- Missing deduplication in signer: [2](#0-1) 
- Signature computation using stored nonce: [3](#0-2) 
- Coordinator duplicate rejection: [4](#0-3) 

**Root Cause:**
The `Party::gen_nonce()` function unconditionally overwrites the internal `self.nonce` field each time it is called. [5](#0-4)  The signer's `nonce_request()` handler calls `gen_nonces()` without checking if a nonce has already been generated for the current signing round (identified by `dkg_id`, `sign_id`, `sign_iter_id`). [6](#0-5) 

When duplicate `NonceRequest` messages are processed, the signer generates a new nonce and sends a new `NonceResponse`. However, the coordinator's `gather_nonces()` function rejects duplicate `NonceResponse` messages from the same signer. [4](#0-3)  This creates a critical mismatch: the coordinator uses the first public nonce in signature aggregation, but the signer's internal nonce has been overwritten with a different value.

**Why Existing Mitigations Fail:**
The coordinator protects against duplicate `NonceResponse` messages but cannot prevent the signer from processing duplicate `NonceRequest` messages. The signer has no state tracking to detect and ignore duplicate requests for the same signing round. [7](#0-6) 

### Impact Explanation

**Specific Harm:**
When signature shares are computed, the signer uses `self.nonce.d` and `self.nonce.e` in the calculation: `z = d + e * binding(...)`. [8](#0-7)  If the stored nonce differs from the public nonce the coordinator used to compute binding values and aggregate the signature, the final aggregated signature will fail verification.

**Quantified Impact:**
Each successful attack causes one signing round to fail completely. The signing operation must be retried from the beginning with new nonces. In a blockchain context using WSTS for threshold signatures, this delays transaction signing and could prevent timely block production or transaction confirmations.

**Who is Affected:**
All participants in the signing round are affected. The entire signing operation fails, not just the attacked signer's contribution.

**Severity Justification:**
This constitutes a "transient consensus failure" as defined in the Medium severity category. The signing round fails but can be retried. It does not cause permanent loss of funds, chain splits, or acceptance of invalid signatures.

### Likelihood Explanation

**Required Attacker Capabilities:**
1. **With message authentication disabled** (`verify_packet_sigs=false`): Any network-level attacker who can observe and replay `NonceRequest` packets
2. **With message authentication enabled** (`verify_packet_sigs=true`): Either (a) compromise of the coordinator's signing key, or (b) a malicious or buggy coordinator that sends duplicate `NonceRequest` messages

**Attack Complexity:**
Low. The attacker simply needs to replay a `NonceRequest` packet to the target signer between the time the signer sends its `NonceResponse` and receives the `SignatureShareRequest`. Network delays provide a natural window of opportunity.

**Economic Feasibility:**
Minimal cost - requires only packet capture and replay capabilities on the network path between coordinator and signers.

**Detection Risk:**
Low risk of detection. The attack appears as legitimate protocol messages. The only observable effect is signature verification failures, which could be attributed to network issues or software bugs.

**Estimated Probability:**
High if message authentication is disabled. Medium if a coordinator key is compromised or the coordinator implementation has bugs. Low in well-configured deployments with message authentication and trusted coordinators.

### Recommendation

**Proposed Code Changes:**

1. Add signing round tracking to the signer state machine. Track processed `NonceRequest` messages by `(dkg_id, sign_id, sign_iter_id)` tuple.

2. Modify `nonce_request()` in `src/state_machine/signer/mod.rs` to check if a nonce has already been generated for the current signing round:

```rust
fn nonce_request<R: RngCore + CryptoRng>(
    &mut self,
    nonce_request: &NonceRequest,
    rng: &mut R,
) -> Result<Vec<Message>, Error> {
    // Check if we've already processed this signing round
    if self.sign_id == nonce_request.sign_id && 
       self.sign_iter_id == nonce_request.sign_iter_id &&
       self.dkg_id == nonce_request.dkg_id {
        info!(%self.signer_id, "Ignoring duplicate NonceRequest");
        return Ok(vec![]);
    }
    
    // Update current signing round identifiers
    self.sign_id = nonce_request.sign_id;
    self.sign_iter_id = nonce_request.sign_iter_id;
    
    // Existing nonce generation logic...
    let nonces = self.signer.gen_nonces(&self.network_private_key, rng);
    // ... rest of function
}
```

3. Alternative: Add a state transition such that after sending `NonceResponse`, the signer moves to a `NonceWaiting` state and ignores further `NonceRequest` messages until receiving `SignatureShareRequest`.

**Testing Recommendations:**
- Add integration test that sends duplicate `NonceRequest` messages and verifies they are ignored
- Add test that verifies signature succeeds even with attempted replay attacks
- Test boundary conditions: duplicate requests with different messages, different sign_ids, etc.

**Deployment Considerations:**
- Ensure message authentication is enabled in production (`verify_packet_sigs=true`)
- Document the signing round deduplication behavior
- Consider adding metrics/logging for duplicate request detection

### Proof of Concept

**Exploitation Steps:**

1. **Setup:** Configure WSTS coordinator and signer with message authentication disabled for testing
2. **Normal Flow Initiated:** Coordinator sends `NonceRequest(dkg_id=1, sign_id=1, sign_iter_id=1, message=M)`
3. **Signer Responds:** 
   - Signer generates nonce_A = {d: random1, e: random2}
   - Stores: `Party.nonce = nonce_A`
   - Computes: `PublicNonce_A = {D: random1*G, E: random2*G}`
   - Sends `NonceResponse(PublicNonce_A)`
4. **Attack:** Replay the same `NonceRequest(dkg_id=1, sign_id=1, sign_iter_id=1, message=M)` to signer
5. **Signer Processes Duplicate:**
   - Signer generates nonce_B = {d: random3, e: random4} (different random values)
   - Overwrites: `Party.nonce = nonce_B`
   - Computes: `PublicNonce_B = {D: random3*G, E: random4*G}`
   - Sends second `NonceResponse(PublicNonce_B)`
6. **Coordinator Behavior:**
   - Accepts first `NonceResponse(PublicNonce_A)`
   - Rejects second `NonceResponse(PublicNonce_B)` as duplicate from same signer_id
   - Stores only `PublicNonce_A` for this signer
7. **Signing Phase:**
   - Coordinator sends `SignatureShareRequest` with `PublicNonce_A` in nonce list
   - Signer computes: `z = nonce_B.d + nonce_B.e * binding(...)` (using overwritten nonce)
   - Expected: `z = nonce_A.d + nonce_A.e * binding(...)` (based on PublicNonce_A)
8. **Result:** Signature aggregation fails verification

**Expected vs Actual Behavior:**
- **Expected:** Duplicate `NonceRequest` messages are ignored, nonces remain consistent
- **Actual:** Each `NonceRequest` overwrites stored nonces, creating mismatch with coordinator's expectations

**Reproduction:**
Can be reproduced in existing integration tests by modifying the coordinator to send duplicate `NonceRequest` messages and observing signature verification failure.

### Citations

**File:** src/v1.rs (L96-104)
```rust
    pub fn gen_nonce<RNG: RngCore + CryptoRng>(
        &mut self,
        secret_key: &Scalar,
        rng: &mut RNG,
    ) -> PublicNonce {
        self.nonce = Nonce::random(secret_key, rng);

        PublicNonce::from(&self.nonce)
    }
```

**File:** src/v1.rs (L217-229)
```rust
    pub fn sign(&self, msg: &[u8], signers: &[u32], nonces: &[PublicNonce]) -> SignatureShare {
        let (_, aggregate_nonce) = compute::intermediate(msg, signers, nonces);
        let mut z = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        z += compute::challenge(&self.group_key, &aggregate_nonce, msg)
            * &self.private_key
            * compute::lambda(self.id, signers);

        SignatureShare {
            id: self.id,
            z_i: z,
            key_ids: vec![self.id],
        }
    }
```

**File:** src/state_machine/signer/mod.rs (L484-484)
```rust
            Message::NonceRequest(nonce_request) => self.nonce_request(nonce_request, rng),
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

**File:** src/state_machine/coordinator/frost.rs (L535-540)
```rust
            let have_nonces = self.public_nonces.contains_key(&nonce_response.signer_id);

            if have_nonces {
                info!(signer_id = %nonce_response.signer_id, "Received duplicate NonceResponse");
                return Ok(());
            }
```
