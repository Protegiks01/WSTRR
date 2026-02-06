### Title
Missing sign_iter_id Validation in SignatureShareResponse Allows Cross-Iteration Signature Share Replay

### Summary
The `sign_iter_id` field exists in `SignatureShareResponse` to track signing iteration attempts within a signing round, but the coordinator fails to validate it when gathering signature shares. This allows signature shares computed with nonces from a previous iteration to be accepted and aggregated with nonces from the current iteration, causing signature verification to fail and falsely identifying honest signers as malicious, leading to denial of service.

### Finding Description

**Code Locations:**

The vulnerability stems from inconsistent validation of `sign_iter_id` across message types:

1. **NonceResponse validation (PRESENT):** [1](#0-0) 

2. **SignatureShareResponse validation (MISSING):** [2](#0-1) 

3. **Hash computation omission:** [3](#0-2) 

**Root Cause:**

The `sign_iter_id` field tracks retry iterations within the same signing round (`sign_id`). When signature share gathering times out, the coordinator increments `sign_iter_id` and retries with new nonces: [4](#0-3) 

The coordinator validates `dkg_id` and `sign_id` in `SignatureShareResponse` messages but does NOT validate `sign_iter_id`. Additionally, `sign_iter_id` is not included in the `SignatureShareResponse` hash function, unlike `NonceResponse` which properly includes it: [5](#0-4) 

**Why Existing Mitigations Fail:**

The wait list check at lines 1015-1025 of `fire.rs` only prevents duplicate responses from the same signer within an iteration, but does not prevent accepting stale responses from previous iterations that have the same `sign_id` but different `sign_iter_id`.

### Impact Explanation

**Specific Harm:**

When signature shares from iteration N are aggregated with nonces from iteration N+1, the aggregated signature verification fails because signature shares are computed as `z_i = d_i + ρ_i * b_i * c` where the binding values depend on the specific nonces used. Mismatched nonces cause verification failure.

The coordinator's `check_signature_shares` function then incorrectly identifies honest signers as having provided bad signatures: [6](#0-5) 

**Quantified Impact:**

- **Transient Consensus Failures:** Honest signers are falsely accused of providing invalid signatures
- **Denial of Service:** If applications mark parties from `BadPartySigs` errors as malicious, enough false accusations could prevent reaching the signing threshold
- **Protocol Disruption:** The signing round fails, requiring additional retries with further risk of false accusations

**Who is Affected:**

All WSTS deployments using the coordinator state machine with timeout-based retries are affected.

**Severity Justification:**

This maps to **Medium severity** as defined in the protocol scope: "Any transient consensus failures." The vulnerability causes signing rounds to fail incorrectly and honest signers to be falsely identified as malicious, but does not directly cause fund loss or permanent network shutdown.

### Likelihood Explanation

**Required Attacker Capabilities:**

No active attacker is required - natural network conditions trigger this vulnerability:
1. Normal network delays that cause messages to arrive after timeouts
2. No cryptographic breaks needed
3. No privileged access required

**Attack Complexity:**

Low complexity:
1. Signing round begins with `sign_iter_id = 1`
2. Signer A sends `SignatureShareResponse` but network delays the message
3. Coordinator times out, increments to `sign_iter_id = 2`, requests new nonces
4. The delayed message from iteration 1 arrives during iteration 2
5. Coordinator accepts it (validates only `sign_id`, not `sign_iter_id`)
6. Aggregation with mismatched nonces fails verification
7. Signer A is falsely identified as malicious

**Economic Feasibility:**

Zero cost - occurs naturally with network delays and timeout conditions.

**Detection Risk:**

The vulnerability manifests as `BadPartySigs` errors that appear legitimate, making it difficult to distinguish from actual malicious behavior.

**Estimated Probability:**

High - any deployment with network latency variability and signing timeouts will eventually encounter this condition.

### Recommendation

**Proposed Code Changes:**

Add `sign_iter_id` validation in the `gather_sig_shares` function:

```rust
if sig_share_response.sign_iter_id != self.current_sign_iter_id {
    return Err(Error::BadSignIterId(
        sig_share_response.sign_iter_id,
        self.current_sign_iter_id,
    ));
}
```

Insert this validation after line 1037 in `src/state_machine/coordinator/fire.rs`, alongside the existing `dkg_id` and `sign_id` checks.

**Alternative Mitigations:**

1. Include `sign_iter_id` in the `SignatureShareResponse` hash computation: [7](#0-6) 

2. Clear `self.signature_shares` when transitioning to a new iteration to prevent stale shares from being used.

**Testing Recommendations:**

Create a test case that:
1. Starts a signing round
2. Delays one signer's `SignatureShareResponse`
3. Triggers a timeout and retry (new `sign_iter_id`)
4. Delivers the delayed response
5. Verifies it is rejected with `BadSignIterId` error

**Deployment Considerations:**

This fix requires updating the coordinator state machine. Existing deployments should be patched to prevent false accusations of honest signers during network disruptions.

### Proof of Concept

**Exploitation Steps:**

1. **Setup:** Configure coordinator with `num_signers=3`, `threshold=2`, `sign_timeout=5s`

2. **Initial Signing Round:**
   - Coordinator starts: `sign_id=100`, `sign_iter_id=1`
   - Requests nonces from signers A, B, C
   - All respond with nonces for `sign_iter_id=1`

3. **Signature Share Request:**
   - Coordinator sends `SignatureShareRequest` with `sign_iter_id=1`
   - Signer A computes signature share using `sign_iter_id=1` nonces
   - Signer A's response is delayed by 6 seconds (network issue)
   - Signers B, C timeout

4. **Retry Iteration:**
   - Timeout expires at 5 seconds
   - Coordinator increments: `sign_iter_id=2` (line 816 of fire.rs)
   - Requests NEW nonces from remaining signers including A
   - Signer A responds with NEW nonces for `sign_iter_id=2`
   - Coordinator sends `SignatureShareRequest` with `sign_iter_id=2`

5. **Vulnerability Trigger:**
   - Delayed response from step 3 arrives (6 seconds total)
   - Contains: `sign_id=100`, `sign_iter_id=1` (from old iteration)
   - Coordinator validates only `sign_id` (matches: 100) [8](#0-7) 
   - Coordinator ACCEPTS the stale signature share

6. **Aggregation Failure:**
   - Coordinator aggregates using nonces from `sign_iter_id=2` [9](#0-8) 
   - But includes signature share computed with nonces from `sign_iter_id=1`
   - Signature verification fails at aggregation [10](#0-9) 
   - `check_signature_shares` identifies signer A as having bad signature
   - Returns `OperationResult::SignError(BadPartySigs([party_A]))`

**Expected vs Actual Behavior:**

- **Expected:** Coordinator rejects `SignatureShareResponse` with `sign_iter_id=1` when `current_sign_iter_id=2`
- **Actual:** Coordinator accepts the response, causing aggregation failure and false accusation

**Reproduction Instructions:**

Run the WSTS coordinator with network delay simulation that delays one signer's response beyond the timeout threshold, then deliver it during the retry iteration. Observe `BadPartySigs` error identifying the delayed signer as malicious despite providing a valid (but stale) signature share.

### Citations

**File:** src/state_machine/coordinator/fire.rs (L816-816)
```rust
        self.current_sign_iter_id = self.current_sign_iter_id.wrapping_add(1);
```

**File:** src/state_machine/coordinator/fire.rs (L856-860)
```rust
            if nonce_response.sign_iter_id != self.current_sign_iter_id {
                return Err(Error::BadSignIterId(
                    nonce_response.sign_iter_id,
                    self.current_sign_iter_id,
                ));
```

**File:** src/state_machine/coordinator/fire.rs (L1027-1037)
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
```

**File:** src/state_machine/coordinator/fire.rs (L1115-1124)
```rust
            let nonce_responses = message_nonce
                .public_nonces
                .values()
                .cloned()
                .collect::<Vec<NonceResponse>>();

            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();
```

**File:** src/net.rs (L354-354)
```rust
        hasher.update(self.sign_iter_id.to_be_bytes());
```

**File:** src/net.rs (L450-464)
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
```

**File:** src/v2.rs (L406-408)
```rust
            if z_i * G != (r_sign * Rs[i] + cx_sign * cx) {
                bad_party_sigs.push(sig_shares[i].id);
            }
```

**File:** src/v2.rs (L457-461)
```rust
        if sig.verify(&key, msg) {
            Ok(sig)
        } else {
            Err(self.check_signature_shares(msg, nonces, sig_shares, key_ids, None))
        }
```
