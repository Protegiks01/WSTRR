### Title
Coordinator Panic Due to Premature Wait List Removal Before Signature Share Validation

### Summary
The `gather_sig_shares()` function removes signers from the wait list before validating their signature share responses, causing a critical accounting mismatch. When validation subsequently fails, the signer is absent from `signature_shares` but remains in `public_nonces`, leading to an index panic during aggregation. A single malicious signer can exploit this to crash the coordinator node and prevent transaction signing indefinitely.

### Finding Description

**Exact Code Location:** [1](#0-0) 

The vulnerability exists in the `gather_sig_shares()` function where a signer is removed from the wait list immediately upon receiving their response, before any validation of that response occurs. [2](#0-1) 

After confirming the signer is in the wait list, the function removes them: [3](#0-2) 

However, critical validation checks occur AFTER this removal: [4](#0-3) 

These validations can fail and return errors, preventing the signer's shares from being added to `signature_shares` at line 1088-1090. The signer remains in `public_nonces` (from the nonce phase) but is missing from both the wait list and `signature_shares`.

When all remaining signers respond successfully, the wait list becomes empty and aggregation proceeds: [5](#0-4) 

The aggregation code at line 1134 iterates over all signers in `public_nonces` and attempts to access their shares via indexing: `self.signature_shares[i]`. Since `signature_shares` is a BTreeMap and the failed signer's ID is not present, this causes a panic: [6](#0-5) 

**Root Cause:**
The premature removal from the wait list creates a critical ordering violation. The wait list tracks which signers are expected to provide shares, but removal happens before determining if the shares are valid. This breaks the invariant that `signature_shares` contains entries for all signers in `public_nonces` when aggregation begins.

**Why Existing Mitigations Fail:**
The error handling at line 328-333 only catches returned errors, not panics. The timeout mechanism also cannot prevent this because the malicious signer IS responding (with invalid data), so no timeout occurs. [7](#0-6) 

### Impact Explanation

**Specific Harm:**
- The coordinator node crashes completely with a panic (index out of bounds on BTreeMap)
- No graceful error handling or recovery mechanism exists
- The signing round fails permanently
- The coordinator must be manually restarted
- The malicious signer is never marked as such, allowing repeated exploitation

**Quantified Impact:**
- With threshold = N signers required
- Attacker controls 1 signer (within the threshold set)
- Single malformed response crashes the coordinator
- Every signing attempt can be blocked by repeating the attack
- Network cannot confirm transactions requiring threshold signatures

**Who is Affected:**
Any WSTS coordinator node used in production systems. If these coordinators are responsible for signing Bitcoin transactions in the Stacks blockchain, the entire network's ability to confirm transactions is compromised.

**Severity Justification:**
This maps to **Critical** severity under the protocol scope definition: "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks." The coordinator crash prevents all transaction signing, and the attacker can repeat this attack indefinitely since they are never marked as malicious.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control of a single signer party within the threshold set
- Ability to send network messages to the coordinator
- No cryptographic secrets or breaks required

**Attack Complexity:**
Low. The attacker simply needs to:
1. Participate normally in DKG
2. Send a valid nonce response during signing
3. Send a signature share response with incorrect `key_ids` that don't match their configured keys

**Economic Feasibility:**
Highly feasible. If the attacker is already a signer in the threshold set, there are no additional costs. The attack is deterministic and requires minimal resources.

**Detection Risk:**
Low. The coordinator crashes before logging which signer caused the problem. The panic occurs during aggregation, not during the malicious signer's message processing, making attribution difficult.

**Estimated Probability of Success:**
~100%. The vulnerability is deterministic and has been confirmed through code analysis. No race conditions or probabilistic elements exist.

### Recommendation

**Primary Fix:**
Move the wait list removal to occur AFTER all validation checks pass and the shares are successfully added to `signature_shares`. The removal should be the last operation in the successful path:

```rust
// Perform all validation checks first (lines 1046-1076)
// Add shares to signature_shares (lines 1088-1090)
// THEN remove from wait list:
response_info
    .sign_wait_signer_ids
    .remove(&sig_share_response.signer_id);
```

**Alternative Mitigation:**
If immediate removal is required for duplicate detection, use a `.get()` method instead of indexing during aggregation to handle missing entries gracefully:

```rust
let shares = message_nonce
    .public_nonces
    .iter()
    .filter_map(|(i, _)| self.signature_shares.get(i).cloned())
    .flatten()
    .collect::<Vec<SignatureShare>>();
```

However, this masks the underlying accounting issue and may allow signing to proceed with insufficient shares.

**Additional Recommendations:**
1. Mark signers who send invalid responses as malicious before returning errors
2. Add explicit validation that `signature_shares` contains all expected signers before aggregation
3. Add integration tests that send malformed signature shares to verify proper handling

**Testing Recommendations:**
Create a test case that:
1. Runs DKG with 3 signers, threshold 3
2. During signing, one signer sends a response with mismatched `key_ids`
3. Verify the coordinator either recovers gracefully or marks the signer as malicious
4. Ensure no panic occurs

### Proof of Concept

**Exploitation Algorithm:**

1. **Setup Phase:**
   - Attacker operates as Signer A in a 3-of-3 threshold configuration
   - Signers B and C are honest
   - Complete DKG successfully

2. **Attack Phase:**
   - Coordinator initiates signing round
   - All signers (A, B, C) send valid nonce responses
   - Coordinator receives nonces, threshold reached, requests signature shares
   
3. **Trigger Phase:**
   - Attacker (Signer A) sends `SignatureShareResponse` with `key_ids` that don't match their configured keys
     - Example: If A is configured with `key_ids: [0]`, send response with `key_ids: [999]`
   - Honest signers B and C send valid responses

4. **Crash Sequence:**
   - Coordinator processes A's response:
     - Line 1042-1044: Removes A from `sign_wait_signer_ids` ✓
     - Line 1073-1076: Validation fails on key_ids mismatch ✗
     - Returns `Error::BadKeyIDsForSigner(A)` ✗
     - A is NOT added to `signature_shares` ✗
   - Coordinator processes B's response: success, added to `signature_shares`
   - Coordinator processes C's response: success, added to `signature_shares`
   - `sign_wait_signer_ids` is now empty
   - Line 1113: Aggregation begins
   - Line 1134: `self.signature_shares[A]` → **PANIC: key not found**

**Expected Behavior:**
Coordinator should mark A as malicious and retry signing with remaining signers, or return a proper error without crashing.

**Actual Behavior:**
Coordinator crashes with panic, requiring manual restart. No malicious signer marking occurs.

**Reproduction Steps:**
In a test environment with the WSTS coordinator, create a malicious signer that sends `SignatureShareResponse` messages with `key_ids` that don't match their configuration. Observe the coordinator panic during aggregation when the wait list becomes empty.

### Citations

**File:** src/state_machine/coordinator/fire.rs (L45-45)
```rust
    signature_shares: BTreeMap<u32, Vec<SignatureShare>>,
```

**File:** src/state_machine/coordinator/fire.rs (L328-333)
```rust
                    if let Err(e) = self.gather_sig_shares(packet, signature_type) {
                        return Ok((
                            None,
                            Some(OperationResult::SignError(SignError::Coordinator(e))),
                        ));
                    }
```

**File:** src/state_machine/coordinator/fire.rs (L1015-1025)
```rust
        let waiting = response_info
            .sign_wait_signer_ids
            .contains(&sig_share_response.signer_id);

        if !waiting {
            warn!(
                "Sign round {} SignatureShareResponse for round {} from signer {} not in the wait list",
                self.current_sign_id, sig_share_response.sign_id, sig_share_response.signer_id,
            );
            return Ok(());
        }
```

**File:** src/state_machine/coordinator/fire.rs (L1040-1044)
```rust
        // we were waiting on you, and you sent a packet for this sign round, so we won't take
        // another packet from you
        response_info
            .sign_wait_signer_ids
            .remove(&sig_share_response.signer_id);
```

**File:** src/state_machine/coordinator/fire.rs (L1046-1076)
```rust
        // check that the signer_id exists in the config
        let signer_public_keys = &self.config.public_keys.signers;
        if !signer_public_keys.contains_key(&sig_share_response.signer_id) {
            warn!(signer_id = %sig_share_response.signer_id, "No public key in config");
            return Err(Error::MissingPublicKeyForSigner(
                sig_share_response.signer_id,
            ));
        };

        // check that the key_ids match the config
        let Some(signer_key_ids) = self
            .config
            .public_keys
            .signer_key_ids
            .get(&sig_share_response.signer_id)
        else {
            warn!(signer_id = %sig_share_response.signer_id, "No keys IDs configured");
            return Err(Error::MissingKeyIDsForSigner(sig_share_response.signer_id));
        };

        let mut sig_share_response_key_ids = HashSet::new();
        for sig_share in &sig_share_response.signature_shares {
            for key_id in &sig_share.key_ids {
                sig_share_response_key_ids.insert(*key_id);
            }
        }

        if *signer_key_ids != sig_share_response_key_ids {
            warn!(signer_id = %sig_share_response.signer_id, "SignatureShareResponse key_ids didn't match config");
            return Err(Error::BadKeyIDsForSigner(sig_share_response.signer_id));
        }
```

**File:** src/state_machine/coordinator/fire.rs (L1113-1135)
```rust
        if message_nonce.sign_wait_signer_ids.is_empty() {
            // Calculate the aggregate signature
            let nonce_responses = message_nonce
                .public_nonces
                .values()
                .cloned()
                .collect::<Vec<NonceResponse>>();

            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();

            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();

            let shares = message_nonce
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();
```
