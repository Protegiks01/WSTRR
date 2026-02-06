### Title
Duplicate key_ids in NonceResponse Bypass HashSet Validation, Causing Denial of Service via Incorrect Lagrange Interpolation

### Summary
A malicious signer can inject duplicate key_ids into their `NonceResponse` message, bypassing coordinator validation that uses HashSet comparison. These duplicates propagate through the signing protocol and cause incorrect Lagrange coefficient computation in all signers' signature shares, resulting in guaranteed signature verification failure and denial of service. A single compromised signer can prevent all threshold signatures from succeeding indefinitely.

### Finding Description

**Exact Code Locations:**
1. Validation bypass: [1](#0-0) 
2. Duplicate preservation during aggregation: [2](#0-1) 
3. Signer extraction preserving duplicates: [3](#0-2) 
4. Incorrect Lagrange computation: [4](#0-3) 
5. Signature share computation with wrong coefficients: [5](#0-4) 

**Root Cause:**
The coordinator validates `NonceResponse.key_ids` by converting the Vec to a HashSet before comparing with the configured signer's key_ids. [1](#0-0)  This HashSet conversion silently removes duplicates, allowing a malicious `NonceResponse` with `key_ids = [1, 1, 2, 3]` to pass validation when the config expects `{1, 2, 3}`.

The validated `NonceResponse` (with duplicates intact) is stored [6](#0-5)  and later included in the `SignatureShareRequest`. When collecting key_ids for aggregation, the coordinator flattens all `NonceResponse.key_ids` into a Vec, preserving duplicates. [2](#0-1) 

Signers extract key_ids from the `SignatureShareRequest.nonce_responses` by flattening them, which also preserves duplicates. [3](#0-2)  These duplicated key_ids are passed to the signing functions.

**Why the Vulnerability Occurs:**
The `lambda()` function computes Lagrange interpolation coefficients by iterating over all elements in the `key_ids` slice. [4](#0-3)  If a key_id appears multiple times in the slice, it multiplies the coefficient by the same factor multiple times.

For example, `lambda(2, [1, 1, 2, 3])` computes:
- j=1: multiply by 1/(1-2) = -1 → lambda = -1
- j=1 (duplicate): multiply by 1/(1-2) = -1 → lambda = 1 (sign flips!)
- j=2: skip (i==j)
- j=3: multiply by 3/(3-2) = 3 → lambda = 3

The correct value should be `lambda(2, [1, 2, 3]) = -3`, but with duplicates it becomes `3`, causing the Lagrange coefficient to be wrong (even the sign is flipped).

**Why Existing Mitigations Fail:**
- The `validate_key_id()` function only validates individual key_id ranges, not duplicate detection. [7](#0-6) 
- The coordinator's validation uses HashSet equality, which is semantically correct for "does this signer control these keys?" but fails to enforce the signing invariant "Lagrange interpolation must use the correct key set with no duplicates."
- The `SignatureShare` structure includes a `key_ids` field [8](#0-7) , but when signature shares are received, the coordinator validates their key_ids as a set [9](#0-8) , again allowing duplicates to pass.

### Impact Explanation

**Specific Harm:**
A single compromised signer can cause all threshold signature attempts to fail by including duplicate key_ids in their `NonceResponse`. Since all honest signers compute their signature shares using the same incorrect Lagrange coefficients derived from the duplicated key_ids, every signature share becomes mathematically incorrect. The aggregated signature will fail verification [10](#0-9) , and the signing round aborts.

**Quantified Impact:**
- **Immediate**: 100% signature failure rate while malicious signer participates
- **Persistent**: The malicious signer is not detected or excluded, so they remain in future signing rounds
- **Network-wide**: If WSTS signatures are required for Stacks blockchain transaction confirmation (as suggested by the security scope), this prevents the network from confirming valid transactions

**Affected Parties:**
- All honest signers waste computational resources computing invalid signature shares
- The coordinator cannot produce valid signatures for any message
- If integrated with Stacks: all network participants are unable to confirm transactions

**Severity Justification:**
According to the provided scope, this maps to **Critical** severity: "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks." A single compromised signer (which could be <10% of the signer set) can prevent the network from producing any valid signatures, blocking transaction confirmation indefinitely until the malicious signer is manually removed from the configuration.

If the integration context limits this to single-node impact, it would be **Low** severity: "Any remotely-exploitable denial of service in a node."

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control of a single signer's private key (either through compromise or being a Byzantine participant)
- Ability to send network messages to the coordinator
- No cryptographic breaks required

**Attack Complexity:**
Very low. The attacker simply modifies their `NonceResponse` message to include duplicate key_ids before sending. For example:
```
// Legitimate: key_ids = [1, 2, 3]
// Malicious: key_ids = [1, 1, 2, 3]
```

**Economic Feasibility:**
Extremely low cost. The attack requires no additional resources beyond normal signer participation. There is no detection mechanism, so the attacker faces no consequences.

**Detection Risk:**
None. The validation explicitly allows the malicious message through. The coordinator logs signature failures but does not identify the root cause or the malicious signer.

**Estimated Probability:**
High. In a threshold signature scheme, if any signer becomes compromised (whether through key theft, Byzantine behavior, or software bugs), they can trivially execute this attack. The attack is deterministic—once deployed, it succeeds 100% of the time until the malicious signer is manually removed from the configuration.

### Recommendation

**Primary Fix - Validate Vec Directly:**
Modify the NonceResponse validation to check the key_ids Vec directly without converting to HashSet, and explicitly reject duplicates:

```rust
// In src/state_machine/coordinator/fire.rs, replace lines 881-889:
let nonce_response_key_ids = nonce_response
    .key_ids
    .iter()
    .cloned()
    .collect::<HashSet<u32>>();
    
// Check for duplicates first
if nonce_response.key_ids.len() != nonce_response_key_ids.len() {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids contains duplicates");
    return Ok(());
}

// Then check set equality
if *signer_key_ids != nonce_response_key_ids {
    warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
    return Ok(());
}
```

Apply the same fix to FROST coordinator validation [11](#0-10)  and SignatureShareResponse validation [9](#0-8) .

**Alternative Mitigation:**
Add a runtime check in the `lambda()` function to detect and reject duplicate key_ids, though this is less efficient than preventing them at the protocol layer.

**Testing Recommendations:**
1. Unit test for `lambda()` with duplicate key_ids to verify incorrect results
2. Integration test where a signer sends NonceResponse with duplicate key_ids
3. Verify coordinator rejects the malicious NonceResponse
4. Verify signature protocol continues successfully with only honest signers

**Deployment Considerations:**
This is a protocol-level change that requires coordinated upgrade of all coordinators. Existing signing rounds in progress when the fix is deployed should be aborted and restarted.

### Proof of Concept

**Exploitation Steps:**

1. **Attacker Setup**: Control a signer with key_ids [1, 2, 3] in the configuration

2. **During Nonce Phase**: When coordinator requests nonces [12](#0-11) , create malicious `NonceResponse`:
   - Legitimate signers send: `key_ids: vec![1, 2, 3]`
   - Attacker sends: `key_ids: vec![1, 1, 2, 3]` (duplicate key_id 1)

3. **Validation Bypass**: Coordinator validates at [1](#0-0) :
   - Converts `[1, 1, 2, 3]` to HashSet `{1, 2, 3}`
   - Compares with config's `{1, 2, 3}` → MATCH
   - Validation PASSES

4. **Propagation**: Coordinator stores malicious NonceResponse [6](#0-5)  and creates SignatureShareRequest [13](#0-12) 

5. **Incorrect Computation**: All signers extract key_ids `[1, 1, 2, 3, ...]` [3](#0-2)  and compute signature shares using wrong Lagrange coefficients

6. **Verification Failure**: Coordinator aggregates shares [14](#0-13)  and attempts verification [15](#0-14)  → FAILS

**Expected vs Actual Behavior:**
- **Expected**: `lambda(2, [1, 2, 3]) = -3`
- **Actual with duplicates**: `lambda(2, [1, 1, 2, 3]) = 3` (wrong sign, wrong magnitude)

**Reproduction:**
In a test environment with 4 signers (threshold 3), have one signer modify their NonceResponse to include `key_ids: vec![1, 1]` instead of `vec![1]`. Observe that all subsequent signing attempts fail verification, and the failure persists across multiple rounds because the malicious signer continues to send the same malicious NonceResponse.

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

**File:** src/state_machine/coordinator/fire.rs (L881-889)
```rust
            let nonce_response_key_ids = nonce_response
                .key_ids
                .iter()
                .cloned()
                .collect::<HashSet<u32>>();
            if *signer_key_ids != nonce_response_key_ids {
                warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
                return Ok(());
            }
```

**File:** src/state_machine/coordinator/fire.rs (L933-933)
```rust
                .insert(nonce_response.signer_id, nonce_response.clone());
```

**File:** src/state_machine/coordinator/fire.rs (L978-985)
```rust
        let sig_share_request = SignatureShareRequest {
            dkg_id: self.current_dkg_id,
            sign_id: self.current_sign_id,
            sign_iter_id: self.current_sign_iter_id,
            nonce_responses,
            message: self.message.clone(),
            signature_type,
        };
```

**File:** src/state_machine/coordinator/fire.rs (L1066-1076)
```rust
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

**File:** src/state_machine/coordinator/fire.rs (L1126-1129)
```rust
            let key_ids = nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.clone())
                .collect::<Vec<u32>>();
```

**File:** src/state_machine/signer/mod.rs (L800-804)
```rust
            let key_ids: Vec<u32> = sign_request
                .nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.iter().copied())
                .collect::<Vec<u32>>();
```

**File:** src/compute.rs (L70-80)
```rust
pub fn lambda(i: u32, key_ids: &[u32]) -> Scalar {
    let mut lambda = Scalar::one();
    let i_scalar = id(i);
    for j in key_ids {
        if i != *j {
            let j_scalar = id(*j);
            lambda *= j_scalar / (j_scalar - i_scalar);
        }
    }
    lambda
}
```

**File:** src/v2.rs (L262-265)
```rust
        let mut cx = Scalar::zero();
        for key_id in self.key_ids.iter() {
            cx += c * &self.private_keys[key_id] * compute::lambda(*key_id, key_ids);
        }
```

**File:** src/v2.rs (L328-330)
```rust
        for sig_share in sig_shares {
            z += sig_share.z_i;
        }
```

**File:** src/v2.rs (L455-461)
```rust
        let (key, sig) = self.sign_with_tweak(msg, nonces, sig_shares, key_ids, None)?;

        if sig.verify(&key, msg) {
            Ok(sig)
        } else {
            Err(self.check_signature_shares(msg, nonces, sig_shares, key_ids, None))
        }
```

**File:** src/common.rs (L213-220)
```rust
pub struct SignatureShare {
    /// The ID of the party
    pub id: u32,
    /// The party signature
    pub z_i: Scalar,
    /// The key IDs of the party
    pub key_ids: Vec<u32>,
}
```

**File:** src/common.rs (L314-316)
```rust
pub fn validate_key_id(key_id: u32, num_keys: u32) -> bool {
    key_id > 0 && key_id <= num_keys
}
```

**File:** src/state_machine/coordinator/frost.rs (L631-641)
```rust
            let mut sig_share_response_key_ids = HashSet::new();
            for sig_share in &sig_share_response.signature_shares {
                for key_id in &sig_share.key_ids {
                    sig_share_response_key_ids.insert(*key_id);
                }
            }

            if *signer_key_ids != sig_share_response_key_ids {
                warn!(signer_id = %sig_share_response.signer_id, "SignatureShareResponse key_ids didn't match config");
                return Ok(());
            }
```
