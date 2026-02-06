### Title
NonceResponse Accepts Duplicate key_ids Causing Signature Verification Failure

### Summary
The coordinator's NonceResponse validation converts the `key_ids` array to a HashSet for comparison, which automatically removes duplicates. A malicious signer can send duplicate key_ids (e.g., `[3, 4, 4]` instead of `[3, 4]`), bypassing validation while corrupting Lagrange interpolation coefficients for all participants. This causes all group signatures to fail verification, resulting in a denial of service.

### Finding Description

The vulnerability exists in the NonceResponse validation logic in the coordinator state machine. [1](#0-0) 

The coordinator validates NonceResponse messages by converting the `key_ids` vector to a HashSet: [2](#0-1) 

This HashSet conversion automatically removes duplicates, so a malicious NonceResponse with `key_ids: [3, 4, 4]` becomes `{3, 4}` during validation and passes the check against the configured key set `{3, 4}`. There is no validation that `key_ids.len() == nonces.len()` or that `key_ids` contains no duplicates.

When gathering signature shares, the coordinator flattens all key_ids from NonceResponses using `flat_map`, preserving duplicates: [3](#0-2) 

These corrupted key_ids are then used by all signers to compute Lagrange coefficients: [4](#0-3) 

The lambda function computes Lagrange interpolation coefficients by iterating over all key_ids: [5](#0-4) 

When key_ids contains duplicates (e.g., `[1, 2, 3, 4, 4]`), the lambda calculation for other keys becomes incorrect. For example, `lambda(1, [1, 2, 3, 4, 4])` computes `(2/(2-1)) * (3/(3-1)) * (4/(4-1)) * (4/(4-1)) = 16/3`, whereas the correct value is `lambda(1, [1, 2, 3, 4]) = 4`.

All parties (honest signers, malicious signer, and aggregator) use the same corrupted key_ids array, resulting in incorrect Lagrange coefficients. Since these coefficients are used to reconstruct the group secret key from participating key shares, and the group public key was fixed during DKG, the signature verification fails.

### Impact Explanation

**Severity: Low** (Denial of Service)

This vulnerability allows a single malicious signer to prevent the creation of any valid signatures by the threshold signing group. When a malicious signer sends a NonceResponse with duplicate key_ids:

1. All honest signers compute signature shares using incorrect Lagrange coefficients
2. The aggregator combines these shares into a group signature
3. The group signature fails verification against the fixed group public key
4. No valid signatures can be produced until the malicious signer cooperates or is removed

In a blockchain context where WSTS is used for multi-signature wallets or validator signing:
- Transactions cannot be signed and broadcast
- Blocks cannot be signed by validators
- The network experiences service degradation proportional to the number of affected signing groups

This maps to **Low severity** under the protocol scope as it is "Any remotely-exploitable denial of service in a node" that can impact signing operations. While serious, it does not cause permanent loss of funds, chain splits, or network shutdown - the system can recover by reconfiguring without the malicious signer.

### Likelihood Explanation

**Likelihood: High**

**Required Attacker Capabilities:**
- Control of a single signer in a threshold signing group
- Ability to send modified NonceResponse messages
- No cryptographic breaks required

**Attack Complexity:**
The attack is trivial to execute. The attacker simply modifies their NonceResponse message to include duplicate key_ids before sending. Example:
- Normal: `key_ids: [3, 4]`, `nonces: [n1, n2]`
- Attack: `key_ids: [3, 4, 4]`, `nonces: [n1, n2, n3]` (where n3 can be any valid nonce)

**Detection Risk:**
The attack is immediately detectable after the first failed signature verification, but by then the signing round has already failed. The coordinator logs would show valid NonceResponses and signature shares, making it non-obvious which signer is malicious.

**Estimated Probability:**
Near 100% success rate for causing denial of service. Any signer in any signing group can execute this attack at will.

### Recommendation

**Primary Fix: Add duplicate detection and length validation**

Add explicit validation in the NonceResponse gathering logic: [6](#0-5) 

After the existing key_ids validation, add:

```rust
// Check for duplicate key_ids
if nonce_response.key_ids.len() != nonce_response_key_ids.len() {
    warn!(signer_id = %nonce_response.signer_id, "NonceResponse contains duplicate key_ids");
    return Ok(());
}

// Validate that key_ids and nonces arrays have matching lengths
if nonce_response.key_ids.len() != nonce_response.nonces.len() {
    warn!(signer_id = %nonce_response.signer_id, "NonceResponse key_ids and nonces length mismatch");
    return Ok(());
}
```

**Alternative Mitigation:**
Deduplicate key_ids immediately upon receipt before storing the NonceResponse, though this could mask malicious behavior.

**Testing Recommendations:**
1. Add unit test that sends NonceResponse with duplicate key_ids and verifies rejection
2. Add integration test showing signature verification failure with duplicate key_ids
3. Test length mismatch between key_ids and nonces arrays

**Deployment Considerations:**
This is a breaking change that tightens validation. Deploy to all coordinators simultaneously to maintain consistent behavior across the network.

### Proof of Concept

**Attack Algorithm:**

1. Setup: 2 signers in threshold group
   - Alice (signer 0): controls keys [1, 2]
   - Bob (signer 1, malicious): controls keys [3, 4]
   - Threshold: 3 keys required

2. DKG completes normally, group public key established

3. Signing round begins:
   - Alice sends NonceResponse: `key_ids: [1, 2]`, `nonces: [n1, n2]`
   - Bob sends NonceResponse: `key_ids: [3, 4, 4]`, `nonces: [n3, n4, n5]`

4. Coordinator validation:
   - Converts Bob's key_ids to HashSet: `{3, 4}`
   - Compares against configured keys: `{3, 4}` ✓ PASSES
   - Stores NonceResponse with duplicate key_ids

5. Signature share computation:
   - Flattened key_ids: `[1, 2, 3, 4, 4]`
   - Alice computes lambda(1, [1,2,3,4,4]) = 16/3 (should be 4)
   - Alice computes lambda(2, [1,2,3,4,4]) with wrong coefficient
   - Bob also uses wrong coefficients for his keys
   - All signature shares are computed with incorrect Lagrange interpolation

6. Aggregation:
   - Coordinator combines signature shares
   - Resulting signature fails verification: `z*G != R + c*GroupPublicKey`

7. Result: Denial of service - no valid signatures produced

**Expected behavior:** Validation should reject NonceResponse with duplicate key_ids

**Actual behavior:** Validation passes, causing all signatures to fail verification

### Citations

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

**File:** src/state_machine/coordinator/frost.rs (L502-533)
```rust
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
```

**File:** src/state_machine/coordinator/frost.rs (L675-678)
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
