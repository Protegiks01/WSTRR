### Title
State Restoration Enables Nonce Reuse Across Different Messages Leading to Private Key Extraction

### Summary
Loading signer state from backup restores private nonces that were used in previous signing rounds. When combined with a malicious or buggy coordinator that reuses old NonceResponses with new messages, the same private nonce can be used to sign different messages. This violates the fundamental FROST security requirement that nonces must never be reused, enabling private key extraction through standard cryptanalytic techniques.

### Finding Description

**Exact Code Location:**

The vulnerability spans multiple components:

1. **Nonce Persistence**: [1](#0-0) 
   Private nonces are saved to state and restored on load.

2. **Nonce Usage Without Validation**: [2](#0-1) 
   Signer accepts SignatureShareRequest and signs with its current private nonce without validating correspondence to expected nonce.

3. **Private Nonce in Signature**: [3](#0-2) 
   The signing function uses the restored private nonce components.

**Root Cause:**

The v2::Signer persists the private nonce (`self.nonce`) in its saved state. When a signer's state is restored from backup, this brings back a previously used nonce. The critical flaw is that the signer's `sign_share_request` handler does not validate:

1. That the message in the NonceResponse matches the message in SignatureShareRequest
2. That its current private nonce corresponds to the public nonce claimed in the NonceResponse
3. That the nonce hasn't already been consumed [4](#0-3) 

The only validation is that nonces are non-zero. The signer blindly uses whatever private nonce is loaded in `self.signer.nonce` to create signature shares, regardless of what message or public nonce the coordinator claims.

**Why Existing Mitigations Fail:**

The protocol includes round IDs (`sign_id`, `sign_iter_id`) but these are not cryptographically bound to the nonce. A coordinator can present any combination of old NonceResponses with new messages and round IDs. The NonceResponse includes the message field, but signers never validate that this matches the SignatureShareRequest message.

### Impact Explanation

**Specific Harm:**

When the same private nonce is used to sign two different messages, the private key can be extracted. For a signature share created with nonce `(d, e)`:

```
s = d + e*b + λ*a*c
```

Where:
- `d, e` are private nonce components
- `b` is the binding coefficient (depends on message)
- `λ*a` is the private key share
- `c` is the challenge (depends on message)

With two signatures using the same nonce for different messages M1 and M2, an attacker can solve for `λ*a` since they know `s1, s2, b1, b2, c1, c2`.

**Quantified Impact:**

- **Complete private key compromise** of affected threshold signature group
- **All funds controlled** by the threshold signature become vulnerable to theft
- **Invalid signatures** can be forged after key extraction
- In blockchain context: **Direct loss of funds** without any spending restrictions

**Affected Parties:**

Any WSTS deployment using state persistence is vulnerable. This includes:
- Stacks blockchain signer nodes that save state for crash recovery
- Any threshold custody system using WSTS with state backup/restore
- All participants in the signing group (compromise of one key share weakens the entire group)

**Severity Justification:**

Maps to **Critical** severity under the protocol scope: "Any confirmation of an invalid transaction, such as with an incorrect nonce" and "Any causing the direct loss of funds other than through any form of freezing."

The vulnerability enables extraction of private keys, which in turn allows arbitrary fund theft and signature forgery.

### Likelihood Explanation

**Required Attacker Capabilities:**

1. **State Manipulation**: Ability to trigger state save/restore on at least one signer (e.g., through crashes, restarts, or backup restoration)
2. **Coordinator Control**: Either:
   - Malicious coordinator that deliberately reuses NonceResponses, OR
   - Ability to trigger coordinator bugs that fail to clear old nonces, OR
   - Ability to replay network messages

**Attack Complexity:**

Medium complexity. The attack requires:
1. Monitoring signing rounds to capture NonceResponses
2. Triggering or waiting for signer state restoration
3. Causing coordinator to reuse old NonceResponses with new messages

**Economic Feasibility:**

Highly feasible:
- State persistence is common in production systems for reliability
- Coordinator compromise or bugs are realistic (Byzantine fault model)
- No expensive computational resources required
- High economic incentive (complete key compromise)

**Detection Risk:**

Low detection risk:
- Normal protocol messages are used
- No obvious signature of attack until private key is extracted
- Victim signer believes it's operating normally
- Malicious signatures appear valid until aggregation

**Estimated Probability:**

In production deployments with state persistence and potential coordinator vulnerabilities: **Moderate to High**. The attack is practical and doesn't require breaking cryptographic primitives.

### Recommendation

**Primary Fix:**

Implement nonce commitment validation in the signer:

1. **Store public nonce with private nonce**: When generating a nonce in `gen_nonce()`, store both the private nonce and its corresponding public nonce together with the message and round IDs it was generated for.

2. **Validate nonce correspondence**: In `sign_share_request()`, verify that:
   - The NonceResponse for this signer contains the same public nonce as stored
   - The NonceResponse.message matches SignatureShareRequest.message
   - The sign_id matches the stored value
   - The nonce hasn't been marked as consumed

3. **Mark nonces as consumed**: After signing, mark the nonce as used and reject any future attempts to use it.

**Implementation Changes:**

Add to `src/v2.rs`:
```rust
pub struct Party {
    // ... existing fields ...
    nonce: Nonce,
    nonce_metadata: Option<NonceMetadata>, // NEW
}

pub struct NonceMetadata {
    public_nonce: PublicNonce,
    message: Vec<u8>,
    sign_id: u64,
    consumed: bool,
}
```

Add validation in `src/state_machine/signer/mod.rs` in `sign_share_request()` before signing.

**Alternative Mitigation:**

If primary fix is too invasive, implement these defenses:

1. **Don't persist nonces in saved state**: Clear nonces before saving state, forcing fresh generation on restore
2. **Add nonce-to-round binding**: Cryptographically bind nonces to (dkg_id, sign_id, sign_iter_id, message)
3. **Coordinator-side validation**: Ensure coordinators never reuse NonceResponses across different messages

**Testing Recommendations:**

1. Add unit test that attempts nonce reuse across messages
2. Add integration test simulating state restore during signing
3. Fuzz test with malformed SignatureShareRequest messages
4. Add invariant checking that nonces are never reused

**Deployment Considerations:**

This is a breaking change requiring coordination across all signers. Deploy with:
- Version negotiation to ensure all parties support nonce validation
- Migration path for existing saved states
- Monitoring for nonce reuse attempts

### Proof of Concept

**Exploitation Algorithm:**

```
Step 1: Setup (Attacker as Malicious Coordinator)
  - Deploy WSTS with state persistence enabled
  - Control coordinator node

Step 2: Initial Signing Round (Message M1)
  - Send NonceRequest(sign_id=1, message=M1)
  - Collect NonceResponse from all signers
  - Victim signer generates nonce N1=(d1,e1), sends pub(N1)=(D1,E1)
  - Store NonceResponse_victim containing pub(N1) and M1
  - Send SignatureShareRequest(sign_id=1, message=M1, nonces=[...])
  - Victim signs M1: s1 = d1 + e1*b1 + λ*a*c1
  - Victim generates new nonce N2 after signing

Step 3: Trigger State Restore
  - Wait for or force victim signer crash/restart
  - Ensure state restore loads backup containing old nonce N1
  - Confirm via logging that victim has restored nonce N1

Step 4: Malicious Signing Round (Message M2)
  - Prepare new message M2 ≠ M1
  - WITHOUT sending NonceRequest, directly send:
    SignatureShareRequest(
      sign_id=2,
      message=M2,
      nonce_responses=[stored NonceResponse_victim, ...]
    )
  - Victim receives request, extracts pub(N1) from nonce_responses
  - Victim signs M2 using restored private nonce N1
  - Victim produces: s2 = d1 + e1*b2 + λ*a*c2

Step 5: Extract Private Key
  - Attacker now has s1, s2 for same nonce (d1, e1)
  - Compute binding coefficients: b1 = H(L, pub(N1), M1)
  - Compute binding coefficients: b2 = H(L, pub(N1), M2)
  - Compute challenges: c1 = H(P, R1, M1), c2 = H(P, R2, M2)
  - Solve for private key share: λ*a = (s1 - s2 - e1*(b1-b2)) / (c1 - c2)
  - Repeat with sufficient signers to reconstruct full private key

Expected: Signature rejection or fresh nonce requirement
Actual: Nonce reuse across different messages, enabling key extraction
```

**Reproduction Instructions:**

1. Set up WSTS v2 signer with state persistence
2. Complete one signing round with message M1
3. Save signer state after nonce generation
4. Restore signer from this saved state
5. As coordinator, send SignatureShareRequest for different message M2 but reuse NonceResponse from M1
6. Observe that signer produces signature share for M2 using old nonce
7. Collect two signature shares using same nonce, extract private key component

**Notes**

The vulnerability fundamentally stems from treating nonces as stateless values when they must be stateful to ensure single-use. The FROST protocol requires strict nonce freshness, but the implementation allows reuse through state restoration without any tracking or validation mechanism.

The `public_nonces` field in the Signer state machine struct is actually unused - it's initialized empty, only cleared during reset, and never populated. The real issue is the private nonce stored within the v1/v2 Signer implementations being persisted and restored without consumption tracking.

### Citations

**File:** src/v2.rs (L225-260)
```rust
    pub fn sign_with_tweak(
        &self,
        msg: &[u8],
        party_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        tweak: Option<Scalar>,
    ) -> SignatureShare {
        // When using BIP-340 32-byte public keys, we have to invert the private key if the
        // public key is odd.  But if we're also using BIP-341 tweaked keys, we have to do
        // the same thing if the tweaked public key is odd.  In that case, only invert the
        // public key if exactly one of the internal or tweaked public keys is odd
        let mut cx_sign = Scalar::one();
        let tweaked_public_key = if let Some(t) = tweak {
            if t != Scalar::zero() {
                let key = compute::tweaked_public_key_from_tweak(&self.group_key, t);
                if key.has_even_y() ^ self.group_key.has_even_y() {
                    cx_sign = -cx_sign;
                }

                key
            } else {
                if !self.group_key.has_even_y() {
                    cx_sign = -cx_sign;
                }
                self.group_key
            }
        } else {
            self.group_key
        };
        let (_, R) = compute::intermediate(msg, party_ids, nonces);
        let c = compute::challenge(&tweaked_public_key, &R, msg);
        let mut r = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        if tweak.is_some() && !R.has_even_y() {
            r = -r;
        }
```

**File:** src/v2.rs (L519-539)
```rust
    fn load(state: &traits::SignerState) -> Self {
        // v2 signer contains single party
        assert_eq!(state.parties.len(), 1);

        let party_state = &state.parties[0].1;

        Self {
            party_id: state.id,
            key_ids: state.key_ids.clone(),
            num_keys: state.num_keys,
            num_parties: state.num_parties,
            threshold: state.threshold,
            f: party_state.polynomial.clone(),
            private_keys: party_state
                .private_keys
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            group_key: state.group_key,
            nonce: party_state.nonce.clone(),
        }
```

**File:** src/state_machine/signer/mod.rs (L757-818)
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
```
