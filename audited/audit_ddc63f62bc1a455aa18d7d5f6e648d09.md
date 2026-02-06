### Title
Incorrect Malicious Signer Identification Due to Unauthenticated SignatureShare.id Field in v2

### Summary
The v2 coordinator does not validate that the `id` field within `SignatureShare` objects matches the authenticated `signer_id` of the sender. A malicious signer can create signature shares with an incorrect `id` field, causing signature verification to fail and blame assignment to target an innocent party instead of the actual malicious signer. This enables a compromised signer to frame honest parties and cause repeated signing failures. [1](#0-0) 

### Finding Description

**Root Cause:**

The vulnerability exists in v2 (not v1) due to insufficient validation of the `SignatureShare` structure. While packet-level authentication ensures messages come from legitimate signers, the coordinator fails to validate that the `id` field within signature shares matches the authenticated sender. [2](#0-1) 

The coordinator stores signature shares indexed by `SignatureShareResponse.signer_id` (the authenticated sender), but never validates that `SignatureShare.id` inside those shares matches this sender ID. [3](#0-2) 

During aggregation, nonces and signature shares are paired based on the coordinator's storage index (the authenticated signer ID), but the aggregator extracts party IDs from `SignatureShare.id` for binding computation: [4](#0-3) 

The binding computation depends critically on the party ID: [5](#0-4) 

When verification fails, the blame is assigned based on `SignatureShare.id`: [6](#0-5) 

**Why Existing Mitigations Fail:**

Packet-level authentication validates the message sender but not the content: [7](#0-6) 

The coordinator validates that `key_ids` match the configured keys for the sender, but does not validate the `id` field: [8](#0-7) 

**Note:** v1 is not affected by this vulnerability because the aggregator never uses the `key_ids` field, only the `id` field, and in v1 each party controls only one key where `id == key_id`. [9](#0-8) 

### Impact Explanation

**Specific Harm:**

1. A malicious signer can cause signature verification to fail by providing mismatched `id` values
2. An innocent party is incorrectly identified as malicious in the `BadPartySigs` error
3. The coordinator returns this error without automatic retry (unlike timeout handling)
4. External systems relying on blame assignment may exclude innocent signers
5. Repeated attacks could exclude enough honest signers to drop below the signing threshold

**Quantified Impact:**

In a deployment with 10 signers and threshold 7:
- Attacker compromises 1 signer (10% of participants)
- Frames 3 innocent signers over multiple signing rounds
- System now has only 6 uncompromised, non-excluded signers
- Below threshold, unable to produce signatures
- Qualifies as "transient consensus failures" per protocol scope

**Who Is Affected:**

Any deployment using v2 (weighted threshold) where:
- A signer node is compromised
- The coordinator's error handling trusts blame assignment
- Signing operations are critical for system liveness

**Severity Justification:**

Medium severity per protocol scope: "Any transient consensus failures." The vulnerability causes signing protocol failures with incorrect blame assignment, potentially leading to exclusion of honest parties and temporary loss of signing capability.

### Likelihood Explanation

**Required Attacker Capabilities:**

1. Control of one signer node (compromise via malware, insider threat, or node vulnerability)
2. Ability to modify signer software to create malformed `SignatureShare` objects
3. No additional cryptographic secrets required beyond being a legitimate signer

**Attack Complexity:**

Low. The attack requires only a single-line code modification:

In `v2::Party::sign_with_tweak()`, change line 272 from:
```rust
id: self.party_id,
```
to:
```rust
id: <target_victim_id>,
```

**Economic Feasibility:**

- No special resources required beyond compromising a single signer
- No timing constraints or race conditions to exploit
- Can be executed repeatedly to frame multiple parties
- Detection requires detailed logging and correlation of packet-level sender with signature share contents

**Detection Risk:**

Medium. Without explicit validation logging, the attack appears as legitimate signature failures from the framed party. Detecting requires correlating:
- Packet-level authenticated sender ID
- SignatureShare.id within the packet
- Failure patterns across multiple rounds

**Estimated Probability:**

If a signer is compromised: High (>70%). The attack is trivial to execute once a signer node is controlled.

### Recommendation

**Primary Fix:**

Add validation in the coordinator to ensure `SignatureShare.id` matches the authenticated `signer_id`:

```rust
// In gather_sig_shares, after line 1076:
for sig_share in &sig_share_response.signature_shares {
    if sig_share.id != sig_share_response.signer_id {
        warn!(
            signer_id = %sig_share_response.signer_id,
            share_id = %sig_share.id,
            "SignatureShare id doesn't match authenticated signer_id"
        );
        return Err(Error::InvalidSignatureShareId(
            sig_share_response.signer_id,
            sig_share.id,
        ));
    }
}
```

**Testing Recommendations:**

1. Add test case that creates signature shares with mismatched `id` field
2. Verify coordinator rejects these shares with appropriate error
3. Test that the actual malicious signer is correctly identified (not the framed party)
4. Add integration test with multiple signers where one attempts to frame another

**Deployment Considerations:**

1. This is a breaking change that will reject previously "valid" but malicious messages
2. Deploy to all coordinators simultaneously to ensure consistent validation
3. Add logging to monitor any rejected messages during rollout
4. Consider adding similar validation for other fields (key_ids already validated)

### Proof of Concept

**Exploitation Algorithm:**

1. **Setup**: Deployment with signers A (signer_id=5), B (signer_id=3), C (signer_id=1)

2. **Attacker compromises Signer A**

3. **Modify Signer A's code**:
   - In `v2::Party::sign_with_tweak()` at line 272
   - Change from `id: self.party_id` (which is 5)
   - To `id: 3` (targeting victim Signer B)

4. **Normal protocol execution**:
   - Coordinator requests nonces, all signers respond
   - Coordinator stores `public_nonces[5]` from Signer A
   - Coordinator requests signature shares

5. **Malicious signature share**:
   - Signer A creates `SignatureShareResponse { signer_id: 5, signature_shares: [SignatureShare { id: 3, z_i: ..., key_ids: [5,6] }] }`
   - Packet authentication succeeds (valid signature from signer 5)
   - Coordinator stores under key 5: `signature_shares[5] = [SignatureShare { id: 3, ... }]`

6. **Aggregation**:
   - Coordinator pairs: `nonces[i]` from signer 5 with `shares[i]` having `id: 3`
   - Aggregator computes: `party_ids = [..., 3, ...]` (extracted from SignatureShare.id)
   - Binding: `binding(3, nonces, msg)` with nonces that include signer 5's nonce
   - Mismatch: Signer A computed `r = d + e * binding(5, ...)`, but aggregator expects `binding(3, ...)`

7. **Verification Failure**:
   - Signature verification fails
   - `check_signature_shares()` blames signer 3 (from SignatureShare.id)
   - Innocent Signer B (signer_id=3) is identified as malicious

8. **Impact**:
   - Coordinator returns `BadPartySigs([3])`
   - External system may exclude Signer B
   - Actual malicious Signer A remains undetected

**Expected vs Actual Behavior:**

- **Expected**: Malicious signer 5 is detected and blamed
- **Actual**: Innocent signer 3 is blamed due to unauthenticated id field

**Reproduction Steps:**

Use the existing test infrastructure and modify one signer to return incorrect id values, then verify the blame assignment is incorrect.

### Citations

**File:** src/common.rs (L211-220)
```rust
#[derive(Clone, Deserialize, Serialize, PartialEq)]
/// A share of the party signature with related values
pub struct SignatureShare {
    /// The ID of the party
    pub id: u32,
    /// The party signature
    pub z_i: Scalar,
    /// The key IDs of the party
    pub key_ids: Vec<u32>,
}
```

**File:** src/state_machine/coordinator/fire.rs (L1055-1076)
```rust
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

**File:** src/state_machine/coordinator/fire.rs (L1088-1090)
```rust
        self.signature_shares.insert(
            sig_share_response.signer_id,
            sig_share_response.signature_shares.clone(),
```

**File:** src/state_machine/coordinator/fire.rs (L1131-1135)
```rust
            let shares = message_nonce
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();
```

**File:** src/v2.rs (L308-309)
```rust
        let party_ids: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (_Rs, R) = compute::intermediate(msg, &party_ids, nonces);
```

**File:** src/v2.rs (L406-408)
```rust
            if z_i * G != (r_sign * Rs[i] + cx_sign * cx) {
                bad_party_sigs.push(sig_shares[i].id);
            }
```

**File:** src/compute.rs (L85-96)
```rust
pub fn intermediate(msg: &[u8], party_ids: &[u32], nonces: &[PublicNonce]) -> (Vec<Point>, Point) {
    let rhos: Vec<Scalar> = party_ids
        .iter()
        .map(|&i| binding(&id(i), nonces, msg))
        .collect();
    let R_vec: Vec<Point> = zip(nonces, rhos)
        .map(|(nonce, rho)| nonce.D + rho * nonce.E)
        .collect();

    let R = R_vec.iter().fold(Point::zero(), |R, &R_i| R + R_i);
    (R_vec, R)
}
```

**File:** src/net.rs (L583-597)
```rust
            Message::SignatureShareResponse(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!(
                            "Received a SignatureShareResponse message with an invalid signature."
                        );
                        return false;
                    }
                } else {
                    warn!(
                        "Received a SignatureShareResponse message with an unknown id: {}",
                        msg.signer_id
                    );
                    return false;
                }
```

**File:** src/v1.rs (L224-228)
```rust
        SignatureShare {
            id: self.id,
            z_i: z,
            key_ids: vec![self.id],
        }
```
