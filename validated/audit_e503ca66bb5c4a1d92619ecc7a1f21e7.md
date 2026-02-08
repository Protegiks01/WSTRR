# Audit Report

## Title
Incorrect Malicious Signer Identification Due to Unauthenticated SignatureShare.id Field in v2

## Summary
The v2 coordinator does not validate that the `id` field within `SignatureShare` objects matches the authenticated `signer_id` of the sender. A malicious signer can create signature shares with a spoofed `id` field, causing signature verification to fail and blame to be incorrectly assigned to an innocent party.

## Finding Description

The vulnerability exists due to insufficient validation of the `SignatureShare` structure in v2. While packet-level authentication ensures messages come from legitimate signers, the coordinator fails to validate that the `id` field within signature shares matches the authenticated sender.

**Attack Flow:**

1. The coordinator stores signature shares indexed by the authenticated `signer_id` from the packet but never validates that `SignatureShare.id` matches this sender ID. [1](#0-0) 

2. The coordinator validates that `key_ids` match the configured keys for the sender, but does NOT validate the `id` field. [2](#0-1) 

3. During aggregation, the aggregator extracts party IDs from `SignatureShare.id` for binding computation. [3](#0-2) 

4. The binding computation depends critically on the party ID - it is serialized directly into the hash input used to compute the binding value. [4](#0-3) 

5. When an honest signer creates their signature share, they compute it using their actual party ID for the binding value. If a malicious signer provides a signature share with a spoofed `id`, the aggregator will use the spoofed party ID for binding computation, creating a mismatch that causes verification to fail. [5](#0-4) 

6. When verification fails, blame is assigned based on `SignatureShare.id`, incorrectly identifying the innocent party whose ID was spoofed. [6](#0-5) 

**The Exploit:**

A compromised signer modifies their code to create signature shares with an incorrect `id` field. In v2::Party::sign_with_tweak(), the malicious signer changes the `id` field from their own party_id to a victim's party_id. [7](#0-6) 

## Impact Explanation

This vulnerability enables a compromised signer to frame honest parties for signing failures. A malicious signer provides a signature share with a spoofed `id` field, causing signature verification to fail. The `BadPartySigs` error incorrectly identifies the innocent party whose ID was spoofed. External systems relying on blame assignment may exclude the innocent signer. Repeated attacks could exclude enough honest signers to drop below the signing threshold, causing temporary loss of signing capability.

This maps to **Medium severity** per the protocol scope: "Any transient consensus failures." The vulnerability causes signing protocol failures with incorrect blame assignment, potentially leading to exclusion of honest parties.

## Likelihood Explanation

**Required Attacker Capabilities:**
- Control of one signer node (within the threshold-1 threat model)
- Ability to modify signer software to create malformed `SignatureShare` objects
- No additional cryptographic secrets required beyond being a legitimate signer

**Attack Complexity:** Low. The attack requires only modifying the `id` field in the signer software. No timing constraints, race conditions, or complex cryptographic operations are needed.

**Estimated Probability:** If a signer is compromised, the attack is trivial to execute, requiring only a single-line code modification.

## Recommendation

Add validation in the coordinator's `gather_sig_shares` method to ensure that each `SignatureShare.id` matches the expected party ID for the authenticated sender. For v2, implement a check using the existing `validate_party_id` trait method:

```rust
// In gather_sig_shares, after validating key_ids:
for sig_share in &sig_share_response.signature_shares {
    if !Aggregator::validate_party_id(
        sig_share_response.signer_id,
        sig_share.id,
        &self.config.public_keys.signer_key_ids,
    ) {
        warn!(signer_id = %sig_share_response.signer_id, 
              party_id = %sig_share.id,
              "SignatureShare id doesn't match signer");
        return Err(Error::BadPartyIdForSigner(sig_share_response.signer_id, sig_share.id));
    }
}
```

This validation ensures that the `id` field in each signature share is consistent with the authenticated sender's identity according to the protocol version (v2 requires `party_id == signer_id`).

## Proof of Concept

The vulnerability can be demonstrated by modifying a signer to set `id: victim_party_id` instead of `id: self.party_id` in the `sign_with_tweak` method, then observing that: (1) the coordinator accepts the signature share without validating the `id` field, (2) aggregation fails due to binding value mismatch, and (3) blame is incorrectly assigned to the victim party instead of the malicious signer.

## Notes

My analysis indicates that v1 may also be vulnerable to this attack, contrary to the claim in the original report. In v1, the coordinator similarly does not validate the `id` field against `signer_id`, and party IDs are extracted from `SignatureShare.id` for binding computation. [8](#0-7) [9](#0-8) 

The claim that v1 is protected because "party_id == key_id" and the coordinator validates key_ids is insufficient - a malicious v1 signer can set `id=victim_id` while keeping `key_ids=[attacker_id]`, passing coordinator validation but causing the same incorrect blame assignment. Both v1 and v2 implementations should add validation of the `id` field.

### Citations

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

**File:** src/state_machine/coordinator/fire.rs (L1088-1091)
```rust
        self.signature_shares.insert(
            sig_share_response.signer_id,
            sig_share_response.signature_shares.clone(),
        );
```

**File:** src/v2.rs (L255-257)
```rust
        let (_, R) = compute::intermediate(msg, party_ids, nonces);
        let c = compute::challenge(&tweaked_public_key, &R, msg);
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

**File:** src/v2.rs (L359-360)
```rust
        let party_ids: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (Rs, R) = compute::intermediate(msg, &party_ids, nonces);
```

**File:** src/v2.rs (L407-408)
```rust
                bad_party_sigs.push(sig_shares[i].id);
            }
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

**File:** src/v1.rs (L325-326)
```rust
        let signers: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (_Rs, R) = compute::intermediate(msg, &signers, nonces);
```

**File:** src/v1.rs (L415-416)
```rust
                bad_party_sigs.push(sig_shares[i].id);
            }
```
