# Audit Report

## Title
Coordinator Assumes Message Ordering Without Validation in v1 Aggregation

## Summary
The coordinator (fire/frost) collects nonces and signature shares from v1 signers by flat-mapping their responses, assuming positional correspondence between nonces and signature shares. However, the coordinator only validates that the SET of key_ids matches using HashSet comparison, not the ORDER. A malicious v1 signer controlling multiple parties can send NonceResponse and SignatureShareResponse with mismatched internal ordering, causing the aggregator to pair wrong nonces with wrong parties during signature verification, resulting in denial of service.

## Finding Description
The vulnerability exists in the v1 signing protocol where signers control multiple Party objects, each generating its own nonce and signature share.

**The Attack Flow:**

1. **Nonce Collection**: The coordinator collects nonces by flat-mapping NonceResponse.nonces from each signer: [1](#0-0) 

2. **Signature Share Collection**: The coordinator collects signature shares by flat-mapping from the signature_shares HashMap: [2](#0-1) 

3. **Validation Gap**: The coordinator only validates SET equality of key_ids using HashSet comparison, not ordering: [3](#0-2) 

4. **Aggregator Assumption**: The v1 aggregator extracts party IDs from signature shares positionally and calls compute::intermediate with the nonces array: [4](#0-3) 

5. **Positional Pairing**: compute::intermediate zips party_ids with nonces by position, assuming party_ids[i] corresponds to nonces[i]: [5](#0-4) 

**The Exploit:**

A malicious v1 signer with parties [1,2,3] can:
- Send NonceResponse with key_ids=[1,2,3], nonces=[N1,N2,N3]
- Send SignatureShareResponse with signature_shares reordered: [share3, share2, share1] where share_i.id=i
- The coordinator validates only that {1,2,3} == {3,2,1} as sets (passes)
- The aggregator pairs: party 3 with N1, party 2 with N2, party 1 with N3
- This is incorrect because N1 was generated for party 1, causing verification to fail

**Why v1 Specific:**

In v1, each signer controls multiple Party objects that each generate separate nonces and shares: [6](#0-5) [7](#0-6) 

In v2, each signer generates only ONE nonce regardless of how many key_ids they control: [8](#0-7) 

## Impact Explanation
This vulnerability enables a denial of service attack against the signing protocol. When a malicious v1 signer participates with reordered signature shares, the aggregator pairs incorrect nonces with parties during signature verification. The verification in check_signature_shares will fail: [9](#0-8) 

**Impact Classification: Medium** - This causes transient consensus failures as defined in the scope. All signature attempts fail when the malicious signer participates, preventing block production or transaction signing until the malicious signer is identified and removed. This does not cause permanent loss of funds or persistent consensus failures, but temporarily prevents the system from creating valid signatures.

## Likelihood Explanation
**Likelihood: High**

Required capabilities:
- Attacker must be a legitimate v1 signer with valid DKG shares
- Attacker can construct custom Packet messages with reordered signature_shares vector
- No cryptographic breaks or key compromise required

Attack complexity is LOW:
1. Participate in DKG normally to become legitimate signer
2. During signing, send standard NonceResponse
3. Send SignatureShareResponse with signature_shares reordered (e.g., reverse order)
4. Coordinator's HashSet validation passes but aggregation fails

The attack is easily detectable (all signatures fail) but the system lacks mechanisms to distinguish this from other signature failures, making remediation require manual intervention.

## Recommendation
Add ordering validation in the coordinator to ensure that within each signer's responses, the ordering of key_ids in NonceResponse matches the ordering of signature share IDs in SignatureShareResponse.

**Fix in src/state_machine/coordinator/fire.rs (around line 1066):**

```rust
// After collecting signature shares, validate ordering matches nonces
let nonce_response = message_nonce
    .public_nonces
    .get(&sig_share_response.signer_id)
    .ok_or(Error::MissingNonceForSigner(sig_share_response.signer_id))?;

// Validate that signature share IDs match nonce key_ids in order
if nonce_response.key_ids.len() != sig_share_response.signature_shares.len() {
    return Err(Error::BadKeyIDsForSigner(sig_share_response.signer_id));
}

for (i, expected_key_id) in nonce_response.key_ids.iter().enumerate() {
    if sig_share_response.signature_shares[i].id != *expected_key_id {
        warn!(
            signer_id = %sig_share_response.signer_id,
            "Signature share ordering doesn't match nonce ordering"
        );
        return Err(Error::BadKeyIDsForSigner(sig_share_response.signer_id));
    }
}
```

## Proof of Concept
The vulnerability can be demonstrated by creating a test where a v1 signer with multiple parties sends correctly ordered nonces but reordered signature shares, causing aggregation to fail even though all cryptographic operations were performed correctly.

**Notes:**
- This vulnerability ONLY affects v1 deployments where signers control multiple parties
- v2 is not affected because each v2::Party generates exactly one nonce per signer
- The vulnerability requires a malicious signer within the threshold, which is allowed by the threat model
- Detection is straightforward (all signatures fail) but remediation requires identifying the malicious signer

### Citations

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

**File:** src/state_machine/coordinator/fire.rs (L1121-1124)
```rust
            let nonces = nonce_responses
                .iter()
                .flat_map(|nr| nr.nonces.clone())
                .collect::<Vec<PublicNonce>>();
```

**File:** src/state_machine/coordinator/fire.rs (L1131-1135)
```rust
            let shares = message_nonce
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();
```

**File:** src/v1.rs (L321-326)
```rust
        if nonces.len() != sig_shares.len() {
            return Err(AggregatorError::BadNonceLen(nonces.len(), sig_shares.len()));
        }

        let signers: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (_Rs, R) = compute::intermediate(msg, &signers, nonces);
```

**File:** src/v1.rs (L411-416)
```rust
            if z_i * G
                != r_sign * Rs[i]
                    + cx_sign * (compute::lambda(sig_shares[i].id, &signers) * c * public_key)
            {
                bad_party_sigs.push(sig_shares[i].id);
            }
```

**File:** src/v1.rs (L676-685)
```rust
    fn gen_nonces<RNG: RngCore + CryptoRng>(
        &mut self,
        secret_key: &Scalar,
        rng: &mut RNG,
    ) -> Vec<PublicNonce> {
        self.parties
            .iter_mut()
            .map(|p| p.gen_nonce(secret_key, rng))
            .collect()
    }
```

**File:** src/v1.rs (L715-718)
```rust
        self.parties
            .iter()
            .map(|p| p.sign_precomputed(msg, key_ids, nonces, &aggregate_nonce))
            .collect()
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

**File:** src/v2.rs (L627-633)
```rust
    fn gen_nonces<RNG: RngCore + CryptoRng>(
        &mut self,
        secret_key: &Scalar,
        rng: &mut RNG,
    ) -> Vec<PublicNonce> {
        vec![self.gen_nonce(secret_key, rng)]
    }
```
