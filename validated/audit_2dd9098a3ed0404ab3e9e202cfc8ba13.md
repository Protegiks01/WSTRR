# Audit Report

## Title
Denial of Service via Duplicate Key IDs in SignatureShare

## Summary
A malicious signer within the threshold can craft `SignatureShare` messages with thousands of duplicate `key_ids` that bypass coordinator validation but cause severe CPU exhaustion during signature verification failure handling. The coordinator's validation logic checks only set equality using HashSet deduplication, while the aggregator's `check_signature_shares` function iterates through every `key_id` including duplicates, resulting in O(n×m) complexity that enables CPU exhaustion and signing round disruption.

## Finding Description

The `SignatureShare` struct contains an unbounded `Vec<u32>` for `key_ids` with no size limits or deduplication enforcement. [1](#0-0) 

During signature share validation in the FROST coordinator, the code collects all `key_ids` into a `HashSet` for validation against configured keys. [2](#0-1) 

This validation compares only the SET of `key_ids`, not the underlying array length or duplicates. An attacker can send `[1,1,1,...,2,2,2,...,3,3,3,...]` with thousands of duplicates, and the HashSet will deduplicate to `{1,2,3}`, passing validation if that matches the configured set. The FIRE coordinator has identical vulnerable validation logic. [3](#0-2) 

The validated `SignatureShare` with duplicates intact is stored directly via cloning. [4](#0-3) 

When signature verification fails, which the attacker can force by providing an incorrect `z_i` value, the aggregator calls `check_signature_shares`. [5](#0-4) 

This function iterates through ALL `key_ids` in each `SignatureShare`, including duplicates, without any deduplication. [6](#0-5) 

For each `key_id`, it calls `compute::lambda` which itself loops through all `key_ids` in the signing round. [7](#0-6) 

The total complexity is O(num_duplicates × total_signing_keys). With 100,000 duplicate `key_ids` in one malicious share and 1,000 total signing keys, this results in 100 million iterations involving expensive scalar arithmetic operations (multiplications and divisions).

The message signing mechanism includes all key_ids (including duplicates) in the hash that gets signed. [8](#0-7) 

There are no message size limits or maximum array length validations to prevent this attack.

## Impact Explanation

This vulnerability maps to **Low** severity under the defined scope: "Any remotely-exploitable denial of service in a node", with potential escalation to **Medium** if integrated into consensus-critical systems.

**Specific Harm:**
- Coordinator CPU exhaustion processing malicious signature shares (100+ million scalar operations)
- Memory pressure from storing large `key_ids` arrays (400KB+ per malicious share)
- Signing rounds delayed or completely failed due to coordinator resource exhaustion
- Multiple coordinators affected if attacker broadcasts malicious shares
- Legitimate signers blocked from completing valid signatures

**Who Is Affected:**
- All coordinators receiving the malicious signature share
- Legitimate signers waiting for signing round completion  
- Systems depending on threshold signatures for critical operations

The attack causes coordinator nodes to experience severe CPU exhaustion beyond normal malicious signer disruption. While malicious signers can already cause signing failures by providing incorrect signatures, this vulnerability amplifies the disruption by orders of magnitude through computational complexity exploitation.

## Likelihood Explanation

**Required Attacker Capabilities:**
- Valid signer credentials (must be within the threshold-1 malicious signer allowance)
- Ability to send messages to coordinators during signing rounds
- Ability to sign messages with their private key

**Attack Complexity:**
Low. The attacker modifies the `SignatureShareResponse` creation to inflate `key_ids` arrays with duplicates, provides an incorrect `z_i` value, signs with their valid key, and sends during any signing round.

**Economic Feasibility:**
High. Requires no additional infrastructure beyond normal signer participation, minimal bandwidth (~400KB per message), and can be repeated across multiple signing rounds.

**Detection:**
The malicious signer will eventually be identified by `check_signature_shares` (if the coordinator doesn't timeout first), but CPU exhaustion occurs before identification completes. Attribution requires deep packet inspection.

**Estimated Probability:**
High once an attacker controls valid signer credentials within the protocol's threat model allowance.

## Recommendation

Add duplicate key_id validation in the coordinator's signature share processing logic:

```rust
// In frost.rs and fire.rs signature share validation
let mut sig_share_response_key_ids = HashSet::new();
let mut total_key_ids = 0;

for sig_share in &sig_share_response.signature_shares {
    // Check for duplicates within each signature share
    let mut share_key_ids = HashSet::new();
    for key_id in &sig_share.key_ids {
        if !share_key_ids.insert(*key_id) {
            warn!(signer_id = %sig_share_response.signer_id, 
                  "Duplicate key_id detected in SignatureShare");
            return Err(Error::DuplicateKeyIDsInShare(sig_share_response.signer_id));
        }
        sig_share_response_key_ids.insert(*key_id);
        total_key_ids += 1;
    }
}

// Add maximum key_ids limit
const MAX_KEY_IDS_PER_SHARE: usize = 1000;
if total_key_ids > MAX_KEY_IDS_PER_SHARE {
    warn!(signer_id = %sig_share_response.signer_id, 
          "Excessive key_ids in SignatureShareResponse");
    return Err(Error::ExcessiveKeyIDs(sig_share_response.signer_id));
}
```

Additionally, consider implementing message size limits to prevent excessively large payloads.

## Proof of Concept

```rust
#[test]
fn test_duplicate_key_ids_dos() {
    // Setup: Create coordinator with 3 signers, threshold 2
    let mut coordinator = setup_frost_coordinator(3, 2);
    
    // Malicious signer creates signature share with 10,000 duplicate key_ids
    let mut duplicate_key_ids = Vec::new();
    for _ in 0..5000 {
        duplicate_key_ids.push(1);
        duplicate_key_ids.push(2);
    }
    
    let malicious_share = SignatureShare {
        id: 0,
        z_i: Scalar::random(&mut rng), // Incorrect value to force verification failure
        key_ids: duplicate_key_ids,
    };
    
    let sig_share_response = SignatureShareResponse {
        dkg_id: 1,
        sign_id: 1,
        sign_iter_id: 0,
        signer_id: 0,
        signature_shares: vec![malicious_share],
    };
    
    // Sign and send the malicious response
    let packet = sign_message(sig_share_response, signer_key);
    
    // Measure time to process
    let start = Instant::now();
    coordinator.process_signature_share(packet).unwrap();
    let duration = start.elapsed();
    
    // With 10,000 duplicates and normal processing, this should take excessive time
    // demonstrating the DoS condition
    assert!(duration.as_secs() > 10, "Processing should be severely delayed");
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

**File:** src/state_machine/coordinator/frost.rs (L652-655)
```rust
            self.signature_shares.insert(
                sig_share_response.signer_id,
                sig_share_response.signature_shares.clone(),
            );
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

**File:** src/v2.rs (L389-404)
```rust
        for i in 0..sig_shares.len() {
            let z_i = sig_shares[i].z_i;
            let mut cx = Point::zero();

            for key_id in &sig_shares[i].key_ids {
                let kid = compute::id(*key_id);
                let public_key = match compute::poly(&kid, &self.poly) {
                    Ok(p) => p,
                    Err(_) => {
                        bad_party_keys.push(sig_shares[i].id);
                        Point::zero()
                    }
                };

                cx += compute::lambda(*key_id, key_ids) * c * public_key;
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

**File:** src/compute.rs (L70-79)
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
```

**File:** src/net.rs (L457-463)
```rust
        for signature_share in &self.signature_shares {
            hasher.update(signature_share.id.to_be_bytes());
            hasher.update(signature_share.z_i.to_bytes());
            for key_id in &signature_share.key_ids {
                hasher.update(key_id.to_be_bytes());
            }
        }
```
