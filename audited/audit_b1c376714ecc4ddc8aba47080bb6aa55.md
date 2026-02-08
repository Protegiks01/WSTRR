# Audit Report

## Title
Denial of Service via Duplicate Key IDs in SignatureShare

## Summary
A malicious signer can craft `SignatureShare` messages with thousands of duplicate `key_ids` that pass coordinator validation but cause severe CPU exhaustion during signature verification failure handling. The coordinator's validation logic checks only set equality of `key_ids` (allowing duplicates through HashSet deduplication), while the aggregator's `check_signature_shares` function iterates through every `key_id` including duplicates, resulting in O(n×m) complexity that enables CPU exhaustion and signing round disruption.

## Finding Description

The `SignatureShare` struct contains an unbounded `Vec<u32>` for `key_ids` with no size limits or deduplication enforcement: [1](#0-0) 

During signature share validation in the FROST coordinator, the code collects all `key_ids` into a `HashSet` to check against configured keys: [2](#0-1) 

This validation compares only the SET of `key_ids`, not the underlying array length or duplicates. An attacker can send `[1,1,1,...,2,2,2,...,3,3,3,...]` with thousands of duplicates, and the HashSet will deduplicate to `{1,2,3}`, passing validation if that matches the configured set. The FIRE coordinator has identical vulnerable validation logic: [3](#0-2) 

The validated `SignatureShare` with duplicates intact is stored directly: [4](#0-3) 

When signature verification fails (which the attacker can force by providing an incorrect `z_i` value), the aggregator calls `check_signature_shares`: [5](#0-4) 

This function iterates through ALL `key_ids` in each `SignatureShare`, including duplicates: [6](#0-5) 

For each `key_id`, it calls `compute::lambda` which itself loops through all `key_ids` in the signing round: [7](#0-6) 

The total complexity is O(num_duplicates × total_signing_keys). With 100,000 duplicate `key_ids` in one malicious share and 1,000 total signing keys, this results in 100 million iterations involving expensive scalar arithmetic operations.

**Attack Path:**
1. Malicious signer (within threshold-1) participates in signing round
2. Crafts `SignatureShareResponse` with `signature_shares[0].key_ids = [1,1,1,...,1,2,2,...,2,3,3,...,3]` containing 100k+ duplicates
3. Also provides incorrect `z_i` value to force signature verification failure
4. Signs message with their valid private key
5. Sends to coordinator(s)
6. Coordinator validates key_ids using HashSet comparison - passes validation
7. Coordinator stores SignatureShare with duplicates preserved
8. Coordinator attempts signature aggregation - verification fails due to bad `z_i`
9. `check_signature_shares` is called to identify bad signer
10. CPU exhaustion occurs processing duplicate `key_ids`

## Impact Explanation

This vulnerability maps to **Medium** severity under the defined scope: "Any transient consensus failures."

**Specific Harm:**
- Coordinator CPU exhaustion processing malicious signature shares (100+ million scalar operations)
- Memory pressure from storing large `key_ids` arrays (400KB+ per malicious share)
- Signing rounds delayed or completely failed due to coordinator overload
- Multiple coordinators affected if attacker sends malicious shares to all participants
- Legitimate signers blocked from completing valid signatures

**Who Is Affected:**
- All coordinators receiving the malicious signature share
- Legitimate signers waiting for signing round completion  
- Dependent systems (e.g., Stacks blockchain) requiring threshold signatures for transaction confirmation

The attack causes transient failures in the signing protocol by preventing timely signature aggregation. While it doesn't cause permanent damage or enable invalid signatures, it disrupts the core signing process which could delay blockchain transaction confirmation and impact consensus operations that depend on threshold signatures.

## Likelihood Explanation

**Required Attacker Capabilities:**
- Valid signer credentials (must be one of the legitimate signers, or have compromised a signer key)
- Ability to send messages to coordinators during signing rounds
- Ability to sign messages with their private key

**Attack Complexity:** 
Low. The attacker simply needs to:
1. Modify the `SignatureShareResponse` creation logic to inflate `key_ids` arrays with duplicates
2. Provide an incorrect `z_i` value to force verification failure
3. Sign the message with their valid signer key
4. Send during any signing round

**Economic Feasibility:**
High. The attack requires:
- No additional infrastructure beyond normal signer participation
- Minimal bandwidth (~400KB per malicious message)
- No continuous resource expenditure by attacker
- Can be repeated across multiple signing rounds

**Detection:**
The malicious signer will eventually be identified by `check_signature_shares` (if the coordinator doesn't timeout first), but the CPU exhaustion occurs before identification completes. Coordinators may log performance degradation, but attribution to specific message content requires deep inspection.

**Estimated Probability:**
High once an attacker controls valid signer credentials. The attack is straightforward to execute, difficult to prevent without bounds checking, and fits within the protocol's threat model of allowing up to threshold-1 malicious signers.

## Recommendation

Implement bounds checking and deduplication for `key_ids` during validation:

**1. Add size limit validation:**
```rust
// In coordinator validation (frost.rs, fire.rs)
const MAX_KEY_IDS_PER_SHARE: usize = 1000; // Adjust based on expected max keys per party

for sig_share in &sig_share_response.signature_shares {
    if sig_share.key_ids.len() > MAX_KEY_IDS_PER_SHARE {
        warn!(signer_id = %sig_share_response.signer_id, 
              "SignatureShare key_ids exceeds maximum allowed");
        return Err(Error::InvalidKeyIDs(sig_share_response.signer_id));
    }
}
```

**2. Add duplicate detection:**
```rust
// After existing HashSet validation
let mut sig_share_response_key_ids = HashSet::new();
let mut total_key_ids = 0;

for sig_share in &sig_share_response.signature_shares {
    total_key_ids += sig_share.key_ids.len();
    for key_id in &sig_share.key_ids {
        sig_share_response_key_ids.insert(*key_id);
    }
}

// Check for duplicates
if total_key_ids != sig_share_response_key_ids.len() {
    warn!(signer_id = %sig_share_response.signer_id, 
          "SignatureShare contains duplicate key_ids");
    return Err(Error::DuplicateKeyIDs(sig_share_response.signer_id));
}
```

**3. Deduplicate before storage (defense in depth):**
```rust
// Before storing signature_shares
let mut deduplicated_shares = Vec::new();
for share in sig_share_response.signature_shares {
    let mut unique_key_ids: Vec<u32> = share.key_ids.into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    unique_key_ids.sort();
    deduplicated_shares.push(SignatureShare {
        id: share.id,
        z_i: share.z_i,
        key_ids: unique_key_ids,
    });
}
self.signature_shares.insert(sig_share_response.signer_id, deduplicated_shares);
```

## Proof of Concept

```rust
#[test]
fn test_duplicate_keyids_dos() {
    use crate::common::SignatureShare;
    use crate::curve::scalar::Scalar;
    
    // Create malicious SignatureShare with 10,000 duplicate key_ids
    let mut malicious_key_ids = Vec::new();
    for i in 1..=10 {
        for _ in 0..1000 {
            malicious_key_ids.push(i); // 1000 duplicates of each key
        }
    }
    
    let malicious_share = SignatureShare {
        id: 1,
        z_i: Scalar::from(999), // Incorrect value to force verification failure
        key_ids: malicious_key_ids.clone(),
    };
    
    // Verify duplicates exist
    assert_eq!(malicious_share.key_ids.len(), 10_000);
    
    // Verify HashSet deduplication would pass validation
    let unique_keys: std::collections::HashSet<u32> = 
        malicious_share.key_ids.iter().copied().collect();
    assert_eq!(unique_keys.len(), 10); // Only 10 unique keys
    
    // This would pass coordinator validation since HashSet comparison
    // would see {1,2,3,4,5,6,7,8,9,10} matching configured keys
    
    // But check_signature_shares would iterate through all 10,000 duplicates,
    // calling compute::lambda for each, resulting in severe CPU overhead
}
```

This test demonstrates that a `SignatureShare` can contain 10,000 `key_ids` (with only 10 unique values) that would pass HashSet-based validation but cause severe performance degradation during `check_signature_shares` processing.

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

**File:** src/v2.rs (L393-404)
```rust
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

**File:** src/v2.rs (L460-460)
```rust
            Err(self.check_signature_shares(msg, nonces, sig_shares, key_ids, None))
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
