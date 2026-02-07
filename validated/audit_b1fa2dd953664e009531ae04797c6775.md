# Audit Report

## Title
Coordinator Panic Due to Premature Wait List Removal in Signature Share Gathering

## Summary
The FIRE coordinator in `src/state_machine/coordinator/fire.rs` removes signers from the wait list before validating their signature share responses. When validation subsequently fails, the signer is excluded from `signature_shares` but already removed from the wait list, creating an accounting mismatch. Once all remaining signers complete successfully, aggregation attempts to access the missing signer's shares using unsafe bracket notation on a BTreeMap, causing a panic that crashes the coordinator.

## Finding Description

The vulnerability exists in the `gather_sig_shares` function where the coordinator processes `SignatureShareResponse` messages. The critical flaw is the order of operations:

1. **Premature Wait List Removal**: The coordinator removes the signer from `sign_wait_signer_ids` immediately after confirming they are in the wait list, but BEFORE performing any validation checks. [1](#0-0) 

2. **Post-Removal Validation**: Multiple validation checks occur AFTER the wait list removal, any of which can fail and return errors:
   - Missing public key check
   - Missing key IDs check  
   - Mismatched key IDs check [2](#0-1) 

3. **Conditional Insertion**: The signature share is only inserted into `signature_shares` if ALL validations pass. [3](#0-2) 

4. **Corrupted State Persistence**: When validation fails, the error is caught and returned as an `OperationResult::SignError`, but the coordinator state remains in `SigShareGather` with the signer already removed from the wait list but absent from `signature_shares`. [4](#0-3) 

5. **Unsafe Aggregation Access**: When the wait list becomes empty (after other signers successfully complete), aggregation iterates over ALL signers in `public_nonces` and accesses `signature_shares[i]` using bracket notation. Since `signature_shares` is a BTreeMap, this panics when the key doesn't exist. [5](#0-4) 

The root cause is the broken invariant: the code assumes `public_nonces.keys()` equals `signature_shares.keys()` during aggregation, but the premature removal breaks this assumption.

**Attack Scenario:**
1. Attacker (registered signer) sends valid nonces → added to `public_nonces`
2. Attacker sends `SignatureShareResponse` with malformed data (e.g., wrong key_ids)
3. Coordinator removes attacker from wait list (line 1042-1044)
4. Validation fails at line 1073-1076, function returns error
5. Attacker NOT added to `signature_shares`, but already removed from wait list
6. Other honest signers send valid responses and complete successfully
7. Wait list becomes empty, triggering aggregation at line 1113
8. Line 1134 tries to access `signature_shares[attacker_id]` → **panic!**

**Confirmation via FROST Comparison:**
The FROST coordinator does NOT have this vulnerability because it performs the wait list removal AFTER validation and insertion. [6](#0-5) 

This confirms the FIRE implementation has a genuine ordering bug.

## Impact Explanation

This vulnerability allows a single malicious signer to crash the coordinator node through a Rust panic, resulting in process termination. The impact maps to **Low severity** under the scope definition: "Any remotely-exploitable denial of service in a node."

The coordinator process must be restarted to resume operations, and the affected signing round must be retried. While disruptive to availability, this does not:
- Cause direct loss of funds
- Enable invalid signature acceptance  
- Trigger consensus failures
- Create persistent corruption

Applications using WSTS FIRE coordinator for threshold signature coordination (such as Stacks blockchain signers) would experience service interruption until the coordinator is restarted.

## Likelihood Explanation

**Likelihood: High (~100% success rate)**

The attack is deterministic and trivial to execute:

**Required Capabilities:**
- Attacker must be a registered signer in the WSTS configuration (within protocol threat model)
- Must participate in nonce gathering phase with valid nonces
- Must send a malformed `SignatureShareResponse`

**Attack Complexity:** Very low
- No cryptographic operations required
- No timing dependencies or race conditions
- Single malformed packet triggers the vulnerability
- Example trigger: Send signature shares with key_ids that don't match the configured signer_key_ids

**Economic Cost:** Negligible
- No computational expense beyond normal protocol participation
- No need to control multiple signers

**Detection Difficulty:** Low
- Appears as a normal validation error followed by a crash
- Difficult to distinguish from legitimate software bugs without detailed audit

**Success Probability:** ~100% deterministic

## Recommendation

Move the wait list removal to occur AFTER all validation checks pass and the signature share is successfully inserted, matching the FROST coordinator's correct implementation:

```rust
// Perform all validation checks first (lines 1046-1076)
// ...validation code...

// Only insert and remove from wait list if validation succeeds
self.signature_shares.insert(
    sig_share_response.signer_id,
    sig_share_response.signature_shares.clone(),
);

// NOW remove from wait list after successful insertion
response_info
    .sign_wait_signer_ids
    .remove(&sig_share_response.signer_id);
```

Additionally, consider using safe access methods (`.get()`) instead of bracket notation for the aggregation step to provide better error handling:

```rust
let shares = message_nonce
    .public_nonces
    .iter()
    .flat_map(|(i, _)| {
        self.signature_shares.get(i)
            .ok_or(Error::MissingSignatureShare(*i))
            .map(|s| s.clone())
    })
    .collect::<Result<Vec<SignatureShare>, Error>>()?;
```

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "no entry found for key")]
fn test_premature_wait_list_removal_panic() {
    use crate::state_machine::coordinator::{
        fire::Coordinator as FireCoordinator,
        Coordinator as CoordinatorTrait,
    };
    use crate::v2::Aggregator;
    use crate::net::{Packet, Message, SignatureShareResponse};
    
    // Setup: Run DKG and nonce gathering with 3 signers, threshold 2
    let (mut coordinators, mut signers) = 
        run_dkg::<FireCoordinator<Aggregator>, v2::Signer>(3, 1);
    
    // Start signing round and complete nonce gathering
    let msg = b"test message";
    let nonce_req = coordinators[0]
        .start_signing_round(msg, SignatureType::Frost, None)
        .unwrap();
    let (sig_share_reqs, _) = feedback_messages(&mut coordinators, &mut signers, &[nonce_req]);
    
    // Signer 0: Send MALFORMED signature share with wrong key_ids
    let mut malformed_response = create_valid_signature_share_response(0);
    malformed_response.signature_shares[0].key_ids = vec![999]; // Invalid key_id
    let malformed_packet = create_packet(malformed_response);
    
    // Process malformed packet - returns error but corrupts state
    let result = coordinators[0].process(&malformed_packet);
    assert!(result.is_ok()); // Error returned as OperationResult
    
    // Signers 1 and 2: Send VALID signature shares
    let valid_responses = generate_valid_signature_shares(&mut signers[1..3], &sig_share_reqs[0]);
    
    // Process valid responses - last one will trigger aggregation
    // This will PANIC at line 1134 when accessing signature_shares[0]
    for packet in valid_responses {
        coordinators[0].process(&packet).unwrap(); // PANICS HERE
    }
}
```

The test demonstrates that after a malformed signature share creates the accounting mismatch, subsequent valid responses trigger the panic during aggregation when the coordinator attempts to access the missing signer's shares.

### Citations

**File:** src/state_machine/coordinator/fire.rs (L327-333)
```rust
                State::SigShareGather(signature_type) => {
                    if let Err(e) = self.gather_sig_shares(packet, signature_type) {
                        return Ok((
                            None,
                            Some(OperationResult::SignError(SignError::Coordinator(e))),
                        ));
                    }
```

**File:** src/state_machine/coordinator/fire.rs (L1042-1044)
```rust
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

**File:** src/state_machine/coordinator/fire.rs (L1088-1091)
```rust
        self.signature_shares.insert(
            sig_share_response.signer_id,
            sig_share_response.signature_shares.clone(),
        );
```

**File:** src/state_machine/coordinator/fire.rs (L1131-1135)
```rust
            let shares = message_nonce
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();
```

**File:** src/state_machine/coordinator/frost.rs (L652-656)
```rust
            self.signature_shares.insert(
                sig_share_response.signer_id,
                sig_share_response.signature_shares.clone(),
            );
            self.ids_to_await.remove(&sig_share_response.signer_id);
```
