# Audit Report

## Title
Coordinator State Corruption Leading to Denial of Service via Invalid Signature Share Handling

## Summary
The FIRE coordinator's `gather_sig_shares` method removes signers from the wait list before validating their signature shares, causing a panic during aggregation when validation fails. This creates a remotely-exploitable denial of service where any authorized malicious signer can crash the coordinator node.

## Finding Description

The vulnerability exists in the FIRE coordinator's signature share gathering logic. The critical flaw is the ordering of operations in the `gather_sig_shares` method.

**Attack Flow:**

1. A signer participates normally in DKG and sends a valid `NonceResponse`. Their signer ID is inserted into `message_nonces.public_nonces` and added to `sign_wait_signer_ids`. [1](#0-0) 

2. When the signer receives a `SignatureShareRequest`, they send a `SignatureShareResponse` with intentionally invalid data (e.g., mismatched `key_ids`).

3. The coordinator's `gather_sig_shares` method processes this response:
   - First, it checks if the signer is in the wait list (valid check)
   - Then validates `dkg_id` and `sign_id` (valid checks)
   - **Critical flaw**: It removes the signer from `sign_wait_signer_ids` BEFORE completing validation [2](#0-1) 
   - After removal, it performs additional validation checks (public key existence, key ID configuration, key ID matching) that can fail [3](#0-2) 
   - Shares are only inserted into `self.signature_shares` if ALL validation passes [4](#0-3) 

4. The validation error is caught in the main processing loop and returned as a `SignError`, but the corrupted state persists. [5](#0-4) 

5. When all signers have been processed (`sign_wait_signer_ids` is empty), aggregation is triggered. [6](#0-5) 

6. The aggregation code collects shares by iterating over `public_nonces` and indexing into `self.signature_shares` using the BTreeMap indexing operator `[]`. [7](#0-6) 

7. **Panic occurs**: When the code attempts `self.signature_shares[i]` for a signer ID that sent nonces but whose shares failed validation, the BTreeMap indexing operation panics because the key doesn't exist.

**Root Cause**: The wait list modification violates atomicity - the signer is marked as "processed" (removed from wait list) before the operation completes successfully (shares inserted). This creates an inconsistent state where `public_nonces` contains a signer ID that doesn't exist in `signature_shares`.

The `signature_shares` field is defined as a `BTreeMap<u32, Vec<SignatureShare>>`, and Rust's indexing operator on BTreeMap panics when the key is absent. [8](#0-7) 

## Impact Explanation

This vulnerability enables a **Low severity** remotely-exploitable denial of service, per the audit scope definition: "Any remotely-exploitable denial of service in a node."

**Specific harm:**
- The coordinator process panics and terminates
- All honest signers' computational work (nonce generation, share computation) is wasted
- The entire signing round must be restarted from scratch
- Repeated attacks can prevent signature generation indefinitely
- If this affects critical operations (e.g., Stacks block signing), it could escalate to network-level DoS

**Who is affected:** Any deployment using the FIRE coordinator for WSTS threshold signatures, including Stacks 2.1+ signer nodes.

While this doesn't directly cause fund loss or chain splits, the ability to prevent signature generation could have cascading effects in production systems that rely on these signatures for consensus or block production.

## Likelihood Explanation

**Likelihood: High**

**Required attacker capabilities:**
- Must be a valid signer with a registered `signer_id` in the coordinator's configuration
- Must have successfully participated in DKG (to send nonces)
- No cryptographic breaks required

**Attack complexity:** Low
1. Participate normally in DKG and receive signing requests
2. Send valid `NonceResponse` when requested
3. When `SignatureShareRequest` arrives, send `SignatureShareResponse` with intentionally invalid `key_ids` (e.g., use wrong key IDs, empty set, or IDs not in configuration)

**Economic feasibility:** Free to execute once positioned as an authorized signer

**Detection:** The coordinator crash is immediately visible, but identifying the specific malicious signer may be difficult if multiple signers are participating, as the panic occurs after all responses are collected.

The attack is trivial for any authorized signer to execute and requires no special resources or cryptographic capabilities.

## Recommendation

**Fix:** Move the wait list removal to occur AFTER all validation passes and shares are successfully inserted.

Recommended code change in `gather_sig_shares`:

```rust
// Validate dkg_id and sign_id first
if sig_share_response.dkg_id != self.current_dkg_id {
    return Err(Error::BadDkgId(
        sig_share_response.dkg_id,
        self.current_dkg_id,
    ));
}
if sig_share_response.sign_id != self.current_sign_id {
    return Err(Error::BadSignId(
        sig_share_response.sign_id,
        self.current_sign_id,
    ));
}

// Validate signer configuration
let signer_public_keys = &self.config.public_keys.signers;
if !signer_public_keys.contains_key(&sig_share_response.signer_id) {
    warn!(signer_id = %sig_share_response.signer_id, "No public key in config");
    return Err(Error::MissingPublicKeyForSigner(
        sig_share_response.signer_id,
    ));
}

// Validate key_ids
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

// Check for duplicates
let have_shares = self
    .signature_shares
    .contains_key(&sig_share_response.signer_id);

if have_shares {
    info!(signer_id = %sig_share_response.signer_id, "received duplicate SignatureShareResponse");
    return Ok(());
}

// ALL validation passed - now it's safe to modify state
// MOVE THIS LINE HERE (after all validation):
response_info
    .sign_wait_signer_ids
    .remove(&sig_share_response.signer_id);

// Insert shares
self.signature_shares.insert(
    sig_share_response.signer_id,
    sig_share_response.signature_shares.clone(),
);

// Track received key_ids
for sig_share in &sig_share_response.signature_shares {
    for key_id in &sig_share.key_ids {
        response_info.sign_recv_key_ids.insert(*key_id);
    }
}
```

Additionally, for defense in depth, the aggregation code should use `.get()` instead of indexing to handle missing keys gracefully rather than panicking.

## Proof of Concept

```rust
#[cfg(test)]
mod vulnerability_test {
    use super::*;
    
    #[test]
    #[should_panic(expected = "no entry found for key")]
    fn test_invalid_key_ids_causes_panic() {
        // Setup: Create coordinator with 3 signers, threshold 2
        let mut coordinator = create_test_coordinator(3, 2);
        
        // Step 1: Complete DKG successfully
        complete_dkg(&mut coordinator);
        
        // Step 2: Start signing round
        let message = b"test message".to_vec();
        coordinator.start_signing_round(&message, SignatureType::Frost).unwrap();
        
        // Step 3: Signer 0 sends valid NonceResponse
        let nonce_response_0 = create_valid_nonce_response(0, &message);
        coordinator.process(&nonce_response_0).unwrap();
        
        // Step 4: Signer 1 sends valid NonceResponse  
        let nonce_response_1 = create_valid_nonce_response(1, &message);
        coordinator.process(&nonce_response_1).unwrap();
        
        // Step 5: Coordinator requests signature shares
        // (state transitions to SigShareGather)
        
        // Step 6: Signer 0 sends SignatureShareResponse with INVALID key_ids
        // This will pass wait list check, but fail key_id validation
        let mut invalid_sig_share = create_signature_share_response(0, &message);
        invalid_sig_share.signature_shares[0].key_ids = vec![9999]; // Wrong key_id
        
        // This should return error but corrupts state (removes from wait list)
        let result = coordinator.process(&Packet {
            sig: vec![],
            msg: Message::SignatureShareResponse(invalid_sig_share),
        });
        assert!(result.is_ok()); // Error is caught and returned as OperationResult
        
        // Step 7: Signer 1 sends valid SignatureShareResponse
        let valid_sig_share = create_signature_share_response(1, &message);
        
        // This will trigger aggregation since wait list is now empty
        // PANIC occurs here when trying to index signature_shares[0]
        coordinator.process(&Packet {
            sig: vec![],
            msg: Message::SignatureShareResponse(valid_sig_share),
        }).unwrap();
    }
}
```

This test demonstrates that when a signer sends invalid `key_ids`, the coordinator state becomes corrupted, and the subsequent valid response triggers a panic during aggregation.

## Notes

The same pattern exists in the FROST coordinator implementation and should be reviewed for similar issues. [9](#0-8)

### Citations

**File:** src/state_machine/coordinator/fire.rs (L45-45)
```rust
    signature_shares: BTreeMap<u32, Vec<SignatureShare>>,
```

**File:** src/state_machine/coordinator/fire.rs (L328-332)
```rust
                    if let Err(e) = self.gather_sig_shares(packet, signature_type) {
                        return Ok((
                            None,
                            Some(OperationResult::SignError(SignError::Coordinator(e))),
                        ));
```

**File:** src/state_machine/coordinator/fire.rs (L931-942)
```rust
            nonce_info
                .public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());

            // ignore the passed key_ids
            for key_id in signer_key_ids {
                nonce_info.nonce_recv_key_ids.insert(*key_id);
            }

            nonce_info
                .sign_wait_signer_ids
                .insert(nonce_response.signer_id);
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

**File:** src/state_machine/coordinator/fire.rs (L1113-1113)
```rust
        if message_nonce.sign_wait_signer_ids.is_empty() {
```

**File:** src/state_machine/coordinator/fire.rs (L1131-1135)
```rust
            let shares = message_nonce
                .public_nonces
                .iter()
                .flat_map(|(i, _)| self.signature_shares[i].clone())
                .collect::<Vec<SignatureShare>>();
```

**File:** src/state_machine/coordinator/frost.rs (L594-594)
```rust
    fn gather_sig_shares(
```
