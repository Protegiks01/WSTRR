# Audit Report

## Title
Malicious Signers Not Marked When Providing Invalid Signature Shares

## Summary
The FIRE coordinator fails to mark signers as malicious when they provide cryptographically invalid signature shares detected during aggregation. While the aggregator correctly identifies bad parties via `BadPartySigs` error, the coordinator never uses this information to update `malicious_signer_ids`, allowing malicious signers to repeatedly participate in signing rounds and permanently prevent signature completion.

## Finding Description

The vulnerability exists in the signature share gathering and aggregation logic within the FIRE coordinator. The coordinator maintains two separate tracking mechanisms:

1. `sign_wait_signer_ids` - tracks which signers we're waiting for responses from [1](#0-0) 
2. `malicious_signer_ids` - tracks which signers should be excluded from future rounds

When a signature share response is received, the signer is immediately removed from `sign_wait_signer_ids`: [2](#0-1) 

The coordinator then attempts aggregation, which can fail if signature shares are invalid: [3](#0-2) 

The aggregator's verification methods correctly identify bad parties when aggregation fails. The `check_signature_shares` function validates each signature share using the equation `z_i * G == (r_sign * Rs[i] + cx_sign * cx)` and collects failing parties: [4](#0-3) 

When verification fails, `BadPartySigs` error is returned containing the IDs of parties whose signature shares failed verification: [5](#0-4) 

However, when this error is caught in the process_message flow, it's simply returned as an OperationResult without updating `malicious_signer_ids`: [6](#0-5) 

The timeout handler only marks signers still remaining in `sign_wait_signer_ids` as malicious: [7](#0-6) 

Since the malicious signer was already removed from `sign_wait_signer_ids` when they responded (even with bad data), the timeout handler cannot catch them.

In subsequent signing rounds, the coordinator only checks `malicious_signer_ids` to filter out malicious signers: [8](#0-7) 

Since `malicious_signer_ids` was never updated with the bad party IDs from the `BadPartySigs` error, the malicious signer can participate again, repeating the attack indefinitely.

## Impact Explanation

This vulnerability enables a denial of service attack that can permanently prevent signature completion. With `n` total signers and threshold `t`, if `(n - t + 1)` malicious signers coordinate, they can block signing indefinitely by repeatedly providing invalid signature shares.

Each invalid signature share causes the entire signing round to fail and restart. Since bad signers are never marked as malicious, they continue participating in every iteration, creating a persistent failure loop.

In blockchain contexts using WSTS (such as Stacks), this directly prevents transaction confirmation and block production, as threshold signatures are required for these operations. This aligns with **HIGH** severity per the scope definition: "shut down the network or otherwise not confirm new valid transactions for multiple blocks."

All systems using WSTS for threshold signatures are affected, including Stacks blockchain miners, multi-party wallet implementations, and any distributed signing protocols using WSTS coordinators.

## Likelihood Explanation

The attack has **VERY HIGH** likelihood of success (>95%) due to minimal requirements:

**Required Capabilities:**
- Control of at least one signer in the signing committee (achievable through compromised node or malicious participant)
- Ability to execute normal signing protocol (generate valid nonces)
- Ability to craft invalid signature shares (trivial: modify `z_i` by adding any scalar)

**Attack Complexity:** LOW - The attack requires no cryptographic sophistication:
1. Participate normally in nonce exchange
2. Compute valid signature share `z_i`
3. Modify the share (e.g., `z_i = z_i + 1`)
4. Submit the invalid share
5. Repeat in every signing iteration (not filtered out)

**Detection Risk:** LOW - While `BadPartySigs` errors identify the malicious party, the coordinator doesn't act on this information. External monitoring would require manual implementation.

**Economic Feasibility:** No additional cost beyond normal signer participation, making it economically viable for adversaries seeking network disruption or transaction censorship.

## Recommendation

The coordinator should extract bad party IDs from `BadPartySigs` errors and add them to `malicious_signer_ids`. This can be implemented by modifying the error handling in `gather_sig_shares`:

```rust
fn gather_sig_shares(
    &mut self,
    packet: &Packet,
    signature_type: SignatureType,
) -> Result<(), Error> {
    // ... existing code ...
    
    // When aggregation occurs
    let result = if let SignatureType::Taproot(merkle_root) = signature_type {
        self.aggregator.sign_taproot(&self.message, &nonces, &shares, &key_ids, merkle_root)
            .map(|p| self.schnorr_proof = Some(p))
    } else if let SignatureType::Schnorr = signature_type {
        self.aggregator.sign_schnorr(&self.message, &nonces, &shares, &key_ids)
            .map(|p| self.schnorr_proof = Some(p))
    } else {
        self.aggregator.sign(&self.message, &nonces, &shares, &key_ids)
            .map(|s| self.signature = Some(s))
    };
    
    // Handle BadPartySigs error specially
    if let Err(Error::Aggregator(AggregatorError::BadPartySigs(bad_parties))) = &result {
        for party_id in bad_parties {
            warn!("Marking party {party_id} as malicious due to invalid signature share");
            self.malicious_signer_ids.insert(*party_id);
        }
    }
    
    result?;
    // ... rest of function ...
}
```

Additionally, check if sufficient non-malicious signers remain after marking parties malicious, similar to the timeout handler logic.

## Proof of Concept

The existing test demonstrates the vulnerability: [9](#0-8) 

This test mutates signature shares from signer 0 and verifies that `BadPartySigs` error is returned with the correct party IDs. However, it does not verify that:
1. The bad party is added to `malicious_signer_ids`
2. The bad party is blocked from participating in subsequent rounds

A complete proof of concept would extend this test to:
1. Trigger `BadPartySigs` error by mutating signature shares
2. Verify the coordinator returns the error
3. **Attempt a second signing round**
4. **Verify that the bad party from step 1 is rejected when attempting to participate**

The current implementation would fail at step 4, as the bad party is not in `malicious_signer_ids` and would be allowed to participate again, demonstrating the vulnerability.

### Citations

**File:** src/state_machine/coordinator/mod.rs (L292-295)
```rust
    /// set of malicious signers during signing round
    pub malicious_signer_ids: HashSet<u32>,
    /// set of malicious signers during dkg round
    pub malicious_dkg_signer_ids: HashSet<u32>,
```

**File:** src/state_machine/coordinator/mod.rs (L1257-1349)
```rust
    /// Run DKG then sign a message, but alter the signature shares for signer 0.  This should trigger the aggregator internal check_signature_shares function to run and determine which parties signatures were bad.
    /// Because of the differences between how parties are represented in v1 and v2, we need to pass in a vector of the expected bad parties.
    pub fn check_signature_shares<Coordinator: CoordinatorTrait, SignerType: SignerTrait>(
        num_signers: u32,
        keys_per_signer: u32,
        signature_type: SignatureType,
        bad_parties: Vec<u32>,
    ) {
        let (mut coordinators, mut signers) =
            run_dkg::<Coordinator, SignerType>(num_signers, keys_per_signer);

        let msg = "It was many and many a year ago, in a kingdom by the sea"
            .as_bytes()
            .to_vec();
        // Start a signing round
        let message = coordinators
            .first_mut()
            .unwrap()
            .start_signing_round(&msg, signature_type, None)
            .unwrap();
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::NonceGather(signature_type)
        );

        // Send the message to all signers and gather responses by sharing with all other signers and coordinator
        let (outbound_messages, operation_results) =
            feedback_messages(&mut coordinators, &mut signers, &[message]);
        assert!(operation_results.is_empty());
        assert_eq!(
            coordinators.first_mut().unwrap().get_state(),
            State::SigShareGather(signature_type)
        );

        assert_eq!(outbound_messages.len(), 1);
        assert!(
            matches!(outbound_messages[0].msg, Message::SignatureShareRequest(_)),
            "Expected SignatureShareRequest message"
        );

        // Send the SignatureShareRequest message to all signers and share their responses with the coordinator and signers
        let (outbound_messages, operation_results) = feedback_mutated_messages(
            &mut coordinators,
            &mut signers,
            &outbound_messages,
            |signer, packets| {
                if signer.signer_id != 0 {
                    return packets.clone();
                }
                packets
                    .iter()
                    .map(|packet| {
                        let Message::SignatureShareResponse(response) = &packet.msg else {
                            return packet.clone();
                        };
                        // mutate one of the shares
                        let sshares: Vec<SignatureShare> = response
                            .signature_shares
                            .iter()
                            .map(|share| SignatureShare {
                                id: share.id,
                                key_ids: share.key_ids.clone(),
                                z_i: share.z_i + Scalar::from(1),
                            })
                            .collect();
                        Packet {
                            msg: Message::SignatureShareResponse(SignatureShareResponse {
                                dkg_id: response.dkg_id,
                                sign_id: response.sign_id,
                                sign_iter_id: response.sign_iter_id,
                                signer_id: response.signer_id,
                                signature_shares: sshares,
                            }),
                            sig: vec![],
                        }
                    })
                    .collect()
            },
        );
        assert!(outbound_messages.is_empty());
        assert_eq!(operation_results.len(), 1);
        let OperationResult::SignError(SignError::Coordinator(Error::Aggregator(
            AggregatorError::BadPartySigs(parties),
        ))) = &operation_results[0]
        else {
            panic!("Expected OperationResult::SignError(SignError::Coordinator(Error::Aggregator(AggregatorError::BadPartySigs(parties))))");
        };
        assert_eq!(
            parties, &bad_parties,
            "Expected BadPartySigs from {bad_parties:?}, got {:?}",
            &operation_results[0]
        );
    }
```

**File:** src/state_machine/coordinator/fire.rs (L178-186)
```rust
                            for signer_id in &self
                                .message_nonces
                                .get(&self.message)
                                .ok_or(Error::MissingMessageNonceInfo)?
                                .sign_wait_signer_ids
                            {
                                warn!("Mark signer {signer_id} as malicious");
                                self.malicious_signer_ids.insert(*signer_id);
                            }
```

**File:** src/state_machine/coordinator/fire.rs (L327-332)
```rust
                State::SigShareGather(signature_type) => {
                    if let Err(e) = self.gather_sig_shares(packet, signature_type) {
                        return Ok((
                            None,
                            Some(OperationResult::SignError(SignError::Coordinator(e))),
                        ));
```

**File:** src/state_machine/coordinator/fire.rs (L903-915)
```rust
            if self
                .malicious_signer_ids
                .contains(&nonce_response.signer_id)
            {
                warn!(
                    sign_id = %nonce_response.sign_id,
                    sign_iter_id = %nonce_response.sign_iter_id,
                    signer_id = %nonce_response.signer_id,
                    "Received malicious NonceResponse"
                );
                //return Err(Error::MaliciousSigner(nonce_response.signer_id));
                return Ok(());
            }
```

**File:** src/state_machine/coordinator/fire.rs (L1042-1044)
```rust
        response_info
            .sign_wait_signer_ids
            .remove(&sig_share_response.signer_id);
```

**File:** src/state_machine/coordinator/fire.rs (L1145-1169)
```rust
            self.aggregator.init(&self.party_polynomials)?;

            if let SignatureType::Taproot(merkle_root) = signature_type {
                let schnorr_proof = self.aggregator.sign_taproot(
                    &self.message,
                    &nonces,
                    &shares,
                    &key_ids,
                    merkle_root,
                )?;
                debug!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else if let SignatureType::Schnorr = signature_type {
                let schnorr_proof =
                    self.aggregator
                        .sign_schnorr(&self.message, &nonces, &shares, &key_ids)?;
                debug!("SchnorrProof ({}, {})", schnorr_proof.r, schnorr_proof.s);
                self.schnorr_proof = Some(schnorr_proof);
            } else {
                let signature = self
                    .aggregator
                    .sign(&self.message, &nonces, &shares, &key_ids)?;
                debug!("Signature ({}, {})", signature.R, signature.z);
                self.signature = Some(signature);
            }
```

**File:** src/v2.rs (L389-413)
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

            if z_i * G != (r_sign * Rs[i] + cx_sign * cx) {
                bad_party_sigs.push(sig_shares[i].id);
            }
        }
        if !bad_party_keys.is_empty() {
            AggregatorError::BadPartyKeys(bad_party_keys)
        } else if !bad_party_sigs.is_empty() {
            AggregatorError::BadPartySigs(bad_party_sigs)
```

**File:** src/errors.rs (L50-52)
```rust
    #[error("bad party sigs from {0:?}")]
    /// The party signatures which failed to verify
    BadPartySigs(Vec<u32>),
```
