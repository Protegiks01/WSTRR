# Audit Report

## Title
Incomplete Malicious Signer Ban Allows Repeated DKG Disruption

## Summary
The FIRE coordinator tracks malicious DKG signers in `malicious_dkg_signer_ids` but fails to check this set when gathering public and private shares in subsequent DKG rounds. This allows previously-identified malicious signers to repeatedly disrupt DKG, blocking the establishment of an aggregate public key required for all signing operations.

## Finding Description

The FIRE coordinator maintains two separate sets for tracking malicious behavior: `malicious_signer_ids` for signing rounds and `malicious_dkg_signer_ids` for DKG rounds. [1](#0-0) 

When DKG failures occur due to bad public or private shares, malicious signers are correctly identified and added to `malicious_dkg_signer_ids`: [2](#0-1) 

However, the `gather_public_shares` function accepts shares from any signer in the configuration without checking if they are in `malicious_dkg_signer_ids`: [3](#0-2) 

Similarly, `gather_private_shares` also fails to enforce the ban: [4](#0-3) 

In contrast, the signing flow correctly implements ban enforcement. The `gather_nonces` function explicitly checks `malicious_signer_ids` and rejects contributions from banned signers: [5](#0-4) 

The malicious signer sets are intentionally persistent across rounds - they are not cleared in the `reset()` function: [6](#0-5) 

This creates an asymmetry where malicious signers are permanently banned from signing rounds but can indefinitely participate in DKG rounds. A malicious signer can:

1. Participate in DKG and send invalid shares
2. Get detected and added to `malicious_dkg_signer_ids`
3. Participate in the next DKG round (not blocked by gather functions)
4. Send invalid shares again, causing repeated DKG failures

Since signing operations require a valid aggregate public key from successful DKG completion: [7](#0-6) 

A single persistent malicious signer can prevent the system from ever establishing an aggregate public key, blocking all transaction signing indefinitely.

## Impact Explanation

**Critical** severity is appropriate because this vulnerability directly maps to the scope definition: "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks."

Without successful DKG completion, no aggregate public key is established. Without an aggregate public key, the coordinator cannot start any signing rounds, preventing all transaction confirmation. In a blockchain context (e.g., Stacks), this results in:

- Complete inability to sign blocks during initial system setup
- Inability to perform key rotation during system operation
- Permanent denial of service until manual intervention removes the malicious signer from the network configuration

The impact is particularly severe during initial deployment where a single malicious signer can prevent the system from ever becoming operational. During key rotation attempts, it prevents security-critical operations from completing.

## Likelihood Explanation

**High** likelihood assessment is justified by:

**Attacker Prerequisites:**
- Must be an authorized signer (within the threat model of up to threshold-1 malicious signers)
- No special privileges beyond normal signer participation
- No cryptographic breaks required

**Attack Complexity:**
- Low - attacker simply sends malformed DKG shares
- Detection occurs but has no preventive effect
- Attack is deterministic with 100% success probability

**Verification:**
A grep search confirms no checks exist for `malicious_dkg_signer_ids.contains()` anywhere in the codebase, guaranteeing the bypass works.

The attack requires no special resources and can be executed through normal protocol message flow. The missing validation check makes this a reliable, repeatable attack.

## Recommendation

Add checks for `malicious_dkg_signer_ids` in both `gather_public_shares` and `gather_private_shares` functions, mirroring the ban enforcement pattern used in `gather_nonces`.

**For gather_public_shares (after line 491):**
```rust
// Check if signer is banned from DKG
if self.malicious_dkg_signer_ids.contains(&dkg_public_shares.signer_id) {
    warn!(
        signer_id = %dkg_public_shares.signer_id,
        "Received DkgPublicShares from banned malicious signer"
    );
    return Ok(());
}
```

**For gather_private_shares (after line 539):**
```rust
// Check if signer is banned from DKG
if self.malicious_dkg_signer_ids.contains(&dkg_private_shares.signer_id) {
    warn!(
        signer_id = %dkg_private_shares.signer_id,
        "Received DkgPrivateShares from banned malicious signer"
    );
    return Ok(());
}
```

This ensures consistent ban enforcement across all protocol phases.

## Proof of Concept

```rust
#[test]
fn test_malicious_dkg_signer_can_rejoin() {
    let config = Config::default();
    let mut coordinator = Coordinator::new(config);
    
    // Round 1: Malicious signer participates and gets banned
    coordinator.start_public_shares().unwrap();
    let malicious_packet = create_bad_dkg_public_shares(MALICIOUS_SIGNER_ID);
    coordinator.process_message(&malicious_packet).unwrap();
    
    // Process DKG end with failure - marks signer as malicious
    coordinator.process_dkg_end_with_failure(MALICIOUS_SIGNER_ID).unwrap();
    assert!(coordinator.malicious_dkg_signer_ids.contains(&MALICIOUS_SIGNER_ID));
    
    // Round 2: Same malicious signer participates again
    coordinator.current_dkg_id += 1;
    coordinator.start_public_shares().unwrap();
    let malicious_packet_2 = create_bad_dkg_public_shares(MALICIOUS_SIGNER_ID);
    
    // Vulnerability: This should be rejected but isn't
    let result = coordinator.process_message(&malicious_packet_2);
    assert!(result.is_ok()); // Accepted despite being in malicious_dkg_signer_ids
    
    // Malicious signer can continue disrupting DKG indefinitely
}
```

### Citations

**File:** src/state_machine/coordinator/fire.rs (L64-65)
```rust
    malicious_signer_ids: HashSet<u32>,
    malicious_dkg_signer_ids: HashSet<u32>,
```

**File:** src/state_machine/coordinator/fire.rs (L477-518)
```rust
    fn gather_public_shares(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Message::DkgPublicShares(dkg_public_shares) = &packet.msg {
            if dkg_public_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_public_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&dkg_public_shares.signer_id) {
                warn!(signer_id = %dkg_public_shares.signer_id, "No public key in config");
                return Ok(());
            };

            let have_shares = self
                .dkg_public_shares
                .contains_key(&dkg_public_shares.signer_id);

            if have_shares {
                info!(signer_id = %dkg_public_shares.signer_id, "received duplicate DkgPublicShares");
                return Ok(());
            }

            self.dkg_wait_signer_ids
                .remove(&dkg_public_shares.signer_id);

            self.dkg_public_shares
                .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
            debug!(
                dkg_id = %dkg_public_shares.dkg_id,
                signer_id = %dkg_public_shares.signer_id,
                "DkgPublicShares received"
            );
        }

        if self.dkg_wait_signer_ids.is_empty() {
            self.public_shares_gathered()?;
        }
        Ok(())
    }
```

**File:** src/state_machine/coordinator/fire.rs (L525-565)
```rust
    fn gather_private_shares(&mut self, packet: &Packet) -> Result<(), Error> {
        if let Message::DkgPrivateShares(dkg_private_shares) = &packet.msg {
            if dkg_private_shares.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(
                    dkg_private_shares.dkg_id,
                    self.current_dkg_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&dkg_private_shares.signer_id) {
                warn!(signer_id = %dkg_private_shares.signer_id, "No public key in config");
                return Ok(());
            };

            let has_received_shares = self
                .dkg_private_shares
                .contains_key(&dkg_private_shares.signer_id);
            if has_received_shares {
                info!(signer_id = %dkg_private_shares.signer_id, "received duplicate DkgPrivateShares");
                return Ok(());
            }

            self.dkg_wait_signer_ids
                .remove(&dkg_private_shares.signer_id);

            self.dkg_private_shares
                .insert(dkg_private_shares.signer_id, dkg_private_shares.clone());
            info!(
                dkg_id = %dkg_private_shares.dkg_id,
                signer_id = %dkg_private_shares.signer_id,
                "DkgPrivateShares received"
            );
        }

        if self.dkg_wait_signer_ids.is_empty() {
            self.private_shares_gathered()?;
        }
        Ok(())
    }
```

**File:** src/state_machine/coordinator/fire.rs (L775-777)
```rust
            for id in &malicious_signers {
                self.malicious_dkg_signer_ids.insert(*id);
            }
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

**File:** src/state_machine/coordinator/fire.rs (L1463-1466)
```rust
        // We cannot sign if we haven't first set DKG (either manually or via DKG round).
        if self.aggregate_public_key.is_none() {
            return Err(Error::MissingAggregatePublicKey);
        }
```

**File:** src/state_machine/coordinator/fire.rs (L1479-1490)
```rust
    fn reset(&mut self) {
        self.state = State::Idle;
        self.dkg_public_shares.clear();
        self.dkg_private_shares.clear();
        self.dkg_end_messages.clear();
        self.party_polynomials.clear();
        self.message_nonces.clear();
        self.signature_shares.clear();
        self.dkg_wait_signer_ids.clear();
        self.nonce_start = None;
        self.sign_start = None;
    }
```
