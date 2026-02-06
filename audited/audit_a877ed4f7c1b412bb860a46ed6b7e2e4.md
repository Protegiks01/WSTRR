### Title
Incomplete Malicious Signer Ban Allows Repeated DKG Disruption

### Summary
Signers marked as malicious during DKG rounds are added to `malicious_dkg_signer_ids` but this set is not checked when gathering public or private shares in subsequent DKG rounds. This allows previously-identified malicious signers to repeatedly participate in and disrupt DKG, preventing the establishment of an aggregate public key required for signing operations and thus blocking transaction confirmation indefinitely.

### Finding Description

The FIRE coordinator implementation tracks malicious signers in two separate sets: `malicious_signer_ids` for signing-round malicious behavior and `malicious_dkg_signer_ids` for DKG-round malicious behavior. [1](#0-0) 

When malicious behavior is detected during DKG (e.g., bad public shares or bad private shares), the offending signers are correctly added to `malicious_dkg_signer_ids`: [2](#0-1) 

However, the `gather_public_shares` function does not check if incoming shares are from signers in `malicious_dkg_signer_ids`. It only verifies the signer exists in the config and handles duplicates: [3](#0-2) 

Similarly, `gather_private_shares` also fails to check `malicious_dkg_signer_ids`: [4](#0-3) 

In contrast, the signing flow correctly implements the ban. The `gather_nonces` function explicitly checks `malicious_signer_ids` and rejects nonces from banned signers: [5](#0-4) 

The malicious signer sets are intentionally persistent across rounds (not cleared in `reset()`): [6](#0-5) 

This asymmetry creates a critical vulnerability: malicious signers are permanently banned from signing rounds but can indefinitely participate in DKG rounds.

### Impact Explanation

**Direct Impact**: A malicious signer can repeatedly disrupt DKG rounds by participating and sending invalid shares, causing DKG failures. Without successful DKG completion, no aggregate public key is established, blocking all signing operations.

**Concrete Scenario**: 
- Network has 10 signers, threshold requires 7 keys
- Signer A is identified as malicious in DKG round 1 (sends bad shares)
- Coordinator marks A in `malicious_dkg_signer_ids`
- DKG round 2 begins: Signer A participates again (not blocked)
- A sends bad shares again, causing another DKG failure
- This repeats indefinitely

**Chain-Level Impact**: Without a valid aggregate public key from DKG, the threshold signature system cannot sign any transactions. In a blockchain context (e.g., Stacks), this prevents block confirmation and transaction processing, matching the Critical severity definition: "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks."

**Quantified Impact**: A single persistent malicious signer can block DKG indefinitely, preventing transaction confirmation for an unbounded number of blocks until manual intervention removes the signer from the network entirely.

### Likelihood Explanation

**Attacker Prerequisites**:
- Must be an authorized signer in the threshold system (has valid signer_id and keys)
- No additional privileges required beyond normal signer participation
- No cryptographic breaks needed

**Attack Complexity**: Low
1. Participate in initial DKG round
2. Send intentionally malformed shares (bad public/private shares)
3. Get detected and added to `malicious_dkg_signer_ids`
4. Continue participating in subsequent DKG rounds (bypass due to missing check)
5. Repeat step 2 to cause persistent DKG failures

**Detection Risk**: High detection but low consequence. The attacker's malicious behavior is detected and logged each time, but the ban mechanism fails to prevent future participation, making detection ineffective.

**Economic Feasibility**: Trivial. Attack requires only standard signer participation, no special resources.

**Success Probability**: 100% deterministic. The missing check guarantees malicious signers can participate in future DKG rounds.

### Recommendation

**Primary Fix**: Add malicious signer checks to DKG share gathering functions:

In `gather_public_shares` (after line 491):
```rust
if self.malicious_dkg_signer_ids.contains(&dkg_public_shares.signer_id) {
    warn!(signer_id = %dkg_public_shares.signer_id, "Rejected DkgPublicShares from malicious signer");
    return Ok(());
}
```

In `gather_private_shares` (after line 539):
```rust
if self.malicious_dkg_signer_ids.contains(&dkg_private_shares.signer_id) {
    warn!(signer_id = %dkg_private_shares.signer_id, "Rejected DkgPrivateShares from malicious signer");
    return Ok(());
}
```

Optionally, consider returning an error (`Err(Error::MaliciousSigner(signer_id))`) instead of silently ignoring, to make the ban more explicit.

**Testing Recommendations**:
1. Add test case that runs DKG with malicious signer, detects them, then runs second DKG round and verifies they cannot participate
2. Verify malicious signing round signers are properly blocked (already working)
3. Test that malicious DKG signers are blocked from both public and private share phases

**Deployment Considerations**: This is a critical security fix that should be deployed urgently. Existing deployments may have accumulated malicious signers in `malicious_dkg_signer_ids` that are currently still participating. After deploying the fix, consider clearing the DKG state and restarting DKG with the proper bans in effect.

### Proof of Concept

**Exploitation Algorithm**:

1. **Setup**: Network with N signers, threshold T, signer_id = M is the attacker
2. **DKG Round 1**:
   - Coordinator calls `start_dkg_round()`
   - All signers send `DkgPublicShares`
   - Attacker M sends valid `DkgPublicShares` 
   - All signers send `DkgPrivateShares`
   - Attacker M sends malformed `DkgPrivateShares` (corrupt encrypted shares)
   - Other signers detect bad shares, report in `DkgEnd`
   - Coordinator adds M to `malicious_dkg_signer_ids` (line 776)
   - DKG fails with `DkgEndFailure`

3. **DKG Round 2**:
   - Coordinator calls `start_dkg_round()` again
   - All signers send `DkgPublicShares`
   - Attacker M sends `DkgPublicShares` again (**not rejected due to missing check**)
   - `gather_public_shares` accepts M's shares (lines 477-518)
   - All signers send `DkgPrivateShares`
   - Attacker M sends malformed `DkgPrivateShares` again (**not rejected**)
   - `gather_private_shares` accepts M's shares (lines 525-565)
   - Other signers report M as malicious again
   - DKG fails again

4. **Result**: Steps 3 repeats indefinitely. DKG never completes, no aggregate key established, no signatures possible.

**Expected Behavior**: After DKG Round 1, attacker M should be permanently excluded from DKG Round 2 and all subsequent rounds.

**Actual Behavior**: Attacker M can participate in all future DKG rounds, causing repeated failures.

**Reproduction**: Run the existing test `bad_private_shares_dkg` but add a second DKG round attempt after the failure. The malicious signer will be allowed to participate again.

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

**File:** src/state_machine/coordinator/fire.rs (L1478-1490)
```rust
    // Reset internal state
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
