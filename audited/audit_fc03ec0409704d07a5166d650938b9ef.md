### Title
Malicious DKG Signers Can Participate in Subsequent Rounds Due to Separate Tracking Sets

### Summary
The FIRE coordinator tracks malicious signers in two separate sets (`malicious_dkg_signer_ids` and `malicious_signer_ids`) but only checks `malicious_signer_ids` during signing rounds and checks neither set during DKG rounds. This allows signers detected as malicious during DKG to participate in subsequent DKG and signing rounds, enabling them to repeatedly disrupt the protocol and cause transient consensus failures.

### Finding Description

The FIRE coordinator maintains two separate HashSet fields for tracking malicious signers:
- `malicious_dkg_signer_ids` (line 65): for signers malicious during DKG
- `malicious_signer_ids` (line 64): for signers malicious during signing [1](#0-0) 

When a signer is detected as malicious during DKG (by sending bad public shares or bad private shares), they are added to `malicious_dkg_signer_ids`: [2](#0-1) 

However, the `gather_public_shares` function, which processes DKG public shares, does not check either malicious signer set: [3](#0-2) 

Similarly, `gather_private_shares` also lacks any check of malicious signer sets: [4](#0-3) 

During signing, `gather_nonces` only checks `malicious_signer_ids`, not `malicious_dkg_signer_ids`: [5](#0-4) 

The `reset()` function clears DKG state but deliberately preserves both malicious signer sets (they are not cleared): [6](#0-5) 

**Root Cause**: The separate tracking was likely intended to distinguish between DKG-phase and signing-phase misbehavior, but the implementation fails to enforce exclusion of malicious signers across both phases. The coordinator assumes external systems will handle signer exclusion after receiving `DkgError::DkgEndFailure`, but provides no enforcement mechanism.

### Impact Explanation

**Specific Harm**:
1. **Repeated DKG Disruption**: A malicious signer detected in DKG round N can participate in DKG round N+1 and beyond, repeatedly sending bad shares and causing DKG failures. This prevents the system from establishing an aggregate public key needed for signing.

2. **Signing Round Disruption**: If DKG eventually succeeds (e.g., the malicious signer behaves correctly in a retry or threshold is barely met), the malicious signer can still participate in signing rounds. During signing timeout (line 185), they can cause delays forcing retry iterations. [7](#0-6) 

**Quantified Impact**:
- With N total signers and M malicious: if `num_keys - M*keys_per_signer < threshold`, the system cannot complete signing
- Each timeout adds `sign_timeout` duration (configurable) to completion time
- Multiple retry iterations compound delays geometrically

**Who is Affected**: All participants in the threshold signature protocol who depend on timely DKG completion and signing operations.

**Severity Justification**: This maps to **Medium severity** under the protocol scope as "Any transient consensus failures." While the system can eventually recover after timeouts expire or external intervention excludes malicious signers, the repeated disruption constitutes a transient consensus failure.

### Likelihood Explanation

**Required Attacker Capabilities**:
- Control of at least one signer node in the protocol
- Ability to send malformed DKG shares (bad public commitments or invalid private shares)
- Persistence across multiple protocol rounds

**Attack Complexity**: Low
1. Attacker participates in DKG round 1, sends bad shares
2. Coordinator detects misbehavior, adds attacker to `malicious_dkg_signer_ids`
3. DKG round 1 fails with `DkgError::DkgEndFailure`
4. External system retries by calling `start_dkg_round()` without modifying signer set
5. Attacker participates again in DKG round 2 (no check of `malicious_dkg_signer_ids`)
6. Repeat steps 1-5 indefinitely, or proceed to step 7
7. If DKG eventually succeeds, attacker participates in signing rounds (only `malicious_signer_ids` checked)
8. Attacker refuses to send signature shares, causing timeouts

**Economic Feasibility**: High - requires only running a signer node, no special hardware or cryptographic breaks needed.

**Detection Risk**: High - misbehavior is detected and logged, but coordinator doesn't enforce exclusion.

**Estimated Probability of Success**: 95%+ - this is a deterministic design flaw with no cryptographic or timing assumptions required.

### Recommendation

**Primary Fix**: Merge the two malicious signer sets or check both sets consistently:

**Option 1 - Union Check**: During `gather_public_shares`, `gather_private_shares`, and `gather_nonces`, check if signer is in either malicious set:

```rust
if self.malicious_dkg_signer_ids.contains(&signer_id) 
   || self.malicious_signer_ids.contains(&signer_id) {
    warn!(signer_id = %signer_id, "Rejecting message from known malicious signer");
    return Ok(());
}
```

**Option 2 - Single Set**: Merge `malicious_dkg_signer_ids` into `malicious_signer_ids` when detected:

```rust
// In gather_dkg_end, line 776:
self.malicious_signer_ids.insert(*id);  // Instead of malicious_dkg_signer_ids
```

**Option 3 - API Enhancement**: Add a method to explicitly exclude signers from future rounds:

```rust
pub fn exclude_signers(&mut self, signer_ids: &HashSet<u32>) {
    for id in signer_ids {
        self.malicious_signer_ids.insert(*id);
        self.malicious_dkg_signer_ids.insert(*id);
    }
}
```

**Testing Recommendations**:
1. Add test case where signer is malicious in DKG round 1, verify they cannot participate in DKG round 2
2. Add test case where signer is malicious in DKG, verify they cannot participate in subsequent signing
3. Add test for `reset()` preserving malicious signer sets across rounds

**Deployment Considerations**: This is a breaking change to coordinator behavior. Existing deployments relying on external exclusion mechanisms may need updates to their orchestration logic.

### Proof of Concept

**Exploitation Algorithm**:

```
Setup:
- 5 signers (IDs 0-4), 10 total keys, threshold = 7
- Attacker controls signer 0 with 2 keys

Step 1 - DKG Round 1 (Malicious Behavior):
  1.1. Coordinator sends DkgBegin(dkg_id=1)
  1.2. Attacker (signer 0) sends DkgPublicShares with invalid polynomial commitments
  1.3. Honest signers send valid DkgPublicShares
  1.4. Coordinator sends DkgPrivateBegin
  1.5. All signers send DkgPrivateShares
  1.6. Coordinator sends DkgEndBegin
  1.7. Honest signers detect bad shares from signer 0, send DkgEnd(status=Failure)
  1.8. Coordinator validates, confirms signer 0 is malicious
  1.9. Signer 0 added to malicious_dkg_signer_ids
  1.10. Coordinator returns DkgError::DkgEndFailure

Step 2 - DKG Round 2 (Repeated Participation):
  2.1. External system calls coordinator.start_dkg_round(dkg_id=2)
  2.2. Coordinator sends DkgBegin(dkg_id=2)
  2.3. Attacker (signer 0) sends DkgPublicShares again
  2.4. gather_public_shares() processes it (no check of malicious_dkg_signer_ids!)
  2.5. Attacker can repeat malicious behavior or behave correctly
  2.6. If behaves correctly: DKG succeeds with attacker's shares included
  2.7. If malicious again: DKG fails, but attacker can retry in round 3

Step 3 - Signing Round (If DKG Succeeded):
  3.1. Coordinator calls start_signing_round(message, sign_id=1)
  3.2. Coordinator sends NonceRequest
  3.3. Attacker (signer 0) can participate (only malicious_signer_ids checked)
  3.4. Attacker refuses to send NonceResponse or signature shares
  3.5. Signing timeout occurs after sign_timeout duration
  3.6. Coordinator adds signer 0 to malicious_signer_ids
  3.7. Coordinator retries with sign_iter_id=2
  3.8. Now signer 0 excluded from signing, but already caused delay

Expected Behavior: Signer 0 should be rejected in steps 2.4 and 3.3
Actual Behavior: Signer 0 can participate, causing repeated disruptions
```

**Verification**: Check coordinator logs during step 2.4 - no warning about malicious signer appears. The `gather_public_shares` function at line 477 processes the packet without checking `malicious_dkg_signer_ids`.

### Notes

This vulnerability is specific to the FIRE coordinator implementation, which includes timeout handling and malicious signer tracking. The FROST coordinator also defines both malicious signer sets in `SavedState` but doesn't actively use them for filtering: [8](#0-7) 

The separate tracking appears to be a design decision to distinguish between DKG-phase and signing-phase misbehavior, potentially for forensics or accountability. However, the lack of cross-phase enforcement creates a security gap that enables the repeated participation attack described above.

### Citations

**File:** src/state_machine/coordinator/fire.rs (L64-65)
```rust
    malicious_signer_ids: HashSet<u32>,
    malicious_dkg_signer_ids: HashSet<u32>,
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

**File:** src/state_machine/coordinator/fire.rs (L775-776)
```rust
            for id in &malicious_signers {
                self.malicious_dkg_signer_ids.insert(*id);
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

**File:** src/state_machine/coordinator/frost.rs (L882-883)
```rust
            malicious_signer_ids: Default::default(),
            malicious_dkg_signer_ids: Default::default(),
```
