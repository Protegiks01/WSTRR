### Title
DKG Polynomial Mismatch via State Machine Race Condition Enables Denial of Service

### Summary
A malicious coordinator can cause honest signers to send private shares that don't match their previously broadcast polynomial commitments by injecting a second `DkgBegin` message after public shares are distributed. This triggers polynomial regeneration in targeted signers while other signers retain the original commitments, causing DKG validation failures and enabling repeated denial of service attacks on the threshold signature system.

### Finding Description

**Location:** `src/state_machine/signer/mod.rs`, function `dkg_private_begin()` at line 926

**Root Cause:**
The vulnerability stems from multiple interacting design flaws:

1. **Permissive State Transition:** The state machine allows transitioning from `DkgPublicGather` back to `DkgPublicDistribute`, enabling polynomial regeneration mid-protocol. [1](#0-0) 

2. **Missing DKG ID Validation:** The `dkg_private_begin()`, `dkg_public_share()`, and `dkg_private_shares()` functions do not validate that incoming message `dkg_id` fields match the signer's current `self.dkg_id`. [2](#0-1) [3](#0-2) 

3. **Polynomial Regeneration:** When `dkg_begin()` is called, it invokes `reset()` which regenerates all polynomials via `reset_polys()`. [4](#0-3) [5](#0-4) 

4. **Duplicate Message Rejection:** The duplicate check in `dkg_public_share()` prevents updating cached commitments, ensuring the mismatch persists. [6](#0-5) 

**Why Existing Mitigations Fail:**
- Packet signature verification protects against unauthorized attackers but assumes coordinator honesty
- Duplicate message rejection intended as protection actually enables the attack by preventing commitment updates
- No validation exists to ensure polynomials remain unchanged between `get_poly_commitments()` and `get_shares()` calls

### Impact Explanation

**Specific Harm:**
When the attack succeeds, honest signers detect invalid private shares during validation, causing DKG to fail with `DkgStatus::Failure(DkgFailure::BadPrivateShares)`. The validation check in `compute_secret()` compares received shares against cached commitments and fails: [7](#0-6) 

**Quantified Impact:**
- Each attack forces a complete DKG restart
- Attack is repeatable indefinitely by malicious coordinator
- Honest signer is incorrectly blamed for sending bad shares
- If DKG is required for critical signing operations (e.g., Bitcoin peg transactions in Stacks), sustained attacks prevent transaction confirmations

**Affected Parties:**
All signers participating in DKG are affected as the protocol fails to establish keys

**Severity Justification:**
This vulnerability maps to **Low** severity per the audit scope: "Any remotely-exploitable denial of service in a node" or "Any network denial of service impacting more than 10 percent of miners that does not shut down the network." The attack causes repeated DKG failures, creating a denial of service condition, but does not directly cause fund loss, invalid signatures being accepted, or chain-level consensus failures.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control of coordinator OR compromise of coordinator's message signing key
- Ability to send authenticated `DkgBegin` messages (verified via packet signatures) [8](#0-7) 

**Attack Complexity:**
Low - attack requires only sending a second `DkgBegin` message with different `dkg_id` at the right time (after `DkgPublicShares` are distributed but before `DkgPrivateBegin`)

**Economic Feasibility:**
High - no computational cost beyond normal coordinator operations

**Detection Risk:**
Medium - repeated DKG failures would be observable, but the blamed signer appears at fault in logs

**Probability of Success:**
High if coordinator is compromised; the state machine reliably accepts the malicious message sequence

### Recommendation

**Primary Fix - Add DKG ID Validation:**
1. Validate `dkg_id` matches `self.dkg_id` in `dkg_public_share()`, `dkg_private_begin()`, and `dkg_private_shares()`
2. Reject messages with mismatched `dkg_id` to prevent state desynchronization

**Secondary Fix - Restrict State Transitions:**
Remove the `DkgPublicGather → DkgPublicDistribute` transition from allowed state changes, preventing polynomial regeneration after public shares are distributed: [1](#0-0) 

**Alternative Mitigation:**
Add a flag to track whether polynomial commitments have been sent. Prevent `reset()` or `reset_polys()` from being called once commitments are broadcast until DKG completes or explicitly aborted.

**Testing Recommendations:**
- Add integration test simulating coordinator sending duplicate `DkgBegin` messages
- Verify DKG fails gracefully with appropriate error rather than blaming honest signers
- Test that `dkg_id` validation correctly rejects out-of-order messages

**Deployment Considerations:**
- Changes affect state machine invariants and message handling
- Requires coordinated upgrade of all signers
- Consider compatibility with existing DKG sessions in progress

### Proof of Concept

**Attack Steps:**

1. **Initial DKG:** Coordinator sends `DkgBegin(dkg_id=1)` to all signers
   - Signer A generates polynomial P_A1, sends `DkgPublicShares(dkg_id=1, commitments=C_A1)`
   - Signer B generates polynomial P_B1, sends `DkgPublicShares(dkg_id=1, commitments=C_B1)`
   - Both signers transition to `DkgPublicGather` state

2. **Signers Cache Commitments:** 
   - Signer A receives and caches C_B1
   - Signer B receives and caches C_A1

3. **Attack Trigger:** Coordinator sends `DkgBegin(dkg_id=2)` to Signer A only
   - Signer A in state `DkgPublicGather` (transition to `DkgPublicDistribute` allowed per line 1163)
   - Signer A calls `reset(2)`, clearing cached shares and regenerating polynomial to P_A2
   - Signer A sends `DkgPublicShares(dkg_id=2, commitments=C_A2)` 
   - Signer A transitions to `DkgPublicGather`

4. **Duplicate Rejection:** Signer B receives second `DkgPublicShares` from Signer A
   - Duplicate check at line 1008 detects existing entry for `signer_id=A`
   - Second message rejected, Signer B retains C_A1 (commitments for P_A1)

5. **Private Share Distribution:** Coordinator sends `DkgPrivateBegin(dkg_id=2)`
   - No `dkg_id` validation occurs at line 892
   - Signer A (with polynomial P_A2) calls `get_shares()` at line 926
   - Returns shares evaluated from P_A2
   - Signer B calls `get_shares()`, returns shares from P_B1

6. **Validation Failure:** Signer B receives Signer A's private shares
   - Signer B has commitments C_A1 cached
   - Signer B received shares for polynomial P_A2
   - Validation at line 193 of `v1.rs` fails: `s * G != compute::poly(id, C_A1.poly)`
   - DKG fails with `DkgFailure::BadPrivateShares`, blaming Signer A

**Expected vs Actual Behavior:**
- **Expected:** Shares from `get_shares()` should match commitments from `get_poly_commitments()` for same polynomial
- **Actual:** After coordinator triggers polynomial regeneration, `get_shares()` returns shares for P_A2 while other signers have commitments C_A1, causing validation failure

**Reproduction:**
Setup 2+ signers with malicious coordinator, execute above sequence with proper timing of second `DkgBegin` message between public and private share phases.

## Notes

This vulnerability violates the stated DKG invariant: "All expected private shares must be present and verify against commitments." The state machine design allows polynomial regeneration mid-protocol without proper synchronization, and the lack of `dkg_id` validation permits message processing from different DKG rounds simultaneously. While the attack requires coordinator compromise, the severity is appropriate for the scope as it enables repeatable denial of service against the threshold signature system.

### Citations

**File:** src/state_machine/signer/mod.rs (L417-424)
```rust
    pub fn reset<T: RngCore + CryptoRng>(&mut self, dkg_id: u64, rng: &mut T) {
        self.dkg_id = dkg_id;
        self.commitments.clear();
        self.decrypted_shares.clear();
        self.decryption_keys.clear();
        self.invalid_private_shares.clear();
        self.public_nonces.clear();
        self.signer.reset_polys(rng);
```

**File:** src/state_machine/signer/mod.rs (L463-470)
```rust
        if self.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
        }
```

**File:** src/state_machine/signer/mod.rs (L844-850)
```rust
    fn dkg_begin<R: RngCore + CryptoRng>(
        &mut self,
        dkg_begin: &DkgBegin,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        self.reset(dkg_begin.dkg_id, rng);
        self.move_to(State::DkgPublicDistribute)?;
```

**File:** src/state_machine/signer/mod.rs (L892-896)
```rust
    fn dkg_private_begin<R: RngCore + CryptoRng>(
        &mut self,
        dkg_private_begin: &DkgPrivateBegin,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
```

**File:** src/state_machine/signer/mod.rs (L974-977)
```rust
    pub fn dkg_public_share(
        &mut self,
        dkg_public_shares: &DkgPublicShares,
    ) -> Result<Vec<Message>, Error> {
```

**File:** src/state_machine/signer/mod.rs (L1004-1010)
```rust
        let have_shares = self
            .dkg_public_shares
            .contains_key(&dkg_public_shares.signer_id);

        if have_shares {
            info!(signer_id = %dkg_public_shares.signer_id, "received duplicate DkgPublicShares");
            return Ok(vec![]);
```

**File:** src/state_machine/signer/mod.rs (L1161-1165)
```rust
            State::DkgPublicDistribute => {
                prev_state == &State::Idle
                    || prev_state == &State::DkgPublicGather
                    || prev_state == &State::DkgPrivateDistribute
            }
```

**File:** src/v1.rs (L191-203)
```rust
        for (i, s) in private_shares.iter() {
            if let Some(comm) = public_shares.get(i) {
                if s * G != compute::poly(&self.id(), &comm.poly)? {
                    bad_shares.push(*i);
                }
            } else {
                warn!("unable to check private share from {}: no corresponding public share, even though we checked for it above", i);
            }
        }

        if !bad_shares.is_empty() {
            return Err(DkgError::BadPrivateShares(bad_shares));
        }
```
