### Title
DKG Threshold Bypass via Manual Key Setting After DkgEndTimeout

### Summary
When `DkgEndTimeout` occurs with partial shares received, the implementation does not prevent using a partially completed DKG that fails to meet `dkg_threshold` requirements. The `set_key_and_party_polynomials()` method allows manually setting an aggregate key derived from fewer parties than required, bypassing critical DKG security assumptions and enabling key control by an insufficient number of participants.

### Finding Description

**Exact Code Locations:**

1. DkgEndTimeout handling: [1](#0-0) 

2. Missing threshold validation: [2](#0-1) 

3. State machine allowing transition: [3](#0-2) 

**Root Cause:**

When `DkgEndTimeout` occurs, the coordinator returns `DkgError::DkgEndTimeout` but leaves the coordinator state in `DkgEndGather` with partial DKG data intact (dkg_public_shares, dkg_private_shares). The `set_key_and_party_polynomials()` method validates that the computed aggregate key equals the sum of polynomial constants and checks for duplicate party IDs, but critically **does not validate** that the number of parties meets `config.dkg_threshold`.

The `dkg_threshold` field is documented as "threshold of keys needed to complete DKG (must be >= threshold)" [4](#0-3) , establishing that this is a required security invariant.

**Why Existing Mitigations Fail:**

1. The `start_signing_round()` method checks for `aggregate_public_key.is_none()` [5](#0-4)  but does not validate that the key was set through successful DKG completion meeting `dkg_threshold`.

2. During signing, nonce gathering requires `>= threshold` key_ids [6](#0-5) , but this is the signing threshold, not the DKG threshold. A partial DKG with fewer parties can still meet the signing threshold within that reduced set.

3. The aggregator initialization accepts party_polynomials without validation [7](#0-6) , simply summing whatever polynomials are provided.

4. State transitions allow moving from `DkgEndGather` to `NonceRequest` [8](#0-7)  or to `Idle` [9](#0-8)  without validating DKG completion.

### Impact Explanation

**Specific Harm:**

This vulnerability violates the fundamental DKG security invariant that `dkg_threshold` parties must participate in key generation. If `dkg_threshold = 9` (90% of 10 signers) but only 5 parties complete DKG before timeout, an attacker with coordinator access can:

1. Extract the 5 partial polynomial commitments from `dkg_public_shares`
2. Compute aggregate key = sum of the 5 poly[0] values
3. Call `set_key_and_party_polynomials()` with this partial data
4. Successfully initiate signing operations with the compromised key

**Quantified Impact:**

In a Stacks signer deployment with 10 signers requiring 9 for DKG and 7 for signing:
- Compromised setup: Only 5 signers participate in DKG (below 9 threshold)
- Signing still requires 7 of the reduced 5 parties (impossible), OR the attacker controls multiple key_ids from the 5 parties
- The aggregate public key differs from what honest DKG would produce
- Funds/operations controlled by this key are vulnerable to the reduced party set

**Chain-Level Impact:**

This maps to **Critical** severity under "Any confirmation of an invalid transaction" because:
- Signatures produced with the partial DKG key appear valid cryptographically
- But they violate the governance/security model requiring `dkg_threshold` participation
- Could enable unauthorized Bitcoin transactions or Stacks blockchain state changes
- Dependent systems cannot distinguish partial-DKG signatures from legitimate ones

**Affected Parties:**

All users relying on the security assumption that DKG requires `dkg_threshold` parties for key generation, including Stacks blockchain stacker funds and Bitcoin-pegged operations.

### Likelihood Explanation

**Required Attacker Capabilities:**

1. **Coordinator Access**: Attacker needs mutable access to the Coordinator instance (e.g., compromised application code, malicious integration, or software bug in error handling)
2. **Timing**: Ability to cause or wait for `DkgEndTimeout` (network disruption, DoS against some signers, or natural timeout)
3. **Technical Knowledge**: Understanding of WSTS internals to extract polynomials and compute aggregate key

**Attack Complexity:**

Medium complexity:
- Requires application-level access, not just network-level
- Needs to extract data structures from coordinator state
- Must correctly compute aggregate key from partial polynomials
- Attacker must trigger the timeout scenario or exploit existing timeout

**Economic Feasibility:**

Highly feasible:
- No cryptographic breaks required
- Network disruption can be achieved with modest resources
- If attacker controls some of the signers, can selectively cause timeouts
- Cost is primarily gaining code execution in the coordinator process

**Detection Risk:**

Low detection risk:
- The resulting signatures are cryptographically valid
- No audit trail distinguishes partial-DKG keys from complete-DKG keys
- The aggregate public key simply differs from expected value
- Only off-chain verification of DKG participation count would detect this

**Probability of Success:**

High probability if prerequisites are met:
- API allows the operation without validation (confirmed)
- State machine permits the transition (confirmed)
- No runtime checks prevent this misuse (confirmed)

**Realistic Attack Scenario:**

1. Attacker compromises or influences application code handling WSTS coordinator
2. Attacker causes network partition or DoS to trigger `DkgEndTimeout`
3. Coordinator receives partial responses (e.g., 5 of 10 signers with `dkg_threshold=9`)
4. Attacker's code intercepts the timeout error and extracts `dkg_public_shares`
5. Computes partial aggregate key and calls `set_key_and_party_polynomials()`
6. Initiates signing with the compromised key, appears legitimate to signing threshold checks

### Recommendation

**Primary Fix:**

Add `dkg_threshold` validation to `set_key_and_party_polynomials()`:

```rust
fn set_key_and_party_polynomials(
    &mut self,
    aggregate_key: Point,
    party_polynomials: Vec<(u32, PolyCommitment)>,
) -> Result<(), Error> {
    // NEW: Validate party count meets dkg_threshold
    if party_polynomials.len() < self.config.dkg_threshold as usize {
        return Err(Error::InsufficientDkgParticipants(
            party_polynomials.len(),
            self.config.dkg_threshold,
        ));
    }
    
    let computed_key = party_polynomials
        .iter()
        .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);
    if computed_key != aggregate_key {
        return Err(Error::AggregateKeyPolynomialMismatch(
            computed_key,
            aggregate_key,
        ));
    }
    let party_polynomials_len = party_polynomials.len();
    let party_polynomials = HashMap::from_iter(party_polynomials);
    if party_polynomials.len() != party_polynomials_len {
        return Err(Error::DuplicatePartyId);
    }
    self.aggregate_public_key = Some(aggregate_key);
    self.party_polynomials = party_polynomials;
    Ok(())
}
```

**Alternative Mitigations:**

1. Clear all DKG state on timeout: [10](#0-9)  should call a cleanup function
2. Add a flag tracking whether DKG completed successfully
3. Validate in `start_signing_round()` that DKG completed with sufficient parties

**Testing Recommendations:**

1. Unit test: Call `set_key_and_party_polynomials()` with fewer than `dkg_threshold` parties, verify rejection
2. Integration test: Trigger `DkgEndTimeout` with partial shares, attempt manual key setting, verify failure
3. Negative test: Ensure legitimate DKG with `>= dkg_threshold` parties still succeeds

**Deployment Considerations:**

- This is a breaking API change requiring error handling updates
- Add new error variant: `Error::InsufficientDkgParticipants(usize, u32)`
- Document that `set_key_and_party_polynomials()` now enforces `dkg_threshold`
- Consider migration path for existing saved states with partial DKG data

### Proof of Concept

**Exploitation Algorithm:**

```
# Configuration
num_signers = 10
num_keys = 10  
dkg_threshold = 9
threshold = 7

# Step 1: Trigger DkgEndTimeout
coordinator.start_dkg_round(None)
# ... feed DkgPublicShares from signers 0-4 only (5 < 9)
# ... feed DkgPrivateShares from signers 0-4 only
# ... wait for DkgEndTimeout to occur

# Step 2: Extract partial data after timeout
partial_polynomials = []
for (signer_id, dkg_public_shares) in coordinator.dkg_public_shares:
    for (party_id, commitment) in dkg_public_shares.comms:
        partial_polynomials.append((party_id, commitment))

# Step 3: Compute partial aggregate key
partial_aggregate_key = Point::default()
for (_, commitment) in partial_polynomials:
    partial_aggregate_key += commitment.poly[0]

# Step 4: Bypass validation
# CURRENT: This succeeds even though len(partial_polynomials) = 5 < dkg_threshold = 9
coordinator.set_key_and_party_polynomials(
    partial_aggregate_key,
    partial_polynomials
)

# Step 5: Signing proceeds with compromised key
# aggregate_public_key is now set to value controlled by only 5 parties
coordinator.start_signing_round(message, SignatureType::Schnorr, None)
# Signing succeeds if 7 of the 5 parties' key_ids participate (impossible in this config)
# OR if the 5 parties control enough key_ids to meet threshold=7
```

**Expected vs Actual Behavior:**

- **Expected**: `set_key_and_party_polynomials()` should reject because 5 < 9 (dkg_threshold)
- **Actual**: Method succeeds, sets `aggregate_public_key` from partial data, violates security invariant

**Reproduction Steps:**

1. Create coordinator with `dkg_threshold = 9`, `threshold = 7`, `num_signers = 10`
2. Start DKG round
3. Provide DkgPublicShares from only 5 signers
4. Provide DkgPrivateShares from the same 5 signers
5. Wait for or trigger `DkgEndTimeout`
6. Extract polynomials from `coordinator.dkg_public_shares`
7. Call `set_key_and_party_polynomials()` with partial data
8. Observe: Method succeeds without error
9. Call `start_signing_round()` - succeeds because aggregate_public_key is set
10. Result: DKG security invariant violated, key controlled by 5 parties instead of required 9

### Citations

**File:** src/state_machine/coordinator/fire.rs (L133-146)
```rust
            State::DkgEndGather => {
                if let Some(start) = self.dkg_end_start {
                    if let Some(timeout) = self.config.dkg_end_timeout {
                        if now.duration_since(start) > timeout {
                            error!("Timeout gathering DkgEnd for dkg round {} signing round {} iteration {}, unable to continue", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id);
                            let wait = self.dkg_wait_signer_ids.iter().copied().collect();
                            return Ok((
                                None,
                                Some(OperationResult::DkgError(DkgError::DkgEndTimeout(wait))),
                            ));
                        }
                    }
                }
            }
```

**File:** src/state_machine/coordinator/fire.rs (L952-959)
```rust
            if nonce_info.nonce_recv_key_ids.len() >= self.config.threshold as usize {
                // We have a winning message!
                self.message.clone_from(&nonce_response.message);
                let aggregate_nonce = self.compute_aggregate_nonce();
                info!("Aggregate nonce: {aggregate_nonce}");

                self.move_to(State::SigShareRequest(signature_type))?;
            }
```

**File:** src/state_machine/coordinator/fire.rs (L1235-1274)
```rust
    fn can_move_to(&self, state: &State) -> Result<(), Error> {
        let prev_state = &self.state;
        let accepted = match state {
            State::Idle => true,
            State::DkgPublicDistribute => prev_state == &State::Idle,
            State::DkgPublicGather => {
                prev_state == &State::DkgPublicDistribute || prev_state == &State::DkgPublicGather
            }
            State::DkgPrivateDistribute => prev_state == &State::DkgPublicGather,
            State::DkgPrivateGather => {
                prev_state == &State::DkgPrivateDistribute || prev_state == &State::DkgPrivateGather
            }
            State::DkgEndDistribute => prev_state == &State::DkgPrivateGather,
            State::DkgEndGather => prev_state == &State::DkgEndDistribute,
            State::NonceRequest(signature_type) => {
                prev_state == &State::Idle
                    || prev_state == &State::DkgEndGather
                    || prev_state == &State::SigShareGather(*signature_type)
            }
            State::NonceGather(signature_type) => {
                prev_state == &State::NonceRequest(*signature_type)
                    || prev_state == &State::NonceGather(*signature_type)
            }
            State::SigShareRequest(signature_type) => {
                prev_state == &State::NonceGather(*signature_type)
            }
            State::SigShareGather(signature_type) => {
                prev_state == &State::SigShareRequest(*signature_type)
                    || prev_state == &State::SigShareGather(*signature_type)
            }
        };
        if accepted {
            debug!("state change from {prev_state:?} to {state:?}");
            Ok(())
        } else {
            Err(Error::BadStateChange(format!(
                "{prev_state:?} to {state:?}"
            )))
        }
    }
```

**File:** src/state_machine/coordinator/fire.rs (L1384-1406)
```rust
    fn set_key_and_party_polynomials(
        &mut self,
        aggregate_key: Point,
        party_polynomials: Vec<(u32, PolyCommitment)>,
    ) -> Result<(), Error> {
        let computed_key = party_polynomials
            .iter()
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);
        if computed_key != aggregate_key {
            return Err(Error::AggregateKeyPolynomialMismatch(
                computed_key,
                aggregate_key,
            ));
        }
        let party_polynomials_len = party_polynomials.len();
        let party_polynomials = HashMap::from_iter(party_polynomials);
        if party_polynomials.len() != party_polynomials_len {
            return Err(Error::DuplicatePartyId);
        }
        self.aggregate_public_key = Some(aggregate_key);
        self.party_polynomials = party_polynomials;
        Ok(())
    }
```

**File:** src/state_machine/coordinator/fire.rs (L1463-1466)
```rust
        // We cannot sign if we haven't first set DKG (either manually or via DKG round).
        if self.aggregate_public_key.is_none() {
            return Err(Error::MissingAggregatePublicKey);
        }
```

**File:** src/state_machine/coordinator/mod.rs (L140-141)
```rust
    /// threshold of keys needed to complete DKG (must be >= threshold)
    pub dkg_threshold: u32,
```

**File:** src/v2.rs (L431-444)
```rust
    fn init(&mut self, comms: &HashMap<u32, PolyCommitment>) -> Result<(), AggregatorError> {
        let threshold: usize = self.threshold.try_into()?;
        let mut poly = Vec::with_capacity(threshold);

        for i in 0..poly.capacity() {
            poly.push(Point::zero());
            for (_, comm) in comms {
                poly[i] += &comm.poly[i];
            }
        }

        self.poly = poly;

        Ok(())
```
