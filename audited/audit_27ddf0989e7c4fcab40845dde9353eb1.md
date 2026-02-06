### Title
Non-Participating Signers Can Abort DKG Through Invalid Private Shares

### Summary
The `dkg_ended()` function fails the entire DKG round if `invalid_private_shares` contains any entries, even if those invalid shares are from signers not included in the final participating set defined by `DkgEndBegin.signer_ids`. This allows any configured signer to cause a denial-of-service by sending corrupted private shares, which prevents honest signers from completing DKG even when they have sufficient valid shares to succeed.

### Finding Description

**Location:** `src/state_machine/signer/mod.rs`, function `dkg_ended()`, lines 504-671

**Root Cause:**

The vulnerability exists in the conditional logic at line 611 that determines whether to attempt secret computation: [1](#0-0) 

This check evaluates whether `invalid_private_shares` is empty across ALL signers who sent private shares during the DKG round, not just those in the final participating set. When this map is non-empty, the code skips calling `compute_secrets()` entirely and immediately returns a failure: [2](#0-1) 

However, signers are added to `invalid_private_shares` during the `dkg_private_shares()` handler whenever decryption or scalar parsing fails, regardless of whether they will be in the final participating set: [3](#0-2) [4](#0-3) 

The coordinator determines the final participating signers and sends them in `DkgEndBegin.signer_ids`. Earlier in `dkg_ended()`, the code correctly validates shares only from these participating signers: [5](#0-4) [6](#0-5) 

The inconsistency is that share validation uses the filtered `signer_ids_set`, but the decision to call `compute_secrets()` uses the unfiltered `invalid_private_shares` map.

**Why Existing Mitigations Fail:**

There is no check in `dkg_private_shares()` to verify that the sender is expected to participate in the final DKG round. The function accepts private shares from any configured signer: [7](#0-6) 

The coordinator's malicious signer detection in `gather_dkg_end()` happens after the fact and cannot prevent honest signers from already reporting failures: [8](#0-7) 

### Impact Explanation

**Specific Harm:**
- DKG cannot complete successfully, preventing establishment of the threshold signing key
- Without a valid threshold key, the system cannot proceed to the signing phase
- All participating nodes report `DkgStatus::Failure`, causing the coordinator to abort with `Error::DkgFailure`

**Quantification:**
Consider a configuration with 10 signers, threshold=7, dkg_threshold=7:
1. Attacker controls 1 signer (Signer A)
2. Signer A sends corrupted `DkgPrivateShares` during the private share phase
3. All 9 honest signers receive these shares, decryption fails, Signer A is added to their `invalid_private_shares`
4. Coordinator sends `DkgEndBegin` with 9 honest signers (excluding Signer A)
5. All 9 honest signers have valid shares and meet the threshold, but still report failure due to line 611
6. DKG aborts, must be restarted
7. Attacker can repeat indefinitely, preventing any DKG completion

**Who is Affected:**
All signers participating in DKG are affected. The system cannot establish threshold keys needed for operation.

**Severity Justification:**
This maps to **Low** severity per the provided scope: "Any remotely-exploitable denial of service in a node" and "Any network denial of service impacting more than 10 percent of miners that does not shut down the network." While this affects all DKG participants, it is fundamentally a DoS attack that prevents key establishment but does not directly compromise cryptographic security or cause fund loss.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Control or compromise of a single signer configured in the system
- Ability to send network messages during the DKG private share phase
- No cryptographic capabilities required

**Attack Complexity:**
- Low complexity: Simply send `DkgPrivateShares` messages with intentionally corrupted encrypted data
- Can use random bytes or malformed ciphertext to trigger decryption failures
- No need to break encryption or understand the DKG protocol deeply

**Economic Feasibility:**
- Minimal cost: requires only network bandwidth to send malformed messages
- No computational resources needed beyond normal signer operation
- Attack can be repeated indefinitely at no additional cost

**Detection Risk:**
- Attack is detectable through logging (decryption failures are logged)
- Coordinator identifies malicious signer and adds to `malicious_dkg_signer_ids`
- However, detection does not prevent the DoS from succeeding in the current round

**Estimated Probability:**
- High probability of success: 100% success rate if attacker controls any configured signer
- Attack always succeeds because honest signers cannot distinguish between shares from participating vs non-participating signers until after processing

### Recommendation

**Proposed Code Changes:**

In `dkg_ended()`, filter `invalid_private_shares` to only include signers from the participating set before checking if it's empty:

```rust
// After line 549 (after signer_ids_set is created)
// Filter invalid shares to only those from participating signers
let participating_invalid_shares: HashMap<u32, BadPrivateShare> = self.invalid_private_shares
    .iter()
    .filter(|(signer_id, _)| signer_ids_set.contains(signer_id))
    .map(|(k, v)| (*k, v.clone()))
    .collect();

// Replace line 611 with:
let dkg_end = if participating_invalid_shares.is_empty() {
    // existing compute_secrets logic...
} else {
    DkgEnd {
        dkg_id: self.dkg_id,
        signer_id: self.signer_id,
        status: DkgStatus::Failure(DkgFailure::BadPrivateShares(
            participating_invalid_shares,
        )),
    }
};
```

**Alternative Mitigations:**
1. Add a check in `dkg_private_shares()` to reject shares from signers not in `dkg_private_begin_msg.signer_ids`
2. Clear `invalid_private_shares` when receiving `DkgEndBegin` and only track invalid shares from the final participating set

**Testing Recommendations:**
1. Unit test: Create scenario with 5 signers, have non-participating signer send bad shares, verify DKG still succeeds
2. Integration test: Simulate malicious signer sending corrupted shares, then being excluded from final set, verify honest signers complete DKG
3. Regression test: Ensure legitimate bad shares from participating signers still cause appropriate failures

**Deployment Considerations:**
- This is a breaking change to DKG validation logic
- Coordinate deployment across all signers simultaneously
- Consider backward compatibility if mixed versions must interoperate

### Proof of Concept

**Exploitation Algorithm:**

1. **Setup:** System configured with signers 0-4, threshold=3, dkg_threshold=3
2. **Attacker:** Controls signer 4
3. **Attack Steps:**
   - Wait for `DkgBegin` message, all signers send `DkgPublicShares` normally
   - Wait for `DkgPrivateBegin` message
   - Signer 4 crafts `DkgPrivateShares` with random/corrupted encrypted bytes instead of valid encrypted scalars
   - Send malformed `DkgPrivateShares` to all other signers
   - Signers 0-3 send valid `DkgPrivateShares`
   - Signers 0-3 receive signer 4's shares, decryption fails at line 1076, signer 4 added to `invalid_private_shares`
   - Coordinator detects signer 4 sent bad shares, sends `DkgEndBegin` with `signer_ids = [0,1,2,3]` (excluding signer 4)
   - Signers 0-3 execute `dkg_ended()`:
     * Line 529-534: `signer_ids_set = {0,1,2,3}`
     * Lines 551-608: Validate shares from signers 0-3 only - all valid
     * Have 4 keys total, meets `dkg_threshold=3` - pass
     * Line 611: `invalid_private_shares.is_empty()` returns `false` (contains signer 4)
     * Lines 652-660: Return `DkgStatus::Failure` without calling `compute_secrets()`
   - Coordinator receives failures from all honest signers at line 785-788, aborts DKG

4. **Expected Behavior:** DKG should succeed because signers 0-3 have valid shares and meet threshold

5. **Actual Behavior:** DKG fails because `invalid_private_shares` contains signer 4, even though signer 4 is not in the participating set

6. **Reproduction:** 
   - Modify signer 4's `dkg_private_begin()` to encrypt random bytes instead of actual shares
   - Run DKG round with all 5 signers
   - Observe that honest signers report failure despite having sufficient valid shares
   - Check logs for decryption failures and confirm signer 4 is in `invalid_private_shares` but not in final `signer_ids`

### Citations

**File:** src/state_machine/signer/mod.rs (L529-534)
```rust
        let signer_ids_set: HashSet<u32> = dkg_end_begin
            .signer_ids
            .iter()
            .filter(|&&id| id < self.total_signers)
            .copied()
            .collect::<HashSet<u32>>();
```

**File:** src/state_machine/signer/mod.rs (L551-583)
```rust
        for signer_id in &signer_ids_set {
            if let Some(shares) = self.dkg_public_shares.get(signer_id) {
                if shares.comms.is_empty() {
                    missing_public_shares.insert(*signer_id);
                } else {
                    for (party_id, comm) in shares.comms.iter() {
                        if !check_public_shares(comm, threshold, &self.dkg_id.to_be_bytes()) {
                            bad_public_shares.insert(*signer_id);
                        } else {
                            self.commitments.insert(*party_id, comm.clone());
                        }
                    }
                }
            } else {
                missing_public_shares.insert(*signer_id);
            }
            if let Some(shares) = self.dkg_private_shares.get(signer_id) {
                // signer_id sent shares, but make sure that it sent shares for every one of this signer's key_ids
                if shares.shares.is_empty() {
                    missing_private_shares.insert(*signer_id);
                } else {
                    for dst_key_id in self.signer.get_key_ids() {
                        for (_src_key_id, shares) in &shares.shares {
                            if shares.get(&dst_key_id).is_none() {
                                missing_private_shares.insert(*signer_id);
                            }
                        }
                    }
                }
            } else {
                missing_private_shares.insert(*signer_id);
            }
        }
```

**File:** src/state_machine/signer/mod.rs (L611-611)
```rust
        let dkg_end = if self.invalid_private_shares.is_empty() {
```

**File:** src/state_machine/signer/mod.rs (L652-660)
```rust
        } else {
            DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::BadPrivateShares(
                    self.invalid_private_shares.clone(),
                )),
            }
        };
```

**File:** src/state_machine/signer/mod.rs (L1037-1056)
```rust
        // check that the signer_id exists in the config
        let Some(_signer_public_key) = self.public_keys.signers.get(&src_signer_id) else {
            warn!(%src_signer_id, "No public key configured");
            return Ok(vec![]);
        };

        let Ok(kex_public_key) = self.get_kex_public_key(src_signer_id) else {
            return Ok(vec![]);
        };

        for (party_id, _shares) in &dkg_private_shares.shares {
            if !SignerType::validate_party_id(
                src_signer_id,
                *party_id,
                &self.public_keys.signer_key_ids,
            ) {
                warn!("Signer {src_signer_id} sent a polynomial commitment for party {party_id}");
                return Ok(vec![]);
            }
        }
```

**File:** src/state_machine/signer/mod.rs (L1083-1086)
```rust
                                self.invalid_private_shares.insert(
                                    src_signer_id,
                                    self.make_bad_private_share(src_signer_id, rng)?,
                                );
```

**File:** src/state_machine/signer/mod.rs (L1091-1094)
```rust
                            self.invalid_private_shares.insert(
                                src_signer_id,
                                self.make_bad_private_share(src_signer_id, rng)?,
                            );
```

**File:** src/state_machine/coordinator/fire.rs (L779-789)
```rust
            if reported_failures.is_empty() {
                debug!("no dkg failures");
                self.dkg_end_gathered()?;
            } else {
                // TODO: see if we have sufficient non-malicious signers to continue
                warn!("got dkg failures");
                return Err(Error::DkgFailure {
                    reported_failures,
                    malicious_signers,
                });
            }
```
