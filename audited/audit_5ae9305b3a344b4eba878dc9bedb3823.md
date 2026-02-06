### Title
Incorrect Threshold Check After Marking Signers Malicious Causes Denial of Service

### Summary
The FIRE coordinator's signature share timeout handler uses the configured total number of keys instead of the actual number of keys that completed DKG when checking if sufficient non-malicious signers remain. This causes the coordinator to incorrectly continue retrying signature rounds that can never succeed, leading to a persistent denial of service where no signatures can be produced.

### Finding Description
The vulnerability exists in the `process_timeout` function of the FIRE coordinator when handling signature share timeouts. [1](#0-0) 

When a signature share timeout occurs, the coordinator marks all non-responding signers as malicious (lines 178-186) and then checks if sufficient non-malicious keys remain to meet the threshold (line 191). The critical flaw is that this check uses `self.config.num_keys`, which represents the configured total number of keys in the system. [2](#0-1) 

However, the actual number of keys participating in the system may be less than `config.num_keys` if DKG completed with fewer participants. During DKG timeout handling, the coordinator allows DKG to proceed if `dkg_threshold` is met, even if not all configured keys participate: [3](#0-2) 

The actual participating keys are stored in `party_polynomials`, which is populated during DKG completion: [4](#0-3) 

The root cause is that line 191 should check against the actual number of keys in `party_polynomials.len()` rather than the configured `num_keys`. When DKG completes with fewer keys than configured, the threshold check produces incorrect results, allowing the coordinator to continue when it should terminate with `InsufficientSigners`.

### Impact Explanation
This vulnerability causes a persistent denial of service in the coordinator node. Once triggered, the coordinator becomes stuck in an infinite retry loop:

1. The coordinator believes it has enough non-malicious keys to meet the threshold
2. It requests new nonces from the remaining signers
3. Malicious signers are rejected during nonce gathering
4. The actual number of responding signers is insufficient (below threshold)
5. Timeout occurs again, returning to step 1

**Specific Harm:**
- Coordinator wastes CPU cycles and network bandwidth indefinitely retrying impossible signing rounds
- No signatures can be produced for any message while stuck in this state
- Requires manual intervention (restart) to recover, losing accumulated state

**Quantified Impact:**
In a system with 10 configured keys where only 9 complete DKG (90% participation, common with `dkg_threshold = 9`), if 3 signers become malicious, the coordinator incorrectly continues with 6 available keys when threshold requires 7.

**Who is Affected:**
Any deployment using the FIRE coordinator with:
- `dkg_threshold < num_keys` (allows partial DKG participation)
- Network conditions causing signer timeouts
- Multiple coordinator nodes can be simultaneously affected

**Severity Justification:**
This maps to **Low** severity per the protocol scope: "Any remotely-exploitable denial of service in a node." While it prevents signature generation, it does not directly cause loss of funds, chain splits, or invalid transaction confirmations. However, if WSTS is critical infrastructure for transaction signing, this could indirectly impact transaction confirmation rates.

### Likelihood Explanation
**Required Conditions:**
- System configured with `dkg_threshold < num_keys` (standard configuration per test code) [5](#0-4) 
- DKG completes with fewer than `num_keys` participants (one or more signers drop during DKG)
- During signing, enough signers timeout such that: `config.num_keys - malicious >= threshold` but `actual_dkg_keys - malicious < threshold`

**No Attacker Required:**
This vulnerability can be triggered by natural network conditions without any malicious actor:
1. Network partition causes one signer to drop during DKG
2. Later network issues cause multiple signers to timeout during signing
3. Vulnerability triggers automatically

**Attack Complexity:** Low
- No cryptographic breaks needed
- No privileged access required  
- Occurs during normal protocol operation
- Can happen accidentally or be triggered by simple network disruptions

**Economic Feasibility:** Trivial
- Attacker only needs to cause network delays/drops (DoS on individual signers)
- No stake or funds at risk
- Effect persists until manual coordinator restart

**Detection Risk:** Low
- Appears as normal timeout/retry behavior
- Difficult to distinguish from legitimate network issues
- No cryptographic evidence of attack

**Probability:** High in networks with unreliable connectivity or adversarial participants.

### Recommendation
Replace the threshold check to use the actual number of keys from DKG instead of the configured total:

```rust
// Calculate actual participating keys from DKG
let actual_num_keys: u32 = self.party_polynomials.len().try_into()
    .map_err(Error::TryFromInt)?;

let num_malicious_keys: u32 =
    self.compute_num_key_ids(self.malicious_signer_ids.iter())?;

// Check against actual keys, not configured keys
if actual_num_keys - num_malicious_keys < self.config.threshold {
    error!("Insufficient non-malicious signers, unable to continue");
    let mal = self.malicious_signer_ids.iter().copied().collect();
    return Ok((
        None,
        Some(OperationResult::SignError(
            SignError::InsufficientSigners(mal),
        )),
    ));
}
```

**Alternative Mitigation:**
Add validation during DKG completion to ensure `party_polynomials.len() >= threshold`, preventing the system from entering a state where the threshold cannot be met even with all non-malicious signers participating.

**Testing Recommendations:**
1. Add unit test with DKG completing at `dkg_threshold` (less than `num_keys`)
2. Timeout enough signers during signing so configured check passes but actual check fails
3. Verify coordinator correctly returns `InsufficientSigners` error instead of retrying

**Deployment Considerations:**
This fix should be applied before deployment in production networks with unreliable connectivity or adversarial participants.

### Proof of Concept

**Setup Parameters:**
- `num_signers = 10` (1 key each)
- `num_keys = 10` 
- `threshold = 7` (70%)
- `dkg_threshold = 9` (90%)

**Exploitation Steps:**

1. **DKG Phase:** Start DKG with all 10 signers, but signer #9 drops out due to network issue. Only 9 signers complete DKG successfully, meeting `dkg_threshold = 9`. After DKG: `party_polynomials.len() = 9`.

2. **First Signing Iteration:** Start signing round. All 9 DKG signers send nonces (9 keys). Only 6 signers send signature shares within timeout. Signers #3, #4, #5 timeout.

3. **Timeout Handler Execution:**
   - Marks signers #3, #4, #5 as malicious (3 keys total)
   - Computes `num_malicious_keys = 3`
   - Executes check: `10 - 3 = 7 < 7` → FALSE
   - Continues to new nonce request (line 202-204)

4. **Second Signing Iteration:** Requests nonces. Malicious signers #3, #4, #5 are rejected. Only 6 non-malicious signers respond (6 keys). All 6 send signature shares, but aggregation requires threshold = 7 keys.

5. **Result:** Coordinator attempts aggregation with 6 keys but needs 7, fails signature validation. Returns to step 2, creating infinite retry loop.

**Expected Behavior:** After step 3, coordinator should detect `9 - 3 = 6 < 7` and return `InsufficientSigners` error.

**Actual Behavior:** Coordinator continues indefinitely retrying with insufficient keys, consuming resources without producing valid signatures.

**Reproduction:** Use test framework from coordinator/mod.rs with modified setup to have one signer drop during DKG, then trigger timeouts during signing to mark 3 signers malicious while actual participating keys minus malicious equals threshold minus one.

### Citations

**File:** src/state_machine/coordinator/fire.rs (L77-102)
```rust
            State::DkgPublicGather => {
                if let Some(start) = self.dkg_public_start {
                    if let Some(timeout) = self.config.dkg_public_timeout {
                        if now.duration_since(start) > timeout {
                            // check dkg_threshold to determine if we can continue
                            let dkg_size = self.compute_dkg_public_size()?;

                            if self.config.dkg_threshold > dkg_size {
                                error!("Timeout gathering DkgPublicShares for dkg round {} signing round {} iteration {}, dkg_threshold not met ({dkg_size}/{}), unable to continue", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, self.config.dkg_threshold);
                                let wait = self.dkg_wait_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::DkgError(DkgError::DkgPublicTimeout(
                                        wait,
                                    ))),
                                ));
                            } else {
                                // we hit the timeout but met the threshold, continue
                                warn!("Timeout gathering DkgPublicShares for dkg round {} signing round {} iteration {}, dkg_threshold was met ({dkg_size}/{}), ", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, self.config.dkg_threshold);
                                self.public_shares_gathered()?;
                                let packet = self.start_private_shares()?;
                                return Ok((Some(packet), None));
                            }
                        }
                    }
                }
```

**File:** src/state_machine/coordinator/fire.rs (L173-211)
```rust
            State::SigShareGather(signature_type) => {
                if let Some(start) = self.sign_start {
                    if let Some(timeout) = self.config.sign_timeout {
                        if now.duration_since(start) > timeout {
                            warn!("Timeout gathering signature shares for signing round {} iteration {}", self.current_sign_id, self.current_sign_iter_id);
                            for signer_id in &self
                                .message_nonces
                                .get(&self.message)
                                .ok_or(Error::MissingMessageNonceInfo)?
                                .sign_wait_signer_ids
                            {
                                warn!("Mark signer {signer_id} as malicious");
                                self.malicious_signer_ids.insert(*signer_id);
                            }

                            let num_malicious_keys: u32 =
                                self.compute_num_key_ids(self.malicious_signer_ids.iter())?;

                            if self.config.num_keys - num_malicious_keys < self.config.threshold {
                                error!("Insufficient non-malicious signers, unable to continue");
                                let mal = self.malicious_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::SignError(
                                        SignError::InsufficientSigners(mal),
                                    )),
                                ));
                            }

                            self.move_to(State::NonceRequest(signature_type))?;
                            let packet = self.request_nonces(signature_type)?;
                            return Ok((Some(packet), None));
                        }
                    }
                }
            }
        }
        Ok((None, None))
    }
```

**File:** src/state_machine/coordinator/fire.rs (L794-812)
```rust
    fn dkg_end_gathered(&mut self) -> Result<(), Error> {
        // Cache the polynomials used in DKG for the aggregator
        for signer_id in self.dkg_private_shares.keys() {
            for (party_id, comm) in &self.dkg_public_shares[signer_id].comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
        }

        // Calculate the aggregate public key
        let key = self
            .dkg_end_messages
            .keys()
            .flat_map(|signer_id| self.dkg_public_shares[signer_id].comms.clone())
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

        info!("Aggregate public key: {key}");
        self.aggregate_public_key = Some(key);
        self.move_to(State::Idle)
    }
```

**File:** src/state_machine/coordinator/mod.rs (L131-158)
```rust
/// Config fields common to all Coordinators
#[derive(Default, Clone, PartialEq)]
pub struct Config {
    /// total number of signers
    pub num_signers: u32,
    /// total number of keys
    pub num_keys: u32,
    /// threshold of keys needed to form a valid signature
    pub threshold: u32,
    /// threshold of keys needed to complete DKG (must be >= threshold)
    pub dkg_threshold: u32,
    /// private key used to sign network messages
    pub message_private_key: Scalar,
    /// timeout to gather DkgPublicShares messages
    pub dkg_public_timeout: Option<Duration>,
    /// timeout to gather DkgPrivateShares messages
    pub dkg_private_timeout: Option<Duration>,
    /// timeout to gather DkgEnd messages
    pub dkg_end_timeout: Option<Duration>,
    /// timeout to gather nonces
    pub nonce_timeout: Option<Duration>,
    /// timeout to gather signature shares
    pub sign_timeout: Option<Duration>,
    /// the public keys and key_ids for all signers
    pub public_keys: PublicKeys,
    /// whether to verify the signature on Packets
    pub verify_packet_sigs: bool,
}
```

**File:** src/state_machine/coordinator/mod.rs (L579-582)
```rust
        let mut rng = create_rng();
        let num_keys = num_signers * keys_per_signer;
        let threshold = (num_keys * 7) / 10;
        let dkg_threshold = (num_keys * 9) / 10;
```
