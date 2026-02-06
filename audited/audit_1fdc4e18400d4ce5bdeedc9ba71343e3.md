### Title
Indiscriminate Malicious Signer Marking on Timeout Enables Denial of Service Through Network-Layer Attacks

### Summary
The FIRE coordinator's `process_timeout()` function marks all non-responsive signers as permanently malicious during signature share gathering timeouts without distinguishing between network-DoS victims and actually malicious actors. An attacker with network-level DoS capabilities can systematically exclude honest signers from the signing pool, eventually causing complete signing failure (network shutdown) or gaining veto power over signature operations.

### Finding Description

**Exact Code Location:** [1](#0-0) 

**Root Cause:**
When the `SigShareGather` state times out, the coordinator unconditionally marks all signers in `sign_wait_signer_ids` as malicious: [2](#0-1) 

The code does not distinguish between:
1. Signers who are malicious (providing invalid shares or refusing to participate)
2. Signers who are honest but network-DoS'd (unable to respond due to external attacks)

**Permanent Exclusion Mechanism:**
Once marked malicious, signers are permanently excluded from future signing rounds. Their nonce responses are ignored in subsequent attempts: [3](#0-2) 

The `malicious_signer_ids` set is never cleared - there is no recovery mechanism for falsely accused signers. Even the `reset()` function does not clear this set: [4](#0-3) 

**Why Existing Mitigations Fail:**
The coordinator has a `check_signature_shares()` function that can cryptographically verify which signers provided invalid shares, but this is only called after aggregation fails, not proactively during timeout handling. The timeout logic makes no attempt to verify whether non-responsive signers are actually malicious before marking them.

**Attack Flow:**
Signers are added to `sign_wait_signer_ids` when they successfully provide nonces: [5](#0-4) 

They are removed when signature shares are received: [6](#0-5) 

An attacker can DoS honest signers between nonce provision and signature share submission, causing them to timeout and be marked malicious.

### Impact Explanation

**Specific Harm:**
When WSTS is used in the Stacks blockchain for threshold signing (e.g., Bitcoin peg operations, block signing), this vulnerability can cause:

1. **Complete Network Shutdown (Critical Impact):** If enough honest signers are marked malicious such that `num_keys - num_malicious_keys < threshold`, all future signing operations fail with `SignError::InsufficientSigners`: [7](#0-6) 

This maps to the Critical severity definition: "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks."

2. **Attacker Veto Power (Critical Impact):** If the attacker controls A key_ids where A < threshold T, and DoS's enough honest signers to reduce honest non-malicious key_ids to H where H < T - A, then:
   - Honest signers alone cannot reach threshold
   - Attacker must participate for any signature to succeed
   - Attacker gains veto power over which transactions/blocks are signed

**Quantified Impact:**
- Setup: 10 signers, threshold = 7 key_ids, attacker controls 3 key_ids
- Attacker DoS's 4 honest signers repeatedly across multiple signing rounds
- Result: Only 6 key_ids remain non-malicious (3 attacker + 3 honest)
- Outcome: Below threshold, all signing operations fail permanently

**Who Is Affected:**
- Stacks blockchain users (cannot confirm transactions)
- Bitcoin peg operations (cannot move funds)
- Any system relying on WSTS for threshold signatures

### Likelihood Explanation

**Required Attacker Capabilities:**
1. **Network-level DoS capability:** Attacker must be able to block or delay network traffic between specific signers and the coordinator
   - Position: Network adversary with access to routing infrastructure, or ability to conduct targeted DDoS attacks
   - Does not require compromising signer hosts or breaking cryptography

2. **Timing precision:** Attacker must DoS signers during the SigShareGather phase (after nonces are collected but before signature shares arrive)
   - Window: Duration of `config.sign_timeout` setting

3. **Signer participation:** Attacker should control some signers (even if below threshold) to maintain influence after honest signers are excluded

**Attack Complexity:**
- **Moderate:** Requires sustained network-level attacks but no cryptographic breaks
- **Persistence:** Attack must be repeated across multiple signing rounds to accumulate enough malicious markings
- **Target selection:** Attacker can selectively DoS specific honest signers to maximize impact

**Economic Feasibility:**
- Network DoS attacks are commodity services (DDoS-for-hire)
- Cost increases with network protection, but is realistic for well-funded attackers
- Return on investment depends on value at stake (for Stacks/Bitcoin peg, could be substantial)

**Detection Risk:**
- **Moderate:** Repeated timeouts and growing malicious_signer_ids would be visible in logs
- However, without out-of-band verification, operators cannot distinguish legitimate malicious detection from false accusations
- No programmatic alerting or recovery mechanism exists

**Estimated Probability:**
- **High** if signers communicate over public internet with standard DDoS protection
- **Medium** if signers use private networks with strong DDoS mitigation
- **Low** only if signers are on isolated networks with physical security

### Recommendation

**Primary Fix - Add Cryptographic Verification Before Marking Malicious:**

Modify the timeout handler to distinguish between non-responsive and cryptographically-invalid signers:

1. When timeout occurs, do NOT immediately mark signers as malicious
2. If some signature shares were received, use `check_signature_shares()` to identify cryptographically invalid shares
3. Only mark those specific signers as malicious
4. For non-responsive signers, retry with increased timeout or mark as "temporarily unavailable" with recovery mechanism

**Proposed Code Changes:**

```rust
State::SigShareGather(signature_type) => {
    if let Some(start) = self.sign_start {
        if let Some(timeout) = self.config.sign_timeout {
            if now.duration_since(start) > timeout {
                // Don't mark non-responsive signers as malicious
                // Only retry with new nonce request
                warn!("Timeout gathering signature shares, retrying without marking malicious");
                
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
```

**Alternative Mitigations:**

1. **Add recovery mechanism:** Implement time-based or manual clearing of malicious_signer_ids
2. **Add health checks:** Coordinator pings signers before marking as malicious
3. **Add retry count:** Only mark malicious after N consecutive failures
4. **Add cryptographic proof:** Require signers to prove they attempted to respond (signed timeout acknowledgment)

**Testing Recommendations:**
1. Add unit tests simulating network delays without marking signers malicious
2. Add integration tests with controlled network partitions
3. Test recovery scenarios where temporarily-unavailable signers return
4. Verify that only cryptographically-invalid shares trigger malicious marking

**Deployment Considerations:**
- Existing deployments may have falsely-accused signers in malicious_signer_ids
- Consider migration path to clear historical false accusations
- Document operational procedures for identifying and recovering from false malicious markings
- Add monitoring for malicious_signer_ids growth rate

### Proof of Concept

**Exploitation Algorithm:**

```
Setup:
- N signers with K total key_ids
- Threshold T key_ids required
- Attacker controls A key_ids where A < T
- Honest signers control H key_ids where H >= T

Attack:
1. Coordinator initiates signing round
2. All signers (including honest) respond with nonces
3. Coordinator sends SignatureShareRequest
4. ATTACKER ACTION: DoS honest signers S_1, S_2, ..., S_n
   - Block network traffic between these signers and coordinator
   - Use DDoS, routing attacks, or firewall rules
5. Timeout expires (config.sign_timeout)
6. Coordinator marks S_1, S_2, ..., S_n as malicious
7. Let D = sum of key_ids controlled by S_1, S_2, ..., S_n
8. Check: K - D >= T?
   - If NO: Signing fails immediately (network shutdown)
   - If YES: Coordinator retries with NonceRequest
9. In retry, S_1, S_2, ..., S_n responses ignored (marked malicious)
10. Repeat attack in subsequent rounds to accumulate more malicious markings
11. Eventually: K - D < T or H - D < T - A
12. Result: Signing becomes impossible or attacker gains veto power
```

**Concrete Example:**

```
Initial Configuration:
- 10 signers: S0-S9
- Each controls 1 key_id
- Threshold: 7 key_ids
- Attacker controls: S0, S1, S2 (3 key_ids)
- Honest signers: S3-S9 (7 key_ids)

Round 1:
- All signers provide nonces
- Attacker DoS's S3, S4, S5 during SigShareGather
- Timeout occurs
- S3, S4, S5 marked malicious
- Remaining: 7 key_ids (3 attacker + 4 honest)
- Check: 7 >= 7, continues

Round 2 (retry):
- S3, S4, S5 responses ignored (malicious)
- All signers provide nonces except S3-S5
- Attacker DoS's S6 during SigShareGather
- Timeout occurs
- S6 marked malicious
- Remaining: 6 key_ids (3 attacker + 3 honest)
- Check: 6 < 7, SIGNING FAILS

Result:
- All future signing operations return InsufficientSigners error
- Network cannot confirm transactions (Critical impact)
```

**Reproduction Instructions:**

1. Set up WSTS FIRE coordinator with 10 signers, threshold 7
2. Configure short sign_timeout (e.g., 1 second)
3. Initiate signing round
4. During SigShareGather phase, use iptables/firewall rules to block 4 honest signers
5. Wait for timeout
6. Observe honest signers marked malicious in logs
7. Attempt new signing round
8. Observe marked signers' nonces are ignored
9. Repeat to accumulate more malicious markings
10. Observe signing eventually fails with InsufficientSigners

### Citations

**File:** src/state_machine/coordinator/fire.rs (L173-207)
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

**File:** src/state_machine/coordinator/fire.rs (L940-942)
```rust
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

**File:** src/state_machine/coordinator/fire.rs (L1478-1491)
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
}
```
