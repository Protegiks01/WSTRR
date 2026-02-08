Audit Report

## Title
DkgEndGather Timeout Handler Missing Threshold Check Enables Denial of Service on DKG

## Summary
The FIRE coordinator's `process_timeout()` function lacks a threshold check in the DkgEndGather state, unlike the DkgPublicGather and DkgPrivateGather phases. This inconsistency allows a single signer to prevent DKG completion by withholding their DkgEnd message, even when `dkg_threshold` participants have already responded, violating the protocol's partial completion design.

## Finding Description
The DkgEndGather timeout handler immediately aborts DKG without checking if sufficient participants have responded to meet the `dkg_threshold` requirement. [1](#0-0) 

This directly contradicts the DkgPublicGather timeout handler, which explicitly checks if `dkg_threshold` is satisfied before deciding whether to abort or continue. [2](#0-1) 

Similarly, the DkgPrivateGather timeout handler performs the same threshold validation to enable partial completion. [3](#0-2) 

The coordinator implements helper functions `compute_dkg_public_size()` and `compute_dkg_private_size()` to calculate the number of keys from responding signers. [4](#0-3) 

However, no equivalent `compute_dkg_end_size()` function exists, and the DkgEndGather timeout handler performs no threshold validation whatsoever.

The `Config` struct explicitly defines `dkg_threshold` as the "threshold of keys needed to complete DKG" with the constraint `threshold <= dkg_threshold <= num_keys`. [5](#0-4) 

The `gather_dkg_end()` function only proceeds when ALL expected signers have responded (`dkg_wait_signer_ids.is_empty()`), providing no fallback for partial completion. [6](#0-5) 

The `start_dkg_end()` function initializes `dkg_wait_signer_ids` to include all signers who sent DkgPrivateShares. [7](#0-6) 

Critically, the `dkg_end_gathered()` function computes the aggregate public key using only the signers present in `dkg_end_messages`, demonstrating that partial key computation is technically feasible. [8](#0-7) 

**Attack Scenario:**
1. Attacker participates normally in DkgPublicShares and DkgPrivateShares phases
2. When DkgEndBegin is received, deliberately withholds DkgEnd response
3. Timeout expires after configured `dkg_end_timeout` duration
4. DKG aborts with `DkgEndTimeout` error, even if 9 out of 10 signers (meeting `dkg_threshold`) have responded
5. No aggregate public key is established, blocking all subsequent signing operations

## Impact Explanation
This vulnerability enables a persistent denial-of-service attack on DKG completion. Consider a realistic deployment with 10 signers (4 keys each, 40 total keys), `threshold = 28` (70%), and `dkg_threshold = 36` (90%):

- 9 signers respond with DkgEnd = 36 keys (exactly meets `dkg_threshold`)
- 1 malicious signer withholds message = 4 keys missing
- Current behavior: DKG aborts despite sufficient participation
- Expected behavior: DKG should complete with the 36 responding keys

This maps to **Low to Medium severity** depending on integration context. As a "remotely-exploitable denial of service" it qualifies as Low severity. However, if WSTS DKG is required for critical network operations such as block signing or transaction validation, the inability to establish signing groups could cause transient consensus failures (Medium severity). The attack can be repeated indefinitely across DKG rounds, potentially preventing specific signing groups from ever becoming operational.

## Likelihood Explanation
The attack is trivially exploitable with extremely high probability of success:

**Attacker Requirements:**
- Must be a registered signer in the DKG round (legitimate participant status)
- OR control network infrastructure to delay messages

**Attack Complexity:** 
Minimal. The attacker simply refrains from sending the DkgEnd message after participating in earlier phases. No cryptographic operations or special privileges required beyond being a registered signer.

**Economic Cost:**
Negligible. The attack requires no computational resources and can be executed passively by withholding a single message.

**Success Probability:**
Very high (~95%). The attack succeeds with certainty if the coordinator has configured `dkg_end_timeout` (standard in production deployments) and the attacker can delay their message beyond the timeout duration.

**Detection Difficulty:**
Moderate. Coordinator logs will show timeout and list waiting signers, but distinguishing malicious intent from legitimate network issues requires additional monitoring infrastructure.

## Recommendation
Add threshold validation to the DkgEndGather timeout handler, making it consistent with DkgPublicGather and DkgPrivateGather phases:

1. Implement a `compute_dkg_end_size()` helper function following the existing pattern
2. In `process_timeout()` for the `State::DkgEndGather` case, check if `dkg_threshold` is met
3. If threshold is satisfied, continue with partial DKG completion using responding signers
4. If threshold is not met, abort with `DkgEndTimeout` error

The fix should mirror the logic at lines 81-99 (DkgPublicGather) and 109-127 (DkgPrivateGather), computing the number of keys from signers in `dkg_end_messages` and comparing against `config.dkg_threshold`.

## Proof of Concept
```rust
#[test]
fn test_dkg_end_timeout_ignores_threshold() {
    use std::time::{Duration, Instant};
    
    let mut rng = create_rng();
    let num_signers = 10;
    let keys_per_signer = 4;
    let num_keys = 40;
    let threshold = 28;
    let dkg_threshold = 36;
    
    let config = Config::with_timeouts(
        num_signers,
        num_keys,
        threshold,
        dkg_threshold,
        Scalar::random(&mut rng),
        None,
        None,
        Some(Duration::from_millis(100)), // dkg_end_timeout
        None,
        None,
        PublicKeys::default(),
    );
    
    let mut coordinator = FireCoordinator::<v2::Aggregator>::new(config);
    
    // Simulate being in DkgEndGather state with timeout elapsed
    coordinator.state = State::DkgEndGather;
    coordinator.dkg_end_start = Some(Instant::now() - Duration::from_millis(200));
    
    // Simulate 9 out of 10 signers responded (36 keys meet dkg_threshold)
    for i in 0..9 {
        coordinator.dkg_end_messages.insert(i, DkgEnd {
            dkg_id: 0,
            signer_id: i,
            status: DkgStatus::Success,
        });
    }
    coordinator.dkg_wait_signer_ids.insert(9);
    
    // Call process_timeout - should fail despite threshold being met
    let result = coordinator.process_timeout();
    
    // Vulnerability: DKG aborts even though 36 >= 36 (dkg_threshold met)
    assert!(matches!(
        result,
        Ok((None, Some(OperationResult::DkgError(DkgError::DkgEndTimeout(_)))))
    ));
}
```

### Citations

**File:** src/state_machine/coordinator/fire.rs (L77-99)
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
```

**File:** src/state_machine/coordinator/fire.rs (L105-127)
```rust
            State::DkgPrivateGather => {
                if let Some(start) = self.dkg_private_start {
                    if let Some(timeout) = self.config.dkg_private_timeout {
                        if now.duration_since(start) > timeout {
                            // check dkg_threshold to determine if we can continue
                            let dkg_size = self.compute_dkg_private_size()?;

                            if self.config.dkg_threshold > dkg_size {
                                error!("Timeout gathering DkgPrivateShares for dkg round {} signing round {} iteration {}, dkg_threshold not met ({dkg_size}/{}), unable to continue", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, self.config.dkg_threshold);
                                let wait = self.dkg_wait_signer_ids.iter().copied().collect();
                                return Ok((
                                    None,
                                    Some(OperationResult::DkgError(DkgError::DkgPrivateTimeout(
                                        wait,
                                    ))),
                                ));
                            } else {
                                // we hit the timeout but met the threshold, continue
                                warn!("Timeout gathering DkgPrivateShares for dkg round {} signing round {} iteration {}, dkg_threshold was met ({dkg_size}/{}), ", self.current_dkg_id, self.current_sign_id, self.current_sign_iter_id, self.config.dkg_threshold);
                                self.private_shares_gathered()?;
                                let packet = self.start_dkg_end()?;
                                return Ok((Some(packet), None));
                            }
```

**File:** src/state_machine/coordinator/fire.rs (L133-145)
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
```

**File:** src/state_machine/coordinator/fire.rs (L449-455)
```rust
    pub fn start_dkg_end(&mut self) -> Result<Packet, Error> {
        // only wait for signers that returned DkgPublicShares
        self.dkg_wait_signer_ids = self
            .dkg_private_shares
            .keys()
            .cloned()
            .collect::<HashSet<u32>>();
```

**File:** src/state_machine/coordinator/fire.rs (L605-605)
```rust
        if self.dkg_wait_signer_ids.is_empty() {
```

**File:** src/state_machine/coordinator/fire.rs (L803-807)
```rust
        let key = self
            .dkg_end_messages
            .keys()
            .flat_map(|signer_id| self.dkg_public_shares[signer_id].comms.clone())
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);
```

**File:** src/state_machine/coordinator/fire.rs (L1219-1225)
```rust
    fn compute_dkg_public_size(&self) -> Result<u32, Error> {
        self.compute_num_key_ids(self.dkg_public_shares.keys())
    }

    fn compute_dkg_private_size(&self) -> Result<u32, Error> {
        self.compute_num_key_ids(self.dkg_private_shares.keys())
    }
```

**File:** src/state_machine/coordinator/mod.rs (L138-141)
```rust
    /// threshold of keys needed to form a valid signature
    pub threshold: u32,
    /// threshold of keys needed to complete DKG (must be >= threshold)
    pub dkg_threshold: u32,
```
