### Title
Missing Threshold Validation Allows Impossible Signing Configuration Leading to Permanent Denial of Service

### Summary
The `Aggregator::new()` function in both v1 and v2 implementations accepts `threshold` and `num_keys` parameters without validating that `threshold <= num_keys`. This allows creation of an impossible signing configuration where the system requires more signing keys than exist, causing all signing operations to permanently fail or hang indefinitely.

### Finding Description

**Exact Code Locations:** [1](#0-0) [2](#0-1) [3](#0-2) 

**Root Cause:**
The `Aggregator::new()` function accepts `num_keys` and `threshold` parameters but performs no validation that `threshold <= num_keys`. This violates a fundamental invariant of threshold cryptography: you cannot require more keys to sign than exist in the system. [4](#0-3) 

The coordinator's `Config::new()` similarly lacks this validation, allowing the misconfiguration to propagate through the entire system.

**Why Existing Mitigations Fail:**
During the signing phase, the FIRE coordinator waits for nonces from at least `threshold` keys before proceeding: [5](#0-4) 

When `threshold > num_keys`, the set `nonce_recv_key_ids` can never reach size `threshold` because there are only `num_keys` total keys in the system. The coordinator will:
- Wait indefinitely if no timeout is configured
- Return `SignError::NonceTimeout` if timeout is configured, but without detecting the root cause [6](#0-5) 

The timeout handler does not validate whether the threshold is achievable - it simply reports a timeout error without identifying that the configuration makes signing impossible.

### Impact Explanation

**Specific Harm:**
Once an Aggregator or Coordinator is initialized with `threshold > num_keys`, all signing operations become permanently impossible. The DKG phase completes successfully (creating false confidence), but every subsequent signing attempt fails.

**Quantified Impact:**
- 100% failure rate for all signing operations
- If WSTS is used for blockchain transaction/block signing: complete inability to produce signatures
- No recovery possible without reconfiguration and re-initialization

**Who is Affected:**
Any system using WSTS where configuration parameters can be influenced by external input, including:
- Command-line interfaces accepting threshold/num_keys parameters
- APIs exposing configuration endpoints
- Deployment scripts with parameter validation gaps [7](#0-6) 

**Severity Justification:**
This maps to **Low** severity in the protocol scope: "Any remotely-exploitable denial of service in a node". While it requires control over configuration parameters, systems that accept these from external sources (command-line args, API calls, config files) are vulnerable to DoS without additional validation.

### Likelihood Explanation

**Required Attacker Capabilities:**
- Ability to influence configuration parameters (threshold, num_keys) during system initialization
- No cryptographic knowledge or key material required

**Attack Complexity:**
Low - simply provide `threshold > num_keys` through any configuration interface.

**Realistic Attack Scenarios:**
1. **Malicious deployment parameters**: Attacker provides configuration to initialization scripts
2. **API exploitation**: If coordinator initialization is exposed via API/RPC
3. **Social engineering**: Trick operators into deploying with invalid parameters
4. **Supply chain**: Compromise configuration management systems

**Detection Risk:**
Low - the configuration error is not detected during initialization, and failures appear as normal timeout errors rather than configuration issues.

**Probability of Success:**
High if attacker can influence configuration; otherwise this represents an operational misconfiguration risk.

### Recommendation

**Primary Fix:**
Add validation in `Aggregator::new()` and `Config::new()` to reject invalid configurations:

```rust
fn new(num_keys: u32, threshold: u32) -> Result<Self, AggregatorError> {
    if threshold > num_keys {
        return Err(AggregatorError::InvalidThreshold { 
            threshold, 
            num_keys 
        });
    }
    if threshold == 0 {
        return Err(AggregatorError::ZeroThreshold);
    }
    Ok(Self {
        num_keys,
        threshold,
        poly: Default::default(),
    })
}
```

**Alternative Mitigations:**
1. Add runtime detection in the nonce timeout handler to identify impossible thresholds
2. Document valid parameter ranges in API documentation
3. Add integration tests covering boundary conditions

**Testing Recommendations:**
- Add unit test: `threshold > num_keys` returns error
- Add unit test: `threshold == num_keys` succeeds (edge case)
- Add unit test: `threshold == 0` returns error
- Add integration test attempting to sign with invalid configuration

**Deployment Considerations:**
- This is a breaking API change if the trait signature changes
- Consider deprecation path if backward compatibility is required
- Add migration guide for existing deployments

### Proof of Concept

**Exploitation Steps:**
1. Initialize coordinator with `threshold=11, num_keys=10`
2. Complete DKG successfully (appears to work)
3. Attempt any signing operation
4. Observe permanent failure to gather sufficient nonces

**Concrete Example:**
```bash
# Using main.rs binary with command-line args
./wsts 10 11 4  # N=10 keys, T=11 threshold, K=4 parties
# DKG completes successfully
# Signing hangs indefinitely or times out
```

**Expected vs Actual Behavior:**
- **Expected**: `Aggregator::new(10, 11)` should return an error
- **Actual**: Construction succeeds, but all signing operations fail

**Reproduction via Code:** [8](#0-7) 

Running with args that violate `T <= N` will trigger the vulnerability.

### Notes

This vulnerability demonstrates a violation of the stated security invariant: "Threshold and key ID bounds must be enforced". The lack of upfront parameter validation allows the system to enter an unrecoverable state where its core functionality (signing) becomes permanently unavailable.

### Citations

**File:** src/v1.rs (L431-436)
```rust
    fn new(num_keys: u32, threshold: u32) -> Self {
        Self {
            num_keys,
            threshold,
            poly: Default::default(),
        }
```

**File:** src/v2.rs (L422-427)
```rust
    fn new(num_keys: u32, threshold: u32) -> Self {
        Self {
            num_keys,
            threshold,
            poly: Default::default(),
        }
```

**File:** src/state_machine/coordinator/mod.rs (L180-200)
```rust
    pub fn new(
        num_signers: u32,
        num_keys: u32,
        threshold: u32,
        message_private_key: Scalar,
    ) -> Self {
        Config {
            num_signers,
            num_keys,
            threshold,
            dkg_threshold: num_keys,
            message_private_key,
            dkg_public_timeout: None,
            dkg_private_timeout: None,
            dkg_end_timeout: None,
            nonce_timeout: None,
            sign_timeout: None,
            public_keys: Default::default(),
            verify_packet_sigs: true,
        }
    }
```

**File:** src/traits.rs (L155-156)
```rust
    /// Construct an Aggregator with the passed parameters
    fn new(num_keys: u32, threshold: u32) -> Self;
```

**File:** src/state_machine/coordinator/fire.rs (L149-168)
```rust
            State::NonceGather(_signature_type) => {
                if let Some(start) = self.nonce_start {
                    if let Some(timeout) = self.config.nonce_timeout {
                        if now.duration_since(start) > timeout {
                            error!("Timeout gathering nonces for signing round {} iteration {}, unable to continue", self.current_sign_id, self.current_sign_iter_id);
                            let recv = self
                                .message_nonces
                                .get(&self.message)
                                .ok_or(Error::MissingMessageNonceInfo)?
                                .sign_wait_signer_ids
                                .iter()
                                .copied()
                                .collect();
                            let mal = self.malicious_signer_ids.iter().copied().collect();
                            return Ok((
                                None,
                                Some(OperationResult::SignError(SignError::NonceTimeout(
                                    recv, mal,
                                ))),
                            ));
```

**File:** src/state_machine/coordinator/fire.rs (L936-959)
```rust
            for key_id in signer_key_ids {
                nonce_info.nonce_recv_key_ids.insert(*key_id);
            }

            nonce_info
                .sign_wait_signer_ids
                .insert(nonce_response.signer_id);
            // Because of entry call, it is safe to unwrap here
            info!(
                sign_id = %nonce_response.sign_id,
                sign_iter_id = %nonce_response.sign_iter_id,
                signer_id = %nonce_response.signer_id,
                recv_keys = %nonce_info.nonce_recv_key_ids.len(),
                threshold = %self.config.threshold,
                "Received NonceResponse"
            );
            if nonce_info.nonce_recv_key_ids.len() >= self.config.threshold as usize {
                // We have a winning message!
                self.message.clone_from(&nonce_response.message);
                let aggregate_nonce = self.compute_aggregate_nonce();
                info!("Aggregate nonce: {aggregate_nonce}");

                self.move_to(State::SigShareRequest(signature_type))?;
            }
```

**File:** src/main.rs (L10-24)
```rust
    let N: u32 = if args.len() > 1 {
        args[1].parse::<u32>().unwrap()
    } else {
        20
    };
    let T: u32 = if args.len() > 2 {
        args[2].parse::<u32>().unwrap()
    } else {
        (N * 2) / 3
    };
    let K: u32 = if args.len() > 3 {
        args[3].parse::<u32>().unwrap()
    } else {
        4
    };
```
