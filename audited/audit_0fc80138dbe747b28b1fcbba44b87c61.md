### Title
Private Share Memory Exposure After DkgPrivateTimeout - Lack of Secure Memory Zeroization

### Summary
When `DkgPrivateTimeout` occurs during DKG, signers that have already received and decrypted private shares retain plaintext cryptographic material in memory without secure zeroization. The `decrypted_shares` HashMap containing sensitive Scalar values (private polynomial evaluations) persists until the next DKG round, creating a window where memory dumps or exploits could expose threshold signature private key material.

### Finding Description

**Exact Code Location:**

The vulnerability exists in the signer state machine's handling of decrypted private shares: [1](#0-0) 

When signers receive DkgPrivateShares messages, they decrypt and store the plaintext shares: [2](#0-1) 

The coordinator's timeout handling returns an error but does not trigger cleanup: [3](#0-2) 

The timeout error is defined as: [4](#0-3) 

**Root Cause:**

The signer's `decrypted_shares` field stores plaintext Scalar values representing private polynomial evaluations f_i(key_id). When DkgPrivateTimeout occurs:

1. The coordinator detects timeout and returns `DkgError::DkgPrivateTimeout` with only signer IDs
2. Signers that already received and processed DkgPrivateShares retain decrypted values in memory
3. No cleanup or zeroization is triggered on timeout
4. The `reset()` method that clears these values is only called when starting a new DKG round: [5](#0-4) 

**Why Existing Mitigations Fail:**

1. **No Zeroization:** The codebase does not use the `zeroize` crate or implement secure memory erasure. A grep search confirms zero matches for "zeroize" in the codebase.

2. **HashMap.clear() is insufficient:** The reset method calls `.clear()` on HashMaps, which removes entries but does not guarantee secure erasure of the underlying memory containing Scalar values.

3. **SavedState also affected:** Both the active `Signer` struct and `SavedState` contain the `decrypted_shares` field with no Drop implementations for secure cleanup: [6](#0-5) 

4. **External dependency:** The Scalar type comes from the p256k1 crate (version 7.2), and while it may implement Drop, the HashMap container's behavior and timing of cleanup is not guaranteed to be secure. [7](#0-6) 

### Impact Explanation

**Specific Harm:**

An attacker who gains memory access to signer processes can extract plaintext private polynomial shares. With threshold number of shares, the attacker can:
- Reconstruct private keys for specific key IDs
- Sign arbitrary messages as if they were legitimate threshold participants
- Potentially forge transactions in systems using WSTS (like Stacks blockchain)

**Quantified Impact:**

Consider a 5-signer setup with threshold=3:
- DkgPrivateTimeout occurs with 2 signers timing out
- 3 signers have decrypted shares in memory from each other
- Attacker compromises memory from 3 signers (threshold reached)
- Attacker extracts `decrypted_shares[party_id][key_id] = Scalar` for all parties
- With 3 shares per key_id, attacker can interpolate the secret polynomial and reconstruct private keys
- This enables signing of fraudulent transactions

**Who is Affected:**

- All signers that successfully received DkgPrivateShares before timeout
- Any blockchain or system relying on WSTS for threshold signatures
- Particularly critical for Stacks blockchain integration

**Severity Justification:**

This maps to **High** severity per the protocol scope:
- "Any remotely-exploitable memory access, disk access, or persistent code execution" - The memory leak can be exploited through memory dumps (core dumps, crash reports, swap files) or memory read exploits
- Could escalate to **Critical** if it enables "confirmation of an invalid transaction" through key compromise

### Likelihood Explanation

**Required Attacker Capabilities:**

1. **Memory access to signer process(es):**
   - Physical access to dump memory
   - Remote exploit enabling memory reads (buffer overflow, etc.)
   - Access to core dumps, crash dumps, or swap files
   - Cloud environment with snapshot capabilities

2. **DkgPrivateTimeout occurrence:**
   - Network partition or latency
   - Signer crashes or unavailability
   - Configured timeout values being reached

3. **Timing window:**
   - Attack must occur after timeout but before next DKG round
   - Window depends on application's error handling and retry logic

**Attack Complexity:**

- **Medium:** Requires memory access which varies by deployment
- Physical access: High barrier but possible for insider threats
- Remote memory exploit: Requires additional vulnerability
- Core dumps: Often automatically generated on crashes (Low barrier)
- Swap files: May persist even after process termination (Low barrier)

**Economic Feasibility:**

- Profitable if WSTS is used for high-value transactions
- Cost depends on target environment security
- Core dump analysis is low-cost once obtained

**Detection Risk:**

- Memory dumps may be legitimate (debugging, monitoring)
- No cryptographic operation triggers detection
- Difficult to detect memory reads in progress

**Estimated Probability:**

- **Medium-Low** in hardened production environments
- **Medium-High** in development/testing environments with crash reporting
- **High** if combined with another memory disclosure vulnerability

### Recommendation

**Immediate Fixes:**

1. **Implement Zeroization:**
   - Add `zeroize` crate dependency to Cargo.toml
   - Wrap sensitive fields with `Zeroizing<T>` or implement custom Drop
   - Example for Signer struct:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
pub struct Signer<SignerType: SignerTrait> {
    // ... other fields ...
    #[zeroize(skip)]
    pub commitments: HashMap<u32, PolyCommitment>,
    /// Sensitive: must be zeroized
    decrypted_shares: HashMap<u32, HashMap<u32, Scalar>>,
    /// Sensitive: must be zeroized  
    decryption_keys: HashMap<u32, (u32, Point)>,
    /// Sensitive: must be zeroized
    kex_private_key: Scalar,
    // ... other fields ...
}
```

2. **Explicit Cleanup on Timeout:**
   - Add a cleanup method that zeroizes sensitive fields
   - Call this method when returning DkgPrivateTimeout error
   - Ensure coordinator notifies signers to cleanup on timeout

3. **Secure HashMap Handling:**
   - Consider using custom HashMap implementations that zeroize on drop
   - Or manually iterate and zeroize each Scalar before clearing

**Alternative Mitigations:**

1. **Memory Protection:**
   - Use `mlock()` to prevent swapping of sensitive memory pages
   - Enable memory encryption where available

2. **Timeout Handling:**
   - Implement automatic cleanup after timeout errors
   - Add explicit reset() call in error handling paths

**Testing Recommendations:**

1. Create unit test that:
   - Triggers DkgPrivateTimeout with partial shares received
   - Attempts to read memory after timeout
   - Verifies all Scalar values are zeroed

2. Integration test simulating memory dump scenario

3. Fuzzing timeout conditions to ensure cleanup occurs

**Deployment Considerations:**

1. **Backward Compatibility:** Adding zeroization is transparent to API consumers
2. **Performance:** Zeroization overhead is negligible compared to crypto operations
3. **Priority:** High - Should be addressed before production deployment
4. **Audit:** Verify p256k1 Scalar type also implements secure erasure

### Proof of Concept

**Exploitation Steps:**

1. **Setup:** Deploy 5 signers with threshold=3, DKG private timeout=30s

2. **Trigger Timeout:**
   ```
   - Start DKG round, all signers send DkgPublicShares
   - Coordinator sends DkgPrivateBegin
   - Signers 0,1,2 send DkgPrivateShares to each other
   - Signers 3,4 are blocked (network partition or crash)
   - Wait 30 seconds for timeout
   - Coordinator returns DkgPrivateTimeout([3, 4])
   ```

3. **Memory State After Timeout:**
   ```
   Signer 0 memory contains:
   - decrypted_shares[party_1][key_0] = Scalar(f_1(0))  
   - decrypted_shares[party_1][key_1] = Scalar(f_1(1))
   - decrypted_shares[party_2][key_0] = Scalar(f_2(0))
   - decrypted_shares[party_2][key_1] = Scalar(f_2(1))
   - kex_private_key = Scalar(ephemeral_key)
   
   Similarly for Signers 1 and 2
   ```

4. **Memory Extraction:**
   ```bash
   # Trigger crash to generate core dump
   kill -SIGSEGV <signer_0_pid>
   
   # Or access memory directly
   gdb -p <signer_0_pid>
   (gdb) dump memory dump.bin 0x<heap_start> 0x<heap_end>
   ```

5. **Share Reconstruction:**
   ```
   From dumps of Signers 0, 1, 2:
   - Extract all decrypted_shares HashMap contents
   - For each key_id, collect f_i(key_id) from 3+ parties
   - Use Lagrange interpolation to reconstruct f(0) = private_key
   ```

6. **Key Compromise:**
   ```
   With reconstructed private keys:
   - Sign arbitrary messages
   - Forge transactions
   - Impersonate threshold signature group
   ```

**Expected vs Actual Behavior:**

- **Expected:** After DkgPrivateTimeout, all decrypted shares should be securely erased from memory
- **Actual:** Plaintext Scalar values persist in memory until next DKG round or process termination

**Reproduction Instructions:**

1. Build WSTS with debug symbols: `cargo build --features testing`
2. Run integration test with timeout: Set `dkg_private_timeout = Duration::from_secs(5)`
3. In test, simulate 2 signers not responding after DkgPrivateBegin
4. After timeout error returned, attach debugger to remaining signers
5. Inspect memory for HashMap at `decrypted_shares` address
6. Verify Scalar values are still present and readable
7. Compare with behavior after calling `reset()` - values should be cleared

### Citations

**File:** src/state_machine/signer/mod.rs (L138-140)
```rust
    /// map of decrypted DKG private shares
    /// src_party_id => (dst_key_id => private_share)
    decrypted_shares: HashMap<u32, HashMap<u32, Scalar>>,
```

**File:** src/state_machine/signer/mod.rs (L221-223)
```rust
    /// map of decrypted DKG private shares
    /// src_party_id => (dst_key_id => private_share)
    pub decrypted_shares: HashMap<u32, HashMap<u32, Scalar>>,
```

**File:** src/state_machine/signer/mod.rs (L417-432)
```rust
    pub fn reset<T: RngCore + CryptoRng>(&mut self, dkg_id: u64, rng: &mut T) {
        self.dkg_id = dkg_id;
        self.commitments.clear();
        self.decrypted_shares.clear();
        self.decryption_keys.clear();
        self.invalid_private_shares.clear();
        self.public_nonces.clear();
        self.signer.reset_polys(rng);
        self.dkg_public_shares.clear();
        self.dkg_private_shares.clear();
        self.dkg_private_begin_msg = None;
        self.dkg_end_begin_msg = None;
        self.kex_private_key = Scalar::random(rng);
        self.kex_public_keys.clear();
        self.state = State::Idle;
    }
```

**File:** src/state_machine/signer/mod.rs (L1028-1110)
```rust
    /// handle incoming DkgPrivateShares
    pub fn dkg_private_shares<R: RngCore + CryptoRng>(
        &mut self,
        dkg_private_shares: &DkgPrivateShares,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        // go ahead and decrypt here, since we know the signer_id and hence the pubkey of the sender
        let src_signer_id = dkg_private_shares.signer_id;

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

        if self.dkg_private_shares.contains_key(&src_signer_id) {
            info!(signer_id = %dkg_private_shares.signer_id, "received duplicate DkgPrivateShares");
            return Ok(vec![]);
        }

        self.dkg_private_shares
            .insert(src_signer_id, dkg_private_shares.clone());

        // make a HashSet of our key_ids so we can quickly query them
        let key_ids: HashSet<u32> = self.signer.get_key_ids().into_iter().collect();

        let shared_key = self.kex_private_key * kex_public_key;
        let shared_secret = make_shared_secret(&self.kex_private_key, &kex_public_key);

        for (src_id, shares) in &dkg_private_shares.shares {
            let mut decrypted_shares = HashMap::new();
            for (dst_key_id, bytes) in shares {
                if key_ids.contains(dst_key_id) {
                    match decrypt(&shared_secret, bytes) {
                        Ok(plain) => match Scalar::try_from(&plain[..]) {
                            Ok(s) => {
                                decrypted_shares.insert(*dst_key_id, s);
                            }
                            Err(e) => {
                                warn!("Failed to parse Scalar for dkg private share from src_id {src_id} to dst_id {dst_key_id}: {e:?}");
                                self.invalid_private_shares.insert(
                                    src_signer_id,
                                    self.make_bad_private_share(src_signer_id, rng)?,
                                );
                            }
                        },
                        Err(e) => {
                            warn!("Failed to decrypt dkg private share from src_id {src_id} to dst_id {dst_key_id}: {e:?}");
                            self.invalid_private_shares.insert(
                                src_signer_id,
                                self.make_bad_private_share(src_signer_id, rng)?,
                            );
                        }
                    }
                }
            }
            self.decrypted_shares.insert(*src_id, decrypted_shares);
            self.decryption_keys
                .insert(*src_id, (dkg_private_shares.signer_id, shared_key));
        }
        debug!(
            "received DkgPrivateShares from signer {} {}/{}",
            dkg_private_shares.signer_id,
            self.decrypted_shares.len(),
            self.signer.get_num_parties(),
        );
        Ok(vec![])
    }
```

**File:** src/state_machine/coordinator/fire.rs (L105-130)
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
                        }
                    }
                }
```

**File:** src/state_machine/mod.rs (L42-44)
```rust
    /// DKG private timeout
    #[error("DKG private timeout, waiting for {0:?}")]
    DkgPrivateTimeout(Vec<u32>),
```

**File:** Cargo.toml (L29-29)
```text
p256k1 = { version = "7.2", default-features = false }
```
