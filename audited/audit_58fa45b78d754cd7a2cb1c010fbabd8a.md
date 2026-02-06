### Title
Insecure Memory Cleanup in clear_polys() Allows Secret Recovery from Memory

### Summary
The `clear_polys()` function in both v1 and v2 implementations fails to securely zero out sensitive cryptographic material before deallocation. The function only sets polynomial fields to `None` without explicit memory zeroing, and completely ignores private keys and nonces. This allows attackers with memory access to recover polynomial coefficients, private keys, and nonces, potentially leading to complete signature forgery and loss of funds if threshold parties are compromised.

### Finding Description

**Exact Code Locations:**

In `src/v1.rs`, the `clear_poly()` method simply sets the polynomial to None: [1](#0-0) 

The v1 `Signer::clear_polys()` calls this for each party: [2](#0-1) 

In `src/v2.rs`, the implementation directly sets the polynomial to None: [3](#0-2) 

**Sensitive Data Structures:**

The v1 Party struct contains sensitive fields that are not properly cleared: [4](#0-3) 

The v2 Party struct similarly contains uncleared sensitive data: [5](#0-4) 

The Nonce struct contains two Scalar values that remain in memory: [6](#0-5) 

**Root Cause:**

1. **No explicit memory zeroing**: The implementations rely on Rust's default `Drop` behavior by setting fields to `None`. When Rust deallocates memory, it does not zero the contents, leaving sensitive data in deallocated memory until overwritten.

2. **No zeroize crate usage**: The project dependencies show no use of cryptographic memory zeroing libraries: [7](#0-6) 

3. **Incomplete clearing**: The function name `clear_polys()` only addresses polynomials, but leaves `private_key`/`private_keys` and `nonce` fields completely untouched in the Party structures.

4. **External dependencies**: The `Polynomial<Scalar>` type from the `polynomial` crate (v0.2.5) is a general-purpose library not designed for cryptographic use and unlikely to implement secure memory zeroing.

**Why Existing Mitigations Fail:**

No mitigations exist. The codebase has:
- No Drop trait implementations for secure zeroing
- No use of volatile writes or zeroize crate
- No explicit zeroing of sensitive fields
- No documentation indicating secure cleanup is handled elsewhere

### Impact Explanation

**Specific Harm:**

An attacker who gains memory access can recover:
1. **Polynomial coefficients**: Used in DKG to derive each party's private key contribution
2. **Private keys**: Direct ability to forge signature shares for compromised parties
3. **Nonces**: Could enable nonce-reuse attacks or private key recovery

**Quantified Impact:**

- **Single party compromise**: Attacker can forge signature shares for that party
- **Threshold party compromise**: If attacker recovers secrets from ≥ threshold parties, they gain complete signature forgery capability
- **Example scenario**: For a 7-of-10 threshold, compromising memory from 7 parties gives full control over all signatures

**Who Is Affected:**

- Any WSTS deployment protecting cryptocurrency wallets (direct loss of funds)
- Stacks blockchain nodes using WSTS for consensus (invalid transaction confirmation)
- Multi-signature setups relying on WSTS for authorization

**Severity Justification:**

This maps to **Critical** severity under the protocol scope:
- "Any causing the direct loss of funds" - Recovered keys enable unauthorized fund transfers
- "Any confirmation of an invalid transaction" - Forged signatures can authorize invalid transactions
- The vulnerability enables complete bypass of threshold signature security if threshold parties are compromised

### Likelihood Explanation

**Required Attacker Capabilities:**

1. **Memory access** via one of these vectors:
   - System/process crash producing core dumps
   - VM/container snapshots in cloud environments
   - Swap files or hibernation files on disk
   - Physical access to machines (cold boot attacks)
   - Exploitation of separate memory disclosure vulnerability
   - Insider threat with system-level access

2. **Technical capability** to:
   - Parse memory dumps or snapshots
   - Identify scalar values and polynomial structures
   - Reconstruct keys from memory patterns

3. **Timing**: Access memory before it's overwritten (varies by system load)

**Attack Complexity:**

- **Medium**: Requires memory access but no cryptographic breaks
- Core dump analysis tools are readily available
- Memory forensics is well-documented
- Cloud snapshot extraction is straightforward with proper access

**Economic Feasibility:**

- **High**: In cloud environments, snapshots are routine and often stored indefinitely
- Cost is primarily gaining access to storage/backup systems
- Return is potentially complete wallet/key control

**Detection Risk:**

- **Low**: Memory extraction often leaves no trace
- Snapshot access may appear as normal administrative activity
- Core dumps are expected system behavior

**Estimated Probability:**

- **Medium to High** in production environments where:
  - Core dumps are enabled (common for debugging)
  - VM snapshots are used for backups (standard cloud practice)
  - Physical security is not perfect
  - Multiple attack vectors exist simultaneously

### Recommendation

**Primary Fix - Implement Secure Memory Zeroing:**

1. Add the `zeroize` crate to dependencies:
```toml
zeroize = { version = "1.7", features = ["derive"] }
```

2. Implement `Zeroize` and `ZeroizeOnDrop` for sensitive types or manually zero memory in `clear_polys()` using `zeroize::Zeroize::zeroize()` on:
   - Polynomial coefficients before dropping
   - All private key fields
   - All nonce fields

3. Rename and expand function to `clear_secrets()` to reflect complete cleanup scope

**Specific Code Changes:**

For `src/v1.rs`:
- In `Party::clear_poly()`: Before setting `self.f = None`, if polynomial exists, manually zero each coefficient
- Add `Party::clear_secrets()` method that zeros: polynomial, private_key, nonce
- Update `Signer::clear_polys()` to call `clear_secrets()` instead

For `src/v2.rs`:
- Before `self.f = None`, manually zero polynomial coefficients
- Zero all entries in `private_keys` HashMap
- Zero `nonce` fields
- Consider implementing Drop trait for Party to ensure automatic cleanup

**Testing Recommendations:**

1. Write tests that verify memory is zeroed:
   - Capture memory addresses of secrets before clearing
   - Call clear function
   - Verify those addresses contain zeros
   
2. Use memory debugging tools (valgrind, sanitizers) to verify no secret leakage

3. Test that serialization/deserialization doesn't bypass zeroing

**Deployment Considerations:**

- This is a breaking change requiring coordination across all WSTS users
- Ensure all parties upgrade simultaneously to maintain compatibility
- Add clear documentation about when `clear_secrets()` must be called
- Consider adding automatic cleanup via Drop trait as defense-in-depth

### Proof of Concept

**Exploitation Algorithm:**

```
1. Prerequisites:
   - WSTS signer process running in target environment
   - Ability to trigger core dump OR access to VM snapshots

2. Trigger memory capture:
   a. For core dumps: Send SIGSEGV to process or wait for crash
   b. For VM snapshots: Access cloud provider snapshot API
   c. For swap: Wait for memory pressure to swap pages to disk
   
3. Extract memory:
   - Obtain core dump file, VM snapshot, or disk image
   - Use memory forensics tools (volatility, strings, hexdump)
   
4. Locate secrets:
   - Search for 32-byte aligned scalar values
   - Polynomial coefficients appear as arrays of scalars
   - Private keys appear as single scalar values
   - Nonces appear as pairs of scalar values
   
5. Reconstruct keys:
   - Parse polynomial coefficients from Party.f field
   - Extract private_key/private_keys directly
   - Extract nonce.d and nonce.e values
   
6. Forge signatures:
   - Use recovered private keys to create signature shares
   - If >= threshold parties compromised, forge complete signatures
   - Submit unauthorized transactions
```

**Expected vs Actual Behavior:**

- **Expected**: After calling `clear_polys()`, all sensitive cryptographic material is securely zeroed in memory
- **Actual**: Sensitive data remains in deallocated memory, recoverable via memory access

**Reproduction Steps:**

1. Initialize WSTS signer with DKG
2. Note memory address of polynomial coefficients (via debugger)
3. Call `signer.clear_polys()`
4. Examine memory at noted addresses
5. Observe: polynomial coefficients still present in memory
6. Observe: private keys and nonces completely untouched
7. With sufficient compromised parties (>= threshold), use recovered keys to forge signatures

**Parameter Values for Testing:**

- Threshold: 7, Total parties: 10
- Compromise 7 parties' memory
- Recover all 7 private keys or polynomial coefficients
- Demonstrates complete signature forgery capability

### Citations

**File:** src/v1.rs (L23-38)
```rust
#[derive(Clone, Eq, PartialEq)]
/// A FROST party, which encapsulates a single polynomial, nonce, and key
pub struct Party {
    /// The ID
    pub id: u32,
    /// The public key
    pub public_key: Point,
    /// The polynomial used for Lagrange interpolation
    pub f: Option<Polynomial<Scalar>>,
    num_keys: u32,
    threshold: u32,
    private_key: Scalar,
    /// The aggregate group public key
    pub group_key: Point,
    nonce: Nonce,
}
```

**File:** src/v1.rs (L131-133)
```rust
    pub fn clear_poly(&mut self) {
        self.f = None;
    }
```

**File:** src/v1.rs (L634-638)
```rust
    fn clear_polys(&mut self) {
        for party in self.parties.iter_mut() {
            party.clear_poly();
        }
    }
```

**File:** src/v2.rs (L23-38)
```rust
#[derive(Clone, Eq, PartialEq)]
/// A WSTS party, which encapsulates a single polynomial, nonce, and one private key per key ID
pub struct Party {
    /// The party ID
    pub party_id: u32,
    /// The key IDs for this party
    pub key_ids: Vec<u32>,
    /// The public keys for this party, indexed by ID
    num_keys: u32,
    num_parties: u32,
    threshold: u32,
    f: Option<Polynomial<Scalar>>,
    private_keys: HashMap<u32, Scalar>,
    group_key: Point,
    nonce: Nonce,
}
```

**File:** src/v2.rs (L587-589)
```rust
    fn clear_polys(&mut self) {
        self.f = None;
    }
```

**File:** src/common.rs (L52-59)
```rust
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
/// A composite private nonce used as a random commitment in the protocol
pub struct Nonce {
    /// The first committed value
    pub d: Scalar,
    /// The second committed value
    pub e: Scalar,
}
```

**File:** Cargo.toml (L19-34)
```text
[dependencies]
aes-gcm = "0.10"
bs58 = "0.5"
elliptic-curve = { version = "0.13.8", features = ["hash2curve"] }
hashbrown = { version = "0.14", features = ["serde"] }
hex = "0.4.3"
num-traits = "0.2"
polynomial = { version = "0.2.5", features = ["serde"] }
primitive-types = "0.12"
rand_core = "0.6"
p256k1 = { version = "7.2", default-features = false }
serde = { version = "1.0", features = ["derive"] }
sha2 = "0.10"
thiserror = "1.0"
tracing = "0.1.37"
tracing-subscriber = { version = "0.3.17", features = ["env-filter"] }
```
