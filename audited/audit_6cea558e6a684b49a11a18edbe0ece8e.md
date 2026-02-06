### Title
Threshold t=1 Configuration Causes All Parties to Share Identical Private Keys Leading to Complete Loss of Distributed Trust

### Summary
When the threshold parameter `t=1` is configured, the WSTS DKG protocol degenerates into a state where all participating parties compute identical private keys instead of distributed key shares. This occurs because t=1 creates constant (degree-0) polynomials, causing all generated shares from each party to be identical across all recipients, completely defeating the distributed trust model and enabling any single compromised party to steal all funds controlled by the group key.

### Finding Description

The vulnerability exists in the polynomial generation logic used during Distributed Key Generation (DKG). When `Party::new()` is called with threshold `t=1`, it creates a degree-0 polynomial through the chain: `Party::new()` → `VSS::random_poly(t-1, rng)` → `VSS::random_poly(0, rng)`. [1](#0-0) [2](#0-1) 

A degree-0 polynomial is mathematically a constant function: f(x) = a₀. When `get_shares()` evaluates this polynomial at different party IDs to generate shares, all evaluations return the same constant value: [3](#0-2) 

For party i with constant polynomial f_i(x) = a_i:
- share for party 1: f_i(1) = a_i
- share for party 2: f_i(2) = a_i  
- share for party 3: f_i(3) = a_i
- All shares are identical = a_i

During DKG, each party broadcasts encrypted shares to all other parties. Because all shares from a given party are identical, every recipient party receives the exact same value from that source party. This means:
- Party 1 receives: {a₁, a₂, a₃, ..., aₙ}
- Party 2 receives: {a₁, a₂, a₃, ..., aₙ}
- Party 3 receives: {a₁, a₂, a₃, ..., aₙ}
- All parties receive identical share sets

In `compute_secret()`, each party sums all received shares to compute their private key: [4](#0-3) 

Since all parties receive identical shares, all parties compute the identical private key: `private_key = a₁ + a₂ + ... + aₙ`. The distributed key generation completely fails to distribute trust.

**Why existing mitigations fail**: The threshold validation in the state machine signer only rejects `t=0` and `t > total_keys`, but explicitly allows `t=1`: [5](#0-4) 

There is no validation preventing this degenerate case, no warning in documentation, and no runtime checks detecting that all parties have computed the same key.

### Impact Explanation

**Specific harm**: Complete compromise of the group private key when any single participant is compromised. In a 1-of-n threshold configuration with t=1:
- All n parties possess the full group private key (not shares, but the complete key)
- Any single compromised party enables an attacker to sign arbitrary transactions
- The "threshold signature" provides zero security over a single-party signature
- All funds controlled by the group key are immediately at risk if any participant is compromised

**Quantification**: In a WSTS deployment controlling Bitcoin funds via threshold signatures:
- With t=7 and n=10 (normal): 3 compromised parties still cannot reconstruct the key
- With t=1 and n=10 (vulnerable): 1 compromised party = full key compromise = 100% fund loss

**Who is affected**: Any WSTS deployment configured with threshold t=1, including:
- Stacks blockchain miners using WSTS for signing
- Bitcoin custody solutions using 1-of-n configurations for operational convenience
- Any system where an administrator mistakenly sets t=1

**Severity justification**: This maps to **CRITICAL** severity under the protocol scope definition: "Any causing the direct loss of funds other than through any form of freezing." A single compromised party in a t=1 configuration can directly steal all funds controlled by the group key by creating valid signatures for unauthorized transactions.

### Likelihood Explanation

**Required attacker capabilities**:
1. System administrator/deployer configures WSTS with t=1 (no special privileges required for configuration)
2. Attacker compromises any single participant's node/keys (through standard attack vectors: malware, social engineering, infrastructure compromise)

**Attack complexity**: Low
- No cryptographic breaks required
- No protocol manipulation needed  
- Standard key compromise techniques apply
- Once configured with t=1, the vulnerability is automatic

**Economic feasibility**: High
- Motivation: Direct theft of funds (e.g., Bitcoin custody)
- Cost: Standard compromise of single participant (varies by target hardening)
- Reward: Complete control of group-managed funds

**Detection risk**: Low during attack, High after
- The t=1 configuration itself is valid and passes all checks
- During DKG, all protocol messages appear normal (shares are encrypted)
- Compromise of a single party looks like a normal operational issue initially
- After funds are stolen, forensics would reveal the t=1 misconfiguration

**Estimated probability**: 
- If t=1 is used: Very High (100% if any party compromised)
- If t=1 is configured: Low to Medium (depends on deployment security practices)
- Overall: Low to Medium (because t=1 is nonsensical for distributed systems, but configuration mistakes happen)

### Recommendation

**Primary fix**: Add validation to reject threshold t=1 as an invalid configuration:

```rust
// In src/state_machine/signer/mod.rs, modify the threshold validation:
if threshold <= 1 || threshold > total_keys {
    return Err(Error::Config(ConfigError::InvalidThreshold));
}
```

**Rationale**: A 1-of-n threshold signature scheme provides no benefit over a single signature and creates severe security risks through the share identity issue. The minimum meaningful threshold is t=2.

**Alternative mitigations**:
1. Add runtime assertion in `Party::new()` to detect and reject t=1:
   ```rust
   pub fn new<RNG: RngCore + CryptoRng>(id: u32, n: u32, t: u32, rng: &mut RNG) -> Self {
       assert!(t >= 2, "threshold must be at least 2 to ensure distributed trust");
       // ... rest of function
   }
   ```

2. Add post-DKG validation to detect if all parties computed identical keys (defense in depth)

3. Add prominent documentation warning about minimum threshold requirements

**Testing recommendations**:
1. Add unit test verifying t=1 is rejected during signer creation
2. Add integration test attempting full DKG with t=1 and verifying it fails appropriately  
3. Test that t=2 (minimum valid threshold) works correctly
4. Add property test ensuring polynomial degree matches expected threshold-1

**Deployment considerations**:
- This is a breaking change for any systems already configured with t=1 (though such configurations are fundamentally insecure)
- Requires coordinated update of all WSTS nodes
- Should be accompanied by configuration validation tooling to catch invalid thresholds before deployment

### Proof of Concept

**Exploitation algorithm**:

1. **Setup**: Configure WSTS with n=5 parties, t=1 threshold
   ```
   Party 1, 2, 3, 4, 5 each with key_id = party_id
   threshold = 1, total_keys = 5
   ```

2. **DKG Phase - Polynomial Generation**:
   ```
   Party 1: f₁(x) = a₁ (constant, degree 0)
   Party 2: f₂(x) = a₂ (constant, degree 0)
   Party 3: f₃(x) = a₃ (constant, degree 0)
   Party 4: f₄(x) = a₄ (constant, degree 0)
   Party 5: f₅(x) = a₅ (constant, degree 0)
   ```

3. **Share Distribution**:
   ```
   Party 1 sends: f₁(1)=a₁, f₁(2)=a₁, f₁(3)=a₁, f₁(4)=a₁, f₁(5)=a₁
   Party 2 sends: f₂(1)=a₂, f₂(2)=a₂, f₂(3)=a₂, f₂(4)=a₂, f₂(5)=a₂
   ... (all shares from each party are identical)
   ```

4. **Share Receipt** (after decryption):
   ```
   Party 1 receives: {a₁, a₂, a₃, a₄, a₅}
   Party 2 receives: {a₁, a₂, a₃, a₄, a₅}
   Party 3 receives: {a₁, a₂, a₃, a₄, a₅}
   Party 4 receives: {a₁, a₂, a₃, a₄, a₅}
   Party 5 receives: {a₁, a₂, a₃, a₄, a₅}
   ```

5. **Private Key Computation**:
   ```
   All parties: private_key = a₁ + a₂ + a₃ + a₄ + a₅
   Result: All parties have IDENTICAL private keys
   ```

6. **Exploitation**: Attacker compromises Party 3
   ```
   - Attacker extracts Party 3's private_key
   - This private_key equals the group private key
   - Attacker can now sign any transaction as the group
   - All funds controlled by group_key are stolen
   ```

**Expected vs Actual Behavior**:
- **Expected**: Each party should have a unique share; t parties needed to reconstruct group key
- **Actual**: All parties have the complete group key; any 1 party can act as the entire group

**Reproduction instructions**:
1. Create a test with `threshold=1, num_keys=5`
2. Run complete DKG with 5 signers
3. Extract `private_key` from each signer's state after DKG
4. Compare keys: `assert_eq!(signer1.private_key, signer2.private_key)` - this will pass
5. Demonstrate that any single party can produce valid group signatures alone

This proof of concept demonstrates that t=1 fundamentally breaks the distributed trust model, making WSTS no more secure than a single-party signature system while creating a larger attack surface through multiple key holders.

### Citations

**File:** src/v1.rs (L54-65)
```rust
    pub fn new<RNG: RngCore + CryptoRng>(id: u32, n: u32, t: u32, rng: &mut RNG) -> Self {
        Self {
            id,
            num_keys: n,
            threshold: t,
            f: Some(VSS::random_poly(t - 1, rng)),
            private_key: Scalar::zero(),
            public_key: Point::zero(),
            group_key: Point::zero(),
            nonce: Nonce::zero(),
        }
    }
```

**File:** src/v1.rs (L136-147)
```rust
    pub fn get_shares(&self) -> HashMap<u32, Scalar> {
        if let Some(poly) = &self.f {
            let mut shares = HashMap::new();
            for i in 1..self.num_keys + 1 {
                shares.insert(i, poly.eval(compute::id(i)));
            }
            shares
        } else {
            warn!("get_shares called with no polynomial");
            Default::default()
        }
    }
```

**File:** src/v1.rs (L150-209)
```rust
    pub fn compute_secret(
        &mut self,
        private_shares: HashMap<u32, Scalar>,
        public_shares: &HashMap<u32, PolyCommitment>,
        ctx: &[u8],
    ) -> Result<(), DkgError> {
        self.private_key = Scalar::zero();
        self.group_key = Point::zero();

        let threshold: usize = self.threshold.try_into()?;
        let mut bad_ids = Vec::new(); //: Vec<u32> = polys
        for (i, comm) in public_shares.iter() {
            if !check_public_shares(comm, threshold, ctx) {
                bad_ids.push(*i);
            } else {
                self.group_key += comm.poly[0];
            }
        }
        if !bad_ids.is_empty() {
            return Err(DkgError::BadPublicShares(bad_ids));
        }

        let mut missing_shares = Vec::new();
        for i in public_shares.keys() {
            if private_shares.get(i).is_none() {
                missing_shares.push((self.id, *i));
            }
        }
        if !missing_shares.is_empty() {
            return Err(DkgError::MissingPrivateShares(missing_shares));
        }

        // batch verification requires that we multiply each term by a random scalar in order to
        // prevent a bypass attack.  Doing this using p256k1's MultiMult trait is problematic,
        // because it needs to have every term available so it can return references to them,
        // so we wouldn't be able to save any memory since we'd have to multiple each polynomial
        // coefficient by a different random scalar.
        // we could implement a MultiMultCopy trait that allows us to do the multiplication inline,
        // at the cost of many copies, or use large amounts of memory and do a standard multimult.
        // Or we could just verify each set of public and private shares separately, using extra CPU
        let mut bad_shares = Vec::new();
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

        self.private_key = private_shares.values().sum();
        self.public_key = self.private_key * G;

        Ok(())
    }
```

**File:** src/vss.rs (L11-14)
```rust
    pub fn random_poly<RNG: RngCore + CryptoRng>(n: u32, rng: &mut RNG) -> Polynomial<Scalar> {
        let params: Vec<Scalar> = (0..n + 1).map(|_| Scalar::random(rng)).collect();
        Polynomial::new(params)
    }
```

**File:** src/state_machine/signer/mod.rs (L296-298)
```rust
        if threshold == 0 || threshold > total_keys {
            return Err(Error::Config(ConfigError::InvalidThreshold));
        }
```
