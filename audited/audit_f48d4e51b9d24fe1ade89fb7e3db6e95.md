### Title
Key Collapsing Vulnerability: All Keys Share Identical Private Keys When Threshold=1

### Summary
When WSTS is configured with threshold=1 and multiple keys (num_keys > 1), the DKG process generates identical private keys for all key IDs due to degree-0 polynomial evaluation. This catastrophic failure breaks key independence, creating a single point of failure where compromising any one key compromises the entire key set, potentially enabling direct loss of funds.

### Finding Description

**Exact Code Location:**
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 

**Root Cause:**

When `threshold=1`, the `random_poly()` function is called with `n=0` (since `n = threshold - 1`). [1](#0-0)  This creates a polynomial with a single coefficient (degree-0), which is mathematically a constant function f(x) = c.

During DKG, each party evaluates their constant polynomial at all key IDs. [3](#0-2)  For a constant polynomial, `f(key_id) = c` for all key_id values. This means:
- Party i's share for key_id 1: f_i(1) = c_i
- Party i's share for key_id 2: f_i(2) = c_i  
- Party i's share for key_id k: f_i(k) = c_i

All key IDs receive identical shares from each party.

When computing final secrets, each key sums its received shares: [4](#0-3) 
- Secret for key 1: s_1 = Σ_i c_i
- Secret for key 2: s_2 = Σ_i c_i
- Secret for key k: s_k = Σ_i c_i

**Result:** All keys have identical private keys: s_1 = s_2 = ... = s_k

**Why Existing Mitigations Fail:**

The validation only enforces `threshold > 0`, not `threshold > 1` when multiple keys exist. [5](#0-4)  There is no check preventing the dangerous combination of `threshold=1` with `num_keys > 1`.

### Impact Explanation

**Specific Harm:**
All keys in the system collapse to a single shared private key, completely breaking key independence. If an attacker compromises any one key through any means (side-channel attack, memory dump, insider threat, implementation bug), they simultaneously compromise ALL keys in the system.

**Quantified Impact:**
Consider a realistic deployment with threshold=1, num_keys=10:
- System appears to have 10 independent keys for weighted signatures
- In reality, all 10 keys share the exact same private key
- Compromising key #5 means the attacker can forge signatures for keys #1-10
- This enables signing arbitrary transactions, potentially causing direct loss of all funds controlled by these keys

**Affected Parties:**
Any WSTS deployment using threshold=1 with multiple keys. While threshold=1 may seem unusual, it is explicitly allowed by validation and could be used in scenarios requiring any-key-can-sign semantics with weighted key ownership.

**Severity: High**

This maps to "High" severity under the protocol scope definition: "Any causing the direct loss of funds other than through any form of freezing." Once any single key is compromised, an attacker gains control of the entire key set, enabling unauthorized transaction signing and fund theft.

### Likelihood Explanation

**Required Attacker Capabilities:**
1. Target system must be configured with threshold=1 and num_keys > 1
2. Attacker must compromise any single key through conventional means (no crypto breaks required)

**Attack Complexity: Low**

The vulnerability is passive - no active exploitation needed during DKG. The attacker simply waits for:
- A threshold=1 deployment to occur (valid configuration)
- Any conventional key compromise opportunity (side-channel, memory access, social engineering, etc.)

**Economic Feasibility: High**

No special resources required beyond standard key compromise techniques. The mathematical flaw is deterministic and automatic.

**Detection Risk: Low**

The key collision is invisible to normal operations. All signatures verify correctly. Only security audits examining the mathematical properties would detect this.

**Estimated Probability:**
- If threshold=1 deployments exist: Moderate to High
- Once a key compromise occurs: Certain (100% of keys compromised)

### Recommendation

**Primary Fix:**

Add validation in `Signer::new()` to enforce minimum polynomial degree when multiple keys exist:

```rust
// In src/state_machine/signer/mod.rs, after line 298
if threshold == 1 && total_keys > 1 {
    return Err(Error::Config(ConfigError::InvalidThreshold));
}
```

**Rationale:**
Threshold=1 with a single key is legitimate (no secret sharing). But threshold=1 with multiple keys breaks the mathematical foundations of Shamir Secret Sharing by generating identical shares.

**Alternative Mitigation:**

If threshold=1 with multiple keys is a required use case, redesign to generate independent secrets per key rather than using polynomial evaluation. However, this would fundamentally change the DKG protocol.

**Testing Recommendations:**
1. Add unit test verifying error when threshold=1 and total_keys > 1
2. Add integration test confirming different keys have different private keys
3. Add test computing private keys for threshold=1, single-key case (should work)

**Deployment Considerations:**
This is a breaking change that rejects previously-valid configurations. Announce the security fix and recommend immediate upgrade for any threshold=1 deployments.

### Proof of Concept

**Mathematical Proof:**

Given:
- threshold = 1, therefore polynomial degree n = 0
- Polynomial f(x) = c (constant)
- Key IDs: {1, 2, ..., k} where k = num_keys

For any party i with polynomial f_i(x) = c_i:
```
f_i(1) = c_i
f_i(2) = c_i
f_i(k) = c_i
```

For each key_id j, the final secret is:
```
s_j = Σ(i=1 to num_parties) f_i(j)
    = Σ(i=1 to num_parties) c_i
    = constant_sum
```

Therefore: s_1 = s_2 = ... = s_k = constant_sum

**Reproduction Steps:**

1. Configure WSTS with:
   - threshold = 1
   - num_keys = 10  
   - num_parties = 3

2. Execute DKG phase per normal protocol

3. After `compute_secret()` completes, inspect `private_keys` HashMap for any party

4. **Expected behavior:** Each key_id should have a unique private key

5. **Actual behavior:** All key_ids have identical private key values

6. Verification: Extract private_keys[1] and private_keys[2], confirm equality

**Exploitation:**
Once deployed with identical keys, attacker needs only to compromise one key (via any conventional means) to control all keys and forge signatures for the entire key set.

### Citations

**File:** src/vss.rs (L11-14)
```rust
    pub fn random_poly<RNG: RngCore + CryptoRng>(n: u32, rng: &mut RNG) -> Polynomial<Scalar> {
        let params: Vec<Scalar> = (0..n + 1).map(|_| Scalar::random(rng)).collect();
        Polynomial::new(params)
    }
```

**File:** src/v2.rs (L69-69)
```rust
            f: Some(VSS::random_poly(threshold - 1, rng)),
```

**File:** src/v2.rs (L106-116)
```rust
    pub fn get_shares(&self) -> HashMap<u32, Scalar> {
        let mut shares = HashMap::new();
        if let Some(poly) = &self.f {
            for i in 1..self.num_keys + 1 {
                shares.insert(i, poly.eval(compute::id(i)));
            }
        } else {
            warn!("get_poly_commitment called with no polynomial");
        }
        shares
    }
```

**File:** src/v2.rs (L188-199)
```rust
        for key_id in &self.key_ids {
            self.private_keys.insert(*key_id, Scalar::zero());
            if let Some(shares) = private_shares.get(key_id) {
                let secret = shares.values().sum();
                self.private_keys.insert(*key_id, secret);
            } else {
                warn!(
                    "no private shares for key_id {}, even though we checked for it above",
                    key_id
                );
            }
        }
```

**File:** src/state_machine/signer/mod.rs (L296-298)
```rust
        if threshold == 0 || threshold > total_keys {
            return Err(Error::Config(ConfigError::InvalidThreshold));
        }
```
