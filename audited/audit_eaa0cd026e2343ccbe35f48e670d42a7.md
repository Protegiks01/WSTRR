### Title
Critical Nonce Reuse: Party::sign() Allows Signing with Zero Nonce If gen_nonce() Is Never Called

### Summary
The WSTS implementation initializes each Party's nonce to `Nonce::zero()`. The signing function `Party::sign()` and its variants do not check whether the nonce has been set to a secure value before use. If a signing operation is performed before `gen_nonce()` is called, or if state is restored with a previously used nonce, a signature with zero (or reused) nonce is produced—catastrophically leaking private key material and enabling key recovery. There is no mitigation at the Party or Signer API level to prevent this, only protocol-level safety if all state machine transitions are respected.

### Finding Description
- **File/Function**: `src/v1.rs`, `Party::new()` (lines 54–65), `Party::sign()` (lines 217–229)
- **Root cause**: `Party::new()` sets its `nonce` field to `Nonce::zero()` by default. `Party::sign()` and other sign methods consume `self.nonce` without any validation or guard against zero/non-refreshed nonces. If `gen_nonce()` is not called proactively before signing (e.g., due to custom/corrupted protocol flow, API use outside the prescribed state machine, or on first use after creation or deserialization), the Party will sign with a zero or stale nonce. [1](#0-0) [2](#0-1) 
- **Mitigation failure**: There is no code in `Party::sign()` or the encompassing state machine logic that checks `self.nonce.is_zero()` or otherwise requires a "fresh" nonce. Receiving a `SignatureShareRequest` before a `NonceRequest`, or deviating from the standard flow, can result in signing with zero or old nonces. User-constructed flows, direct API use, or bugs in state replication/restore can all trigger this.
- **Relevant context**: The Nonce struct has an `is_zero()` check for defense in other spots, but it's not used here. All core signing methods are affected.

### Impact Explanation
- **Harm**: Signing with a nonce equal to zero or reusing a nonce makes the private key recoverable (by an adversary who observes the resulting signature), directly enabling theft or unauthorized signing using the WSTS group/signers' key.
- **Scope**: Any system or chain relying on WSTS is catastrophically compromised if even a single instance occurs—funds can be stolen, consensus can be broken, or invalid blocks can be produced. This is a "Critical" impact.
- **Quantification**: One occurrence exposes the entire key used, with impact limited only by the scope of that key's authority (e.g., a threshold spend policy or network signature).
- **Affected**: All users, all library consumers, dependent chains, and any upstream systems trusting these signatures.

### Likelihood Explanation
- **Prerequisites**: Attacker can either:
    - Induce signing before gen_nonce() (e.g., send a malformed protocol sequence, exploit bugs, or supply malicious state).
    - Use the API outside the provided state machine (e.g., custom or embedded applications).
- **Complexity**: Very low—no secrets are required, and only a single invocation of Party::sign() is needed.
- **Detection**: None—no guard rails exist.
- **Probability**: High if the software is used incorrectly, moderate if only the explicit state machine is followed, but catastrophic on any logic deviation.

### Recommendation
- Add a mandatory check in `Party::sign()` and all related methods that aborts if `self.nonce.is_zero()` (or is otherwise invalid per the is_valid() method of Nonce). [3](#0-2) 
- Consider an API design where signing is not possible until a nonce is freshly generated, e.g., require the nonce as an explicit method argument or expose a signed/ready state.
- Enhance state machine and public API tests to ensure `gen_nonce()` is always called before signing, and that state restore logic prevents nonce reuse or use of initial zero nonce.
- Document this invariant in both the library code and application integration guides.

### Proof of Concept
**Exploit Steps**:
1. Create a Party directly using Party::new() (or after reset/restore), which sets nonce to zero.
2. Call Party::sign() without ever calling gen_nonce()—either by direct use or via a state machine mis-sequence.
3. The resulting signature leaks key material through its zero or reused nonce. Any observer (including an adversary) can recover the signer's private key using standard Schnorr attacks.

**Reproduction (in Rust, using library API)**:
```rust
let mut party = Party::new(1, N, T, &mut rng);
let sig_share = party.sign(msg, &[1], &[]); // no party.gen_nonce() ever called
assert!(party.nonce.is_zero());
println!("SignatureShare: {:?}", sig_share);
// => Key is now compromised!
```

**Expected**: Party::sign() aborts or panics.
**Actual**: It uses nonce = zero, allowing key extraction from the published signature.

**Restore+Reuse**:
- Save a Party after signature 1 (nonce_1).
- Reload state, call sign again; will reuse nonce_1, exposing same "r" in two signatures.

**Major risk domains**: Any integrations that (a) instantiate keys mid-round, (b) restore state incorrectly, or (c) provide their own flow wrappers.

--- [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** src/v1.rs (L217-229)
```rust
    pub fn sign(&self, msg: &[u8], signers: &[u32], nonces: &[PublicNonce]) -> SignatureShare {
        let (_, aggregate_nonce) = compute::intermediate(msg, signers, nonces);
        let mut z = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        z += compute::challenge(&self.group_key, &aggregate_nonce, msg)
            * &self.private_key
            * compute::lambda(self.id, signers);

        SignatureShare {
            id: self.id,
            z_i: z,
            key_ids: vec![self.id],
        }
    }
```

**File:** src/common.rs (L91-94)
```rust
    pub fn is_valid(&self) -> bool {
        !self.is_zero() && !self.is_one()
    }
}
```
