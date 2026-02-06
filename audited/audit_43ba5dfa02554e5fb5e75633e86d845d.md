### Title
Unauthenticated KEX Public Key Allows Private Share Decryption via Low-Order Point Attack

### Summary
The `kex_public_key` field in `DkgPublicShares` messages is not included in the message signature and is never validated against low-order points like `Point::identity()`. An attacker can set or modify this field to a predictable low-order point, causing all private shares encrypted for that recipient to use a constant, publicly-computable shared secret, allowing anyone to decrypt the shares and compromise the DKG protocol's confidentiality.

### Finding Description

**Exact Code Locations:**

1. Message signature does not cover `kex_public_key`: [1](#0-0) 

2. No validation when storing received `kex_public_key`: [2](#0-1) 

3. Encryption uses unvalidated `kex_public_key`: [3](#0-2) 

4. Shared secret computation without point validation: [4](#0-3) 

**Root Cause:**

The vulnerability has two critical components:

1. **Missing Authentication**: The `Signable` implementation for `DkgPublicShares` only hashes `dkg_id`, `signer_id`, and `comms` fields but omits `kex_public_key`. This means an attacker can modify the `kex_public_key` field without invalidating the message signature.

2. **Missing Validation**: Unlike `PublicNonce` which validates points are not `Point::identity()` or generator `G` [5](#0-4) , there is no such validation for `kex_public_key` when `DkgPublicShares` messages are processed.

**Why Existing Mitigations Fail:**

The codebase demonstrates awareness of low-order point attacks through nonce validation, but this protection is not applied to KEX public keys. The signature verification in [6](#0-5)  only validates the signer's identity, not the integrity of the `kex_public_key` field.

### Impact Explanation

**Specific Harm:**

When an attacker sets `kex_public_key = Point::identity()`:
- All senders computing `shared_secret = make_shared_secret(&sender_private_key, &Point::identity())` get: `sender_private_key * Point::identity() = Point::identity()`
- The shared secret becomes: `ansi_x963_derive_key(Point::identity().compress().as_bytes(), "DH_SHARED_SECRET_KEY/")`
- This is a **constant, predictable value** that anyone can compute

**Quantified Impact:**

Private polynomial shares encrypted for the compromised recipient can be decrypted by:
- The malicious party
- Network observers/MITM attackers
- Any other participant

With access to sufficient private shares, attackers can:
- Reconstruct individual party secrets
- Compromise the threshold signature scheme
- Generate unauthorized signatures
- Potentially cause loss of funds in systems using WSTS for custody

**Severity: CRITICAL**

This maps to the "Critical" category as it can lead to:
- "Any confirmation of an invalid transaction" - compromised keys allow signing unauthorized transactions
- "Any causing the direct loss of funds" - if threshold security is broken, funds protected by WSTS signatures are at risk
- "Any chain split" - if some nodes detect the attack while others don't, inconsistent signature validation could cause chain splits

### Likelihood Explanation

**Required Attacker Capabilities:**

**Scenario 1 - Malicious Insider:**
- Attacker is a registered signer (has valid `signer_id`)
- Directly sends `DkgPublicShares` with `kex_public_key = Point::identity()`
- Signature is valid because `kex_public_key` is not covered

**Scenario 2 - Man-in-the-Middle:**
- Attacker can intercept and modify network messages
- Modifies legitimate `DkgPublicShares` messages to replace `kex_public_key` with `Point::identity()`
- Signature remains valid because field is not authenticated

**Attack Complexity: LOW**

- No cryptographic breaks required
- Simple field modification or direct malicious message creation
- Predictable shared secret computation is straightforward
- Standard AES-GCM decryption with known key

**Economic Feasibility: HIGH**

- Minimal resources needed
- Can be executed in a single DKG round
- No specialized hardware or extensive computation required

**Detection Risk: LOW**

The attack is difficult to detect because:
- Messages pass signature verification
- Encryption/decryption operations succeed normally
- No error is raised for identity point usage

**Probability of Success: HIGH**

Both attack scenarios are practical and likely to succeed given the complete lack of validation.

### Recommendation

**Immediate Fix (Required):**

1. **Include `kex_public_key` in signature hash:**

Modify [1](#0-0)  to include:
```rust
hasher.update(self.kex_public_key.compress().as_bytes());
```

2. **Validate `kex_public_key` when received:**

Add validation in [2](#0-1)  before insertion:
```rust
// Validate kex_public_key is not identity or generator
if dkg_public_shares.kex_public_key == Point::identity() 
    || dkg_public_shares.kex_public_key == G {
    warn!(%signer_id, "Invalid kex_public_key (identity or generator)");
    return Ok(vec![]);
}
```

3. **Add defensive check in `make_shared_secret`:**

Modify [4](#0-3)  to validate:
```rust
pub fn make_shared_secret(private_key: &Scalar, public_key: &Point) -> Result<[u8; 32], Error> {
    if *public_key == Point::identity() || *public_key == G {
        return Err(Error::InvalidPoint);
    }
    let shared_key = private_key * public_key;
    Ok(make_shared_secret_from_key(&shared_key))
}
```

**Testing Recommendations:**

1. Add unit test attempting to process `DkgPublicShares` with `Point::identity()` as `kex_public_key`
2. Verify signature verification fails when `kex_public_key` is modified
3. Test that encryption fails gracefully with invalid KEX public keys
4. Add property-based test that shared secrets are unique per sender-recipient pair

**Deployment Considerations:**

This is a breaking protocol change requiring coordinated upgrade of all participants.

### Proof of Concept

**Exploitation Algorithm:**

1. **Attacker Setup:**
   - Register as legitimate signer (obtain `signer_id`)
   - Generate valid polynomial commitments `comms`

2. **Create Malicious DkgPublicShares:**
   ```
   malicious_shares = DkgPublicShares {
       dkg_id: current_dkg_id,
       signer_id: attacker_signer_id,
       comms: valid_commitments,
       kex_public_key: Point::identity()  // Attack payload
   }
   ```

3. **Sign and Broadcast:**
   - Compute signature over hash (which excludes `kex_public_key`)
   - Broadcast as valid `Packet`

4. **Compute Predictable Shared Secret:**
   ```
   // Anyone can compute this:
   identity_bytes = Point::identity().compress().as_bytes()
   shared_secret = ansi_x963_derive_key(
       identity_bytes,
       "DH_SHARED_SECRET_KEY/"
   )
   ```

5. **Decrypt Intercepted Shares:**
   - Observe encrypted private shares sent to attacker's `key_id`
   - Use `shared_secret` to decrypt with AES-256-GCM
   - Extract polynomial evaluation scalars

**Expected vs Actual Behavior:**

**Expected:** Each sender-recipient pair has unique shared secret computed via Diffie-Hellman with unpredictable result.

**Actual:** When `kex_public_key = Point::identity()`, all senders compute the same predictable shared secret `= Point::identity()`, allowing anyone to decrypt the shares.

**Reproduction:**

1. Initialize DKG with malicious signer
2. Malicious signer broadcasts `DkgPublicShares` with `kex_public_key = Point::identity()`
3. Honest signers accept message (signature valid, no validation)
4. During private share distribution, honest signers encrypt shares using predictable shared secret
5. Any party (including non-participants) can decrypt shares by computing the constant shared secret from `Point::identity()`

### Citations

**File:** src/net.rs (L152-163)
```rust
impl Signable for DkgPublicShares {
    fn hash(&self, hasher: &mut Sha256) {
        hasher.update("DKG_PUBLIC_SHARES".as_bytes());
        hasher.update(self.dkg_id.to_be_bytes());
        hasher.update(self.signer_id.to_be_bytes());
        for (party_id, comm) in &self.comms {
            hasher.update(party_id.to_be_bytes());
            for a in &comm.poly {
                hasher.update(a.compress().as_bytes());
            }
        }
    }
```

**File:** src/net.rs (L526-530)
```rust
            Message::DkgPublicShares(msg) => {
                if let Some(public_key) = signers_public_keys.signers.get(&msg.signer_id) {
                    if !msg.verify(&self.sig, public_key) {
                        warn!("Received a DkgPublicShares message with an invalid signature.");
                        return false;
```

**File:** src/state_machine/signer/mod.rs (L937-942)
```rust
                    let Some(kex_public_key) = self.kex_public_keys.get(dst_key_id) else {
                        error!("No KEX public key for key_id {dst_key_id}");
                        return Err(Error::MissingKexPublicKey(*dst_key_id));
                    };
                    let shared_secret = make_shared_secret(&self.kex_private_key, kex_public_key);
                    let encrypted_share = encrypt(&shared_secret, &private_share.to_bytes(), rng)?;
```

**File:** src/state_machine/signer/mod.rs (L1018-1021)
```rust
        for key_id in signer_key_ids {
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
        }
```

**File:** src/util.rs (L48-52)
```rust
pub fn make_shared_secret(private_key: &Scalar, public_key: &Point) -> [u8; 32] {
    let shared_key = private_key * public_key;

    make_shared_secret_from_key(&shared_key)
}
```

**File:** src/common.rs (L161-163)
```rust
    pub fn is_valid(&self) -> bool {
        self.D != Point::identity() && self.E != Point::identity() && self.D != G && self.E != G
    }
```
