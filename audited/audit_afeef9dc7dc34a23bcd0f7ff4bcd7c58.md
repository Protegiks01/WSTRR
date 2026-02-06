### Title
Missing Validation of KEX Public Keys Allows DKG Private Share Decryption via Identity Point Attack

### Summary
The DKG protocol fails to validate ephemeral key exchange public keys before use in Diffie-Hellman operations, allowing an attacker to submit `Point::identity()` as their KEX public key. This results in a predictable shared secret that can be computed by anyone, enabling decryption of all DKG private shares encrypted for the attacker and potentially allowing unauthorized signature generation through threshold manipulation.

### Finding Description

**Exact Code Locations:**

The vulnerability exists across multiple locations: [1](#0-0) 

When processing `DkgPublicShares` messages, the `kex_public_key` field is directly inserted into the signer's `kex_public_keys` map without any validation. [2](#0-1) 

The unvalidated KEX public key is then used in `make_shared_secret()` when encrypting DKG private shares. [3](#0-2) 

Similarly, when decrypting received private shares, the KEX public key is used without prior validation. [4](#0-3) 

The `make_shared_secret()` function accepts any `Point` without validation, computing `shared_key = private_key * public_key` regardless of whether `public_key` is the identity point, generator, or other invalid values.

**Root Cause:**

The codebase demonstrates awareness of point validation requirements, as evidenced by `PublicNonce::is_valid()`: [5](#0-4) 

However, this same validation is not applied to KEX public keys. When a point is the identity (point at infinity), scalar multiplication with any private key yields the identity: `any_scalar * identity = identity`. The shared secret derived from the identity point is therefore constant and publicly computable.

**Why Existing Mitigations Fail:**

No validation exists for KEX public keys at any point in the processing pipeline. The `DkgPublicShares` message structure simply contains the point as a field: [6](#0-5) 

There is no validation in the deserialization path, the storage path, or before use in cryptographic operations.

### Impact Explanation

**Specific Harm:**

1. **Confidentiality Breach:** When an attacker provides `Point::identity()` as their KEX public key, all honest signers will compute the same predictable shared secret when encrypting private shares for the attacker. The shared secret becomes: `SHA256(compress(identity) || counter || "DH_SHARED_SECRET_KEY/")`, which anyone can compute.

2. **Private Share Exposure:** The attacker (or any network observer) can decrypt all DKG private shares intended for the attacker's key IDs, learning the polynomial coefficients that should remain confidential.

3. **Threshold Manipulation:** In WSTS's weighted threshold scheme, if the attacker controls `w_attacker` weight through legitimate key IDs and learns shares for an additional `w_victim` weight by decrypting a victim's shares, they may exceed the signing threshold `t`. This allows generating valid signatures without proper authorization.

4. **Invalid Transaction Confirmation:** Unauthorized signatures could be used to confirm invalid transactions on dependent blockchain systems, mapping to **Critical severity** under the protocol scope.

**Quantified Impact:**

Consider a 3-of-5 weighted threshold setup where:
- Attacker legitimately controls weight 2
- Victim controls weight 2  
- Other honest signers control weight 1
- Threshold = 3

If the attacker decrypts the victim's shares (weight 2), they now effectively control weight 4, exceeding the threshold and enabling unauthorized signing.

**Affected Parties:**

- All signers whose encrypted DKG private shares are transmitted through the network
- Dependent systems relying on WSTS signature validity
- End users whose transactions depend on proper threshold enforcement

### Likelihood Explanation

**Required Attacker Capabilities:**

- **Scenario 1 (Malicious Signer):** Attacker must be a protocol participant with a valid signer ID. They need only the ability to send a crafted `DkgPublicShares` message with `kex_public_key = Point::identity()`.

- **Scenario 2 (Network Attacker):** A man-in-the-middle attacker who can intercept and modify `DkgPublicShares` messages in transit, replacing legitimate KEX public keys with the identity point.

**Attack Complexity:**

The attack is trivial to execute:
1. Construct `DkgPublicShares` with normal polynomial commitments but `kex_public_key = Point::identity()`
2. Broadcast the message during DKG
3. Compute the predictable shared secret: `SHA256(identity_bytes || 0x00000001 || "DH_SHARED_SECRET_KEY/")`
4. Decrypt all AES-GCM encrypted private shares using standard decryption with the known key

**Economic Feasibility:**

No special resources required beyond basic cryptographic library access and network connectivity. The attack requires no computational power beyond normal DKG participation.

**Detection Risk:**

Low detection risk. The malformed KEX public key appears as a valid serialized point, and there is no validation that would flag or reject the message. The only detection would be if other signers manually inspect the KEX public key value, which is unlikely in production deployments.

**Estimated Probability:**

High. Any motivated attacker with signer privileges can execute this attack with near certainty. The only barrier is obtaining a valid signer position in the protocol.

### Recommendation

**Primary Fix:**

Add validation for KEX public keys immediately after receiving `DkgPublicShares` messages and before storing them:

```rust
// In src/state_machine/signer/mod.rs, around line 1018:
let kex_public_key = dkg_public_shares.kex_public_key;

// Validate the KEX public key
if kex_public_key == Point::identity() || kex_public_key == G {
    warn!(%signer_id, "Invalid KEX public key (identity or generator)");
    return Ok(vec![]);
}

for key_id in signer_key_ids {
    self.kex_public_keys.insert(*key_id, kex_public_key);
}
```

**Additional Validation in make_shared_secret:**

Add defensive validation in the utility function itself:

```rust
// In src/util.rs, function make_shared_secret:
pub fn make_shared_secret(private_key: &Scalar, public_key: &Point) -> [u8; 32] {
    // Validate public key is not identity or generator
    assert!(public_key != &Point::identity(), "KEX public key cannot be identity");
    assert!(public_key != &G, "KEX public key cannot be generator");
    
    let shared_key = private_key * public_key;
    make_shared_secret_from_key(&shared_key)
}
```

**Testing Recommendations:**

1. Add unit test attempting DKG with identity point as KEX public key (should fail)
2. Add unit test attempting DKG with generator G as KEX public key (should fail)
3. Add integration test verifying honest signers reject malformed KEX public keys
4. Add fuzz testing for various invalid point values

**Deployment Considerations:**

This fix should be deployed immediately as it breaks a critical security property. All nodes must upgrade before the next DKG round to ensure protection. Consider adding a protocol version check to reject connections from nodes without this fix.

### Proof of Concept

**Exploitation Algorithm:**

1. **Attacker Setup:**
   - Obtain valid signer credentials (signer_id, network_private_key)
   - Prepare polynomial commitments as normal

2. **Craft Malicious DkgPublicShares:**
   ```
   DkgPublicShares {
       dkg_id: <current_round>,
       signer_id: <attacker_id>,
       comms: <valid_polynomial_commitments>,
       kex_public_key: Point::identity()  // The attack payload
   }
   ```

3. **Broadcast Message:**
   - Send the crafted message during the DKG public shares phase
   - Message passes all current validation checks

4. **Compute Predictable Shared Secret:**
   ```
   identity_compressed = compress(Point::identity())
   shared_secret = SHA256(identity_compressed || 0x00000001u32.to_be_bytes() || "DH_SHARED_SECRET_KEY/")
   ```

5. **Intercept Encrypted Shares:**
   - Collect `DkgPrivateShares` messages where `dst_key_id` matches attacker's key IDs
   - Extract ciphertext bytes

6. **Decrypt Private Shares:**
   ```
   For each encrypted_share:
       nonce = encrypted_share[0..12]
       ciphertext = encrypted_share[12..]
       plaintext = AES256GCM.decrypt(key=shared_secret, nonce=nonce, ciphertext=ciphertext)
       private_share = Scalar::from_bytes(plaintext)
   ```

7. **Exploit Decrypted Shares:**
   - Combine with attacker's legitimate shares
   - If total weight ≥ threshold, generate unauthorized signatures
   - Use forged signatures to confirm invalid transactions

**Expected vs Actual Behavior:**

- **Expected:** Encrypted private shares should only be decryptable by the legitimate recipient holding the corresponding KEX private key
- **Actual:** Any party (including passive network observers) can decrypt shares when KEX public key is the identity point

**Reproduction Instructions:**

Create a test case in the WSTS test suite that attempts to run DKG with one signer using `Point::identity()` as their KEX public key. Verify that encrypted shares can be decrypted using only the publicly-known shared secret (compression of identity hashed with ANSI X9.63 KDF).

### Citations

**File:** src/state_machine/signer/mod.rs (L941-941)
```rust
                    let shared_secret = make_shared_secret(&self.kex_private_key, kex_public_key);
```

**File:** src/state_machine/signer/mod.rs (L1019-1020)
```rust
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
```

**File:** src/state_machine/signer/mod.rs (L1070-1070)
```rust
        let shared_secret = make_shared_secret(&self.kex_private_key, &kex_public_key);
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

**File:** src/net.rs (L148-149)
```rust
    /// Ephemeral public key for key exchange
    pub kex_public_key: Point,
```
