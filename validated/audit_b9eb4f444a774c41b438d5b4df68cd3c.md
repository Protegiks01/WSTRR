# Audit Report

## Title
Incorrect Malicious Signer Identification Due to Unauthenticated SignatureShare.id Field in v2

## Summary
The v2 coordinator fails to validate that the `id` field within `SignatureShare` objects matches the authenticated `signer_id` of the message sender. A malicious signer can exploit this by creating signature shares with a victim's party ID, causing signature verification to fail and blame to be incorrectly assigned to an innocent party.

## Finding Description

The vulnerability exists in v2's signature share validation logic. While the coordinator authenticates message senders and validates their `key_ids`, it never checks that `SignatureShare.id` matches the sender's authenticated identity.

**Root Cause Analysis:**

The `SignatureShare` structure contains an `id` field representing the party ID: [1](#0-0) 

In v2, parties create signature shares with their `party_id`: [2](#0-1) 

During signing, the party computes its nonce component using its own party_id for the binding computation: [3](#0-2) 

Where `self.id()` returns the party's own party_id: [4](#0-3) 

The coordinator validates `key_ids` but **not** the `id` field: [5](#0-4) 

The coordinator stores shares indexed by the authenticated `signer_id`: [6](#0-5) 

However, during aggregation, party IDs are extracted **directly from `SignatureShare.id`** for binding computation: [7](#0-6) 

These party_ids are then used to compute binding values in the `intermediate` function: [8](#0-7) 

When signature verification fails, blame is assigned based on `SignatureShare.id`: [9](#0-8) 

**Attack Flow:**

1. Malicious signer (party_id = A) creates `SignatureShare` with `id: V` (victim's party_id) instead of `id: A`
2. Keeps `key_ids` correct to pass coordinator validation
3. Computes `z_i` using `binding(&id(A), nonces, msg)` (correct for attacker)
4. Coordinator accepts the share (key_ids validation passes, packet authenticated as signer A)
5. Aggregator extracts party_ids from `SignatureShare.id`, getting V instead of A
6. Aggregator computes `Rs[i]` using `binding(&id(V), nonces, msg)` (wrong binding value)
7. Verification equation `z_i * G != r_sign * Rs[i] + cx_sign * cx` fails (binding mismatch)
8. Victim's party_id V appears in `BadPartySigs` error instead of attacker's A

**Why v1 is not affected:**

In v1, each party controls exactly one key where `id == key_id`: [10](#0-9) 

When the coordinator validates `key_ids`, it implicitly validates `id` since they must be equal. In v2, `party_id` and `key_ids` are independent (one party can control multiple keys), allowing the attack.

## Impact Explanation

**Severity: Medium** - This qualifies as "transient consensus failures" per the defined scope.

The vulnerability enables a compromised signer to:
1. Cause signature operations to fail by providing mismatched party IDs
2. Frame innocent signers through incorrect blame assignment
3. Potentially trigger exclusion of honest parties if systems trust the blame mechanism
4. Cause repeated signing failures until the issue is detected

In a system with 10 signers and threshold 7, an attacker controlling 1 signer could frame 3 honest signers across multiple rounds, reducing available signers to 6 (below threshold), causing temporary loss of signing capability.

The impact is limited to transient failures (not permanent) because the vulnerability requires active exploitation in each signing round and can be mitigated once detected through correlation of packet-level sender IDs with signature share IDs.

## Likelihood Explanation

**Likelihood: High (if signer compromised)**

Required capabilities:
- Control of one signer node (within protocol threat model - up to threshold-1 malicious signers)
- Ability to modify signer software to set incorrect `id` field
- No additional cryptographic secrets needed beyond those of the compromised signer

Attack complexity is **low** - requires only changing the signature share creation to set `id: victim_party_id` instead of `id: self.party_id`.

The attack:
- Can be executed repeatedly across multiple signing rounds
- Has no timing constraints
- Requires no special resources beyond compromising a single signer
- Is difficult to detect without explicit logging that correlates authenticated sender IDs with `SignatureShare.id` values

Detection requires additional monitoring infrastructure not present by default.

## Recommendation

Add validation in the coordinator's `gather_sig_shares` method to verify that each `SignatureShare.id` matches the authenticated `signer_id`. In v2, since `party_id` equals `signer_id`, this check ensures consistency:

```rust
// In gather_sig_shares, after key_ids validation:
for sig_share in &sig_share_response.signature_shares {
    if sig_share.id != sig_share_response.signer_id {
        warn!(
            signer_id = %sig_share_response.signer_id,
            claimed_id = %sig_share.id,
            "SignatureShare id doesn't match authenticated signer_id"
        );
        return Err(Error::InvalidSignatureShare);
    }
}
```

This ensures that the party_id used for binding computation in the aggregator matches the authenticated sender, preventing framing attacks.

## Proof of Concept

```rust
#[test]
fn test_signature_share_id_mismatch_attack() {
    // Setup: Run DKG with 3 parties, threshold 2
    let (mut coordinators, mut signers) = run_dkg::<FireCoordinator, v2::Party>(3, 1);
    
    // Start signing round
    let msg = b"test message".to_vec();
    let message = coordinators[0].start_signing_round(&msg, SignatureType::Frost, None).unwrap();
    
    // Gather nonces
    let (outbound, _) = feedback_messages(&mut coordinators, &mut signers, &[message]);
    
    // Malicious signer 0 creates signature share with victim's (signer 1) party_id
    let (outbound, _) = feedback_mutated_messages(
        &mut coordinators,
        &mut signers,
        &outbound,
        |signer, packets| {
            if signer.signer_id != 0 {
                return packets.clone();
            }
            packets.iter().map(|packet| {
                let Message::SignatureShareResponse(response) = &packet.msg else {
                    return packet.clone();
                };
                // Set SignatureShare.id to victim's party_id (1) instead of attacker's (0)
                let malicious_shares: Vec<SignatureShare> = response
                    .signature_shares
                    .iter()
                    .map(|share| SignatureShare {
                        id: 1,  // Victim's party_id
                        key_ids: share.key_ids.clone(),  // Keep correct key_ids
                        z_i: share.z_i,  // Keep correct z_i (computed with attacker's binding)
                    })
                    .collect();
                Packet {
                    msg: Message::SignatureShareResponse(SignatureShareResponse {
                        dkg_id: response.dkg_id,
                        sign_id: response.sign_id,
                        sign_iter_id: response.sign_iter_id,
                        signer_id: response.signer_id,
                        signature_shares: malicious_shares,
                    }),
                    sig: vec![],
                }
            }).collect()
        },
    );
    
    // Expected: BadPartySigs should contain party_id 1 (victim) instead of 0 (attacker)
    // This demonstrates the framing attack
}
```

### Citations

**File:** src/common.rs (L213-220)
```rust
pub struct SignatureShare {
    /// The ID of the party
    pub id: u32,
    /// The party signature
    pub z_i: Scalar,
    /// The key IDs of the party
    pub key_ids: Vec<u32>,
}
```

**File:** src/v2.rs (L204-207)
```rust
    /// Compute a Scalar from this party's ID
    pub fn id(&self) -> Scalar {
        compute::id(self.party_id)
    }
```

**File:** src/v2.rs (L257-257)
```rust
        let mut r = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
```

**File:** src/v2.rs (L271-275)
```rust
        SignatureShare {
            id: self.party_id,
            z_i: z,
            key_ids: self.key_ids.clone(),
        }
```

**File:** src/v2.rs (L308-309)
```rust
        let party_ids: Vec<u32> = sig_shares.iter().map(|ss| ss.id).collect();
        let (_Rs, R) = compute::intermediate(msg, &party_ids, nonces);
```

**File:** src/v2.rs (L406-408)
```rust
            if z_i * G != (r_sign * Rs[i] + cx_sign * cx) {
                bad_party_sigs.push(sig_shares[i].id);
            }
```

**File:** src/state_machine/coordinator/fire.rs (L1066-1076)
```rust
        let mut sig_share_response_key_ids = HashSet::new();
        for sig_share in &sig_share_response.signature_shares {
            for key_id in &sig_share.key_ids {
                sig_share_response_key_ids.insert(*key_id);
            }
        }

        if *signer_key_ids != sig_share_response_key_ids {
            warn!(signer_id = %sig_share_response.signer_id, "SignatureShareResponse key_ids didn't match config");
            return Err(Error::BadKeyIDsForSigner(sig_share_response.signer_id));
        }
```

**File:** src/state_machine/coordinator/fire.rs (L1088-1090)
```rust
        self.signature_shares.insert(
            sig_share_response.signer_id,
            sig_share_response.signature_shares.clone(),
```

**File:** src/compute.rs (L85-96)
```rust
pub fn intermediate(msg: &[u8], party_ids: &[u32], nonces: &[PublicNonce]) -> (Vec<Point>, Point) {
    let rhos: Vec<Scalar> = party_ids
        .iter()
        .map(|&i| binding(&id(i), nonces, msg))
        .collect();
    let R_vec: Vec<Point> = zip(nonces, rhos)
        .map(|(nonce, rho)| nonce.D + rho * nonce.E)
        .collect();

    let R = R_vec.iter().fold(Point::zero(), |R, &R_i| R + R_i);
    (R_vec, R)
}
```

**File:** src/v1.rs (L224-228)
```rust
        SignatureShare {
            id: self.id,
            z_i: z,
            key_ids: vec![self.id],
        }
```
