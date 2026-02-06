### Title
Inconsistent SavedState Allows Network Shutdown via Invalid Aggregate Public Key

### Summary
The `SavedState` struct can represent inconsistent DKG state where `dkg_public_shares` and `dkg_private_shares` do not match, with no validation during construction or loading. When such inconsistent state is loaded into a coordinator, it can lead to an invalid aggregate public key (identity point) being accepted as valid, causing all subsequent signing operations to fail and shutting down the network's ability to confirm transactions.

### Finding Description

**Exact Code Locations:**

1. `SavedState` struct definition with public, unvalidated fields: [1](#0-0) 

2. FROST coordinator's `load()` method with no validation: [2](#0-1) 

3. FIRE coordinator's `load()` method with no validation: [3](#0-2) 

4. FROST `dkg_end_gathered()` computing aggregate key from potentially empty `party_polynomials`: [4](#0-3) 

5. FIRE `dkg_end_gathered()` with unsafe indexing that can panic: [5](#0-4) 

6. FROST `start_public_shares()` clears `dkg_public_shares` but NOT `dkg_private_shares`: [6](#0-5) 

7. FIRE `start_public_shares()` clears `dkg_public_shares` but NOT `dkg_private_shares`: [7](#0-6) 

**Root Cause:**

The `SavedState` struct is defined with all public fields and no invariant enforcement. The `Coordinator::load()` implementations in both FROST and FIRE directly map all fields from `SavedState` without any consistency validation. This allows three critical failure modes:

1. **Invalid aggregate key generation**: In FROST's `dkg_end_gathered()`, if `dkg_private_shares` is empty, the loop at line 424 doesn't execute, `party_polynomials` remains empty (or contains only data from a previous round), and the fold operation at line 437 returns `Point::default()` (the identity point), which is set as the aggregate public key with no validation.

2. **FIRE coordinator panic**: In FIRE's `dkg_end_gathered()`, lines 797 and 806 perform direct indexing into `dkg_public_shares` using keys from `dkg_private_shares` without checking existence, causing a panic if the maps are inconsistent.

3. **Stale data persistence**: Neither coordinator's `start_public_shares()` clears `dkg_private_shares` when beginning a new DKG round. If state is saved/loaded between rounds, `dkg_private_shares` can contain stale data from previous rounds while `dkg_public_shares` contains current round data.

**Why Existing Mitigations Fail:**

No mitigations exist. There is no validation in `SavedState` construction, no validation in `Coordinator::load()`, no validation of the computed aggregate public key, and no clearing of stale DKG state when starting new rounds.

### Impact Explanation

**Specific Harm:**

If an inconsistent `SavedState` is loaded where `dkg_private_shares` is empty (or contains mismatched entries) but `party_polynomials`/`dkg_end_messages` are also empty, the DKG process completes with an invalid aggregate public key set to the identity point (`Point::default()`). This invalid key is then returned as a successful DKG result: [8](#0-7) 

**Quantified Impact:**

Once the invalid aggregate key is accepted:
- All subsequent signature generation attempts fail because the signing shares don't correspond to the identity point
- The network cannot produce valid signatures for blocks or transactions
- The network shuts down and cannot confirm new valid transactions
- This persists until the DKG is re-run with valid state

**Who is Affected:**

All participants in the WSTS signing system, and any blockchain or system depending on it for transaction signing or block production.

**Severity Justification:**

This maps directly to **CRITICAL** severity per the protocol scope definition: "Any network to shut down or otherwise not confirm new valid transactions for multiple blocks." The network's signing capability is completely broken until state is manually corrected and DKG is re-run.

### Likelihood Explanation

**Required Attacker Capabilities:**

The attacker must be able to cause the coordinator to load a malicious `SavedState`. This is possible in multiple scenarios:

1. **Direct attack**: If `SavedState` is deserialized from network messages, user input, or any untrusted source, an attacker can craft malicious state directly.

2. **Storage compromise**: If the attacker can modify the persisted state storage, they can inject inconsistent state.

3. **Exploitation of state management bugs**: The stale data issue (not clearing `dkg_private_shares`) creates natural opportunities for inconsistent state during save/load cycles across DKG rounds.

**Attack Complexity:**

LOW. Constructing a malicious `SavedState` is trivial since all fields are public:
1. Create `SavedState` with `dkg_private_shares` empty or mismatched
2. Set `party_polynomials` (FROST) or `dkg_end_messages` (FIRE) to empty
3. Set `state` to `DkgEndGather` or later
4. Cause the coordinator to load this state

**Economic Feasibility:**

HIGH. No specialized resources required beyond the ability to inject state into the system.

**Detection Risk:**

LOW for attacker. The invalid aggregate key appears as a valid point value and is accepted without validation. Only when signing fails does the problem become apparent, by which time the damage is done.

**Estimated Probability:**

- If `SavedState` exposed to untrusted input: HIGH (easily exploitable)
- If state management has bugs allowing stale data: MEDIUM (can occur naturally)
- If only internal trusted persistence: LOW (requires prior compromise)

### Recommendation

**Proposed Code Changes:**

1. **Add validation to `SavedState` loading:**
```rust
fn load(state: &SavedState) -> Result<Self, Error> {
    // Validate consistency
    if state.state == State::DkgEndGather || state.state == State::Idle {
        // Ensure all signers in dkg_private_shares have corresponding dkg_public_shares
        for signer_id in state.dkg_private_shares.keys() {
            if !state.dkg_public_shares.contains_key(signer_id) {
                return Err(Error::BadStateChange(
                    format!("Inconsistent SavedState: dkg_private_shares contains signer {} but dkg_public_shares does not", signer_id)
                ));
            }
        }
        // Validate aggregate_public_key is not identity point if DKG completed
        if let Some(key) = state.aggregate_public_key {
            if key == Point::default() {
                return Err(Error::BadStateChange(
                    "Invalid aggregate public key (identity point)".to_string()
                ));
            }
        }
    }
    // ... rest of load implementation
}
```

2. **Clear `dkg_private_shares` when starting new DKG round:**

In both FROST and FIRE `start_public_shares()`, add:
```rust
self.dkg_private_shares.clear();
```

3. **Validate aggregate key before accepting it:**

In `dkg_end_gathered()` before setting `aggregate_public_key`:
```rust
if key == Point::default() || party_polynomials.is_empty() {
    return Err(Error::BadStateChange(
        "Cannot compute valid aggregate key from empty polynomials".to_string()
    ));
}
```

4. **Use safe indexing in FIRE coordinator:**

Replace direct indexing with checked access:
```rust
for signer_id in self.dkg_private_shares.keys() {
    let Some(dkg_public_shares) = self.dkg_public_shares.get(signer_id) else {
        return Err(Error::BadStateChange(...));
    };
    // ... rest of logic
}
```

**Alternative Mitigations:**

- Make `SavedState` fields private and provide validated constructor
- Add a `validate()` method that must be called after deserialization
- Use Rust type system to enforce state machine invariants at compile time

**Testing Recommendations:**

- Unit tests for `load()` with inconsistent state that should fail
- Integration tests simulating state save/load across DKG rounds
- Fuzz testing of `SavedState` deserialization

### Proof of Concept

**Exploitation Steps:**

1. **Construct malicious SavedState:**
```rust
let mut malicious_state = SavedState::default();
malicious_state.config = valid_config;
malicious_state.dkg_public_shares.insert(0, valid_public_shares_0);
malicious_state.dkg_public_shares.insert(1, valid_public_shares_1);
// Leave dkg_private_shares EMPTY
malicious_state.party_polynomials = HashMap::new(); // Empty
malicious_state.state = State::DkgEndGather;
malicious_state.dkg_wait_signer_ids = HashSet::new(); // Empty so dkg_end_gathered runs immediately
```

2. **Load coordinator from malicious state:**
```rust
let mut coordinator = Coordinator::<SomeAggregator>::load(&malicious_state);
```

3. **Trigger DKG completion:**
Send minimal DkgEnd messages to satisfy the (empty) wait set, causing `dkg_end_gathered()` to execute.

4. **Expected behavior:**
In FROST `dkg_end_gathered()`:
    - Loop at line 424 doesn't execute (empty `dkg_private_shares`)
    - Line 437 fold returns `Point::default()`
    - Line 444 sets `aggregate_public_key = Some(Point::default())`
    - Returns `Ok(())` with invalid key

5. **Observed behavior:**
    - DKG appears to complete successfully
    - `OperationResult::Dkg(Point::default())` returned
    - System accepts identity point as aggregate key
    - All subsequent signing operations fail
    - Network cannot produce valid signatures

**Parameter Values:**

- Any valid `Config`
- Any valid `DkgPublicShares` messages
- Empty `dkg_private_shares`
- Empty `party_polynomials`

**Reproduction:**

Reference existing test pattern that saves/loads state: [9](#0-8) 

Modify to inject inconsistent state before loading.

### Citations

**File:** src/state_machine/coordinator/mod.rs (L248-298)
```rust
#[derive(Default, Clone, Debug, PartialEq)]
pub struct SavedState {
    /// common config fields
    pub config: Config,
    /// current DKG round ID
    pub current_dkg_id: u64,
    /// current signing round ID
    pub current_sign_id: u64,
    /// current signing iteration ID
    pub current_sign_iter_id: u64,
    /// map of DkgPublicShares indexed by signer ID
    pub dkg_public_shares: BTreeMap<u32, DkgPublicShares>,
    /// map of DkgPrivateShares indexed by signer ID
    pub dkg_private_shares: BTreeMap<u32, DkgPrivateShares>,
    /// map of DkgEnd indexed by signer ID
    pub dkg_end_messages: BTreeMap<u32, DkgEnd>,
    /// the current view of a successful DKG's participants' commitments
    pub party_polynomials: HashMap<u32, PolyCommitment>,
    /// map of SignatureShare indexed by signer ID
    pub signature_shares: BTreeMap<u32, Vec<SignatureShare>>,
    /// map of SignRoundInfo indexed by message bytes
    pub message_nonces: BTreeMap<Vec<u8>, SignRoundInfo>,
    /// aggregate public key
    pub aggregate_public_key: Option<Point>,
    /// current Signature
    pub signature: Option<Signature>,
    /// current SchnorrProof
    pub schnorr_proof: Option<SchnorrProof>,
    /// which signers we're currently waiting on for DKG
    pub dkg_wait_signer_ids: HashSet<u32>,
    /// the bytes that we're signing
    pub message: Vec<u8>,
    /// current state of the state machine
    pub state: State,
    /// start time for NonceRequest
    pub nonce_start: Option<Instant>,
    /// start time for DkgBegin
    pub dkg_public_start: Option<Instant>,
    /// start time for DkgPrivateBegin
    pub dkg_private_start: Option<Instant>,
    /// start time for DkgEndBegin
    pub dkg_end_start: Option<Instant>,
    /// start time for SignatureShareRequest
    pub sign_start: Option<Instant>,
    /// set of malicious signers during signing round
    pub malicious_signer_ids: HashSet<u32>,
    /// set of malicious signers during dkg round
    pub malicious_dkg_signer_ids: HashSet<u32>,
    /// coordinator public key
    pub coordinator_public_key: Option<ecdsa::PublicKey>,
}
```

**File:** src/state_machine/coordinator/mod.rs (L776-792)
```rust
        let new_coordinators = coordinators
            .iter()
            .map(|c| Coordinator::load(&c.save()))
            .collect::<Vec<Coordinator>>();

        assert_eq!(coordinators, new_coordinators);

        coordinators = new_coordinators;

        let new_signers = signers
            .iter()
            .map(|s| Signer::<SignerType>::load(&s.save()))
            .collect::<Vec<Signer<SignerType>>>();

        assert_eq!(signers, new_signers);

        signers = new_signers;
```

**File:** src/state_machine/coordinator/frost.rs (L147-155)
```rust
                        // We are done with the DKG round! Return the operation result
                        return Ok((
                            None,
                            Some(OperationResult::Dkg(
                                self.aggregate_public_key
                                    .ok_or(Error::MissingAggregatePublicKey)?,
                            )),
                        ));
                    }
```

**File:** src/state_machine/coordinator/frost.rs (L226-246)
```rust
    pub fn start_public_shares(&mut self) -> Result<Packet, Error> {
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        self.ids_to_await = (0..self.config.num_signers).collect();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting Public Share Distribution"
        );
        let dkg_begin = DkgBegin {
            dkg_id: self.current_dkg_id,
        };

        let dkg_begin_packet = Packet {
            sig: dkg_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgBegin"),
            msg: Message::DkgBegin(dkg_begin),
        };
        self.move_to(State::DkgPublicGather)?;
        Ok(dkg_begin_packet)
    }
```

**File:** src/state_machine/coordinator/frost.rs (L422-446)
```rust
    fn dkg_end_gathered(&mut self) -> Result<(), Error> {
        // Cache the polynomials used in DKG for the aggregator
        for signer_id in self.dkg_private_shares.keys() {
            let Some(dkg_public_shares) = self.dkg_public_shares.get(signer_id) else {
                warn!(%signer_id, "no DkgPublicShares");
                return Err(Error::BadStateChange(format!("Should not have transitioned to DkgEndGather since we were missing DkgPublicShares from signer {signer_id}")));
            };
            for (party_id, comm) in &dkg_public_shares.comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
        }

        // Calculate the aggregate public key
        let key = self
            .party_polynomials
            .iter()
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

        info!(
            %key,
            "Aggregate public key"
        );
        self.aggregate_public_key = Some(key);
        self.move_to(State::Idle)
    }
```

**File:** src/state_machine/coordinator/frost.rs (L826-847)
```rust
    fn load(state: &SavedState) -> Self {
        Self {
            aggregator: Aggregator::new(state.config.num_keys, state.config.threshold),
            config: state.config.clone(),
            current_dkg_id: state.current_dkg_id,
            current_sign_id: state.current_sign_id,
            current_sign_iter_id: state.current_sign_iter_id,
            dkg_public_shares: state.dkg_public_shares.clone(),
            dkg_private_shares: state.dkg_private_shares.clone(),
            dkg_end_messages: state.dkg_end_messages.clone(),
            party_polynomials: state.party_polynomials.clone(),
            public_nonces: state.message_nonces[&Vec::new()].public_nonces.clone(),
            signature_shares: state.signature_shares.clone(),
            aggregate_public_key: state.aggregate_public_key,
            signature: state.signature.clone(),
            schnorr_proof: state.schnorr_proof.clone(),
            message: state.message.clone(),
            ids_to_await: state.dkg_wait_signer_ids.clone(),
            state: state.state.clone(),
            coordinator_public_key: state.coordinator_public_key,
        }
    }
```

**File:** src/state_machine/coordinator/fire.rs (L396-417)
```rust
    pub fn start_public_shares(&mut self) -> Result<Packet, Error> {
        self.dkg_public_shares.clear();
        self.party_polynomials.clear();
        self.dkg_wait_signer_ids = (0..self.config.num_signers).collect();
        info!(
            dkg_id = %self.current_dkg_id,
            "Starting Public Share Distribution"
        );
        let dkg_begin = DkgBegin {
            dkg_id: self.current_dkg_id,
        };
        let dkg_begin_packet = Packet {
            sig: dkg_begin
                .sign(&self.config.message_private_key)
                .expect("Failed to sign DkgBegin"),
            msg: Message::DkgBegin(dkg_begin),
        };

        self.move_to(State::DkgPublicGather)?;
        self.dkg_public_start = Some(Instant::now());
        Ok(dkg_begin_packet)
    }
```

**File:** src/state_machine/coordinator/fire.rs (L794-812)
```rust
    fn dkg_end_gathered(&mut self) -> Result<(), Error> {
        // Cache the polynomials used in DKG for the aggregator
        for signer_id in self.dkg_private_shares.keys() {
            for (party_id, comm) in &self.dkg_public_shares[signer_id].comms {
                self.party_polynomials.insert(*party_id, comm.clone());
            }
        }

        // Calculate the aggregate public key
        let key = self
            .dkg_end_messages
            .keys()
            .flat_map(|signer_id| self.dkg_public_shares[signer_id].comms.clone())
            .fold(Point::default(), |s, (_, comm)| s + comm.poly[0]);

        info!("Aggregate public key: {key}");
        self.aggregate_public_key = Some(key);
        self.move_to(State::Idle)
    }
```

**File:** src/state_machine/coordinator/fire.rs (L1309-1337)
```rust
    fn load(state: &SavedState) -> Self {
        Self {
            aggregator: Aggregator::new(state.config.num_keys, state.config.threshold),
            config: state.config.clone(),
            current_dkg_id: state.current_dkg_id,
            current_sign_id: state.current_sign_id,
            current_sign_iter_id: state.current_sign_iter_id,
            dkg_public_shares: state.dkg_public_shares.clone(),
            dkg_private_shares: state.dkg_private_shares.clone(),
            dkg_end_messages: state.dkg_end_messages.clone(),
            party_polynomials: state.party_polynomials.clone(),
            message_nonces: state.message_nonces.clone(),
            signature_shares: state.signature_shares.clone(),
            aggregate_public_key: state.aggregate_public_key,
            signature: state.signature.clone(),
            schnorr_proof: state.schnorr_proof.clone(),
            message: state.message.clone(),
            dkg_wait_signer_ids: state.dkg_wait_signer_ids.clone(),
            state: state.state.clone(),
            dkg_public_start: state.dkg_public_start,
            dkg_private_start: state.dkg_private_start,
            dkg_end_start: state.dkg_end_start,
            nonce_start: state.nonce_start,
            sign_start: state.sign_start,
            malicious_signer_ids: state.malicious_signer_ids.clone(),
            malicious_dkg_signer_ids: state.malicious_dkg_signer_ids.clone(),
            coordinator_public_key: state.coordinator_public_key,
        }
    }
```
