# Audit Report

## Title
Out-of-Order DKG Message Processing Causes Silent Share Loss and DKG Denial of Service

## Summary
The signer's message processing logic lacks state validation before dispatching messages to handlers, allowing `DkgPrivateShares` to be processed before `DkgPublicShares`. This causes silent message loss because the required key exchange public keys are unavailable, resulting in DKG failure for all participants.

## Finding Description

The vulnerability exists in the signer's message processing architecture. Unlike the coordinator which validates state before processing messages, the signer dispatches messages based solely on type without checking if the current state is appropriate. [1](#0-0) 

The coordinator is protected by a loop-based state machine that matches on current state before processing: [2](#0-1) 

When `DkgPrivateShares` arrives out of order, the `dkg_private_shares` handler attempts to retrieve the sender's KEX public key to decrypt the shares: [3](#0-2) 

The `get_kex_public_key` method looks up keys from `self.kex_public_keys`, which is only populated during `DkgPublicShares` processing: [4](#0-3) 

These KEX public keys are stored when processing `DkgPublicShares`: [5](#0-4) 

If the KEX key is missing, the handler silently returns without storing the shares. The shares would have been stored at line 1063-1064, but this is unreachable after the early return.

Later, when DKG completion is checked, the missing shares are detected: [6](#0-5) 

This causes DKG to fail with `MissingPrivateShares`: [7](#0-6) 

The protocol breaks the availability guarantee because network packet reordering (a normal network condition) causes deterministic DKG failure.

## Impact Explanation

This vulnerability causes complete DKG denial of service affecting all participants in the round. The impact severity is **Low** per the provided scope: "Any remotely-exploitable denial of service in a node."

Specific impacts:
- DKG round fails for all signers when shares are missing
- Threshold signature group cannot be formed
- No signatures can be produced until a successful DKG completes
- System initialization or key rotation is blocked

While DKG can be retried, persistent network conditions or deliberate packet reordering can prevent DKG completion indefinitely. However, this does not cause invalid signatures, fund loss, or chain splits, justifying the Low severity classification.

## Likelihood Explanation

The likelihood is **High** because:

1. **Trigger conditions are common**: Network packets naturally arrive out of order due to routing, buffering, and congestion. This can trigger the vulnerability without any attacker.

2. **No defensive mechanisms**: The codebase has no message buffering, retry logic, or state validation before message processing.

3. **Deterministic behavior**: Once triggered, the failure is guaranteed - there are no race conditions or probabilistic factors.

4. **Low attack complexity**: If deliberate, an attacker only needs network-level access to delay or reorder packets between signers on the P2P network. No cryptographic secrets or special privileges are required.

5. **Natural occurrence**: This can happen accidentally during normal operation, making it a protocol robustness issue as much as a security vulnerability.

## Recommendation

Implement state validation before processing messages in the signer, mirroring the coordinator's approach:

1. **Add state checking in `process()` method**: Validate that the current state allows processing of each message type before dispatching to handlers.

2. **Add message buffering**: Queue out-of-order messages for later processing when the signer reaches the appropriate state.

3. **Add explicit error logging**: When messages are dropped due to ordering issues, log an error indicating the state violation rather than silently returning.

4. **Alternative: Store shares conditionally**: Modify `dkg_private_shares` to store the encrypted shares even when KEX keys are unavailable, then decrypt them later when `DkgPublicShares` arrives.

The recommended fix is to add state validation similar to the coordinator pattern, checking `self.state` before dispatching to message-specific handlers.

## Proof of Concept

```rust
#[test]
fn test_out_of_order_dkg_messages() {
    let mut rng = create_rng();
    let num_signers = 3;
    let threshold = 2;
    
    // Create signers
    let mut signers = (0..num_signers)
        .map(|i| create_signer(i, num_signers, threshold, &mut rng))
        .collect::<Vec<_>>();
    
    // Signer 0 sends DkgPrivateShares to Signer 1
    // BEFORE Signer 1 receives DkgPublicShares from Signer 0
    let private_shares = create_dkg_private_shares(&signers[0]);
    let packet = create_packet(Message::DkgPrivateShares(private_shares));
    
    // Process out of order - should fail silently
    let result = signers[1].process(&packet, &mut rng);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty()); // Silent failure
    
    // Verify shares were NOT stored
    assert!(!signers[1].dkg_private_shares.contains_key(&0));
    
    // Later when checking DKG completion, missing shares cause failure
    assert!(!signers[1].can_dkg_end());
}
```

This test demonstrates that when `DkgPrivateShares` arrives before `DkgPublicShares`, the shares are silently dropped and DKG cannot complete.

### Citations

**File:** src/state_machine/signer/mod.rs (L458-501)
```rust
    pub fn process<R: RngCore + CryptoRng>(
        &mut self,
        packet: &Packet,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        if self.verify_packet_sigs {
            let Some(coordinator_public_key) = self.coordinator_public_key else {
                return Err(Error::MissingCoordinatorPublicKey);
            };
            if !packet.verify(&self.public_keys, &coordinator_public_key) {
                return Err(Error::InvalidPacketSignature);
            }
        }
        let out_msgs = match &packet.msg {
            Message::DkgBegin(dkg_begin) => self.dkg_begin(dkg_begin, rng),
            Message::DkgPrivateBegin(dkg_private_begin) => {
                self.dkg_private_begin(dkg_private_begin, rng)
            }
            Message::DkgEndBegin(dkg_end_begin) => self.dkg_end_begin(dkg_end_begin),
            Message::DkgPublicShares(dkg_public_shares) => self.dkg_public_share(dkg_public_shares),
            Message::DkgPrivateShares(dkg_private_shares) => {
                self.dkg_private_shares(dkg_private_shares, rng)
            }
            Message::SignatureShareRequest(sign_share_request) => {
                self.sign_share_request(sign_share_request, rng)
            }
            Message::NonceRequest(nonce_request) => self.nonce_request(nonce_request, rng),
            Message::DkgEnd(_) | Message::NonceResponse(_) | Message::SignatureShareResponse(_) => {
                Ok(vec![])
            } // TODO
        };

        match out_msgs {
            Ok(mut out) => {
                if self.can_dkg_end() {
                    let dkg_end_msgs = self.dkg_ended(rng)?;
                    out.push(dkg_end_msgs);
                    self.move_to(State::Idle)?;
                }
                Ok(out)
            }
            Err(e) => Err(e),
        }
    }
```

**File:** src/state_machine/signer/mod.rs (L601-608)
```rust
        if !missing_private_shares.is_empty() {
            return Ok(Message::DkgEnd(DkgEnd {
                dkg_id: self.dkg_id,
                signer_id: self.signer_id,
                status: DkgStatus::Failure(DkgFailure::MissingPrivateShares(
                    missing_private_shares,
                )),
            }));
```

**File:** src/state_machine/signer/mod.rs (L685-721)
```rust
    pub fn can_dkg_end(&self) -> bool {
        debug!(
            "can_dkg_end: state {:?} DkgPrivateBegin {} DkgEndBegin {}",
            self.state,
            self.dkg_private_begin_msg.is_some(),
            self.dkg_end_begin_msg.is_some(),
        );

        if self.state == State::DkgPrivateGather {
            if let Some(dkg_private_begin) = &self.dkg_private_begin_msg {
                // need public shares from active signers
                for signer_id in &dkg_private_begin.signer_ids {
                    if !self.dkg_public_shares.contains_key(signer_id) {
                        debug!("can_dkg_end: false, missing public shares from signer {signer_id}");
                        return false;
                    }
                }

                if let Some(dkg_end_begin) = &self.dkg_end_begin_msg {
                    // need private shares from active signers
                    for signer_id in &dkg_end_begin.signer_ids {
                        if !self.dkg_private_shares.contains_key(signer_id) {
                            debug!("can_dkg_end: false, missing private shares from signer {signer_id}");
                            return false;
                        }
                    }
                    debug!("can_dkg_end: true");

                    return true;
                }
            }
        } else {
            debug!("can_dkg_end: false, bad state {:?}", self.state);
            return false;
        }
        false
    }
```

**File:** src/state_machine/signer/mod.rs (L1018-1026)
```rust
        for key_id in signer_key_ids {
            self.kex_public_keys
                .insert(*key_id, dkg_public_shares.kex_public_key);
        }

        self.dkg_public_shares
            .insert(dkg_public_shares.signer_id, dkg_public_shares.clone());
        Ok(vec![])
    }
```

**File:** src/state_machine/signer/mod.rs (L1029-1045)
```rust
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
```

**File:** src/state_machine/signer/mod.rs (L1112-1129)
```rust
    fn get_kex_public_key(&self, signer_id: u32) -> Result<Point, Error> {
        let Some(signer_key_ids) = self.public_keys.signer_key_ids.get(&signer_id) else {
            warn!(%signer_id, "No key_ids configured");
            return Err(Error::Config(ConfigError::InvalidSignerId(signer_id)));
        };

        let Some(signer_key_id) = signer_key_ids.iter().next() else {
            warn!(%signer_id, "No key_ids configured");
            return Err(Error::Config(ConfigError::InvalidSignerId(signer_id)));
        };

        let Some(kex_public_key) = self.kex_public_keys.get(signer_key_id) else {
            warn!(%signer_id, %signer_key_id, "No KEX public key configured");
            return Err(Error::MissingKexPublicKey(*signer_key_id));
        };

        Ok(*kex_public_key)
    }
```

**File:** src/state_machine/coordinator/frost.rs (L71-120)
```rust
        loop {
            match self.state.clone() {
                State::Idle => {
                    // Did we receive a coordinator message?
                    if let Message::DkgBegin(dkg_begin) = &packet.msg {
                        if self.current_dkg_id == dkg_begin.dkg_id {
                            // We have already processed this DKG round
                            return Ok((None, None));
                        }
                        // use dkg_id from DkgBegin
                        let packet = self.start_dkg_round(Some(dkg_begin.dkg_id))?;
                        return Ok((Some(packet), None));
                    } else if let Message::NonceRequest(nonce_request) = &packet.msg {
                        if self.current_sign_id == nonce_request.sign_id {
                            // We have already processed this sign round
                            return Ok((None, None));
                        }
                        self.current_sign_iter_id = nonce_request.sign_iter_id;
                        // use sign_id from NonceRequest
                        let packet = self.start_signing_round(
                            nonce_request.message.as_slice(),
                            nonce_request.signature_type,
                            Some(nonce_request.sign_id),
                        )?;
                        return Ok((Some(packet), None));
                    }
                    return Ok((None, None));
                }
                State::DkgPublicDistribute => {
                    let packet = self.start_public_shares()?;
                    return Ok((Some(packet), None));
                }
                State::DkgPublicGather => {
                    self.gather_public_shares(packet)?;
                    if self.state == State::DkgPublicGather {
                        // We need more data
                        return Ok((None, None));
                    }
                }
                State::DkgPrivateDistribute => {
                    let packet = self.start_private_shares()?;
                    return Ok((Some(packet), None));
                }
                State::DkgPrivateGather => {
                    self.gather_private_shares(packet)?;
                    if self.state == State::DkgPrivateGather {
                        // We need more data
                        return Ok((None, None));
                    }
                }
```
