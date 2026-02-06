> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** src/traits.rs (L125-131)
```rust
    fn sign(
        &self,
        msg: &[u8],
        signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare>;
```

**File:** src/v1.rs (L707-759)
```rust
    fn sign(
        &self,
        msg: &[u8],
        _signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare> {
        let aggregate_nonce = compute::aggregate_nonce(msg, key_ids, nonces).unwrap();
        self.parties
            .iter()
            .map(|p| p.sign_precomputed(msg, key_ids, nonces, &aggregate_nonce))
            .collect()
    }

    fn sign_taproot(
        &self,
        msg: &[u8],
        _signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        merkle_root: Option<[u8; 32]>,
    ) -> Vec<SignatureShare> {
        let aggregate_nonce = compute::aggregate_nonce(msg, key_ids, nonces).unwrap();
        let tweak = compute::tweak(&self.parties[0].group_key, merkle_root);
        self.parties
            .iter()
            .map(|p| {
                p.sign_precomputed_with_tweak(msg, key_ids, nonces, &aggregate_nonce, Some(tweak))
            })
            .collect()
    }

    fn sign_schnorr(
        &self,
        msg: &[u8],
        _signer_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> Vec<SignatureShare> {
        let aggregate_nonce = compute::aggregate_nonce(msg, key_ids, nonces).unwrap();
        self.parties
            .iter()
            .map(|p| {
                p.sign_precomputed_with_tweak(
                    msg,
                    key_ids,
                    nonces,
                    &aggregate_nonce,
                    Some(Scalar::from(0)),
                )
            })
            .collect()
    }
```

**File:** src/v2.rs (L210-276)
```rust
    pub fn sign(
        &self,
        msg: &[u8],
        party_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
    ) -> SignatureShare {
        self.sign_with_tweak(msg, party_ids, key_ids, nonces, None)
    }

    /// Sign `msg` with this party's shares of the group private key, using the set of `party_ids`, `key_ids` and corresponding `nonces` with a tweaked public key. The posible values for tweak are
    /// None    - standard FROST signature
    /// Some(0) - BIP-340 schnorr signature using 32-byte private key adjustments
    /// Some(t) - BIP-340 schnorr signature with BIP-341 tweaked keys, using 32-byte private key adjustments
    #[allow(non_snake_case)]
    pub fn sign_with_tweak(
        &self,
        msg: &[u8],
        party_ids: &[u32],
        key_ids: &[u32],
        nonces: &[PublicNonce],
        tweak: Option<Scalar>,
    ) -> SignatureShare {
        // When using BIP-340 32-byte public keys, we have to invert the private key if the
        // public key is odd.  But if we're also using BIP-341 tweaked keys, we have to do
        // the same thing if the tweaked public key is odd.  In that case, only invert the
        // public key if exactly one of the internal or tweaked public keys is odd
        let mut cx_sign = Scalar::one();
        let tweaked_public_key = if let Some(t) = tweak {
            if t != Scalar::zero() {
                let key = compute::tweaked_public_key_from_tweak(&self.group_key, t);
                if key.has_even_y() ^ self.group_key.has_even_y() {
                    cx_sign = -cx_sign;
                }

                key
            } else {
                if !self.group_key.has_even_y() {
                    cx_sign = -cx_sign;
                }
                self.group_key
            }
        } else {
            self.group_key
        };
        let (_, R) = compute::intermediate(msg, party_ids, nonces);
        let c = compute::challenge(&tweaked_public_key, &R, msg);
        let mut r = &self.nonce.d + &self.nonce.e * compute::binding(&self.id(), nonces, msg);
        if tweak.is_some() && !R.has_even_y() {
            r = -r;
        }

        let mut cx = Scalar::zero();
        for key_id in self.key_ids.iter() {
            cx += c * &self.private_keys[key_id] * compute::lambda(*key_id, key_ids);
        }

        cx = cx_sign * cx;

        let z = r + cx;

        SignatureShare {
            id: self.party_id,
            z_i: z,
            key_ids: self.key_ids.clone(),
        }
    }
```

**File:** src/state_machine/signer/mod.rs (L757-842)
```rust
    fn sign_share_request<R: RngCore + CryptoRng>(
        &mut self,
        sign_request: &SignatureShareRequest,
        rng: &mut R,
    ) -> Result<Vec<Message>, Error> {
        let signer_id_set = sign_request
            .nonce_responses
            .iter()
            .map(|nr| nr.signer_id)
            .collect::<BTreeSet<u32>>();

        // The expected usage is that Signer IDs start at zero and
        // increment by one until self.total_signers - 1. So the checks
        // here should be sufficient for catching empty signer ID sets,
        // duplicate signer IDs, or unknown signer IDs.
        let is_invalid_request = sign_request.nonce_responses.len() != signer_id_set.len()
            || signer_id_set.is_empty()
            || signer_id_set.last() >= Some(&self.total_signers);

        if is_invalid_request {
            warn!("received an invalid SignatureShareRequest");
            return Err(Error::InvalidNonceResponse);
        }

        let nonces = sign_request
            .nonce_responses
            .iter()
            .flat_map(|nr| nr.nonces.clone())
            .collect::<Vec<PublicNonce>>();

        for nonce in &nonces {
            if !nonce.is_valid() {
                warn!(
                    signer_id = %self.signer_id,
                    "received an SignatureShareRequest with invalid nonce"
                );
                return Err(Error::InvalidNonceResponse);
            }
        }

        debug!(signer_id = %self.signer_id, "received a valid SignatureShareRequest");

        if signer_id_set.contains(&self.signer_id) {
            let key_ids: Vec<u32> = sign_request
                .nonce_responses
                .iter()
                .flat_map(|nr| nr.key_ids.iter().copied())
                .collect::<Vec<u32>>();

            let signer_ids = signer_id_set.into_iter().collect::<Vec<_>>();
            let msg = &sign_request.message;
            let signature_shares = match sign_request.signature_type {
                SignatureType::Taproot(merkle_root) => {
                    self.signer
                        .sign_taproot(msg, &signer_ids, &key_ids, &nonces, merkle_root)
                }
                SignatureType::Schnorr => {
                    self.signer
                        .sign_schnorr(msg, &signer_ids, &key_ids, &nonces)
                }
                SignatureType::Frost => self.signer.sign(msg, &signer_ids, &key_ids, &nonces),
            };

            self.signer.gen_nonces(&self.network_private_key, rng);

            let response = SignatureShareResponse {
                dkg_id: sign_request.dkg_id,
                sign_id: sign_request.sign_id,
                sign_iter_id: sign_request.sign_iter_id,
                signer_id: self.signer_id,
                signature_shares,
            };
            info!(
                signer_id = %self.signer_id,
                dkg_id = %sign_request.dkg_id,
                sign_id = %sign_request.sign_id,
                sign_iter_id = %sign_request.sign_iter_id,
                "sending SignatureShareResponse"
            );

            Ok(vec![Message::SignatureShareResponse(response)])
        } else {
            debug!(signer_id = %self.signer_id, "signer not included in SignatureShareRequest");
            Ok(Vec::new())
        }
    }
```

**File:** src/net.rs (L309-326)
```rust
#[derive(Clone, Serialize, Deserialize, PartialEq)]
/// Nonce response message from signers to coordinator
pub struct NonceResponse {
    /// DKG round ID
    pub dkg_id: u64,
    /// Signing round ID
    pub sign_id: u64,
    /// Signing round iteration ID
    pub sign_iter_id: u64,
    /// Signer ID
    pub signer_id: u32,
    /// Key IDs
    pub key_ids: Vec<u32>,
    /// Public nonces
    pub nonces: Vec<PublicNonce>,
    /// Bytes being signed
    pub message: Vec<u8>,
}
```

**File:** src/state_machine/coordinator/fire.rs (L841-940)
```rust
    fn gather_nonces(
        &mut self,
        packet: &Packet,
        signature_type: SignatureType,
    ) -> Result<(), Error> {
        if let Message::NonceResponse(nonce_response) = &packet.msg {
            if nonce_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(nonce_response.dkg_id, self.current_dkg_id));
            }
            if nonce_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    nonce_response.sign_id,
                    self.current_sign_id,
                ));
            }
            if nonce_response.sign_iter_id != self.current_sign_iter_id {
                return Err(Error::BadSignIterId(
                    nonce_response.sign_iter_id,
                    self.current_sign_iter_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&nonce_response.signer_id) {
                warn!(signer_id = %nonce_response.signer_id, "No public key in config");
                return Ok(());
            };

            // check that the key_ids match the config
            let Some(signer_key_ids) = self
                .config
                .public_keys
                .signer_key_ids
                .get(&nonce_response.signer_id)
            else {
                warn!(signer_id = %nonce_response.signer_id, "No keys IDs configured");
                return Ok(());
            };

            let nonce_response_key_ids = nonce_response
                .key_ids
                .iter()
                .cloned()
                .collect::<HashSet<u32>>();
            if *signer_key_ids != nonce_response_key_ids {
                warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
                return Ok(());
            }

            for nonce in &nonce_response.nonces {
                if !nonce.is_valid() {
                    warn!(
                        sign_id = %nonce_response.sign_id,
                        sign_iter_id = %nonce_response.sign_iter_id,
                        signer_id = %nonce_response.signer_id,
                        "Received invalid nonce in NonceResponse"
                    );
                    return Ok(());
                }
            }

            if self
                .malicious_signer_ids
                .contains(&nonce_response.signer_id)
            {
                warn!(
                    sign_id = %nonce_response.sign_id,
                    sign_iter_id = %nonce_response.sign_iter_id,
                    signer_id = %nonce_response.signer_id,
                    "Received malicious NonceResponse"
                );
                //return Err(Error::MaliciousSigner(nonce_response.signer_id));
                return Ok(());
            }

            let nonce_info = self
                .message_nonces
                .entry(nonce_response.message.clone())
                .or_default();

            let have_nonces = nonce_info
                .public_nonces
                .contains_key(&nonce_response.signer_id);

            if have_nonces {
                info!(signer_id = %nonce_response.signer_id, "Received duplicate NonceResponse");
                return Ok(());
            }

            nonce_info
                .public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());

            // ignore the passed key_ids
            for key_id in signer_key_ids {
                nonce_info.nonce_recv_key_ids.insert(*key_id);
            }

            nonce_info
```

**File:** src/state_machine/coordinator/frost.rs (L473-563)
```rust
    fn gather_nonces(
        &mut self,
        packet: &Packet,
        signature_type: SignatureType,
    ) -> Result<(), Error> {
        if let Message::NonceResponse(nonce_response) = &packet.msg {
            if nonce_response.dkg_id != self.current_dkg_id {
                return Err(Error::BadDkgId(nonce_response.dkg_id, self.current_dkg_id));
            }
            if nonce_response.sign_id != self.current_sign_id {
                return Err(Error::BadSignId(
                    nonce_response.sign_id,
                    self.current_sign_id,
                ));
            }
            if nonce_response.sign_iter_id != self.current_sign_iter_id {
                return Err(Error::BadSignIterId(
                    nonce_response.sign_iter_id,
                    self.current_sign_iter_id,
                ));
            }

            // check that the signer_id exists in the config
            let signer_public_keys = &self.config.public_keys.signers;
            if !signer_public_keys.contains_key(&nonce_response.signer_id) {
                warn!(signer_id = %nonce_response.signer_id, "No public key in config");
                return Ok(());
            };

            // check that the key_ids match the config
            let Some(signer_key_ids) = self
                .config
                .public_keys
                .signer_key_ids
                .get(&nonce_response.signer_id)
            else {
                warn!(signer_id = %nonce_response.signer_id, "No keys IDs configured");
                return Ok(());
            };

            let nonce_response_key_ids = nonce_response
                .key_ids
                .iter()
                .cloned()
                .collect::<HashSet<u32>>();
            if *signer_key_ids != nonce_response_key_ids {
                warn!(signer_id = %nonce_response.signer_id, "Nonce response key_ids didn't match config");
                return Ok(());
            }

            for nonce in &nonce_response.nonces {
                if !nonce.is_valid() {
                    warn!(
                        sign_id = %nonce_response.sign_id,
                        sign_iter_id = %nonce_response.sign_iter_id,
                        signer_id = %nonce_response.signer_id,
                        "Received invalid nonce in NonceResponse"
                    );
                    return Ok(());
                }
            }

            let have_nonces = self.public_nonces.contains_key(&nonce_response.signer_id);

            if have_nonces {
                info!(signer_id = %nonce_response.signer_id, "Received duplicate NonceResponse");
                return Ok(());
            }

            self.public_nonces
                .insert(nonce_response.signer_id, nonce_response.clone());
            self.ids_to_await.remove(&nonce_response.signer_id);
            debug!(
                sign_id = %nonce_response.sign_id,
                sign_iter_id = %nonce_response.sign_iter_id,
                signer_id = %nonce_response.signer_id,
                waiting = ?self.ids_to_await,
                "NonceResponse received"
            );
        }
        if self.ids_to_await.is_empty() {
            let aggregate_nonce = self.compute_aggregate_nonce();
            info!(
                %aggregate_nonce,
                "Aggregate nonce"
            );

            self.move_to(State::SigShareRequest(signature_type))?;
        }
        Ok(())
    }
```

**File:** src/compute.rs (L83-96)
```rust
#[allow(non_snake_case)]
/// Compute the intermediate values used in both the parties and the aggregator
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
