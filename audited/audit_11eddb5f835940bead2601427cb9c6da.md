### Title
Missing key_ids <-> nonces length and ordering checks enable binding value manipulation in compute_aggregate_nonce

### Summary
The coordinator's gather_nonces() function fails to ensure the order and length of key_ids and nonces in NonceResponse messages align, allowing malicious signers to misalign these vectors. This enables binding value manipulation during threshold signature aggregation, risking signature forgery and protocol breakage.

### Finding Description
- **Code location**: `src/state_machine/coordinator/fire.rs`, function `gather_nonces`, lines 841-962; function `compute_aggregate_nonce`, lines 1176-1198; call to `compute::intermediate`, line 1195.
- In `gather_nonces`, the coordinator checks that the SET of received key_ids matches the configuration, and validates each nonce with `is_valid()`. However, it does not ensure that:
  - The length of key_ids equals the length of nonces,
  - The order of key_ids matches the corresponding order of nonces.
- When constructing vectors for the intermediate computation, all key_ids from all NonceResponses are concatenated into `party_ids`, and all nonces are concatenated into `nonces`. In `compute_aggregate_nonce`, both vectors are passed directly to `compute::intermediate`.
- In `compute::intermediate`, they are zipped, and if their lengths differ, the extra elements are dropped without error.
- This allows an attacker to send, for example, key_ids=[1,2,3] and nonces=[N3,N1,N2], or send more/fewer nonces than key_ids, enabling deliberate mis-binding of public nonces to key IDs. The binding value for a key could be computed over the wrong nonce, or omitted entirely.
- This directly violates the security invariant that "binding values must commit to all public nonces and the exact message".

**Why mitigations fail**: The relevant check (`if *signer_key_ids != nonce_response_key_ids`) only checks set equality, not length, order, or one-to-one correspondence. No error is signaled if the vectors are misaligned.

### Impact Explanation
- **What breaks:** Attackers can select which nonce gets mapped to which key ID or even omit bindings for keys, thus controlling the binding value computation in protocol aggregation.
- **Quantify impact:** A malicious signer could bias the aggregate nonce or binding values, creating an opportunity to forge or malleate a threshold signature, or undermine the unforgeability of the protocol.
- **Who is affected:** Any protocol participant relying on aggregated threshold signatures for critical consensus or transaction validation.
- **Severity justification:** This can lead to acceptance of invalid signatures, loss of consensus integrity, and direct loss of funds, implicating **Critical** protocol scope.

### Likelihood Explanation
- **Required attacker capabilities:** Any honest or malicious participant who controls their own signing node.
- **Attack complexity:** Trivial (just send a NonceResponse with mismatched key_ids and nonces).
- **Economic feasibility:** No cost beyond participation.
- **Detection risk:** Low, as vectors will typically be processed without error.
- **Estimated probability:** High if not mitigated.

### Recommendation
- In `gather_nonces`, before accepting a NonceResponse:
  - Check that `nonce_response.key_ids.len() == nonce_response.nonces.len()` and that they are sorted/matched as per config expectation.
  - Check that key_ids and nonces are in the canonical/expected order.
  - If not, reject the message and flag the sender as malicious.
- Enforce matching in all aggregator/intermediate computations as a defense-in-depth.
- Write explicit tests to ensure attacks with permuted or truncated vectors fail.
- Review similar checks wherever key_ids/nonces are associated.

### Proof of Concept
1. Craft a NonceResponse message with key_ids = [1,2,3] and nonces = [N2,N1,N3] (permuted), or with len(key_ids) ≠ len(nonces).
2. Coordinator accepts the message.
3. Aggregate nonce computation binds key_ids and nonces incorrectly, resulting in an incorrect signature or an unforgeability break.
4. Reproduction: Test case with malicious signing node in integration test will yield a signature that passes aggregation but does not correctly bind to the intended nonce-key mapping. No error is raised in coordinator. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/state_machine/coordinator/fire.rs (L841-962)
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
                .sign_wait_signer_ids
                .insert(nonce_response.signer_id);
            // Because of entry call, it is safe to unwrap here
            info!(
                sign_id = %nonce_response.sign_id,
                sign_iter_id = %nonce_response.sign_iter_id,
                signer_id = %nonce_response.signer_id,
                recv_keys = %nonce_info.nonce_recv_key_ids.len(),
                threshold = %self.config.threshold,
                "Received NonceResponse"
            );
            if nonce_info.nonce_recv_key_ids.len() >= self.config.threshold as usize {
                // We have a winning message!
                self.message.clone_from(&nonce_response.message);
                let aggregate_nonce = self.compute_aggregate_nonce();
                info!("Aggregate nonce: {aggregate_nonce}");

                self.move_to(State::SigShareRequest(signature_type))?;
            }
        }
        Ok(())
    }
```

**File:** src/state_machine/coordinator/fire.rs (L1176-1198)
```rust
    #[allow(non_snake_case)]
    fn compute_aggregate_nonce(&self) -> Point {
        // XXX this needs to be key_ids for v1 and signer_ids for v2
        let public_nonces = self
            .message_nonces
            .get(&self.message)
            .cloned()
            .unwrap_or_default()
            .public_nonces;
        let party_ids = public_nonces
            .values()
            .cloned()
            .flat_map(|pn| pn.key_ids)
            .collect::<Vec<u32>>();
        let nonces = public_nonces
            .values()
            .cloned()
            .flat_map(|pn| pn.nonces)
            .collect::<Vec<PublicNonce>>();
        let (_, R) = compute::intermediate(&self.message, &party_ids, &nonces);

        R
    }
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
