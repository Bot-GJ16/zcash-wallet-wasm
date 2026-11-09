//! Authenticated discovery and read-only minimum voting eligibility.
#![allow(dead_code)]
#[cfg(test)]
pub(crate) mod tests {
    use super::super::network::VotingNetwork;
    use super::*;
    use std::sync::Mutex;
    use zcash_voting::transport::{OwnedHttpResponse, TransportError, TransportFuture};
    const ID: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const STATIC: &[u8] = include_bytes!("fixtures/static.json");
    const DYNAMIC: &[u8] = include_bytes!("fixtures/dynamic.json");
    struct Fixture {
        replies: Mutex<std::collections::VecDeque<Result<OwnedHttpResponse, TransportError>>>,
        urls: Mutex<Vec<String>>,
    }
    impl HttpTransport for Fixture {
        fn execute(&self, req: OwnedHttpRequest) -> TransportFuture {
            assert_eq!(req.method, "GET");
            assert_eq!(req.timeout_ms, REQUEST_TIMEOUT_MS);
            assert_eq!(req.kind, RequestKind::Idempotent);
            assert!(req.max_response_bytes == CONFIG_LIMIT || req.max_response_bytes == API_LIMIT);
            self.urls.lock().unwrap().push(req.url);
            let reply = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected request");
            Box::pin(async { reply })
        }
    }
    fn ok(body: Vec<u8>) -> Result<OwnedHttpResponse, TransportError> {
        Ok(OwnedHttpResponse {
            content_type: None,
            status: 200,
            body,
        })
    }
    fn fixture(replies: Vec<Result<OwnedHttpResponse, TransportError>>) -> Fixture {
        Fixture {
            replies: Mutex::new(replies.into()),
            urls: Mutex::new(vec![]),
        }
    }
    fn source() -> String {
        format!(
            "https://example.com/static.json?checksum=sha256:{}",
            hex::encode(Sha256::digest(STATIC))
        )
    }
    pub(crate) fn active() -> serde_json::Value {
        serde_json::json!({"vote_round_id": BASE64.encode(hex::decode(ID).unwrap()), "snapshot_height": 100,
            "nc_root": BASE64.encode([1;32]), "nullifier_imt_root": BASE64.encode([2;32]),
            "ea_pk": BASE64.encode([9;32]), "status": 1, "network": "testnet",
            "ceremony_phase_start": 1000, "vote_end_time": 2000, "title": "Synthetic vote",
            "proposals": [{"id":1,"title":"Question","options":[{"label":"Yes"},{"index":1,"label":"No"}]}]})
    }
    fn envelope(entries: Vec<serde_json::Value>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"rounds": entries})).unwrap()
    }
    pub(crate) async fn discover(
        entries: Vec<serde_json::Value>,
        now: u64,
    ) -> (VotingDiscovery, BTreeMap<String, TrustedRound>) {
        discover_for(VotingNetwork::Testnet, entries, now).await
    }
    pub(crate) async fn discover_for(
        network: VotingNetwork,
        entries: Vec<serde_json::Value>,
        now: u64,
    ) -> (VotingDiscovery, BTreeMap<String, TrustedRound>) {
        discover_with_source(
            &fixture(vec![
                ok(STATIC.to_vec()),
                ok(DYNAMIC.to_vec()),
                ok(envelope(entries)),
            ]),
            network,
            &source(),
            now,
        )
        .await
        .unwrap()
    }
    async fn discover_with_source(
        transport: &impl HttpTransport,
        network: VotingNetwork,
        source: &str,
        now: u64,
    ) -> Result<(VotingDiscovery, BTreeMap<String, TrustedRound>), VotingApiError> {
        discover_with_clock(transport, network, source, || Ok(now)).await
    }
    async fn discover_stage_with_source(
        transport: &impl HttpTransport,
        source: &str,
        now: u64,
    ) -> Result<(VotingDiscovery, BTreeMap<String, TrustedRound>), VotingApiError> {
        discover_with_source(transport, VotingNetwork::Testnet, source, now).await
    }

    #[tokio::test]
    async fn discovery_binds_optional_service_network_to_selected_context() {
        for (context, accepted, rejected) in [
            (
                VotingNetwork::Testnet,
                ["test", "testnet"],
                ["main", "mainnet"],
            ),
            (
                VotingNetwork::Mainnet,
                ["main", "mainnet"],
                ["test", "testnet"],
            ),
        ] {
            let mut absent = active();
            absent.as_object_mut().unwrap().remove("network");
            let (discovery, rounds) = discover_for(context, vec![absent], 1500).await;
            assert_eq!(discovery.accepted.len(), 1);
            assert_eq!(rounds[ID].network, context);

            for name in accepted {
                let mut entry = active();
                entry["network"] = serde_json::json!(name);
                let (discovery, rounds) = discover_for(context, vec![entry], 1500).await;
                assert_eq!(discovery.accepted.len(), 1, "{context:?}: {name}");
                assert_eq!(rounds[ID].network, context);
            }

            for value in [
                serde_json::json!(rejected[0]),
                serde_json::json!(rejected[1]),
                serde_json::json!("regtest"),
                serde_json::json!(1),
            ] {
                let mut entry = active();
                entry["network"] = value.clone();
                let (discovery, rounds) = discover_for(context, vec![entry], 1500).await;
                assert!(rounds.is_empty(), "{context:?}: {value}");
                assert_eq!(
                    discovery.rejected[0].code,
                    VotingErrorCode::NetworkMismatch,
                    "{context:?}: {value}"
                );
            }
        }
    }

    #[tokio::test]
    async fn discovery_checks_expiry_after_fetching_active_metadata() {
        use std::sync::{
            Arc,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        };
        struct AdvancingTransport {
            fixture: Fixture,
            clock: Arc<AtomicU64>,
        }
        impl HttpTransport for AdvancingTransport {
            fn execute(&self, req: OwnedHttpRequest) -> TransportFuture {
                let reply = self.fixture.execute(req);
                let clock = self.clock.clone();
                Box::pin(async move {
                    let result = reply.await;
                    clock.fetch_add(1, Ordering::SeqCst);
                    result
                })
            }
        }
        for (initial, expired) in [(1996, false), (1997, true), (1998, true)] {
            let clock = Arc::new(AtomicU64::new(initial));
            let samples = AtomicUsize::new(0);
            let transport = AdvancingTransport {
                fixture: fixture(vec![
                    ok(STATIC.to_vec()),
                    ok(DYNAMIC.to_vec()),
                    ok(envelope(vec![active()])),
                ]),
                clock: clock.clone(),
            };
            let (discovery, trusted) =
                discover_with_clock(&transport, VotingNetwork::Testnet, &source(), || {
                    samples.fetch_add(1, Ordering::SeqCst);
                    Ok(clock.load(Ordering::SeqCst))
                })
                .await
                .unwrap();
            assert_eq!(clock.load(Ordering::SeqCst), initial + 3);
            assert_eq!(samples.load(Ordering::SeqCst), 1);
            assert_eq!(trusted.is_empty(), expired, "initial clock {initial}");
            if expired {
                assert!(discovery.accepted.is_empty());
                assert_eq!(discovery.rejected[0].code, VotingErrorCode::RoundExpired);
            }
        }
    }
    #[tokio::test]
    async fn pinned_discovery_intersects_and_preserves_endpoint_provenance() {
        let mut other = active();
        other["vote_round_id"] = serde_json::json!("01".repeat(32));
        let mut entry = active();
        entry["vote_server_urls"] = serde_json::json!(["https://evil.invalid"]);
        entry["pir_urls"] = entry["vote_server_urls"].clone();
        entry["tree_url"] = serde_json::json!("https://evil.invalid");
        let (discovery, trusted) = discover(vec![entry, other], 1500).await;
        assert_eq!(discovery.accepted.len(), 1);
        assert_eq!(discovery.rejected.len(), 1);
        assert_eq!(
            discovery.rejected[0].code,
            VotingErrorCode::RoundUnauthenticated
        );
        let round = &trusted[ID];
        assert_eq!(round.params.ea_pk, [7; 32]);
        assert_eq!(round.vote_server_urls, ["https://vote.example.com"]);
        assert_eq!(round.pir_urls, ["https://pir.example.com"]);
        assert_eq!(round.tree_url, "https://vote.example.com");
        let identity = round.identity();
        assert_eq!(
            round
                .compare_identity(
                    &serde_json::from_slice(&serde_json::to_vec(&identity).unwrap()).unwrap()
                )
                .unwrap(),
            ()
        );
        let mut changed = round.clone();
        changed.params.nc_root[0] ^= 1;
        assert_eq!(
            changed.compare_identity(&identity).unwrap_err().code,
            VotingErrorCode::RecoveryConflict
        );
        changed = round.clone();
        changed.proposals[0].title.push('!');
        assert!(changed.compare_identity(&identity).is_err());
    }

    #[tokio::test]
    async fn invalid_dynamic_round_does_not_block_authenticated_discovery() {
        let mut dynamic: Value = serde_json::from_slice(DYNAMIC).unwrap();
        dynamic["rounds"]["7ce96992c8eb47cf4c75ec40fbc000917ecd35489c048b35b08f15226ee34d47"] =
            dynamic["rounds"][ID].clone();
        let transport = fixture(vec![
            ok(STATIC.to_vec()),
            ok(serde_json::to_vec(&dynamic).unwrap()),
            ok(envelope(vec![active()])),
        ]);

        let (discovery, trusted) = discover_stage_with_source(&transport, &source(), 1500)
            .await
            .unwrap();
        assert_eq!(discovery.accepted.len(), 1);
        assert!(discovery.rejected.is_empty());
        assert!(trusted.contains_key(ID));
    }

    #[tokio::test]
    async fn static_hash_and_dynamic_signatures_fail_closed_with_ordered_failover() {
        let f = fixture(vec![ok(b"{}".to_vec())]);
        assert_eq!(
            discover_stage_with_source(&f, &source(), 1500)
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::ConfigUntrusted
        );
        assert_eq!(f.urls.lock().unwrap().len(), 1);
        let mut bad: serde_json::Value = serde_json::from_slice(DYNAMIC).unwrap();
        bad["rounds"][ID]["signatures"][0]["sig"] = serde_json::json!(BASE64.encode([0; 64]));
        let f = fixture(vec![
            ok(STATIC.to_vec()),
            ok(serde_json::to_vec(&bad).unwrap()),
            ok(DYNAMIC.to_vec()),
            ok(envelope(vec![active()])),
        ]);
        assert_eq!(
            discover_stage_with_source(&f, &source(), 1500)
                .await
                .unwrap()
                .0
                .accepted
                .len(),
            1
        );
        assert_eq!(
            *f.urls.lock().unwrap(),
            vec![
                "https://example.com/static.json",
                "https://a.example.com/dynamic.json",
                "https://b.example.com/dynamic.json",
                "https://vote.example.com/shielded-vote/v1/rounds/active"
            ]
        );
        let bad = serde_json::to_vec(&bad).unwrap();
        let f = fixture(vec![
            ok(STATIC.to_vec()),
            ok(bad.clone()),
            ok(bad),
            ok(envelope(vec![active()])),
        ]);
        let (d, t) = discover_stage_with_source(&f, &source(), 1500)
            .await
            .unwrap();
        assert!(d.accepted.is_empty());
        assert!(t.is_empty());
        assert!(!d.rejected.is_empty());
    }
    #[tokio::test]
    async fn malformed_expired_network_roots_and_colliding_ids_are_rejected() {
        for (key, value, code) in [
            (
                "network",
                serde_json::json!("mainnet"),
                VotingErrorCode::NetworkMismatch,
            ),
            (
                "network",
                serde_json::json!("regtest"),
                VotingErrorCode::NetworkMismatch,
            ),
            (
                "vote_end_time",
                serde_json::json!(1500),
                VotingErrorCode::RoundExpired,
            ),
            (
                "nc_root",
                serde_json::json!("bad"),
                VotingErrorCode::RoundUnauthenticated,
            ),
            (
                "nullifier_imt_root",
                serde_json::json!(BASE64.encode([255; 32])),
                VotingErrorCode::RoundUnauthenticated,
            ),
            (
                "snapshot_height",
                serde_json::json!(u64::MAX),
                VotingErrorCode::RoundUnauthenticated,
            ),
            (
                "status",
                serde_json::json!(2),
                VotingErrorCode::RoundUnauthenticated,
            ),
            (
                "vote_round_id",
                serde_json::json!("payload secret"),
                VotingErrorCode::RoundUnauthenticated,
            ),
        ] {
            let mut a = active();
            a[key] = value;
            let (d, t) = discover(vec![a], 1500).await;
            assert!(t.is_empty(), "{key}");
            assert_eq!(d.rejected[0].code, code, "{key}");
            assert!(!d.rejected[0].message.contains("payload"));
        }
        assert_eq!(discover(vec![active()], 1999).await.0.accepted.len(), 1);
        let mut hex = active();
        hex["vote_round_id"] = serde_json::json!(ID);
        let (d, t) = discover(vec![active(), hex], 1500).await;
        assert!(t.is_empty());
        assert_eq!(d.rejected.len(), 2);
        for id in [
            "ff".repeat(32),
            format!(" {ID}"),
            BASE64.encode(ID.as_bytes()),
        ] {
            assert!(normalize_round_id(&id).is_err());
        }
        assert_eq!(
            normalize_round_id(&BASE64.encode(hex::decode(ID).unwrap())).unwrap(),
            ID
        );
    }
    #[tokio::test]
    async fn fetch_limits_status_and_unsupported_mirrors_fail_closed() {
        for failure in [
            Err(TransportError::Definite),
            Ok(OwnedHttpResponse {
                content_type: None,
                status: 503,
                body: b"secret body".to_vec(),
            }),
            ok(vec![0; CONFIG_LIMIT + 1]),
        ] {
            let f = fixture(vec![failure]);
            assert_eq!(
                discover_stage_with_source(&f, &source(), 1500)
                    .await
                    .unwrap_err()
                    .code,
                VotingErrorCode::ConfigFetchFailed
            );
        }
        for key in ["vote_server", "vote_protocol", "tally"] {
            let mut bad: serde_json::Value = serde_json::from_slice(DYNAMIC).unwrap();
            bad["supported_versions"][key] = serde_json::json!("v99");
            let f = fixture(vec![
                ok(STATIC.to_vec()),
                ok(serde_json::to_vec(&bad).unwrap()),
                ok(DYNAMIC.to_vec()),
                ok(envelope(vec![active()])),
            ]);
            assert_eq!(
                discover_stage_with_source(&f, &source(), 1500)
                    .await
                    .unwrap()
                    .0
                    .accepted
                    .len(),
                1
            );
        }
    }

    #[tokio::test]
    async fn signed_material_tampering_never_accepts_an_active_round() {
        for field in [
            "ea_pk",
            "layout",
            "round_id",
            "legacy_auth_version",
            "unsupported_auth_version",
        ] {
            let mut doc: Value = serde_json::from_slice(DYNAMIC).unwrap();
            match field {
                "ea_pk" => doc["rounds"][ID]["ea_pk"] = serde_json::json!(BASE64.encode([8; 32])),
                "layout" => doc["pir_layout"]["poly_len"] = serde_json::json!(2048),
                "legacy_auth_version" => doc["rounds"][ID]["auth_version"] = serde_json::json!(1),
                "unsupported_auth_version" => {
                    doc["rounds"][ID]["auth_version"] = serde_json::json!(99)
                }
                _ => {
                    let round = doc["rounds"].as_object_mut().unwrap().remove(ID).unwrap();
                    doc["rounds"]["01".repeat(32)] = round;
                }
            }
            let bytes = serde_json::to_vec(&doc).unwrap();
            let f = fixture(vec![
                ok(STATIC.to_vec()),
                ok(bytes.clone()),
                ok(bytes),
                ok(envelope(vec![active()])),
            ]);
            let (d, t) = discover_stage_with_source(&f, &source(), 1500)
                .await
                .unwrap();
            assert!(d.accepted.is_empty(), "{field}");
            assert!(t.is_empty());
        }
    }

    #[tokio::test]
    async fn correctly_signed_unusable_authority_keys_are_rejected() {
        for dynamic in [
            include_bytes!("fixtures/dynamic-invalid-key.json").as_slice(),
            include_bytes!("fixtures/dynamic-identity-key.json").as_slice(),
        ] {
            let anchor = resolve_static_voting_config(&source(), STATIC).unwrap();
            let resolved = resolve_dynamic_voting_config(
                anchor,
                dynamic,
                ResolveVotingConfigOptions::default(),
            )
            .unwrap();
            assert_eq!(
                resolved.authenticated_rounds.len(),
                1,
                "signature must authenticate"
            );
            let transport = fixture(vec![
                ok(STATIC.to_vec()),
                ok(dynamic.to_vec()),
                ok(envelope(vec![active()])),
            ]);
            let (discovery, trusted) = discover_stage_with_source(&transport, &source(), 1500)
                .await
                .unwrap();
            assert!(trusted.is_empty());
            assert!(discovery.accepted.is_empty());
            assert_eq!(
                discovery.rejected[0].code,
                VotingErrorCode::RoundUnauthenticated
            );
            assert_eq!(
                discovery.rejected[0].message,
                "Voting round could not be authenticated."
            );
        }
    }

    #[tokio::test]
    async fn active_endpoint_failover_is_ordered_bounded_and_handles_empty_round() {
        let mut doc: Value = serde_json::from_slice(DYNAMIC).unwrap();
        doc["vote_servers"].as_array_mut().unwrap().push(
            serde_json::json!({"url":"https://vote2.example.com/mount/","label":"secondary"}),
        );
        for bad in [
            Err(TransportError::Definite),
            ok(vec![0; API_LIMIT + 1]),
            ok(b"malformed".to_vec()),
            Ok(OwnedHttpResponse {
                content_type: None,
                status: 502,
                body: vec![],
            }),
        ] {
            let f = fixture(vec![
                ok(STATIC.to_vec()),
                ok(serde_json::to_vec(&doc).unwrap()),
                bad,
                ok(serde_json::to_vec(&serde_json::json!({"round":active()})).unwrap()),
            ]);
            assert_eq!(
                discover_stage_with_source(&f, &source(), 1500)
                    .await
                    .unwrap()
                    .0
                    .accepted
                    .len(),
                1
            );
            assert_eq!(
                f.urls.lock().unwrap().last().unwrap(),
                "https://vote2.example.com/mount/shielded-vote/v1/rounds/active"
            );
        }
        for response in [
            ok(br#"{"round":null}"#.to_vec()),
            Ok(OwnedHttpResponse {
                content_type: None,
                status: 404,
                body: vec![],
            }),
        ] {
            let f = fixture(vec![ok(STATIC.to_vec()), ok(DYNAMIC.to_vec()), response]);
            let (d, t) = discover_stage_with_source(&f, &source(), 1500)
                .await
                .unwrap();
            assert!(d.accepted.is_empty());
            assert!(t.is_empty());
        }
    }

    #[tokio::test]
    async fn skipped_config_round_is_rejected_only_when_active() {
        let mut dynamic: Value = serde_json::from_slice(DYNAMIC).unwrap();
        dynamic["rounds"][ID]["signatures"][0]["sig"] = serde_json::json!(BASE64.encode([0; 64]));
        let dynamic = serde_json::to_vec(&dynamic).unwrap();
        let resolved = resolve_dynamic_voting_config(
            resolve_static_voting_config(&source(), STATIC).unwrap(),
            &dynamic,
            ResolveVotingConfigOptions::default(),
        )
        .unwrap();
        assert_eq!(resolved.skipped_round_ids, vec![ID]);

        for response in [
            ok(br#"{"round":null}"#.to_vec()),
            ok(br#"{"rounds":[]}"#.to_vec()),
            Ok(OwnedHttpResponse {
                content_type: None,
                status: 404,
                body: vec![],
            }),
        ] {
            let transport = fixture(vec![
                ok(STATIC.to_vec()),
                ok(dynamic.clone()),
                Ok(OwnedHttpResponse {
                    content_type: None,
                    status: 404,
                    body: vec![],
                }),
                response,
            ]);
            let (discovery, trusted) = discover_stage_with_source(&transport, &source(), 1500)
                .await
                .unwrap();
            assert!(discovery.accepted.is_empty());
            assert!(discovery.rejected.is_empty());
            assert!(trusted.is_empty());
        }

        let transport = fixture(vec![
            ok(STATIC.to_vec()),
            ok(dynamic),
            Ok(OwnedHttpResponse {
                content_type: None,
                status: 404,
                body: vec![],
            }),
            ok(envelope(vec![active()])),
        ]);
        let (discovery, trusted) = discover_stage_with_source(&transport, &source(), 1500)
            .await
            .unwrap();
        assert!(discovery.accepted.is_empty());
        assert!(trusted.is_empty());
        assert_eq!(discovery.rejected.len(), 1);
        assert_eq!(discovery.rejected[0].round_id, ID);
        assert_eq!(
            discovery.rejected[0].code,
            VotingErrorCode::RoundUnauthenticated
        );
    }

    #[tokio::test]
    async fn service_layout_versions_proposals_and_helpers_are_strictly_checked() {
        let mut out_of_range = active();
        out_of_range["proposals"][0]["id"] =
            serde_json::json!(zcash_voting::types::MAX_PROPOSAL_ID + 1);
        assert!(discover(vec![out_of_range], 1500).await.1.is_empty());
        for (key, value) in [
            (
                "pir_layout",
                serde_json::json!({"pir_depth":19,"tier0_layers":12,"tier1_layers":7,"poly_len":2048}),
            ),
            (
                "supported_versions",
                serde_json::json!({"pir":["v0"],"vote_protocol":"v99","tally":"v0","vote_server":"v1"}),
            ),
            ("proposals", serde_json::json!([])),
            (
                "helpers",
                serde_json::json!([{"id":"h","url":"https://user:pass@helper.invalid","public_key":BASE64.encode([1;32])}]),
            ),
        ] {
            let mut a = active();
            a[key] = value;
            let (d, t) = discover(vec![a], 1500).await;
            assert!(t.is_empty(), "{key}");
            assert_eq!(d.rejected[0].code, VotingErrorCode::RoundUnauthenticated);
        }
        let mut a = active();
        a["helpers"] = serde_json::json!([{"id":"h","url":"https://helper.example/","public_key":BASE64.encode([1;32])}]);
        let (_, t) = discover(vec![a], 1500).await;
        assert_eq!(t[ID].helpers[0].url, "https://helper.example");
        let original = t[ID].identity();
        let mut changed = t[ID].clone();
        changed.helpers[0].public_key[0] ^= 1;
        assert!(changed.compare_identity(&original).is_err());
    }

    #[test]
    fn eligibility_separates_sync_from_minimum_policy() {
        assert_eq!(
            eligibility_for_inputs("01", 10, 9, &[]).unwrap_err().code,
            VotingErrorCode::WalletNotSynced
        );
        let result = eligibility_for_inputs("01", 10, 10, &[]).unwrap();
        assert!(!result.eligible);
        assert_eq!(result.snapshot_voting_value_zats, "0");
        assert_eq!(result.minimum_required_zats, "12500000");
        assert_eq!(
            result.reason_code,
            Some(VotingEligibilityReason::InsufficientSnapshotValue)
        );
        assert_eq!(result.selected_value_zats, "0");
        assert_eq!(result.voting_power, "0");
        assert_eq!(result.bundle_count, 0);
    }

    #[test]
    fn network_mismatch_error_is_network_neutral() {
        let error = VotingApiError::new(VotingErrorCode::NetworkMismatch);
        assert_eq!(
            error.message,
            "Voting network does not match the selected wallet."
        );
    }

    #[tokio::test]
    async fn complete_service_metadata_is_bound_for_resume() {
        let (_, original) = discover(vec![active()], 1500).await;
        let saved = original[ID].identity();
        for (key, value) in [
            (
                "snapshot_blockhash",
                serde_json::json!(BASE64.encode([3; 32])),
            ),
            ("proposals_hash", serde_json::json!(BASE64.encode([4; 32]))),
        ] {
            let mut changed = active();
            changed[key] = value;
            let (_, rounds) = discover(vec![changed], 1500).await;
            assert!(rounds[ID].compare_identity(&saved).is_err(), "{key}");
        }
    }

    #[test]
    fn eligibility_matches_valar_boundary_quantization_and_privacy_trim() {
        fn note(value: u64, position: u64) -> zcash_voting::NoteInfo {
            zcash_voting::NoteInfo {
                value,
                position,
                commitment: vec![1; 32],
                nullifier: vec![position as u8; 32],
                diversifier: vec![0; 11],
                rho: vec![0; 32],
                rseed: vec![0; 32],
                scope: 0,
                ufvk_str: String::new(),
            }
        }
        let divisor = zcash_voting::governance::BALLOT_DIVISOR;
        for value in [0, divisor - 1, divisor, divisor + 1] {
            let result = eligibility_for_inputs(ID, 100, 100, &[note(value, 0)]).unwrap();
            assert_eq!(result.eligible, value >= divisor);
            assert_eq!(result.snapshot_voting_value_zats, value.to_string());
            assert_eq!(result.minimum_required_zats, divisor.to_string());
            assert_eq!(
                result.reason_code,
                (value < divisor).then_some(VotingEligibilityReason::InsufficientSnapshotValue)
            );
            assert_eq!(
                result.voting_power,
                if value >= divisor { divisor } else { 0 }.to_string()
            );
        }
        let fragmented = (0..20).map(|i| note(2_000_000, i)).collect::<Vec<_>>();
        let fragmented_result = eligibility_for_inputs(ID, 100, 100, &fragmented).unwrap();
        assert_eq!(fragmented_result.snapshot_voting_value_zats, "40000000");
        assert_eq!(
            fragmented_result.reason_code,
            Some(VotingEligibilityReason::InsufficientVotingPower)
        );
        let big = 1000 * divisor;
        let notes: Vec<_> = (0..3)
            .map(|i| note(big, i))
            .chain((3..23).map(|i| note(big / 500, i)))
            .collect();
        let (status, plan) = zcash_voting::minimum_voting_eligibility_and_plan_for_notes(
            &notes,
            zcash_voting::BundlePolicy::default(),
        )
        .unwrap();
        assert!(plan.privacy_trim.dropped_value > 0);
        let result = eligibility_for_inputs(ID, 100, 100, &notes).unwrap();
        assert_eq!(
            result.trimmed_value_zats,
            plan.privacy_trim.dropped_value.to_string()
        );
        assert_eq!(result.voting_power, status.eligible_weight.to_string());
        assert_eq!(
            result.selected_value_zats,
            plan.bundles
                .iter()
                .flatten()
                .map(|n| n.value)
                .sum::<u64>()
                .to_string()
        );
    }

    #[tokio::test]
    async fn eligibility_wallet_boundary_is_read_only_and_display_safe() {
        use zcash_client_backend::data_api::{
            Account as _, AccountBirthday, AccountPurpose, WalletWrite, Zip32Derivation,
        };
        use zcash_protocol::consensus::BlockHeight;
        let network = crate::Network::TestNetwork;
        let mut db = zcash_client_memory::MemoryWalletDb::new(network, 100);
        let birthday = AccountBirthday::from_parts(
            zcash_client_backend::data_api::chain::ChainState::empty(
                BlockHeight::from_u32(3_000_000),
                zcash_primitives::block::BlockHash([0; 32]),
            ),
            None,
        );
        let ufvk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &network,
            &[17; 32],
            zip32::AccountId::ZERO,
        )
        .unwrap()
        .to_unified_full_viewing_key();
        let derivation = Zip32Derivation::new(
            zip32::fingerprint::SeedFingerprint::from_seed(&[17; 32]).unwrap(),
            zip32::AccountId::ZERO,
        );
        let id = db
            .import_account_ufvk(
                "fixture",
                &ufvk,
                &birthday,
                AccountPurpose::Spending {
                    derivation: Some(derivation),
                },
                None,
            )
            .unwrap()
            .id();
        let wallet =
            crate::Wallet::new(db, Client::new("https://example.invalid".into()), network).unwrap();
        let (_, rounds) = discover(vec![active()], 1500).await;
        let before = wallet.db_to_bytes().await.unwrap();
        assert_eq!(
            check_eligibility(&wallet, id, &rounds[ID])
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::WalletNotSynced
        );
        assert_eq!(
            check_eligibility(&wallet, 999.into(), &rounds[ID])
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::NotEligible
        );
        assert_eq!(wallet.db_to_bytes().await.unwrap(), before);
        assert!(wallet.db.try_write().is_ok());
        let error = VotingApiError::from(WalletInputError::Wallet(
            "private notes keys roots payload".into(),
        ));
        assert_eq!(error.message, "Voting inputs are unavailable.");
    }

    #[tokio::test]
    async fn eligibility_rejects_a_wallet_from_the_other_authenticated_round_network() {
        use zcash_client_backend::data_api::{
            Account as _, AccountBirthday, AccountPurpose, WalletWrite, Zip32Derivation,
        };
        use zcash_protocol::consensus::BlockHeight;

        let network = crate::Network::TestNetwork;
        let mut db = zcash_client_memory::MemoryWalletDb::new(network, 100);
        let birthday = AccountBirthday::from_parts(
            zcash_client_backend::data_api::chain::ChainState::empty(
                BlockHeight::from_u32(3_000_000),
                zcash_primitives::block::BlockHash([0; 32]),
            ),
            None,
        );
        let ufvk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &network,
            &[18; 32],
            zip32::AccountId::ZERO,
        )
        .unwrap()
        .to_unified_full_viewing_key();
        let id = db
            .import_account_ufvk(
                "mainnet fixture",
                &ufvk,
                &birthday,
                AccountPurpose::Spending {
                    derivation: Some(Zip32Derivation::new(
                        zip32::fingerprint::SeedFingerprint::from_seed(&[18; 32]).unwrap(),
                        zip32::AccountId::ZERO,
                    )),
                },
                None,
            )
            .unwrap()
            .id();
        let wallet =
            crate::Wallet::new(db, Client::new("https://example.invalid".into()), network).unwrap();
        let mut entry = active();
        entry.as_object_mut().unwrap().remove("network");
        let (_, rounds) = discover_for(VotingNetwork::Mainnet, vec![entry], 1500).await;

        assert_eq!(
            check_eligibility(&wallet, id, &rounds[ID])
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::NetworkMismatch
        );
    }
}
use super::constants::*;
use super::network::VotingNetwork;
use super::types::*;
use super::wallet_adapter::{WalletInputError, gather_eligibility_inputs};
use crate::bindgen::wallet::{AccountId, MemoryWallet};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use tonic_web_wasm_client::Client;
use zcash_voting::config::{
    PinnedConfigSource, ResolveVotingConfigOptions, ResolvedVotingConfig,
    resolve_dynamic_voting_config, resolve_static_voting_config,
};
use zcash_voting::transport::{HttpTransport, OwnedHttpRequest, RequestKind};

#[cfg(target_arch = "wasm32")]
pub(crate) async fn discover_rounds(
    transport: &super::transport::BrowserFetchTransport,
    network: VotingNetwork,
) -> Result<(VotingDiscovery, BTreeMap<String, TrustedRound>), VotingApiError> {
    discover_with_clock(transport, network, network.static_source(), || {
        u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|_| VotingApiError::new(VotingErrorCode::ConfigUntrusted))
    })
    .await
}

async fn fetch(
    transport: &impl HttpTransport,
    url: String,
    limit: usize,
) -> Result<(u16, Vec<u8>), VotingApiError> {
    let request = OwnedHttpRequest {
        method: "GET".into(),
        url,
        headers: vec![],
        body: vec![],
        timeout_ms: REQUEST_TIMEOUT_MS,
        max_response_bytes: limit,
        kind: RequestKind::Idempotent,
    };
    request
        .validate()
        .map_err(|_| VotingApiError::new(VotingErrorCode::ConfigFetchFailed))?;
    let response = transport
        .execute(request)
        .await
        .map_err(|_| VotingApiError::new(VotingErrorCode::ConfigFetchFailed))?;
    if response.body.len() > limit
        || (!(200..300).contains(&response.status) && response.status != 404)
    {
        return Err(VotingApiError::new(VotingErrorCode::ConfigFetchFailed));
    }
    Ok((response.status, response.body))
}

// Source overrides stay private; production selects only a built-in pin from the wallet context.
async fn discover_with_clock(
    transport: &impl HttpTransport,
    network: VotingNetwork,
    source: &str,
    clock: impl Fn() -> Result<u64, VotingApiError>,
) -> Result<(VotingDiscovery, BTreeMap<String, TrustedRound>), VotingApiError> {
    let pin = PinnedConfigSource::parse(source)
        .map_err(|_| VotingApiError::new(VotingErrorCode::ConfigUntrusted))?;
    if pin.sha256.is_none() {
        return Err(VotingApiError::new(VotingErrorCode::ConfigUntrusted));
    }
    let (status, bytes) = fetch(transport, pin.url, CONFIG_LIMIT).await?;
    if status == 404 {
        return Err(VotingApiError::new(VotingErrorCode::ConfigFetchFailed));
    }
    let anchor = resolve_static_voting_config(source, &bytes)
        .map_err(|_| VotingApiError::new(VotingErrorCode::ConfigUntrusted))?;
    let mut resolved = None;
    let mut roundless = None;
    let mut fetched = false;
    for url in &anchor.dynamic_config_urls {
        let Ok((status, bytes)) = fetch(transport, url.clone(), CONFIG_LIMIT).await else {
            continue;
        };
        if status == 404 {
            continue;
        }
        fetched = true;
        let Ok(candidate) = resolve_dynamic_voting_config(
            anchor.clone(),
            &bytes,
            ResolveVotingConfigOptions::default(),
        ) else {
            continue;
        };
        if candidate.authenticated_rounds.is_empty() {
            if roundless.is_none() {
                roundless = Some(candidate);
            }
        } else {
            resolved = Some(candidate);
            break;
        }
    }
    let resolved = resolved.or(roundless).ok_or_else(|| {
        VotingApiError::new(if fetched {
            VotingErrorCode::ConfigUntrusted
        } else {
            VotingErrorCode::ConfigFetchFailed
        })
    })?;
    let mut discovery = VotingDiscovery {
        accepted: vec![],
        rejected: vec![],
        config_fingerprint: resolved.dynamic_config_fingerprint.clone(),
    };
    let mut active = None;
    for endpoint in &resolved.vote_servers {
        let base = endpoint_base(&endpoint.url)
            .map_err(|_| VotingApiError::new(VotingErrorCode::ConfigUntrusted))?;
        let Ok((status, bytes)) = fetch(
            transport,
            format!("{base}/shielded-vote/v1/rounds/active"),
            API_LIMIT,
        )
        .await
        else {
            continue;
        };
        if status == 404 {
            active = Some(vec![]);
            break;
        }
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if let Some(rounds) = value.get("rounds").and_then(Value::as_array) {
            active = Some(rounds.clone());
            break;
        }
        if let Some(round) = value.get("round") {
            active = Some(if round.is_null() {
                vec![]
            } else {
                vec![round.clone()]
            });
            break;
        }
    }
    let active = active.ok_or_else(|| VotingApiError::new(VotingErrorCode::ConfigFetchFailed))?;
    let mut counts = BTreeMap::new();
    for entry in &active {
        if let Some(id) = entry
            .get("vote_round_id")
            .and_then(Value::as_str)
            .and_then(|id| normalize_round_id(id).ok())
        {
            *counts.entry(id).or_insert(0usize) += 1;
        }
    }
    let mut trusted = BTreeMap::new();
    for entry in active {
        let id = entry
            .get("vote_round_id")
            .and_then(Value::as_str)
            .and_then(|id| normalize_round_id(id).ok())
            .unwrap_or_default();
        if id.is_empty()
            || counts[&id] != 1
            || !resolved
                .authenticated_rounds
                .iter()
                .any(|round| round.round_id == id)
        {
            reject(&mut discovery, &id, VotingErrorCode::RoundUnauthenticated);
            continue;
        }
        // Sample after every awaited fetch, once for this round's validation.
        match trusted_round(&resolved, network, &id, &entry, clock()?) {
            Ok(round) => {
                discovery.accepted.push(round.summary.clone());
                trusted.insert(id, round);
            }
            Err(error) => reject(&mut discovery, &id, error.code),
        }
    }
    Ok((discovery, trusted))
}

fn reject(discovery: &mut VotingDiscovery, id: &str, code: VotingErrorCode) {
    let error = VotingApiError::new(code);
    discovery.rejected.push(RejectedRound {
        round_id: normalize_round_id(id).unwrap_or_default(),
        code,
        message: error.message,
    });
}

pub(crate) fn normalize_round_id(value: &str) -> Result<String, VotingApiError> {
    let bytes = if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(value).ok()
    } else if value.len() == 44 {
        BASE64
            .decode(value)
            .ok()
            .filter(|bytes| BASE64.encode(bytes) == value)
    } else {
        None
    };
    let bytes = bytes.ok_or_else(unauthed)?;
    zcash_voting::types::validate_vote_round_id_bytes(&bytes).map_err(|_| unauthed())?;
    Ok(hex::encode(bytes))
}
fn unauthed() -> VotingApiError {
    VotingApiError::new(VotingErrorCode::RoundUnauthenticated)
}
fn endpoint_base(url: &str) -> Result<String, VotingApiError> {
    let canonical =
        zcash_voting::helper::url::canonicalize_helper_base_url(url).map_err(|_| unauthed())?;
    if !canonical.starts_with("https://") {
        return Err(unauthed());
    }
    Ok(canonical)
}
fn uint(value: &Value) -> Result<u64, VotingApiError> {
    value
        .as_u64()
        .or_else(|| {
            value
                .as_str()
                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse().ok())
        })
        .ok_or_else(unauthed)
}
fn text_field(value: &Value) -> Result<String, VotingApiError> {
    value
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(unauthed)
}
fn root(value: &Value) -> Result<Vec<u8>, VotingApiError> {
    let id = normalize_round_id(value.as_str().ok_or_else(unauthed)?)?;
    hex::decode(id).map_err(|_| unauthed())
}

fn trusted_round(
    config: &ResolvedVotingConfig,
    network: VotingNetwork,
    id: &str,
    entry: &Value,
    now: u64,
) -> Result<TrustedRound, VotingApiError> {
    // The built-in trust context supplies the network when the service omits it.
    if let Some(service_network) = entry.get("network") {
        if !service_network
            .as_str()
            .is_some_and(|name| network.accepts_service_network(name))
        {
            return Err(VotingApiError::new(VotingErrorCode::NetworkMismatch));
        }
    }
    if uint(&entry["status"])? != 1 {
        return Err(unauthed());
    }
    let height = uint(&entry["snapshot_height"])?;
    if height == 0 || height > u64::from(u32::MAX) {
        return Err(unauthed());
    }
    let start = uint(&entry["ceremony_phase_start"])?;
    let end = uint(&entry["vote_end_time"])?;
    if start >= end || now < start {
        return Err(unauthed());
    }
    if now >= end {
        return Err(VotingApiError::new(VotingErrorCode::RoundExpired));
    }
    if let Some(layout) = entry.get("pir_layout") {
        if serde_json::from_value::<zcash_voting::wire::PirLayout>(layout.clone())
            .map_err(|_| unauthed())?
            != config.pir_layout
        {
            return Err(unauthed());
        }
    }
    if let Some(versions) = entry.get("supported_versions") {
        if serde_json::from_value::<zcash_voting::config::SupportedVersions>(versions.clone())
            .map_err(|_| unauthed())?
            != config.supported_versions
        {
            return Err(unauthed());
        }
    }
    // These roots still require independent frontier/PIR verification in preparation.
    let params = config
        .trusted_voting_round_params(
            id.into(),
            height,
            root(&entry["nc_root"])?,
            root(&entry["nullifier_imt_root"])?,
        )
        .map_err(|_| unauthed())?;
    let mut proposals = vec![];
    let mut ids = BTreeSet::new();
    for item in entry["proposals"]
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= zcash_voting::types::MAX_PROPOSAL_ID as usize)
        .ok_or_else(unauthed)?
    {
        let proposal_id = u32::try_from(uint(&item["id"])?).map_err(|_| unauthed())?;
        zcash_voting::types::validate_proposal_id(proposal_id).map_err(|_| unauthed())?;
        if !ids.insert(proposal_id) {
            return Err(unauthed());
        }
        let mut options = vec![];
        for (index, option) in item["options"]
            .as_array()
            .filter(|v| (2..=8).contains(&v.len()))
            .ok_or_else(unauthed)?
            .iter()
            .enumerate()
        {
            let declared = option.get("index").map(uint).transpose()?.unwrap_or(0);
            if declared != index as u64 {
                return Err(unauthed());
            }
            options.push(text_field(&option["label"])?);
        }
        proposals.push(Proposal {
            proposal_id,
            title: text_field(&item["title"])?,
            options,
        });
    }
    let mut helpers = vec![];
    let mut helper_ids = BTreeSet::new();
    let mut helper_urls = BTreeSet::new();
    if let Some(items) = entry.get("helpers") {
        for item in items.as_array().ok_or_else(unauthed)? {
            let id = text_field(&item["id"])?;
            let url = endpoint_base(item["url"].as_str().ok_or_else(unauthed)?)?;
            let public_key = BASE64
                .decode(item["public_key"].as_str().ok_or_else(unauthed)?)
                .map_err(|_| unauthed())?;
            if public_key.len() != 32
                || !helper_ids.insert(id.clone())
                || !helper_urls.insert(url.clone())
            {
                return Err(unauthed());
            }
            helpers.push(HelperEndpoint {
                id,
                url,
                public_key,
            });
        }
    }
    let vote_server_urls = config
        .vote_servers
        .iter()
        .map(|e| endpoint_base(&e.url))
        .collect::<Result<Vec<_>, _>>()?;
    let pir_urls = config
        .pir_endpoints
        .iter()
        .map(|e| endpoint_base(&e.url))
        .collect::<Result<Vec<_>, _>>()?;
    let tree_url = vote_server_urls.first().ok_or_else(unauthed)?.clone();
    let name = entry
        .get("title")
        .map(text_field)
        .transpose()?
        .unwrap_or_else(|| id.into());
    let mut metadata = entry.clone();
    metadata["vote_round_id"] = Value::String(id.into());
    let service_metadata_fingerprint = hex::encode(Sha256::digest(
        serde_json::to_vec(&metadata).map_err(|_| unauthed())?,
    ));
    Ok(TrustedRound {
        network,
        service_metadata_fingerprint,
        config_summary: config.into(),
        config_fingerprint: config.dynamic_config_fingerprint.clone(),
        summary: RoundSummary {
            round_id: id.into(),
            name,
            snapshot_height: height,
            starts_at: start.to_string(),
            ends_at: end.to_string(),
            proposal_count: proposals.len() as u32,
        },
        params,
        proposals,
        vote_server_urls,
        pir_urls,
        pir_layout: config.pir_layout,
        tree_url,
        helpers,
    })
}

impl VotingApiError {
    pub(crate) fn new(code: VotingErrorCode) -> Self {
        let message = match code {
            VotingErrorCode::ConfigFetchFailed => "Voting configuration is unavailable.",
            VotingErrorCode::ConfigUntrusted => "Voting configuration could not be authenticated.",
            VotingErrorCode::RoundUnauthenticated => "Voting round could not be authenticated.",
            VotingErrorCode::RoundExpired => "Voting round has expired.",
            VotingErrorCode::NetworkMismatch => {
                "Voting network does not match the selected wallet."
            }
            VotingErrorCode::WalletNotSynced => "Sync the wallet through the voting snapshot.",
            VotingErrorCode::RecoveryConflict => "Saved voting configuration no longer matches.",
            VotingErrorCode::OperationInProgress => "Another voting operation is in progress.",
            VotingErrorCode::PersistenceFailed => {
                "Voting state could not be saved. Export or retry saving this session."
            }
            VotingErrorCode::SubmissionUnknown => {
                "Voting submission outcome is unknown. Resume from saved state."
            }
            VotingErrorCode::SubmissionRejected => "Voting submission was rejected.",
            _ => "Voting inputs are unavailable.",
        };
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<WalletInputError> for VotingApiError {
    fn from(error: WalletInputError) -> Self {
        Self::new(match error {
            WalletInputError::NetworkMismatch => VotingErrorCode::NetworkMismatch,
            WalletInputError::WalletNotSynced { .. } => VotingErrorCode::WalletNotSynced,
            WalletInputError::AccountUnknown
            | WalletInputError::Wallet(_)
            | WalletInputError::Voting(_) => VotingErrorCode::NotEligible,
        })
    }
}

pub(crate) async fn check_eligibility(
    wallet: &MemoryWallet<Client>,
    account_id: AccountId,
    round: &TrustedRound,
) -> Result<VotingEligibility, VotingApiError> {
    let input = gather_eligibility_inputs(
        wallet,
        account_id,
        round.network.network(),
        round.params.snapshot_height,
    )
    .await?;
    eligibility_for_inputs(
        &round.summary.round_id,
        round.params.snapshot_height,
        input.scanned_height,
        &input.notes,
    )
}

fn eligibility_for_inputs(
    round_id: &str,
    snapshot: u64,
    scanned: u64,
    notes: &[zcash_voting::NoteInfo],
) -> Result<VotingEligibility, VotingApiError> {
    if scanned < snapshot {
        return Err(VotingApiError::new(VotingErrorCode::WalletNotSynced));
    }
    let (status, plan) = zcash_voting::minimum_voting_eligibility_and_plan_for_notes(
        notes,
        zcash_voting::BundlePolicy::default(),
    )
    .map_err(|_| VotingApiError::new(VotingErrorCode::NotEligible))?;
    let snapshot_value = notes
        .iter()
        .try_fold(0u128, |sum, note| sum.checked_add(u128::from(note.value)))
        .ok_or_else(|| VotingApiError::new(VotingErrorCode::NotEligible))?;
    let minimum_required = zcash_voting::MINIMUM_VOTING_WEIGHT_ZATOSHI;
    let reason_code = if status.is_eligible() {
        None
    } else if snapshot_value < u128::from(minimum_required) {
        Some(VotingEligibilityReason::InsufficientSnapshotValue)
    } else {
        Some(VotingEligibilityReason::InsufficientVotingPower)
    };
    let selected = plan
        .bundles
        .iter()
        .flatten()
        .try_fold(0u64, |sum, note| sum.checked_add(note.value))
        .ok_or_else(|| VotingApiError::new(VotingErrorCode::NotEligible))?;
    Ok(VotingEligibility {
        round_id: round_id.into(),
        eligible: status.is_eligible(),
        snapshot_voting_value_zats: snapshot_value.to_string(),
        minimum_required_zats: minimum_required.to_string(),
        reason_code,
        selected_value_zats: selected.to_string(),
        voting_power: status.eligible_weight.to_string(),
        selected_note_count: u32::try_from(status.distinct_note_count)
            .map_err(|_| VotingApiError::new(VotingErrorCode::NotEligible))?,
        bundle_count: u32::try_from(plan.bundles.len())
            .map_err(|_| VotingApiError::new(VotingErrorCode::NotEligible))?,
        trimmed_value_zats: plan.privacy_trim.dropped_value.to_string(),
    })
}
