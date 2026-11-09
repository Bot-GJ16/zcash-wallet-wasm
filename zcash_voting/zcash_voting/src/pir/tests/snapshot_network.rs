use super::*;

#[tokio::test]
async fn mainnet_snapshot_accepts_matching_dataset() {
    let transport = Arc::new(RecordingTransport::matching_root_for(
        pir_types::ZcashNetwork::Main,
    ));
    let result = OrderedSnapshotPir::connect(
        compiled_wallet_layout(),
        vec!["https://pir.example".into()],
        transport.clone(),
        crate::Network::Mainnet,
        &[0; 32],
        100,
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(transport.count_hits("/root"), 1);
    assert_eq!(transport.post_count(), 0);
}

#[tokio::test]
async fn snapshot_rejects_wrong_network_before_private_query() {
    for (requested, served) in [
        (crate::Network::Mainnet, pir_types::ZcashNetwork::Test),
        (crate::Network::Testnet, pir_types::ZcashNetwork::Main),
    ] {
        let transport = Arc::new(RecordingTransport::matching_root_for(served));
        let result = OrderedSnapshotPir::connect(
            compiled_wallet_layout(),
            vec!["https://pir.example".into()],
            transport.clone(),
            requested,
            &[0; 32],
            100,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(transport.count_hits("/root"), 1);
        assert_eq!(transport.post_count(), 0);
    }
}
