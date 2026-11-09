use super::*;
use transparent::bundle::{OutPoint, TxOut};
use transparent::keys::TransparentKeyScope;
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::wallet::WalletTransparentOutput;
use zcash_keys::keys::UnifiedAddressRequest;
use zcash_primitives::block::BlockHash;

type TestWallet = Wallet<MemoryWalletDb<Network>, tonic_web_wasm_client::Client>;

pub(super) fn funded_db_at_confirmations(
    confirmations: u32,
) -> (MemoryWalletDb<Network>, crate::bindgen::wallet::AccountId) {
    assert!(confirmations > 0);
    let network = Network::TestNetwork;
    let mut db = MemoryWalletDb::new(network, PRUNING_DEPTH);
    let height = BlockHeight::from_u32(3_000_000);
    let birthday = AccountBirthday::from_parts(ChainState::empty(height, BlockHash([0; 32])), None);
    let ufvk = UnifiedSpendingKey::from_seed(&network, &[31; 32], zip32::AccountId::ZERO)
        .unwrap()
        .to_unified_full_viewing_key();
    let account_id = db
        .import_account_ufvk(
            "confirmations fixture",
            &ufvk,
            &birthday,
            AccountPurpose::Spending {
                derivation: Some(Zip32Derivation::new(
                    SeedFingerprint::from_seed(&[31; 32]).unwrap(),
                    zip32::AccountId::ZERO,
                )),
            },
            None,
        )
        .unwrap()
        .id();
    let address = *db
        .get_last_generated_address_matching(account_id, UnifiedAddressRequest::AllAvailableKeys)
        .unwrap()
        .unwrap()
        .transparent()
        .unwrap();
    let mined = height + 100;
    db.update_chain_tip(mined + confirmations - 1).unwrap();
    let output = WalletTransparentOutput::from_parts(
        OutPoint::new([41; 32], 0),
        TxOut::new(Zatoshis::const_from_u64(200_000), address.script().into()),
        Some(mined),
        Some(account_id),
        Some(TransparentKeyScope::EXTERNAL),
        None,
    )
    .unwrap();
    db.put_received_transparent_utxo(&output).unwrap();
    // Transparent proposals still require retained anchors under both policies.
    for height in [3_000_080, 3_000_101].map(BlockHeight::from_u32) {
        db.with_sapling_tree_mut(|tree| tree.checkpoint(height))
            .unwrap();
        db.with_orchard_tree_mut(|tree| tree.checkpoint(height))
            .unwrap();
    }
    (db, account_id)
}

fn funded_db() -> (MemoryWalletDb<Network>, crate::bindgen::wallet::AccountId) {
    funded_db_at_confirmations(2)
}

fn client() -> tonic_web_wasm_client::Client {
    tonic_web_wasm_client::Client::new("https://example.invalid".into())
}

fn custom_policy() -> ConfirmationsPolicy {
    ConfirmationsPolicy::new(1.try_into().unwrap(), 2.try_into().unwrap(), false).unwrap()
}

#[tokio::test]
async fn transfer_diagnostics_classify_only_input_selection_shortfalls() {
    let (db, account_id) = funded_db_at_confirmations(10);
    let wallet = TestWallet::new(db, client(), Network::TestNetwork).unwrap();
    let address = zcash_client_backend::address::Address::Transparent(
        transparent::address::TransparentAddress::PublicKeyHash([42; 20]),
    );
    let insufficient = wallet
        .estimate_transfer(
            account_id,
            address.to_zcash_address(&Network::TestNetwork),
            100_000,
            TransferFundingSource::Shielded,
            None,
            Some(5_000),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(insufficient, Error::InsufficientTransferFunds(_)));
    assert!(insufficient.to_string().contains("InsufficientFunds"));

    let wrong_network = wallet
        .estimate_transfer(
            account_id,
            address.to_zcash_address(&Network::MainNetwork),
            100_000,
            TransferFundingSource::Shielded,
            None,
            Some(5_000),
            None,
        )
        .await
        .unwrap_err();
    assert!(!matches!(
        wrong_network,
        Error::InsufficientTransferFunds(_)
    ));

    let invalid_fee = wallet
        .estimate_transfer(
            account_id,
            address.to_zcash_address(&Network::TestNetwork),
            100_000,
            TransferFundingSource::Shielded,
            None,
            Some(0),
            None,
        )
        .await
        .unwrap_err();
    assert!(!matches!(invalid_fee, Error::InsufficientTransferFunds(_)));
}

#[tokio::test]
async fn shielding_summary_uses_selection_policy_without_changing_query_or_max() {
    for confirmations in [2, 3, 9, 10] {
        let (db, account_id) = funded_db_at_confirmations(confirmations);
        let wallet = TestWallet::new(db, client(), Network::TestNetwork).unwrap();
        let (summary, shieldable) = wallet
            .get_wallet_summary_with_shieldable_balances()
            .await
            .unwrap()
            .unwrap();
        let expected_query = if confirmations >= 10 { 200_000 } else { 0 };
        let expected_selection = if confirmations >= 3 { 200_000 } else { 0 };
        assert_eq!(
            summary.account_balances()[&account_id]
                .unshielded_balance()
                .spendable_value(),
            Zatoshis::from_u64(expected_query).unwrap()
        );
        assert_eq!(
            shieldable[&account_id],
            Zatoshis::from_u64(expected_selection).unwrap()
        );
        let proposal = wallet.pczt_shield(account_id).await;
        if expected_selection > 0 {
            assert_eq!(proposal.unwrap().transparent().inputs().len(), 1);
        } else {
            assert!(proposal.is_err());
        }
    }
}

#[tokio::test]
async fn custom_policy_controls_estimates_and_unsigned_transparent_transfers() {
    let (db, account_id) = funded_db();
    let mut encoded = Vec::new();
    db.encode(&mut encoded).unwrap();
    let defaulted = TestWallet::new(db, client(), Network::TestNetwork).unwrap();
    let custom = TestWallet::new_with_confirmations_policy(
        MemoryWalletDb::decode_new(&encoded[..], Network::TestNetwork, PRUNING_DEPTH).unwrap(),
        client(),
        Network::TestNetwork,
        custom_policy(),
    )
    .unwrap();
    let recipient = zcash_client_backend::address::Address::Transparent(
        transparent::address::TransparentAddress::PublicKeyHash([42; 20]),
    )
    .to_zcash_address(&Network::TestNetwork);
    for (wallet, spendable) in [(&defaulted, false), (&custom, true)] {
        let fee = wallet
            .estimate_pczt_transparent_transfer_fee(
                account_id,
                recipient.clone(),
                100_000,
                None,
                5_000,
            )
            .await;
        let estimate = wallet
            .estimate_transfer(
                account_id,
                recipient.clone(),
                100_000,
                TransferFundingSource::Transparent,
                None,
                Some(5_000),
                None,
            )
            .await;
        let pczt = wallet
            .pczt_create_transparent_dynamic_fee(
                account_id,
                recipient.clone(),
                100_000,
                None,
                5_000,
            )
            .await;
        if spendable {
            assert_eq!(fee.unwrap(), 10_000);
            assert_eq!(estimate.unwrap().fee_zats, "10000");
            let pczt = pczt.unwrap();
            assert_eq!(pczt.transparent().inputs().len(), 1);
            assert_eq!(*pczt.transparent().inputs()[0].prevout_txid(), [41; 32]);
        } else {
            for error in [fee.unwrap_err(), estimate.unwrap_err(), pczt.err().unwrap()] {
                assert!(error.to_string().contains("InsufficientFunds"), "{error}");
            }
        }
    }
}

#[tokio::test]
async fn custom_policy_makes_two_confirmation_external_funds_spendable_in_clones() {
    let (db, account_id) = funded_db();
    let wallet = TestWallet::new_with_confirmations_policy(
        db,
        client(),
        Network::TestNetwork,
        custom_policy(),
    )
    .unwrap();
    for wallet in [&wallet, &wallet.clone()] {
        let summary = wallet.get_wallet_summary().await.unwrap().unwrap();
        let balance = summary.account_balances()[&account_id].unshielded_balance();
        assert_eq!(balance.spendable_value(), Zatoshis::const_from_u64(200_000));
        assert_eq!(balance.value_pending_spendability(), Zatoshis::ZERO);
        let query_policy = wallet.query_confirmations_policy();
        assert_eq!(u32::from(query_policy.trusted()), 1);
        assert_eq!(u32::from(query_policy.untrusted()), 2);
        assert!(!query_policy.allow_zero_conf_shielding());

        let selection_policy = wallet.selection_confirmations_policy();
        assert_eq!(u32::from(selection_policy.trusted()), 1);
        assert_eq!(u32::from(selection_policy.untrusted()), 1);
        assert!(!selection_policy.allow_zero_conf_shielding());
    }
}

#[tokio::test]
async fn confirmations_policy_is_runtime_configuration_not_wallet_database_state() {
    let (db, account_id) = funded_db();
    let wallet = TestWallet::new_with_confirmations_policy(
        db,
        client(),
        Network::TestNetwork,
        custom_policy(),
    )
    .unwrap();
    let bytes = wallet.db_to_bytes().await.unwrap();
    let decoded =
        || MemoryWalletDb::decode_new(&bytes[..], Network::TestNetwork, PRUNING_DEPTH).unwrap();
    let defaulted = TestWallet::new(decoded(), client(), Network::TestNetwork).unwrap();
    let restored = TestWallet::new_with_confirmations_policy(
        decoded(),
        client(),
        Network::TestNetwork,
        custom_policy(),
    )
    .unwrap();
    for (wallet, spendable) in [(&defaulted, 0), (&restored, 200_000)] {
        let summary = wallet.get_wallet_summary().await.unwrap().unwrap();
        assert_eq!(
            summary.account_balances()[&account_id]
                .unshielded_balance()
                .spendable_value(),
            Zatoshis::from_u64(spendable).unwrap()
        );
        assert_eq!(wallet.db_to_bytes().await.unwrap(), bytes);
    }
}

#[tokio::test]
async fn default_policy_keeps_two_confirmation_external_funds_pending() {
    let (db, account_id) = funded_db();
    let wallet = TestWallet::new(db, client(), Network::TestNetwork).unwrap();
    let summary = wallet.get_wallet_summary().await.unwrap().unwrap();
    let balance = summary.account_balances()[&account_id].unshielded_balance();
    assert_eq!(balance.spendable_value(), Zatoshis::ZERO);
    assert_eq!(
        balance.value_pending_spendability(),
        Zatoshis::const_from_u64(200_000)
    );
}

#[tokio::test]
async fn query_keeps_three_confirmation_external_funds_pending_while_selection_spends_them() {
    let (db, account_id) = funded_db_at_confirmations(3);
    let wallet = TestWallet::new(db, client(), Network::TestNetwork).unwrap();

    let query_policy = wallet.query_confirmations_policy();
    assert_eq!(u32::from(query_policy.trusted()), 3);
    assert_eq!(u32::from(query_policy.untrusted()), 10);
    let selection_policy = wallet.selection_confirmations_policy();
    assert_eq!(u32::from(selection_policy.trusted()), 3);
    assert_eq!(u32::from(selection_policy.untrusted()), 3);

    let summary = wallet.get_wallet_summary().await.unwrap().unwrap();
    let balance = summary.account_balances()[&account_id].unshielded_balance();
    assert_eq!(balance.spendable_value(), Zatoshis::ZERO);
    assert_eq!(
        balance.value_pending_spendability(),
        Zatoshis::const_from_u64(200_000)
    );

    let recipient = zcash_client_backend::address::Address::Transparent(
        transparent::address::TransparentAddress::PublicKeyHash([42; 20]),
    )
    .to_zcash_address(&Network::TestNetwork);
    assert_eq!(
        wallet
            .estimate_pczt_transparent_transfer_fee(
                account_id,
                recipient.clone(),
                100_000,
                None,
                5_000,
            )
            .await
            .unwrap(),
        10_000
    );
    let pczt = wallet
        .pczt_create_transparent_dynamic_fee(account_id, recipient, 100_000, None, 5_000)
        .await
        .unwrap();
    assert_eq!(pczt.transparent().inputs().len(), 1);

    let max = wallet
        .estimate_pczt_max_transparent_transfer(
            account_id,
            zcash_client_backend::address::Address::Transparent(
                transparent::address::TransparentAddress::PublicKeyHash([43; 20]),
            )
            .to_zcash_address(&Network::TestNetwork),
            None,
            5_000,
        )
        .await;
    assert!(
        max.is_err(),
        "Max must exclude funds still pending under the query policy"
    );
}

#[tokio::test]
async fn max_includes_external_funds_after_query_confirmations_are_reached() {
    let (db, account_id) = funded_db_at_confirmations(10);
    let wallet = TestWallet::new(db, client(), Network::TestNetwork).unwrap();
    let recipient = zcash_client_backend::address::Address::Transparent(
        transparent::address::TransparentAddress::PublicKeyHash([44; 20]),
    )
    .to_zcash_address(&Network::TestNetwork);

    let summary = wallet.get_wallet_summary().await.unwrap().unwrap();
    let balance = summary.account_balances()[&account_id].unshielded_balance();
    assert_eq!(balance.spendable_value(), Zatoshis::const_from_u64(200_000));
    assert_eq!(balance.value_pending_spendability(), Zatoshis::ZERO);

    let (amount, fee) = wallet
        .estimate_pczt_max_transparent_transfer(account_id, recipient, None, 5_000)
        .await
        .unwrap();
    assert_eq!(amount + fee, 200_000);
}

#[tokio::test]
#[ignore = "generates a public synthetic wallet for the browser policy tests"]
async fn write_confirmations_policy_browser_fixture() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("CONFIRMATIONS_FIXTURE_DIR").expect("set CONFIRMATIONS_FIXTURE_DIR"),
    );
    std::fs::create_dir_all(&directory).unwrap();
    let (db, _) = funded_db();
    let wallet = TestWallet::new(db, client(), Network::TestNetwork).unwrap();
    std::fs::write(
        directory.join("confirmations-wallet.bin"),
        wallet.db_to_bytes().await.unwrap(),
    )
    .unwrap();
}
