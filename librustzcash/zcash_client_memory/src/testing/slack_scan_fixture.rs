use prost::Message;
use secrecy::Secret;
use serde_json::json;
use zcash_client_backend::data_api::{
    AccountBirthday, WalletRead, WalletWrite,
    chain::{ChainState, scan_cached_blocks},
    testing::{TestBuilder, TestCache, pool::dsl::TestDsl, sapling::SaplingPoolTester},
    wallet::ConfirmationsPolicy,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{
    consensus::{Network, NetworkUpgrade, Parameters},
    local_consensus::LocalNetwork,
    value::Zatoshis,
};

use super::{MemBlockCache, MemoryWalletDb, TestMemDbFactory};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("seed hex"), 16)
                .expect("seed hex byte")
        })
        .collect()
}

#[test]
#[ignore]
fn export_intents_incoming_scan_fixture() {
    let output = std::env::var("NOIR_SCAN_FIXTURE_OUTPUT").expect("fixture output path");
    let mainnet = Network::MainNetwork;
    let network = LocalNetwork {
        overwinter: mainnet.activation_height(NetworkUpgrade::Overwinter),
        sapling: mainnet.activation_height(NetworkUpgrade::Sapling),
        blossom: mainnet.activation_height(NetworkUpgrade::Blossom),
        heartwood: mainnet.activation_height(NetworkUpgrade::Heartwood),
        canopy: mainnet.activation_height(NetworkUpgrade::Canopy),
        nu5: mainnet.activation_height(NetworkUpgrade::Nu5),
        nu6: mainnet.activation_height(NetworkUpgrade::Nu6),
        nu6_1: mainnet.activation_height(NetworkUpgrade::Nu6_1),
        nu6_2: mainnet.activation_height(NetworkUpgrade::Nu6_2),
        nu6_3: mainnet.activation_height(NetworkUpgrade::Nu6_3),
        nu7: mainnet.activation_height(NetworkUpgrade::Nu7),
        #[cfg(zcash_unstable = "nutachyon")]
        nu_tachyon: mainnet.activation_height(NetworkUpgrade::NuTachyon),
    };
    let mut state = TestDsl::from(
        TestBuilder::new()
            .with_network(network)
            .with_data_store_factory(TestMemDbFactory::new())
            .with_block_cache(MemBlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<SaplingPoolTester>();

    let seed = Secret::new(unhex(
        "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840",
    ));
    let birthday_height = mainnet
        .activation_height(NetworkUpgrade::Sapling)
        .expect("Sapling height");
    let birthday = AccountBirthday::from_parts(
        ChainState::empty(birthday_height - 1, BlockHash([0; 32])),
        None,
    );
    let mut wallet = MemoryWalletDb::new(mainnet, 100);
    let (account_id, spending_key) = wallet
        .create_account("", &seed, &birthday, None)
        .expect("create pre-scan account");
    wallet
        .update_chain_tip(birthday_height)
        .expect("set pre-scan chain tip");
    let summary = wallet
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .expect("read pre-scan summary")
        .expect("pre-scan summary exists");
    assert!(summary.account_balances().contains_key(&account_id));
    assert_eq!(summary.fully_scanned_height(), birthday_height - 1);
    assert!(wallet.get_transaction_history(account_id).is_empty());
    let mut snapshot = Vec::new();
    wallet
        .encode(&mut snapshot)
        .expect("encode pre-scan wallet");

    let amount_zatoshis = 123_456_789;
    let viewing_key = spending_key
        .to_unified_full_viewing_key()
        .sapling()
        .expect("Sapling viewing key")
        .clone();
    let (height, _, _) = state.generate_next_block(
        &viewing_key,
        zcash_client_backend::data_api::testing::AddressType::DefaultExternal,
        Zatoshis::const_from_u64(amount_zatoshis),
    );
    let block = state.cache().find_block(height).expect("generated block");
    assert_eq!(block.vtx.len(), 1);
    assert_eq!(height, birthday_height);
    let mut scan_cache = MemBlockCache::new();
    scan_cache.insert(&block);
    scan_cached_blocks(
        &mainnet,
        &scan_cache,
        &mut wallet,
        height,
        &ChainState::empty(height - 1, BlockHash([0; 32])),
        1,
    )
    .expect("scan synthetic receive");
    assert_eq!(wallet.get_transaction_history(account_id).len(), 1);

    let fixture = json!({
        "network": "mainnet",
        "birthdayHeight": u32::from(birthday_height),
        "accountId": *account_id,
        "amountZatoshis": amount_zatoshis,
        "txHash": hex(&block.vtx[0].txid.iter().copied().rev().collect::<Vec<_>>()),
        "snapshotHex": hex(&snapshot),
        "blockHex": hex(&block.encode_to_vec()),
        "blockHashHex": hex(&block.hash),
        "previousHashHex": hex(&block.prev_hash),
    });
    std::fs::write(
        output,
        serde_json::to_vec_pretty(&fixture).expect("serialize fixture"),
    )
    .expect("write fixture");
}
