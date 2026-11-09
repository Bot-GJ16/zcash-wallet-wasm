use zcash_client_backend::data_api::{
    Account as _, ChangeReceivers, InputSource, WalletRead, WalletWrite,
    testing::{TestBuilder, orchard::OrchardPoolTester, pool::dsl::TestDsl},
};
use zcash_primitives::block::BlockHash;

use super::{MemBlockCache, TestMemDbFactory};
use crate::{AccountId, Error};

#[test]
fn account_name_and_change_receivers_follow_account_state() {
    let mut st = TestDsl::from(
        TestBuilder::new()
            .with_data_store_factory(TestMemDbFactory::new())
            .with_block_cache(MemBlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<OrchardPoolTester>();
    let account_id = st.get_account().account().id();
    let account = st.wallet().get_account(account_id).unwrap().unwrap();
    let viewing_key = account
        .ufvk()
        .unwrap()
        .encode(&zcash_protocol::consensus::MAIN_NETWORK);
    assert_eq!(
        st.wallet().get_change_receivers(account_id).unwrap(),
        ChangeReceivers::from_uivk(&account.uivk())
    );

    st.wallet_mut()
        .set_account_name(account_id, "renamed")
        .unwrap();
    let renamed = st.wallet().get_account(account_id).unwrap().unwrap();
    assert_eq!(renamed.name(), Some("renamed"));
    assert_eq!(
        renamed
            .ufvk()
            .unwrap()
            .encode(&zcash_protocol::consensus::MAIN_NETWORK),
        viewing_key
    );

    let missing = AccountId::from(u32::MAX);
    assert!(matches!(
        st.wallet().get_change_receivers(missing),
        Err(Error::AccountUnknown(id)) if id == missing
    ));
    assert!(matches!(
        st.wallet_mut().set_account_name(missing, "missing"),
        Err(Error::AccountUnknown(id)) if id == missing
    ));
}
