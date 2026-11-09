use std::{convert::Infallible, num::NonZeroU32};

use zcash_client_backend::zip321::{Payment, TransactionRequest};
use zcash_client_backend::{
    data_api::{
        Account as _, MaxSpendMode, WalletRead,
        testing::{
            AddressType, DataStoreFactory, TestBuilder,
            orchard::OrchardPoolTester,
            pool::{ShieldedPoolTester, dsl::TestDsl},
            single_output_change_strategy,
        },
        wallet::{
            ConfirmationsPolicy,
            input_selection::{GreedyInputSelector, SpendPolicy},
            ordinary::{self, propose_transfer as propose_ordinary_transfer},
            propose_send_max_transfer, propose_transfer,
        },
    },
    fees::StandardFeeRule,
    wallet::OvkPolicy,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{
    ShieldedPool,
    consensus::BlockHeight,
    local_consensus::LocalNetwork,
    value::Zatoshis,
    zip318::{MAX_RESIDUAL_VALUE, PoolMigrationConstants},
};

use crate::{MemBlockCache, MemoryWalletDb, testing::TestMemDbFactory};

struct ExpiryTestDbFactory;

impl DataStoreFactory for ExpiryTestDbFactory {
    type Error = ();
    type AccountId = <TestMemDbFactory as DataStoreFactory>::AccountId;
    type Account = <TestMemDbFactory as DataStoreFactory>::Account;
    type DsError = crate::Error;
    type DataStore = MemoryWalletDb<LocalNetwork>;

    fn new_data_store(
        &self,
        network: LocalNetwork,
        _interval: Option<
            zcash_client_backend::data_api::anchor_retention::AnchorRetentionInterval,
        >,
        #[cfg(feature = "transparent-inputs")] _gap_limits: Option<
            zcash_keys::keys::transparent::gap_limits::GapLimits,
        >,
    ) -> Result<Self::DataStore, Self::Error> {
        // Keep both recent anchors and the preceding ZIP 318 bucket available to the test.
        Ok(MemoryWalletDb::new(network, 1_000))
    }
}

fn explicit_expiry_crossing(on_boundary: bool, send_max: bool, nu7: bool) {
    let activation = BlockHeight::from_u32(100_000);
    let network = LocalNetwork {
        nu6: Some(activation),
        nu6_1: Some(activation),
        nu6_2: Some(activation),
        nu6_3: Some(activation),
        nu7: nu7.then_some(activation),
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    };
    let mut st = TestDsl::from(
        TestBuilder::new()
            .with_network(network)
            .with_data_store_factory(ExpiryTestDbFactory)
            .with_block_cache(MemBlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32])),
    )
    .build::<OrchardPoolTester>();
    let account = st.get_account();
    let recipient = OrchardPoolTester::sk_default_address(&OrchardPoolTester::sk(&[0xf5; 32]))
        .to_zcash_address(&network);
    let funding = if send_max {
        (MAX_RESIDUAL_VALUE
            + zcash_client_backend::fees::canonical_crossing_fee(&network, activation).unwrap())
        .unwrap()
    } else {
        Zatoshis::const_from_u64(10_000_000)
    };
    let (received, _, _) = st.add_a_single_note_checking_balance(funding);
    let grid = st.wallet().pool_migration_params(&network).anchor_grid();
    let tip = grid.boundary_after(grid.boundary_after(grid.boundary_at_or_above(received)))
        + if on_boundary { 0 } else { 5 };
    let filler_count = u32::from(tip) - u32::from(received);
    let not_ours = OrchardPoolTester::sk_to_fvk(&OrchardPoolTester::sk(&[0xe5; 32]));
    for _ in 0..filler_count {
        st.generate_next_block(
            &not_ours,
            AddressType::DefaultExternal,
            Zatoshis::const_from_u64(10_000),
        );
    }
    st.scan_cached_blocks(received + 1, filler_count as usize);
    let (_, normal_anchor) = st
        .wallet()
        .get_target_and_anchor_heights(NonZeroU32::MIN)
        .unwrap()
        .unwrap();
    assert_eq!(grid.is_boundary(normal_anchor), on_boundary);
    let selector = GreedyInputSelector::new();
    let change =
        single_output_change_strategy(StandardFeeRule::Zip317, None, ShieldedPool::Orchard);
    let request = TransactionRequest::new(vec![Payment::without_memo(
        recipient.clone(),
        MAX_RESIDUAL_VALUE,
    )])
    .unwrap();
    let canonical = if send_max {
        propose_send_max_transfer::<_, _, _, Infallible>(
            st.wallet_mut(),
            &network,
            account.id(),
            &[ShieldedPool::Orchard],
            &StandardFeeRule::Zip317,
            recipient.clone(),
            None,
            MaxSpendMode::MaxSpendable,
            ConfirmationsPolicy::MIN,
            &Default::default(),
            None,
        )
    } else {
        propose_transfer::<_, _, _, _, Infallible>(
            st.wallet_mut(),
            &network,
            account.id(),
            &selector,
            &change,
            request.clone(),
            ConfirmationsPolicy::MIN,
            &SpendPolicy::default(),
            None,
            None,
        )
    }
    .unwrap();
    let canonical_fee = zcash_client_backend::fees::canonical_crossing_fee(
        &network,
        canonical.min_target_height().into(),
    )
    .unwrap();
    // Send-max already computes padded fees; the transfer proposer additionally attempts
    // canonical crossings. Both must use the ordinary anchor policy for custom expiry.
    let canonical_expected = !send_max;
    assert_eq!(
        canonical
            .steps()
            .first()
            .is_canonical_crossing(&st.wallet().pool_migration_params(&network), canonical_fee),
        canonical_expected
    );
    let expiry = BlockHeight::from(canonical.min_target_height()) + 12;
    assert_eq!(
        st.create_pczt_from_proposal::<Infallible, _, Infallible>(
            account.id(),
            OvkPolicy::Sender,
            &canonical,
            Some(expiry),
        )
        .is_err(),
        canonical_expected,
        "default canonical proposals must still reject custom expiry"
    );
    if canonical_expected {
        let default_pczt = st
            .create_pczt_from_proposal::<Infallible, _, Infallible>(
                account.id(),
                OvkPolicy::Sender,
                &canonical,
                None,
            )
            .expect("the default canonical proposal must remain buildable without custom expiry");
        assert_eq!(
            *default_pczt.global().expiry_height(),
            u32::from(zcash_protocol::zip318::expiry_height(
                &zcash_protocol::zip318::BlockSpacing::for_network(&network),
                canonical.min_target_height().into(),
            ))
        );
    }

    let policy = ordinary::confirmations_policy(st.wallet(), &network, ConfirmationsPolicy::MIN)
        .unwrap()
        .unwrap();
    assert_eq!(policy.trusted().get(), 1 + u32::from(on_boundary));
    let ordinary = if send_max {
        propose_send_max_transfer::<_, _, _, Infallible>(
            st.wallet_mut(),
            &network,
            account.id(),
            &[ShieldedPool::Orchard],
            &StandardFeeRule::Zip317,
            recipient,
            None,
            MaxSpendMode::MaxSpendable,
            policy,
            &Default::default(),
            None,
        )
    } else {
        propose_ordinary_transfer::<_, _, _, _, Infallible>(
            st.wallet_mut(),
            &network,
            account.id(),
            &selector,
            &change,
            request,
            ConfirmationsPolicy::MIN,
            &SpendPolicy::default(),
            None,
            None,
        )
    }
    .unwrap();
    let pczt = st
        .create_pczt_from_proposal::<Infallible, _, Infallible>(
            account.id(),
            OvkPolicy::Sender,
            &ordinary,
            Some(expiry),
        )
        .expect("explicit-expiry transfers must be buildable as PCZTs");
    assert_eq!(*pczt.global().expiry_height(), u32::from(expiry));
    assert_eq!(
        ordinary.steps().first().anchor_height(),
        Some(normal_anchor - u32::from(on_boundary))
    );
    assert!(
        !ordinary
            .steps()
            .first()
            .is_canonical_crossing(&st.wallet().pool_migration_params(&network), canonical_fee)
    );
    let txids = st
        .create_proposed_transactions_with_expiry_height::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &ordinary,
            expiry,
        )
        .expect("explicit-expiry transfers must also be buildable as software transactions");
    assert_eq!(
        st.wallet()
            .get_transaction(txids[0])
            .unwrap()
            .unwrap()
            .expiry_height(),
        expiry
    );
}

#[test]
fn explicit_expiry_crossing_at_boundary() {
    explicit_expiry_crossing(true, false, false);
}

#[test]
fn explicit_expiry_crossing_off_boundary() {
    explicit_expiry_crossing(false, false, false);
}

#[test]
fn explicit_expiry_send_max_at_boundary() {
    explicit_expiry_crossing(true, true, false);
}

#[test]
fn explicit_expiry_send_max_off_boundary() {
    explicit_expiry_crossing(false, true, false);
}

#[test]
fn nu7_explicit_expiry_transfer_at_boundary() {
    explicit_expiry_crossing(true, false, true);
}

#[test]
fn nu7_explicit_expiry_send_max_at_boundary() {
    explicit_expiry_crossing(true, true, true);
}
