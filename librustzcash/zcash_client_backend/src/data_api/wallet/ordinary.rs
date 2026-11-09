//! Ordinary proposals for callers that require a non-ZIP-318 expiry height.

use core::num::NonZeroU32;

use zcash_primitives::transaction::TxVersion;
use zcash_protocol::{
    consensus::{self, NetworkUpgrade},
    zip318::PoolMigrationConstants,
};

use crate::{
    data_api::{InputSource, WalletRead, WalletWrite, locking::LockRequest},
    fees::ChangeStrategy,
    proposal::Proposal,
};

use super::{
    ConfirmationsPolicy, ProposeTransferErrT,
    input_selection::{InputSelector, InputSelectorError, SpendPolicy},
    lock_proposal_inputs,
};

/// Returns a policy whose retained anchor is not a ZIP 318 bucket boundary after NU6.3.
///
/// Non-boundary anchors and pre-NU6.3 policies are unchanged. At a boundary, require the
/// preceding block instead: with contiguous checkpoints this adds exactly one confirmation.
/// Untrusted confirmations and zero-conf shielding are never relaxed. If the next retained
/// checkpoint is also a boundary (or unavailable), return `None` instead of proposing a
/// transaction that will reject custom expiry at build time.
///
/// Use the returned policy for send-max fallbacks as well as ordinary transfers.
pub fn confirmations_policy<DbT: WalletRead, ParamsT: consensus::Parameters>(
    wallet_db: &DbT,
    params: &ParamsT,
    policy: ConfirmationsPolicy,
) -> Result<Option<ConfirmationsPolicy>, DbT::Error> {
    let Some((target, anchor)) = wallet_db.get_target_and_anchor_heights(policy.trusted())? else {
        return Ok(None);
    };
    let grid = wallet_db.pool_migration_params(params).anchor_grid();
    if !params.is_nu_active(NetworkUpgrade::Nu6_3, target.into()) || !grid.is_boundary(anchor) {
        return Ok(Some(policy));
    }
    let Some(trusted) = (u32::from(target) - u32::from(anchor))
        .checked_add(1)
        .and_then(NonZeroU32::new)
    else {
        return Ok(None);
    };
    let adjusted = ConfirmationsPolicy::new(
        trusted,
        policy.untrusted().max(trusted),
        #[cfg(feature = "transparent-inputs")]
        policy.allow_zero_conf_shielding(),
    )
    .expect("the untrusted requirement is at least the trusted requirement");
    Ok(wallet_db
        .get_target_and_anchor_heights(adjusted.trusted())?
        .filter(|(_, anchor)| !grid.is_boundary(*anchor))
        .map(|_| adjusted))
}

/// Proposes an ordinary transaction, bypassing automatic canonical ZIP 318 crossings.
///
/// This is the downstream counterpart to [`super::propose_transfer`] for a caller that will
/// supply a custom expiry to a software or PCZT builder. The default proposer is unchanged.
/// See [`confirmations_policy`] for the possible one-confirmation boundary adjustment.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn propose_transfer<DbT, ParamsT, InputsT, ChangeT, CommitmentTreeErrT>(
    wallet_db: &mut DbT,
    params: &ParamsT,
    spend_from_account: <DbT as InputSource>::AccountId,
    input_selector: &InputsT,
    change_strategy: &ChangeT,
    request: zip321::TransactionRequest,
    policy: ConfirmationsPolicy,
    spend_policy: &SpendPolicy,
    lock_inputs: Option<LockRequest>,
    proposed_version: Option<TxVersion>,
) -> Result<
    Proposal<ChangeT::FeeRule, <DbT as InputSource>::NoteRef>,
    ProposeTransferErrT<DbT, CommitmentTreeErrT, InputsT, ChangeT>,
>
where
    DbT: WalletWrite + InputSource<Error = <DbT as WalletRead>::Error>,
    ParamsT: consensus::Parameters + Clone,
    InputsT: InputSelector<InputSource = DbT>,
    ChangeT: ChangeStrategy<MetaSource = DbT>,
{
    let policy = confirmations_policy(wallet_db, params, policy)
        .map_err(InputSelectorError::DataSource)?
        .ok_or(InputSelectorError::SyncRequired)?;
    let (target_height, anchor_height) = wallet_db
        .get_target_and_anchor_heights(policy.trusted())
        .map_err(InputSelectorError::DataSource)?
        .ok_or(InputSelectorError::SyncRequired)?;
    let proposal = input_selector.propose_transaction(
        params,
        wallet_db,
        target_height,
        anchor_height,
        &wallet_db.pool_migration_params(params),
        policy,
        spend_from_account,
        request,
        change_strategy,
        spend_policy,
        proposed_version,
    )?;
    proposal.check_transaction_size()?;
    if let Some(request) = lock_inputs {
        lock_proposal_inputs(
            wallet_db,
            &proposal,
            request.owner(),
            target_height + request.for_blocks(),
        )?;
    }
    Ok(proposal.with_proposed_version(proposed_version))
}
