use std::num::NonZeroU32;

#[cfg(feature = "transparent-inputs")]
use zcash_client_backend::{
    data_api::CoinbaseFilter, fees::StandardFeeRule, wallet::WalletTransparentOutput,
};
use zcash_client_backend::{
    data_api::{
        Account as _, AccountMeta, ChangeReceivers, InputSource, MaxSpendMode, NoteFilter,
        PoolMeta, ReceivedNotes, TargetValue, WalletRead,
        locking::LockFilter,
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    wallet::{NoteId, OutputRef},
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    ShieldedPool,
    consensus::{self, BranchId},
    value::Zatoshis,
};

#[cfg(feature = "transparent-inputs")]
use {
    transparent::{address::TransparentAddress, bundle::OutPoint},
    zcash_client_backend::data_api::TransactionStatus,
    zcash_primitives::transaction::TxId,
    zcash_primitives::transaction::fees::{
        FeeRule,
        transparent::{InputSize, InputView},
        zip317,
    },
    zcash_protocol::consensus::BlockHeight,
};

use crate::{AccountId, MemoryWalletDb, error::Error, to_spendable_notes};

#[cfg(feature = "transparent-inputs")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransparentOutputStatus {
    Spendable,
    Pending,
    Unavailable,
}

impl<P: consensus::Parameters> InputSource for MemoryWalletDb<P> {
    type Error = crate::error::Error;
    type AccountId = AccountId;
    type NoteRef = NoteId;

    fn get_change_receivers(&self, account: AccountId) -> Result<ChangeReceivers, Self::Error> {
        let account = self
            .accounts
            .get(account)
            .ok_or(Error::AccountUnknown(account))?;
        Ok(ChangeReceivers::from_uivk(&account.uivk()))
    }

    fn anchor_computable(
        &self,
        protocol: ShieldedPool,
        height: zcash_protocol::consensus::BlockHeight,
    ) -> Result<bool, Self::Error> {
        Ok(match protocol {
            ShieldedPool::Sapling => self
                .sapling_tree
                .root_at_checkpoint_id(&height)
                .is_ok_and(|root| root.is_some()),
            #[cfg(feature = "orchard")]
            ShieldedPool::Orchard => self
                .orchard_tree
                .root_at_checkpoint_id(&height)
                .is_ok_and(|root| root.is_some()),
            #[cfg(feature = "orchard")]
            ShieldedPool::Ironwood => self
                .ironwood_tree
                .root_at_checkpoint_id(&height)
                .is_ok_and(|root| root.is_some()),
            #[cfg(not(feature = "orchard"))]
            _ => false,
        })
    }

    fn get_spendable_note(
        &self,
        txid: &zcash_primitives::transaction::TxId,
        protocol: ShieldedPool,
        index: u32,
        target_height: TargetHeight,
        lock_filter: LockFilter<'_>,
    ) -> Result<
        Option<
            zcash_client_backend::wallet::ReceivedNote<
                Self::NoteRef,
                zcash_client_backend::wallet::Note,
            >,
        >,
        Self::Error,
    > {
        let note = self
            .received_notes
            .iter()
            .find(|rn| &rn.txid == txid && rn.note.pool() == protocol && rn.output_index == index);

        Ok(if let Some(note) = note {
            if self.note_is_spent(note, target_height)?
                || !self.lock_allows(&note.note_id.into(), target_height.into(), lock_filter)
            {
                None
            } else {
                let (mined_height, transparent_input_height) = self.note_transaction_heights(txid);
                Some(zcash_client_backend::wallet::ReceivedNote::from_parts(
                    note.note_id,
                    *txid,
                    index.try_into().unwrap(),
                    note.note.clone(),
                    note.recipient_key_scope
                        .ok_or(Error::Missing("recipient key scope".into()))?,
                    note.commitment_tree_position
                        .ok_or(Error::Missing("commitment tree position".into()))?,
                    mined_height,
                    transparent_input_height,
                ))
            }
        } else {
            None
        })
    }

    fn select_spendable_notes(
        &self,
        account: Self::AccountId,
        target_value: TargetValue,
        sources: &[ShieldedPool],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<zcash_client_backend::data_api::ReceivedNotes<Self::NoteRef>, Self::Error> {
        let sapling_eligible_notes = if sources.contains(&ShieldedPool::Sapling) {
            self.select_spendable_notes_from_pool(
                account,
                target_value,
                &ShieldedPool::Sapling,
                target_height,
                confirmations_policy,
                exclude,
                lock_filter,
            )?
        } else {
            Vec::new()
        };

        #[cfg(feature = "orchard")]
        let orchard_eligible_notes = if sources.contains(&ShieldedPool::Orchard) {
            self.select_spendable_notes_from_pool(
                account,
                target_value,
                &ShieldedPool::Orchard,
                target_height,
                confirmations_policy,
                exclude,
                lock_filter,
            )?
        } else {
            Vec::new()
        };

        #[cfg(feature = "orchard")]
        let ironwood_eligible_notes = if sources.contains(&ShieldedPool::Ironwood) {
            self.select_spendable_notes_from_pool(
                account,
                target_value,
                &ShieldedPool::Ironwood,
                target_height,
                confirmations_policy,
                exclude,
                lock_filter,
            )?
        } else {
            Vec::new()
        };

        to_spendable_notes(
            &sapling_eligible_notes,
            #[cfg(feature = "orchard")]
            &orchard_eligible_notes,
            #[cfg(feature = "orchard")]
            &ironwood_eligible_notes,
            |note| self.note_transaction_heights(&note.txid),
        )
    }

    fn select_single_spendable_note(
        &self,
        account: Self::AccountId,
        value: Zatoshis,
        sources: &[ShieldedPool],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        for pool in sources {
            let eligible = self.select_spendable_notes_from_pool(
                account,
                TargetValue::AllFunds(MaxSpendMode::MaxSpendable),
                pool,
                target_height,
                confirmations_policy,
                exclude,
                lock_filter,
            )?;
            // Eligibility is ordered by lock tier, then age. Reducing by age alone loses the tier.
            if let Some(note) = eligible.into_iter().find(|note| note.note.value() >= value) {
                let selected = [note];
                return to_spendable_notes(
                    if *pool == ShieldedPool::Sapling {
                        &selected
                    } else {
                        &[]
                    },
                    #[cfg(feature = "orchard")]
                    if *pool == ShieldedPool::Orchard {
                        &selected
                    } else {
                        &[]
                    },
                    #[cfg(feature = "orchard")]
                    if *pool == ShieldedPool::Ironwood {
                        &selected
                    } else {
                        &[]
                    },
                    |note| self.note_transaction_heights(&note.txid),
                );
            }
        }
        Ok(ReceivedNotes::new(
            vec![],
            #[cfg(feature = "orchard")]
            vec![],
            #[cfg(feature = "orchard")]
            vec![],
        ))
    }

    fn select_unspent_notes(
        &self,
        _account: Self::AccountId,
        _sources: &[ShieldedPool],
        _target_height: TargetHeight,
        _exclude: &[Self::NoteRef],
        _lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        unimplemented!()
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_spendable_transparent_outputs(
        &self,
        address: &TransparentAddress,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        output_filter: CoinbaseFilter,
        lock_filter: LockFilter<'_>,
    ) -> Result<Vec<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        // TODO: take into consideration coinbase maturity
        // See <https://github.com/zcash/librustzcash/issues/821>
        let txos = self
            .transparent_received_outputs
            .iter()
            .filter(|(_, txo)| txo.address == *address)
            .filter(|(outpoint, _)| {
                self.lock_allows(
                    &OutputRef::new(
                        *outpoint.txid(),
                        zcash_protocol::PoolType::Transparent,
                        outpoint.n(),
                    ),
                    target_height.into(),
                    lock_filter,
                )
            })
            .map(|(outpoint, txo)| (outpoint, txo, self.tx_table.get(&txo.transaction_id)))
            .filter(|(outpoint, _, _)| {
                self.utxo_is_spendable(outpoint, target_height, confirmations_policy)
                    .unwrap_or(false)
            })
            .filter(|(_, _, tx)| match output_filter {
                CoinbaseFilter::AllTransparentOutputs => true,
                // Coinbase transactions have tx_index == 0. If tx_index is unknown
                // (None), conservatively treat it as **non-coinbase**, matching the SQL
                // implementation's IFNULL(tx_index, 1) == 0 behavior.
                CoinbaseFilter::CoinbaseOnly => {
                    tx.is_some_and(|tx| tx.tx_index().unwrap_or(1) == 0)
                }
                CoinbaseFilter::NonCoinbaseOnly => {
                    !tx.is_some_and(|tx| tx.tx_index().unwrap_or(1) == 0)
                }
            })
            .filter_map(|(outpoint, txo, tx)| {
                txo.to_wallet_transparent_output(outpoint, tx.and_then(|tx| tx.mined_height()))
            })
            .collect();
        Ok(txos)
    }

    #[cfg(feature = "transparent-inputs")]
    #[allow(clippy::too_many_arguments)]
    fn select_spendable_transparent_outputs(
        &self,
        account: Self::AccountId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        output_filter: CoinbaseFilter,
        address_allow_list: Option<&[TransparentAddress]>,
        target_value: TargetValue,
        max_inputs: usize,
        fee_rule: &StandardFeeRule,
        lock_filter: LockFilter<'_>,
    ) -> Result<Vec<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        let target_zat = match target_value {
            TargetValue::AtLeast(value) => Some(u64::from(value)),
            TargetValue::AllFunds(_) => None,
        };

        let mut eligible = self
            .transparent_received_outputs
            .iter()
            .filter(|(_, output)| output.account_id == account)
            .filter(|(outpoint, _)| {
                self.lock_allows(
                    &OutputRef::new(
                        *outpoint.txid(),
                        zcash_protocol::PoolType::Transparent,
                        outpoint.n(),
                    ),
                    target_height.into(),
                    lock_filter,
                )
            })
            .filter(|(_, output)| {
                address_allow_list.is_none_or(|addresses| addresses.contains(&output.address))
            })
            .map(|(outpoint, output)| (outpoint, output, self.tx_table.get(&output.transaction_id)))
            .filter(|(outpoint, _, _)| {
                self.utxo_is_spendable(outpoint, target_height, confirmations_policy)
                    .unwrap_or(false)
            })
            .filter(|(_, _, tx)| match output_filter {
                CoinbaseFilter::AllTransparentOutputs => true,
                CoinbaseFilter::CoinbaseOnly => {
                    tx.is_some_and(|tx| tx.tx_index().unwrap_or(1) == 0)
                }
                CoinbaseFilter::NonCoinbaseOnly => {
                    !tx.is_some_and(|tx| tx.tx_index().unwrap_or(1) == 0)
                }
            })
            .filter(|(_, output, _)| output.txout.value() >= zip317::MARGINAL_FEE)
            .filter_map(|(outpoint, output, tx)| {
                output.to_wallet_transparent_output(outpoint, tx.and_then(|tx| tx.mined_height()))
            })
            .collect::<Vec<_>>();

        eligible.sort_by(|a, b| {
            self.lock_order(
                &OutputRef::new(
                    *a.outpoint().txid(),
                    zcash_protocol::PoolType::Transparent,
                    a.outpoint().n(),
                ),
                target_height.into(),
                lock_filter,
            )
            .cmp(&self.lock_order(
                &OutputRef::new(
                    *b.outpoint().txid(),
                    zcash_protocol::PoolType::Transparent,
                    b.outpoint().n(),
                ),
                target_height.into(),
                lock_filter,
            ))
            .then_with(|| {
                b.value()
                    .cmp(&a.value())
                    .then_with(|| a.outpoint().cmp(b.outpoint()))
            })
        });

        let mut selected = Vec::new();
        let mut accumulated_value = 0u64;
        let mut cumulative_input_size = 0usize;

        for output in eligible {
            if selected.len() >= max_inputs {
                break;
            }

            if let Some(target) = target_zat {
                let cumulative_fee = fee_rule
                    .fee_required(
                        &self.params,
                        BlockHeight::from(target_height),
                        [InputSize::Known(cumulative_input_size)],
                        std::iter::empty::<usize>(),
                        0,
                        0,
                        0,
                        0,
                    )
                    .map_err(|error| Error::Other(format!("fee calculation failed: {error}")))?;
                if accumulated_value.saturating_sub(u64::from(cumulative_fee)) >= target {
                    break;
                }
            }

            let input_size = match output.serialized_size() {
                InputSize::Known(size) => size,
                InputSize::Unknown(_) => zip317::P2PKH_STANDARD_INPUT_SIZE,
            };
            cumulative_input_size = cumulative_input_size.saturating_add(input_size);
            accumulated_value = accumulated_value.saturating_add(u64::from(output.value()));
            selected.push(output);
        }

        Ok(selected)
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_unspent_transparent_output(
        &self,
        outpoint: &OutPoint,
        _target_height: TargetHeight,
    ) -> Result<Option<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        // FIXME: make use of `target_height` to check spendability.
        Ok(self
            .transparent_received_outputs
            .get(outpoint)
            .map(|txo| (txo, self.tx_table.get(&txo.transaction_id)))
            .and_then(|(txo, tx)| {
                txo.to_wallet_transparent_output(outpoint, tx.and_then(|tx| tx.mined_height()))
            }))
    }

    fn get_account_metadata(
        &self,
        account_id: Self::AccountId,
        selector: &NoteFilter,
        target_height: TargetHeight,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<AccountMeta, Self::Error> {
        let confirmations_policy = ConfirmationsPolicy::new_symmetrical(
            NonZeroU32::MIN,
            #[cfg(feature = "transparent-inputs")]
            true,
        );

        let sapling_pool_meta = self.spendable_notes_meta(
            ShieldedPool::Sapling,
            account_id,
            selector,
            target_height,
            confirmations_policy,
            exclude,
            lock_filter,
        )?;

        #[cfg(feature = "orchard")]
        let orchard_pool_meta = self.spendable_notes_meta(
            ShieldedPool::Orchard,
            account_id,
            selector,
            target_height,
            confirmations_policy,
            exclude,
            lock_filter,
        )?;
        #[cfg(not(feature = "orchard"))]
        let orchard_pool_meta = None;

        #[cfg(feature = "orchard")]
        let ironwood_pool_meta = self.spendable_notes_meta(
            ShieldedPool::Ironwood,
            account_id,
            selector,
            target_height,
            confirmations_policy,
            exclude,
            lock_filter,
        )?;
        #[cfg(not(feature = "orchard"))]
        let ironwood_pool_meta = None;

        Ok(AccountMeta::new(
            sapling_pool_meta,
            orchard_pool_meta,
            ironwood_pool_meta,
            self.get_change_receivers(account_id)?,
        ))
    }
}

impl<P: consensus::Parameters> MemoryWalletDb<P> {
    fn note_transaction_heights(
        &self,
        txid: &zcash_primitives::transaction::TxId,
    ) -> (
        Option<zcash_protocol::consensus::BlockHeight>,
        Option<zcash_protocol::consensus::BlockHeight>,
    ) {
        let tx = self.tx_table.get_transaction(txid);
        let transparent_input_height = tx
            .and_then(|entry| entry.raw())
            .and_then(|raw| Transaction::read(raw, BranchId::Sapling).ok())
            .and_then(|tx| {
                tx.transparent_bundle().map(|bundle| {
                    bundle
                        .vin
                        .iter()
                        .filter_map(|input| {
                            self.tx_table
                                .get_transaction(input.prevout().txid())
                                .and_then(|entry| entry.mined_height())
                        })
                        .max()
                })
            })
            .flatten();
        (
            tx.and_then(|entry| entry.mined_height()),
            transparent_input_height,
        )
    }

    // Select the spendable notes to cover the given target value considering only a single pool
    // Returns the notes sorted oldest to newest
    fn select_spendable_notes_from_pool(
        &self,
        account: AccountId,
        target_value: TargetValue,
        pool: &ShieldedPool,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[NoteId],
        lock_filter: LockFilter<'_>,
    ) -> Result<Vec<&crate::ReceivedNote>, Error> {
        let birthday_height = match self.get_wallet_birthday()? {
            Some(birthday) => birthday,
            None => {
                // the wallet birthday can only be unknown if there are no accounts in the wallet; in
                // such a case, the wallet has no notes to spend.
                return Ok(Vec::new());
            }
        };
        // First grab all eligible (unspent, spendable, fully scanned) notes into a vec.
        let mut eligible_notes = self
            .received_notes
            .iter()
            .filter(|note| note.account_id == account)
            .filter(|note| note.note.pool() == *pool)
            .filter(|note| {
                self.lock_allows(&note.note_id.into(), target_height.into(), lock_filter)
            })
            .filter(|note| {
                self.note_is_spendable(
                    note,
                    birthday_height,
                    target_height,
                    confirmations_policy,
                    exclude,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        // sort by oldest first (use location in commitment tree since this gives a total order)
        eligible_notes.sort_by_key(|a| {
            (
                self.lock_order(&a.note_id.into(), target_height.into(), lock_filter),
                a.commitment_tree_position,
            )
        });

        // now take notes until we have enough to cover the target value
        let mut value_acc = Zatoshis::ZERO;
        let selection: Vec<_> = eligible_notes
            .into_iter()
            .take_while(|note| {
                let take = match target_value {
                    TargetValue::AtLeast(target) => value_acc < target,
                    TargetValue::AllFunds(_) => true,
                };
                value_acc = (value_acc + note.note.value()).expect("value overflow");
                take
            })
            .collect();

        Ok(selection)
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn utxo_is_spendable(
        &self,
        outpoint: &OutPoint,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<bool, Error> {
        Ok(matches!(
            self.transparent_output_status(outpoint, target_height, confirmations_policy)?,
            TransparentOutputStatus::Spendable
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn transparent_output_status(
        &self,
        outpoint: &OutPoint,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<TransparentOutputStatus, Error> {
        let utxo = self
            .transparent_received_outputs
            .get(outpoint)
            .ok_or(Error::NoteNotFound)?;
        if self.utxo_is_spent(outpoint, target_height)? {
            return Ok(TransparentOutputStatus::Unavailable);
        }

        let required_confirmations =
            self.transparent_required_confirmations(&utxo.transaction_id, confirmations_policy);
        let confirmed_height = BlockHeight::from(target_height) - u32::from(required_confirmations);
        if let Some(tx) = self.tx_table.get(&utxo.transaction_id) {
            if tx.is_mined_or_unexpired_at(confirmed_height) {
                Ok(TransparentOutputStatus::Spendable)
            } else if tx.is_mined_or_unexpired_at(BlockHeight::from(target_height)) {
                Ok(TransparentOutputStatus::Pending)
            } else {
                Ok(TransparentOutputStatus::Unavailable)
            }
        } else {
            Ok(TransparentOutputStatus::Unavailable)
        }
    }

    #[cfg(feature = "transparent-inputs")]
    fn transaction_is_wallet_created(&self, txid: &TxId) -> bool {
        self.sent_notes.keys().any(|note_id| note_id.txid() == txid)
            || self
                .received_note_spends
                .values()
                .any(|spend_txid| spend_txid == txid)
            || self
                .transparent_received_output_spends
                .values()
                .any(|spend_txid| spend_txid == txid)
    }

    #[cfg(feature = "transparent-inputs")]
    fn transparent_required_confirmations(
        &self,
        txid: &TxId,
        confirmations_policy: ConfirmationsPolicy,
    ) -> NonZeroU32 {
        if self.transaction_is_wallet_created(txid) {
            confirmations_policy.trusted()
        } else {
            confirmations_policy.untrusted()
        }
    }

    #[cfg(feature = "transparent-inputs")]
    fn utxo_is_spent(
        &self,
        outpoint: &OutPoint,
        target_height: TargetHeight,
    ) -> Result<bool, Error> {
        let spend = self.transparent_received_output_spends.get(outpoint);

        let spent = match spend {
            Some(txid) => {
                let spending_tx = self
                    .tx_table
                    .get(txid)
                    .ok_or(Error::TransactionNotFound(*txid))?;
                match spending_tx.status() {
                    TransactionStatus::Mined(_height) => true,
                    TransactionStatus::TxidNotRecognized | TransactionStatus::NotInMainChain => {
                        // transaction either never expires, or expires in the future.
                        spending_tx
                            .expiry_height()
                            .iter()
                            .all(|h| *h >= BlockHeight::from(target_height))
                    }
                }
            }
            None => false,
        };
        Ok(spent)
    }

    fn spendable_notes_meta(
        &self,
        protocol: ShieldedPool,
        account: AccountId,
        filter: &NoteFilter,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[NoteId],
        lock_filter: LockFilter<'_>,
    ) -> Result<Option<PoolMeta>, Error> {
        let birthday_height = match self.get_wallet_birthday()? {
            Some(birthday) => birthday,
            None => {
                return Ok(None);
            }
        };
        let (count, total) = self
            .received_notes
            .iter()
            .filter(|note| note.account_id == account)
            .filter(|note| note.note.pool() == protocol)
            .filter(|note| {
                self.lock_allows(&note.note_id.into(), target_height.into(), lock_filter)
            })
            .filter(|note| {
                self.note_is_spendable(
                    note,
                    birthday_height,
                    target_height,
                    confirmations_policy,
                    exclude,
                )
                .expect("note account & transaction are known to the wallet")
            })
            .filter(|note| {
                self.matches_note_filter(note, filter)
                    .unwrap()
                    .is_some_and(|b| b)
            })
            .fold((0, Zatoshis::ZERO), |(count, total), note| {
                (count + 1, (total + note.note.value()).unwrap())
            });

        Ok(Some(PoolMeta::new(count, total)))
    }

    #[allow(clippy::only_used_in_recursion)]
    fn matches_note_filter(
        &self,
        note: &crate::ReceivedNote,
        filter: &NoteFilter,
    ) -> Result<Option<bool>, Error> {
        match filter {
            NoteFilter::ExceedsMinValue(min_value) => Ok(Some(note.note.value() > *min_value)),
            NoteFilter::ExceedsPriorSendPercentile(_n) => todo!(),
            NoteFilter::ExceedsBalancePercentage(_p) => todo!(),
            // evaluate both conditions.
            // If one cannot be evaluated (e.g. it returns None) it is ignored
            NoteFilter::Combine(a, b) => {
                let matches_a = self.matches_note_filter(note, a)?.unwrap_or(true);
                let matches_b = self.matches_note_filter(note, b)?.unwrap_or(true);
                Ok(Some(matches_a && matches_b))
            }
            // Evaluate the first condition and return the result.
            // If the first condition cannot be evaluated then use the fallback instead
            NoteFilter::Attempt {
                condition,
                fallback,
            } => {
                if let Some(b) = self.matches_note_filter(note, condition)? {
                    Ok(Some(b))
                } else {
                    self.matches_note_filter(note, fallback)
                }
            }
        }
    }
}

#[cfg(all(test, feature = "transparent-inputs"))]
mod tests {
    use super::*;
    use zcash_protocol::consensus::Network;

    #[test]
    fn distinguishes_wallet_created_and_external_transparent_outputs() {
        let mut wallet = MemoryWalletDb::new(Network::TestNetwork, 100);
        let external_txid = TxId::from_bytes([1; 32]);
        let wallet_created_txid = TxId::from_bytes([2; 32]);
        let funding_outpoint = OutPoint::new([3; 32], 0);
        let policy = ConfirmationsPolicy::default();

        assert!(!wallet.transaction_is_wallet_created(&external_txid));
        assert_eq!(
            u32::from(wallet.transparent_required_confirmations(&external_txid, policy)),
            10
        );

        wallet
            .transparent_received_output_spends
            .insert(funding_outpoint, wallet_created_txid);

        assert!(wallet.transaction_is_wallet_created(&wallet_created_txid));
        assert_eq!(
            u32::from(wallet.transparent_required_confirmations(&wallet_created_txid, policy)),
            3
        );
    }
}
