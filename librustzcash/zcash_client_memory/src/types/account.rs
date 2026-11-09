use std::{
    collections::{BTreeMap, BTreeSet},
    ops::{Deref, DerefMut},
};

use subtle::ConditionallySelectable;
use transparent::address::TransparentAddress;
#[cfg(feature = "transparent-inputs")]
use transparent::keys::{
    AccountPubKey, EphemeralIvk, IncomingViewingKey, NonHardenedChildIndex, TransparentKeyScope,
};
use zcash_address::ZcashAddress;
#[cfg(feature = "transparent-inputs")]
use zcash_address::unified::Typecode;
#[cfg(feature = "transparent-inputs")]
use zcash_client_backend::wallet::{Exposure, GapMetadata, TransparentAddressMetadata};
use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{Account as _, AccountBirthday, AccountPurpose, AccountSource},
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey},
    wallet::NoteId,
};
use zcash_keys::{
    address::Receiver,
    keys::{AddressGenerationError, UnifiedIncomingViewingKey},
};
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, NetworkType};
use zip32::DiversifierIndex;

use crate::error::Error;

// TODO: this is a temporary constant to allow merge; in the future, the ephemeral gap limit
// handling in this module should be replaced by generalized transparent gap limit handling
// as is implemented in zcash_client_sqlite/src/wallet/transparent.rs
#[cfg(feature = "transparent-inputs")]
pub(crate) const EPHEMERAL_GAP_LIMIT: u32 = 5;

#[cfg(feature = "transparent-inputs")]
pub(crate) const INTERNAL_GAP_LIMIT: u32 = 5;

/// Internal representation of ID type for accounts. Will be unique for each account.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Default,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct AccountId(u32);

impl From<u32> for AccountId {
    fn from(id: u32) -> Self {
        AccountId(id)
    }
}

impl Deref for AccountId {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ConditionallySelectable for AccountId {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        AccountId(ConditionallySelectable::conditional_select(
            &a.0, &b.0, choice,
        ))
    }
}

/// This is the top-level struct that handles accounts. We could theoretically have this just be a Vec
/// but we want to have control over the internal AccountId values. The account ids are unique.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Accounts {
    pub(crate) nonce: u32,
    pub(crate) accounts: BTreeMap<AccountId, Account>,
}

impl Accounts {
    pub(crate) fn new() -> Self {
        Self {
            nonce: 0,
            accounts: BTreeMap::new(),
        }
    }

    /// Creates a new account. The account id will be determined by the internal nonce.
    /// Do not call this directly, use the `Wallet` methods instead.
    /// Otherwise the scan queue will not be correctly updated
    pub(crate) fn new_account(
        &mut self,
        account_name: &str,
        kind: AccountSource,
        viewing_key: UnifiedFullViewingKey,
        birthday: AccountBirthday,
    ) -> Result<(AccountId, Account), Error> {
        self.nonce += 1;
        let account_id = AccountId(self.nonce);

        let acc = Account::new(
            account_name.to_string(),
            account_id,
            kind,
            viewing_key,
            birthday,
        )?;

        self.accounts.insert(account_id, acc.clone());

        Ok((account_id, acc))
    }

    pub(crate) fn get(&self, account_id: AccountId) -> Option<&Account> {
        self.accounts.get(&account_id)
    }

    pub(crate) fn get_mut(&mut self, account_id: AccountId) -> Option<&mut Account> {
        self.accounts.get_mut(&account_id)
    }
    /// Gets the account ids of all accounts
    pub(crate) fn account_ids(&self) -> impl Iterator<Item = &AccountId> {
        self.accounts.keys()
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn find_account_for_transparent_address(
        &self,
        address: &TransparentAddress,
    ) -> Result<Option<AccountId>, Error> {
        // Look for transparent receivers generated as part of a Unified Address
        if let Some(id) = self
            .accounts
            .iter()
            .find(|(_, account)| {
                account
                    .addresses()
                    .iter()
                    .any(|(_, unified_address)| unified_address.transparent() == Some(address))
            })
            .map(|(id, _)| *id)
        {
            Ok(Some(id))
        } else {
            if let Some(id) = self
                .accounts
                .iter()
                .find(|(_, account)| account.contains_internal_address(address))
                .map(|(id, _)| *id)
            {
                return Ok(Some(id));
            }

            // then look at ephemeral addresses
            if let Some(id) = self.find_account_for_ephemeral_address(address)? {
                Ok(Some(id))
            } else {
                for (account_id, account) in self.accounts.iter() {
                    if account
                        .get_legacy_transparent_address()?
                        .is_some_and(|(legacy_address, _)| legacy_address == *address)
                    {
                        return Ok(Some(*account_id));
                    }
                }
                Ok(None)
            }
        }
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn find_account_for_ephemeral_address(
        &self,
        address: &TransparentAddress,
    ) -> Result<Option<AccountId>, Error> {
        for (account_id, account) in self.accounts.iter() {
            let contains = account
                .ephemeral_addresses()?
                .iter()
                .any(|(eph_addr, _)| eph_addr == address);
            if contains {
                return Ok(Some(*account_id));
            }
        }
        Ok(None)
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn mark_ephemeral_address_as_seen(
        &mut self,
        address: &TransparentAddress,
        tx_id: TxId,
    ) -> Result<(), Error> {
        for account in self.accounts.values_mut() {
            account.mark_ephemeral_address_as_seen(address, tx_id)?
        }
        Ok(())
    }
}

impl Deref for Accounts {
    type Target = BTreeMap<AccountId, Account>;

    fn deref(&self) -> &Self::Target {
        &self.accounts
    }
}

impl DerefMut for Accounts {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.accounts
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EphemeralAddress {
    pub(crate) address: TransparentAddress,
    // Used implies seen
    pub(crate) used: Option<TxId>,
    pub(crate) seen: Option<TxId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InternalAddress {
    pub(crate) address: TransparentAddress,
    pub(crate) exposed_at_height: BlockHeight,
}

/// Recovery candidates are not reservations. Keep checked empty addresses too,
/// so an in-flight response remains recognizable after the gap advances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InternalAddressDiscovery {
    pub(crate) address: TransparentAddress,
    pub(crate) checked_height: Option<BlockHeight>,
}

impl EphemeralAddress {
    #[cfg(feature = "transparent-inputs")]
    fn mark_used(&mut self, tx: TxId) {
        // We update both `used_in_tx` and `seen_in_tx` here, because a used address has
        // necessarily been seen in a transaction. We will not treat this as extending the
        // range of addresses that are safe to reserve unless and until the transaction is
        // observed as mined.
        self.used.replace(tx);
        self.seen.replace(tx);
    }
    #[cfg(feature = "transparent-inputs")]
    fn mark_seen(&mut self, tx: TxId) -> Option<TxId> {
        self.seen.replace(tx)
    }
}

/// An internal representation account stored in the database.
#[derive(Debug, Clone)]
pub struct Account {
    account_name: String,
    account_id: AccountId,
    kind: AccountSource,
    viewing_key: UnifiedFullViewingKey,
    birthday: AccountBirthday,
    /// Stores diversified Unified Addresses that have been generated from accounts in the wallet.
    addresses: BTreeMap<DiversifierIndex, UnifiedAddress>,
    pub(crate) ephemeral_addresses: BTreeMap<u32, EphemeralAddress>, // NonHardenedChildIndex (< 1 << 31)
    pub(crate) internal_addresses: BTreeMap<u32, InternalAddress>,
    pub(crate) internal_address_discovery: BTreeMap<u32, InternalAddressDiscovery>,
    _notes: BTreeSet<NoteId>,
}

impl PartialEq for Account {
    fn eq(&self, other: &Self) -> bool {
        self.account_name == other.account_name
            && self.account_id == other.account_id
            && self.kind == other.kind
            && self
                .viewing_key
                .encode(&zcash_protocol::consensus::MainNetwork)
                == other
                    .viewing_key
                    .encode(&zcash_protocol::consensus::MainNetwork)
            && self.birthday == other.birthday
            && self.addresses == other.addresses
            && self.ephemeral_addresses == other.ephemeral_addresses
            && self.internal_addresses == other.internal_addresses
            && self.internal_address_discovery == other.internal_address_discovery
            && self._notes == other._notes
    }
}

impl Account {
    pub(crate) fn set_name(&mut self, name: &str) {
        self.account_name = name.to_owned();
    }

    pub(crate) fn new(
        account_name: String,
        account_id: AccountId,
        kind: AccountSource,
        viewing_key: UnifiedFullViewingKey,
        birthday: AccountBirthday,
    ) -> Result<Self, Error> {
        let mut acc = Self {
            account_name,
            account_id,
            kind,
            viewing_key,
            birthday,
            ephemeral_addresses: BTreeMap::new(),
            internal_addresses: BTreeMap::new(),
            internal_address_discovery: BTreeMap::new(),
            addresses: BTreeMap::new(),
            _notes: BTreeSet::new(),
        };

        // populate the addresses map with the default address
        let (ua, diversifier_index) =
            acc.default_address(UnifiedAddressRequest::AllAvailableKeys)?;
        acc.addresses.insert(diversifier_index, ua);
        #[cfg(feature = "transparent-inputs")]
        {
            acc.reserve_until(0)?;
            acc.ensure_internal_gap(0)?;
        }
        Ok(acc)
    }

    pub(crate) fn addresses(&self) -> &BTreeMap<DiversifierIndex, UnifiedAddress> {
        &self.addresses
    }

    /// Generates and stores a unified address at the given diversifier index.
    pub(crate) fn address_at(
        &mut self,
        diversifier_index: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<UnifiedAddress, AddressGenerationError> {
        let ua = self.uivk().address(diversifier_index, request)?;
        self.addresses.insert(diversifier_index, ua.clone());
        Ok(ua)
    }

    pub(crate) fn select_receiving_address(
        &self,
        network: NetworkType,
        receiver: &Receiver,
    ) -> Result<Option<ZcashAddress>, Error> {
        Ok(self
            .addresses
            .values()
            .map(|ua| ua.to_zcash_address(network))
            .find(|addr| receiver.corresponds(addr)))
    }

    /// Returns the default Unified Address for the account,
    /// along with the diversifier index that generated it.
    ///
    /// The diversifier index may be non-zero if the Unified Address includes a Sapling
    /// receiver, and there was no valid Sapling receiver at diversifier index zero.
    pub(crate) fn default_address(
        &self,
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), AddressGenerationError> {
        self.uivk().default_address(request)
    }

    pub(crate) fn birthday(&self) -> &AccountBirthday {
        &self.birthday
    }

    pub(crate) fn current_address(&self) -> Result<(UnifiedAddress, DiversifierIndex), Error> {
        Ok(self
            .addresses
            .iter()
            .last()
            .map(|(diversifier_index, ua)| (ua.clone(), *diversifier_index))
            .unwrap()) // can unwrap as the map is never empty
    }

    pub(crate) fn kind(&self) -> &AccountSource {
        &self.kind
    }

    pub(crate) fn next_available_address(
        &mut self,
        request: UnifiedAddressRequest,
    ) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, Error> {
        match self.ufvk() {
            Some(ufvk) => {
                let search_from = self
                    .current_address()
                    .map(|(_, mut diversifier_index)| {
                        diversifier_index.increment().map_err(|_| {
                            Error::AddressGeneration(
                                AddressGenerationError::DiversifierSpaceExhausted,
                            )
                        })?;
                        Ok::<_, Error>(diversifier_index)
                    })
                    .unwrap_or(Ok(DiversifierIndex::default()))?;
                let (ua, diversifier_index) = ufvk.find_address(search_from, request)?;
                self.addresses.insert(diversifier_index, ua.clone());
                Ok(Some((ua, diversifier_index)))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn account_id(&self) -> AccountId {
        self.account_id
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn get_legacy_transparent_address(
        &self,
    ) -> Result<Option<(TransparentAddress, NonHardenedChildIndex)>, Error> {
        Ok(self
            .uivk()
            .p2pkh()
            .as_ref()
            .map(|tivk| tivk.default_address()))
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn transparent_key_scope_for_address(
        &self,
        address: &TransparentAddress,
    ) -> Result<Option<TransparentKeyScope>, Error> {
        if self
            .addresses()
            .iter()
            .any(|(_, unified_address)| unified_address.transparent() == Some(address))
        {
            return Ok(Some(TransparentKeyScope::EXTERNAL));
        }

        if self.contains_internal_address(address) {
            return Ok(Some(TransparentKeyScope::INTERNAL));
        }

        if self
            .ephemeral_addresses()?
            .iter()
            .any(|(ephemeral_address, _)| ephemeral_address == address)
        {
            return Ok(Some(TransparentKeyScope::EPHEMERAL));
        }

        if self
            .get_legacy_transparent_address()?
            .is_some_and(|(legacy_address, _)| legacy_address == *address)
        {
            return Ok(Some(TransparentKeyScope::EXTERNAL));
        }

        Ok(None)
    }
}
#[cfg(feature = "transparent-inputs")]
impl Account {
    pub(crate) fn contains_internal_address(&self, address: &TransparentAddress) -> bool {
        self.internal_address_index(address).is_some()
    }

    pub(crate) fn internal_address_index(&self, address: &TransparentAddress) -> Option<u32> {
        self.internal_addresses
            .iter()
            .find_map(|(index, internal)| (internal.address == *address).then_some(*index))
            .or_else(|| {
                self.internal_address_discovery
                    .iter()
                    .find_map(|(index, candidate)| {
                        (candidate.address == *address).then_some(*index)
                    })
            })
    }

    /// Maintain a rolling lookahead after the last mined use, without exposing
    /// or reserving those addresses for transaction construction.
    pub(crate) fn ensure_internal_gap(&mut self, first_gap_index: u32) -> Result<(), Error> {
        let Some(pubkey) = self.viewing_key.p2pkh() else {
            return Ok(());
        };
        let end = first_gap_index
            .saturating_add(INTERNAL_GAP_LIMIT)
            .min(1 << 31);
        let start = self
            .internal_address_discovery
            .last_key_value()
            .map_or(0, |(index, _)| index + 1);
        if start >= end {
            return Ok(());
        }
        let ivk = pubkey.derive_internal_ivk()?;
        for index in start..end {
            let child = NonHardenedChildIndex::from_index(index)
                .ok_or(AddressGenerationError::DiversifierSpaceExhausted)?;
            self.internal_address_discovery.insert(
                index,
                InternalAddressDiscovery {
                    address: ivk.derive_address(child)?,
                    checked_height: None,
                },
            );
        }
        Ok(())
    }

    pub(crate) fn mark_internal_address_seen(
        &mut self,
        address: &TransparentAddress,
        height: BlockHeight,
    ) {
        if let Some(index) = self.internal_address_index(address) {
            self.internal_addresses
                .entry(index)
                .and_modify(|internal| {
                    internal.exposed_at_height = internal.exposed_at_height.min(height);
                })
                .or_insert(InternalAddress {
                    address: *address,
                    exposed_at_height: height,
                });
        }
    }

    pub(crate) fn next_internal_address_index(&self) -> Result<u32, Error> {
        self.internal_addresses
            .last_key_value()
            .map_or(Ok(0), |(index, _)| {
                index
                    .checked_add(1)
                    .filter(|index| *index < (1 << 31))
                    .ok_or_else(|| AddressGenerationError::DiversifierSpaceExhausted.into())
            })
    }

    fn internal_address_metadata(
        index: u32,
        internal: &InternalAddress,
        first_gap_index: u32,
    ) -> TransparentAddressMetadata {
        let gap_metadata = if index < first_gap_index {
            GapMetadata::GapRecoverable {
                gap_limit: INTERNAL_GAP_LIMIT,
            }
        } else {
            GapMetadata::InGap {
                gap_position: index - first_gap_index,
                gap_limit: INTERNAL_GAP_LIMIT,
            }
        };

        TransparentAddressMetadata::derived(
            TransparentKeyScope::INTERNAL,
            NonHardenedChildIndex::from_index(index)
                .expect("stored internal address index is non-hardened"),
            Exposure::Exposed {
                at_height: internal.exposed_at_height,
                gap_metadata,
            },
            None,
        )
    }

    pub(crate) fn internal_addresses(
        &self,
        first_gap_index: u32,
    ) -> Vec<(TransparentAddress, TransparentAddressMetadata)> {
        let mut addresses = self
            .internal_address_discovery
            .iter()
            .map(|(index, candidate)| {
                (
                    candidate.address,
                    TransparentAddressMetadata::derived(
                        TransparentKeyScope::INTERNAL,
                        NonHardenedChildIndex::from_index(*index)
                            .expect("discovery index is non-hardened"),
                        Exposure::Unknown,
                        None,
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        addresses.extend(self.internal_addresses.iter().map(|(index, internal)| {
            (
                internal.address,
                Self::internal_address_metadata(*index, internal, first_gap_index),
            )
        }));
        addresses.into_iter().collect()
    }

    pub(crate) fn metadata_for_internal_address(
        &self,
        address: &TransparentAddress,
        first_gap_index: u32,
    ) -> Option<TransparentAddressMetadata> {
        self.internal_addresses(first_gap_index)
            .into_iter()
            .find_map(|(candidate, metadata)| (candidate == *address).then_some(metadata))
    }

    pub(crate) fn reserve_internal_addresses(
        &mut self,
        start: u32,
        n: usize,
        exposed_at_height: BlockHeight,
        first_gap_index: u32,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Error> {
        if n == 0 {
            return Ok(vec![]);
        }

        let end = start
            .checked_add(u32::try_from(n)?)
            .filter(|end| *end <= (1 << 31))
            .ok_or(AddressGenerationError::DiversifierSpaceExhausted)?;
        let account_pubkey = self
            .viewing_key
            .p2pkh()
            .ok_or(AddressGenerationError::KeyNotAvailable(Typecode::P2PKH))?;
        let internal_ivk = account_pubkey.derive_internal_ivk()?;

        (start..end)
            .map(|raw_index| {
                let address_index = NonHardenedChildIndex::from_index(raw_index)
                    .ok_or(AddressGenerationError::DiversifierSpaceExhausted)?;
                let address = internal_ivk.derive_address(address_index)?;
                let internal = InternalAddress {
                    address,
                    exposed_at_height,
                };
                let metadata =
                    Self::internal_address_metadata(raw_index, &internal, first_gap_index);
                self.internal_addresses.insert(raw_index, internal);
                Ok((address, metadata))
            })
            .collect()
    }

    pub(crate) fn ephemeral_addresses(
        &self,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Error> {
        Ok(self
            .ephemeral_addresses
            .iter()
            .map(|(idx, addr)| {
                (
                    addr.address,
                    TransparentAddressMetadata::derived(
                        TransparentKeyScope::EPHEMERAL,
                        NonHardenedChildIndex::from_index(*idx).unwrap(),
                        Exposure::Unknown,
                        None,
                    ),
                )
            })
            .collect())
    }
    pub(crate) fn ephemeral_ivk(&self) -> Result<Option<EphemeralIvk>, Error> {
        self.viewing_key
            .p2pkh()
            .map(AccountPubKey::derive_ephemeral_ivk)
            .transpose()
            .map_err(Into::into)
    }

    pub(crate) fn first_unstored_index(&self) -> Result<u32, Error> {
        if let Some((idx, _)) = self.ephemeral_addresses.last_key_value() {
            if *idx >= (1 << 31) + EPHEMERAL_GAP_LIMIT {
                unreachable!("violates constraint index_range_and_address_nullity")
            } else {
                Ok(idx.checked_add(1).unwrap())
            }
        } else {
            Ok(0)
        }
    }

    pub(crate) fn first_unreserved_index(&self) -> Result<u32, Error> {
        self.first_unstored_index()?
            .checked_sub(EPHEMERAL_GAP_LIMIT)
            .ok_or(Error::CorruptedData(
                "ephemeral_addresses corrupted".to_owned(),
            ))
    }

    pub(crate) fn reserve_until(
        &mut self,
        next_to_reserve: u32,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Error> {
        if let Some(ephemeral_ivk) = self.ephemeral_ivk()? {
            let first_unstored = self.first_unstored_index()?;
            let range_to_store =
                first_unstored..(next_to_reserve.checked_add(EPHEMERAL_GAP_LIMIT).unwrap());
            if range_to_store.is_empty() {
                return Ok(Vec::new());
            }
            return range_to_store
                .map(|raw_index| {
                    NonHardenedChildIndex::from_index(raw_index)
                        .map(|address_index| {
                            ephemeral_ivk
                                .derive_ephemeral_address(address_index)
                                .map(|addr| {
                                    self.ephemeral_addresses.insert(
                                        raw_index,
                                        EphemeralAddress {
                                            address: addr,
                                            seen: None,
                                            used: None,
                                        },
                                    );
                                    (
                                        addr,
                                        TransparentAddressMetadata::derived(
                                            TransparentKeyScope::EPHEMERAL,
                                            address_index,
                                            Exposure::Unknown,
                                            None,
                                        ),
                                    )
                                })
                        })
                        .unwrap()
                        .map_err(Into::into)
                })
                .collect::<Result<Vec<_>, _>>();
        }
        Ok(Vec::new())
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn mark_ephemeral_address_as_used(
        &mut self,
        address: &TransparentAddress,
        tx_id: TxId,
    ) -> Result<(), Error> {
        // TODO: ephemeral_address_reuse_check
        for (idx, addr) in self.ephemeral_addresses.iter_mut() {
            if addr.address == *address {
                addr.mark_used(tx_id);

                // Maintain the invariant that the last `EPHEMERAL_GAP_LIMIT` addresses are used and unseen.
                let next_to_reserve = idx.checked_add(1).expect("ensured by constraint");
                self.reserve_until(next_to_reserve)?;
                return Ok(());
            }
        }
        Ok(())
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn mark_ephemeral_address_as_seen(
        &mut self,
        // txns: &TransactionTable,
        address: &TransparentAddress,
        tx_id: TxId,
    ) -> Result<(), Error> {
        for (idx, addr) in self.ephemeral_addresses.iter_mut() {
            if addr.address == *address {
                // TODO: this
                // Figure out which transaction was mined earlier: `tx_ref`, or any existing
                // tx referenced by `seen_in_tx` for the given address. Prefer the existing
                // reference in case of a tie or if both transactions are unmined.
                // This slightly reduces the chance of unnecessarily reaching the gap limit
                // too early in some corner cases (because the earlier transaction is less
                // likely to be unmined).
                //
                // The query should always return a value if `tx_ref` is valid.

                addr.mark_seen(tx_id);
                // Maintain the invariant that the last `EPHEMERAL_GAP_LIMIT` addresses are used and unseen.
                let next_to_reserve = idx.checked_add(1).expect("ensured by constraint");
                self.reserve_until(next_to_reserve)?;
                return Ok(());
            }
        }
        Ok(())
    }
}

impl zcash_client_backend::data_api::Account for Account {
    type AccountId = AccountId;

    fn id(&self) -> AccountId {
        self.account_id
    }

    fn name(&self) -> Option<&str> {
        Some(&self.account_name)
    }

    fn birthday_height(&self) -> zcash_protocol::consensus::BlockHeight {
        self.birthday().height()
    }

    fn source(&self) -> &AccountSource {
        &self.kind
    }

    fn ufvk(&self) -> Option<&UnifiedFullViewingKey> {
        Some(&self.viewing_key)
    }

    fn uivk(&self) -> UnifiedIncomingViewingKey {
        self.viewing_key.to_unified_incoming_viewing_key()
    }
}

mod serialization {
    #[cfg(feature = "orchard")]
    use incrementalmerkletree::frontier::Frontier;
    use zcash_client_backend::data_api::Zip32Derivation;
    use zcash_client_backend::data_api::chain::ChainState;
    use zcash_keys::encoding::AddressCodec;
    use zcash_primitives::block::BlockHash;
    use zcash_primitives::merkle_tree::{read_frontier_v1, write_frontier_v1};
    use zcash_protocol::consensus::Network::MainNetwork as EncodingParams;
    use zip32::fingerprint::SeedFingerprint;

    use super::*;
    use crate::proto::memwallet as proto;
    use crate::read_optional;

    impl From<Accounts> for proto::Accounts {
        fn from(accounts: Accounts) -> Self {
            Self {
                account_nonce: accounts.nonce,
                accounts: accounts
                    .accounts
                    .into_values()
                    .map(|acc| acc.into())
                    .collect(),
            }
        }
    }

    impl From<proto::Accounts> for Accounts {
        fn from(accounts: proto::Accounts) -> Self {
            Self {
                nonce: accounts.account_nonce,
                accounts: accounts
                    .accounts
                    .into_iter()
                    .map(|acc| (AccountId(acc.account_id), acc.try_into().unwrap()))
                    .collect(),
            }
        }
    }

    impl From<Account> for proto::Account {
        fn from(acc: Account) -> Self {
            Self {
                account_name: acc.account_name.clone(),
                account_id: *acc.account_id,
                kind: match acc.kind {
                    AccountSource::Derived { .. } => 0,
                    AccountSource::Imported { .. } => 1,
                },
                seed_fingerprint: match acc.kind {
                    AccountSource::Derived { ref derivation, .. } => {
                        Some(derivation.seed_fingerprint().to_bytes().to_vec())
                    }
                    AccountSource::Imported { ref purpose, .. } => match purpose {
                        AccountPurpose::Spending { derivation } => derivation
                            .as_ref()
                            .map(|d| d.seed_fingerprint().to_bytes().to_vec()),
                        AccountPurpose::ViewOnly => None,
                    },
                },
                account_index: match acc.kind {
                    AccountSource::Derived { ref derivation, .. } => {
                        Some(derivation.account_index().into())
                    }
                    AccountSource::Imported { ref purpose, .. } => match purpose {
                        AccountPurpose::Spending { derivation } => {
                            derivation.as_ref().map(|d| d.account_index().into())
                        }
                        AccountPurpose::ViewOnly => None,
                    },
                },
                purpose: match acc.kind {
                    AccountSource::Derived { .. } => None,
                    AccountSource::Imported { ref purpose, .. } => match purpose {
                        AccountPurpose::Spending { .. } => Some(0),
                        AccountPurpose::ViewOnly => Some(1),
                    },
                },
                key_source: match acc.kind {
                    AccountSource::Derived { ref key_source, .. } => key_source,
                    AccountSource::Imported { ref key_source, .. } => key_source,
                }
                .clone(),
                viewing_key: acc
                    .viewing_key
                    .encode(&EncodingParams)
                    .expect("wallet account UFVK must be encodable"),
                birthday: Some(acc.birthday().clone().try_into().unwrap()),
                addresses: acc
                    .addresses()
                    .iter()
                    .map(|(di, a)| proto::Address {
                        diversifier_index: di.as_bytes().to_vec(),
                        address: a.encode(&EncodingParams), // convention is to encode using mainnet encoding regardless of network
                    })
                    .collect(),
                #[cfg(feature = "transparent-inputs")]
                ephemeral_addresses: acc
                    .ephemeral_addresses
                    .into_iter()
                    .map(|(index, address)| proto::EphemeralAddressRecord {
                        index,
                        ephemeral_address: Some(proto::EphemeralAddress {
                            address: address.address.encode(&EncodingParams),
                            used_in_tx: address.used.map(|u| u.as_ref().to_vec()),
                            seen_in_tx: address.seen.map(|s| s.as_ref().to_vec()),
                        }),
                    })
                    .collect(),
                #[cfg(feature = "transparent-inputs")]
                internal_addresses: acc
                    .internal_addresses
                    .into_iter()
                    .map(|(index, internal)| proto::InternalAddressRecord {
                        index,
                        address: internal.address.encode(&EncodingParams),
                        exposed_at_height: internal.exposed_at_height.into(),
                    })
                    .collect(),
                #[cfg(not(feature = "transparent-inputs"))]
                ephemeral_addresses: Default::default(),
                #[cfg(not(feature = "transparent-inputs"))]
                internal_addresses: Default::default(),
                #[cfg(feature = "transparent-inputs")]
                internal_address_discovery: acc
                    .internal_address_discovery
                    .into_iter()
                    .map(|(index, candidate)| proto::InternalAddressDiscoveryRecord {
                        index,
                        address: candidate.address.encode(&EncodingParams),
                        checked_height: candidate.checked_height.map(Into::into),
                    })
                    .collect(),
                #[cfg(not(feature = "transparent-inputs"))]
                internal_address_discovery: Default::default(),
            }
        }
    }

    impl TryFrom<proto::Account> for Account {
        type Error = crate::Error;

        fn try_from(acc: proto::Account) -> Result<Self, Self::Error> {
            let viewing_key = UnifiedFullViewingKey::decode(&EncodingParams, &acc.viewing_key)
                .map_err(|e| Error::UfvkDecodeError(e.to_string()))?;
            #[cfg(feature = "transparent-inputs")]
            let internal_ivk = viewing_key
                .p2pkh()
                .map(AccountPubKey::derive_internal_ivk)
                .transpose()?;
            let account = Self {
                account_name: acc.account_name.clone(),
                account_id: acc.account_id.into(),
                kind: match acc.kind {
                    0 => AccountSource::Derived {
                        derivation: Zip32Derivation::new(
                            SeedFingerprint::from_bytes(acc.seed_fingerprint().try_into()?),
                            read_optional!(acc, account_index)?.try_into()?,
                            #[cfg(feature = "zcashd-compat")]
                            None,
                        ),
                        key_source: acc.key_source,
                    },
                    1 => AccountSource::Imported {
                        purpose: match read_optional!(acc, purpose)? {
                            0 => AccountPurpose::Spending {
                                derivation: match acc.seed_fingerprint.as_ref() {
                                    Some(seed_fingerprint) => Some(Zip32Derivation::new(
                                        SeedFingerprint::from_bytes(
                                            seed_fingerprint.as_slice().try_into()?,
                                        ),
                                        read_optional!(acc, account_index)?.try_into()?,
                                        #[cfg(feature = "zcashd-compat")]
                                        None,
                                    )),
                                    None => None,
                                },
                            },
                            1 => AccountPurpose::ViewOnly,
                            _ => unreachable!(),
                        },
                        key_source: acc.key_source,
                    },
                    _ => unreachable!(),
                },
                viewing_key,
                birthday: read_optional!(acc, birthday)?.try_into()?,
                addresses: acc
                    .addresses
                    .into_iter()
                    .map(|a| {
                        Ok((
                            DiversifierIndex::from(TryInto::<[u8; 11]>::try_into(
                                a.diversifier_index,
                            )?),
                            UnifiedAddress::decode(&EncodingParams, &a.address)
                                .map_err(|e| Error::UfvkDecodeError(e.to_string()))?,
                        ))
                    })
                    .collect::<Result<_, Error>>()?,
                #[cfg(feature = "transparent-inputs")]
                ephemeral_addresses: acc
                    .ephemeral_addresses
                    .into_iter()
                    .map(|address_record| {
                        let address = read_optional!(address_record, ephemeral_address)?;
                        Ok((
                            address_record.index,
                            EphemeralAddress {
                                address: TransparentAddress::decode(
                                    &EncodingParams,
                                    &address.address,
                                )?,
                                used: address
                                    .used_in_tx
                                    .map::<Result<_, Error>, _>(|s| {
                                        Ok(TxId::from_bytes(s.try_into()?))
                                    })
                                    .transpose()?,
                                seen: address
                                    .seen_in_tx
                                    .map::<Result<_, Error>, _>(|s| {
                                        Ok(TxId::from_bytes(s.try_into()?))
                                    })
                                    .transpose()?,
                            },
                        ))
                    })
                    .collect::<Result<_, Error>>()?,
                #[cfg(feature = "transparent-inputs")]
                internal_addresses: acc
                    .internal_addresses
                    .into_iter()
                    .map(|internal| {
                        Ok((
                            internal.index,
                            InternalAddress {
                                address: TransparentAddress::decode(
                                    &EncodingParams,
                                    &internal.address,
                                )?,
                                exposed_at_height: BlockHeight::from(internal.exposed_at_height),
                            },
                        ))
                    })
                    .collect::<Result<_, Error>>()?,
                #[cfg(not(feature = "transparent-inputs"))]
                ephemeral_addresses: Default::default(),
                #[cfg(not(feature = "transparent-inputs"))]
                internal_addresses: Default::default(),
                #[cfg(feature = "transparent-inputs")]
                internal_address_discovery: acc
                    .internal_address_discovery
                    .into_iter()
                    .enumerate()
                    .map(|(expected_index, candidate)| {
                        if usize::try_from(candidate.index)? != expected_index {
                            return Err(Error::CorruptedData(
                                "non-contiguous internal discovery indices".to_owned(),
                            ));
                        }
                        let index = NonHardenedChildIndex::from_index(candidate.index).ok_or_else(
                            || Error::CorruptedData("hardened internal discovery index".to_owned()),
                        )?;
                        let address =
                            TransparentAddress::decode(&EncodingParams, &candidate.address)?;
                        let expected = internal_ivk
                            .as_ref()
                            .ok_or_else(|| {
                                Error::CorruptedData(
                                    "internal discovery without transparent viewing key".to_owned(),
                                )
                            })?
                            .derive_address(index)?;
                        if address != expected {
                            return Err(Error::CorruptedData(
                                "internal discovery address does not match its derivation"
                                    .to_owned(),
                            ));
                        }
                        Ok((
                            candidate.index,
                            InternalAddressDiscovery {
                                address,
                                checked_height: candidate.checked_height.map(BlockHeight::from),
                            },
                        ))
                    })
                    .collect::<Result<_, Error>>()?,
                #[cfg(not(feature = "transparent-inputs"))]
                internal_address_discovery: Default::default(),
                _notes: Default::default(),
            };
            // Older snapshots have no discovery records. Restore the initial
            // window without treating candidates as allocated change addresses.
            #[cfg(feature = "transparent-inputs")]
            let account = {
                let mut account = account;
                account.ensure_internal_gap(0)?;
                account
            };
            Ok(account)
        }
    }

    impl TryFrom<AccountBirthday> for proto::AccountBirthday {
        type Error = crate::Error;
        fn try_from(birthday: AccountBirthday) -> Result<Self, Self::Error> {
            let cstate = birthday.prior_chain_state();

            let mut sapling_tree_bytes = vec![];
            write_frontier_v1(&mut sapling_tree_bytes, cstate.final_sapling_tree())?;

            #[cfg(feature = "orchard")]
            let orchard_tree_bytes = {
                let mut orchard_tree_bytes = vec![];
                write_frontier_v1(&mut orchard_tree_bytes, cstate.final_orchard_tree())?;
                orchard_tree_bytes
            };
            #[cfg(not(feature = "orchard"))]
            let orchard_tree_bytes = vec![];
            #[cfg(feature = "orchard")]
            let ironwood_tree_bytes = {
                let mut ironwood_tree_bytes = vec![];
                write_frontier_v1(&mut ironwood_tree_bytes, cstate.final_ironwood_tree())?;
                ironwood_tree_bytes
            };
            #[cfg(not(feature = "orchard"))]
            let ironwood_tree_bytes = vec![];

            Ok(Self {
                prior_chain_state: Some(proto::ChainState {
                    block_height: cstate.block_height().into(),
                    block_hash: cstate.block_hash().0.to_vec(),
                    final_sapling_tree: sapling_tree_bytes,
                    final_orchard_tree: orchard_tree_bytes,
                    final_ironwood_tree: ironwood_tree_bytes,
                }),
                recover_until: birthday.recover_until().map(|r| r.into()),
            })
        }
    }

    impl TryFrom<proto::AccountBirthday> for AccountBirthday {
        type Error = crate::Error;
        fn try_from(birthday: proto::AccountBirthday) -> Result<Self, Self::Error> {
            let cs = read_optional!(birthday, prior_chain_state)?;

            let cstate = ChainState::new(
                cs.block_height.into(),
                BlockHash::from_slice(&cs.block_hash),
                read_frontier_v1(&cs.final_sapling_tree[..])?,
                #[cfg(feature = "orchard")]
                read_frontier_v1(&cs.final_orchard_tree[..])?,
                #[cfg(feature = "orchard")]
                if cs.final_ironwood_tree.is_empty() {
                    Frontier::empty()
                } else {
                    read_frontier_v1(&cs.final_ironwood_tree[..])?
                },
            );

            let recover_until = birthday.recover_until.map(|r| r.into());

            Ok(Self::from_parts(cstate, recover_until))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::proto::memwallet as proto;
        use zcash_primitives::block::BlockHash;

        const TEST_VK: &str = "uview1tg6rpjgju2s2j37gkgjq79qrh5lvzr6e0ed3n4sf4hu5qd35vmsh7avl80xa6mx7ryqce9hztwaqwrdthetpy4pc0kce25x453hwcmax02p80pg5savlg865sft9reat07c5vlactr6l2pxtlqtqunt2j9gmvr8spcuzf07af80h5qmut38h0gvcfa9k4rwujacwwca9vu8jev7wq6c725huv8qjmhss3hdj2vh8cfxhpqcm2qzc34msyrfxk5u6dqttt4vv2mr0aajreww5yufpk0gn4xkfm888467k7v6fmw7syqq6cceu078yw8xja502jxr0jgum43lhvpzmf7eu5dmnn6cr6f7p43yw8znzgxg598mllewnx076hljlvynhzwn5es94yrv65tdg3utuz2u3sras0wfcq4adxwdvlk387d22g3q98t5z74quw2fa4wed32escx8dwh4mw35t4jwf35xyfxnu83mk5s4kw2glkgsshmxk";

        #[test]
        fn test_account_serialization_roundtrip() {
            let mut acc = Account::new(
                "test_account_name".to_string(),
                AccountId(0),
                AccountSource::Imported {
                    purpose: AccountPurpose::Spending { derivation: None },
                    key_source: Some("test_key_source".to_string()),
                },
                UnifiedFullViewingKey::decode(&EncodingParams, TEST_VK).unwrap(),
                AccountBirthday::from_sapling_activation(
                    &EncodingParams,
                    BlockHash::from_slice(&[0; 32]),
                ),
            )
            .unwrap();

            #[cfg(feature = "transparent-inputs")]
            acc.reserve_internal_addresses(0, 1, BlockHeight::from(123), 0)
                .unwrap();

            let proto_acc: proto::Account = acc.clone().into();
            let acc2: Account = proto_acc.clone().try_into().unwrap();
            let proto_acc2: proto::Account = acc2.clone().into();

            assert_eq!(proto_acc, proto_acc2);

            let mut legacy_proto = proto_acc2;
            legacy_proto.internal_addresses.clear();
            let legacy_acc: Account = legacy_proto.try_into().unwrap();
            assert!(legacy_acc.internal_addresses.is_empty());
        }
    }
}
