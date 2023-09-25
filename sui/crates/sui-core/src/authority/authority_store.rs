// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::authority_notify_read::NotifyRead;
use super::{authority_store_tables::AuthorityPerpetualTables, *};
use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use either::Either;
use move_core_types::resolver::ModuleResolver;
use once_cell::sync::OnceCell;
use rocksdb::Options;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::iter;
use std::path::Path;
use std::sync::Arc;
use sui_storage::mutex_table::{LockGuard, MutexTable};
use sui_types::accumulator::Accumulator;
use sui_types::digests::TransactionEventsDigest;
use sui_types::error::UserInputError;
use sui_types::message_envelope::Message;
use sui_types::object::Owner;
use sui_types::storage::{
    BackingPackageStore, ChildObjectResolver, DeleteKind, ObjectKey, ObjectStore,
};
use sui_types::sui_system_state::get_sui_system_state;
use sui_types::{base_types::SequenceNumber, fp_bail, fp_ensure, storage::ParentSync};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{debug, info, trace};
use typed_store::rocks::{DBBatch, TypedStoreError};
use typed_store::traits::Map;

const NUM_SHARDS: usize = 4096;
const SHARD_SIZE: usize = 128;

/// ALL_OBJ_VER determines whether we want to store all past
/// versions of every object in the store. Authority doesn't store
/// them, but other entities such as replicas will.
/// S is a template on Authority signature state. This allows SuiDataStore to be used on either
/// authorities or non-authorities. Specifically, when storing transactions and effects,
/// S allows SuiDataStore to either store the authority signed version or unsigned version.
pub struct AuthorityStore {
    /// Internal vector of locks to manage concurrent writes to the database
    mutex_table: MutexTable<ObjectDigest>,

    pub(crate) perpetual_tables: Arc<AuthorityPerpetualTables>,

    // Implementation detail to support notify_read_effects().
    pub(crate) executed_effects_notify_read: NotifyRead<TransactionDigest, TransactionEffects>,

    pub(crate) root_state_notify_read: NotifyRead<EpochId, (CheckpointSequenceNumber, Accumulator)>,
    /// This lock denotes current 'execution epoch'.
    /// Execution acquires read lock, checks certificate epoch and holds it until all writes are complete.
    /// Reconfiguration acquires write lock, changes the epoch and revert all transactions
    /// from previous epoch that are executed but did not make into checkpoint.
    execution_lock: RwLock<EpochId>,
}

pub type ExecutionLockReadGuard<'a> = RwLockReadGuard<'a, EpochId>;
pub type ExecutionLockWriteGuard<'a> = RwLockWriteGuard<'a, EpochId>;

impl AuthorityStore {
    /// Open an authority store by directory path.
    /// If the store is empty, initialize it using genesis.
    pub async fn open(
        path: &Path,
        db_options: Option<Options>,
        genesis: &Genesis,
        committee_store: &Arc<CommitteeStore>,
    ) -> SuiResult<Self> {
        let perpetual_tables = Arc::new(AuthorityPerpetualTables::open(path, db_options.clone()));
        if perpetual_tables.database_is_empty()? {
            perpetual_tables.set_recovery_epoch(0)?;
        }
        let cur_epoch = perpetual_tables.get_recovery_epoch_at_restart()?;
        let committee = committee_store
            .get_committee(&cur_epoch)?
            .expect("Committee of the current epoch must exist");
        Self::open_inner(genesis, perpetual_tables, committee).await
    }

    pub async fn open_with_committee_for_testing(
        path: &Path,
        db_options: Option<Options>,
        committee: &Committee,
        genesis: &Genesis,
    ) -> SuiResult<Self> {
        // TODO: Since we always start at genesis, the committee should be technically the same
        // as the genesis committee.
        assert_eq!(committee.epoch, 0);
        let perpetual_tables = Arc::new(AuthorityPerpetualTables::open(path, db_options.clone()));
        Self::open_inner(genesis, perpetual_tables, committee.clone()).await
    }

    async fn open_inner(
        genesis: &Genesis,
        perpetual_tables: Arc<AuthorityPerpetualTables>,
        committee: Committee,
    ) -> SuiResult<Self> {
        let epoch = committee.epoch;

        let store = Self {
            mutex_table: MutexTable::new(NUM_SHARDS, SHARD_SIZE),
            perpetual_tables,
            executed_effects_notify_read: NotifyRead::new(),
            root_state_notify_read:
                NotifyRead::<EpochId, (CheckpointSequenceNumber, Accumulator)>::new(),
            execution_lock: RwLock::new(epoch),
        };
        // Only initialize an empty database.
        if store
            .database_is_empty()
            .expect("Database read should not fail at init.")
        {
            store
                .bulk_object_insert(&genesis.objects().iter().collect::<Vec<_>>())
                .await
                .expect("Cannot bulk insert genesis objects");

            // insert txn and effects of genesis
            let transaction = VerifiedTransaction::new_unchecked(genesis.transaction().clone());

            store
                .perpetual_tables
                .transactions
                .insert(transaction.digest(), transaction.serializable_ref())
                .unwrap();

            store
                .perpetual_tables
                .effects
                .insert(&genesis.effects().digest(), genesis.effects())
                .unwrap();
            // We don't insert the effects to executed_effects yet because the genesis tx hasn't but will be executed.
            // This is important for fullnodes to be able to generate indexing data right now.

            store
                .perpetual_tables
                .events
                .insert(&genesis.events().digest(), genesis.events())
                .unwrap();
        }

        Ok(store)
    }

    pub fn get_recovery_epoch_at_restart(&self) -> SuiResult<EpochId> {
        self.perpetual_tables.get_recovery_epoch_at_restart()
    }

    pub fn get_effects(
        &self,
        effects_digest: &TransactionEffectsDigest,
    ) -> SuiResult<Option<TransactionEffects>> {
        Ok(self.perpetual_tables.effects.get(effects_digest)?)
    }

    /// Returns true if we have an effects structure for this transaction digest
    pub fn effects_exists(&self, effects_digest: &TransactionEffectsDigest) -> SuiResult<bool> {
        self.perpetual_tables
            .effects
            .contains_key(effects_digest)
            .map_err(|e| e.into())
    }

    pub(crate) fn get_events(
        &self,
        event_digest: &TransactionEventsDigest,
    ) -> SuiResult<TransactionEvents> {
        self.perpetual_tables
            .events
            .get(event_digest)?
            .ok_or(SuiError::TransactionEventsNotFound {
                digest: *event_digest,
            })
    }

    pub fn multi_get_effects<'a>(
        &self,
        effects_digests: impl Iterator<Item = &'a TransactionEffectsDigest>,
    ) -> SuiResult<Vec<Option<TransactionEffects>>> {
        Ok(self.perpetual_tables.effects.multi_get(effects_digests)?)
    }

    pub fn get_executed_effects(
        &self,
        tx_digest: &TransactionDigest,
    ) -> SuiResult<Option<TransactionEffects>> {
        let effects_digest = self.perpetual_tables.executed_effects.get(tx_digest)?;
        match effects_digest {
            Some(digest) => Ok(self.perpetual_tables.effects.get(&digest)?),
            None => Ok(None),
        }
    }

    /// Given a list of transaction digests, returns a list of the corresponding effects only if they have been
    /// executed. For transactions that have not been executed, None is returned.
    pub fn multi_get_executed_effects(
        &self,
        digests: &[TransactionDigest],
    ) -> SuiResult<Vec<Option<TransactionEffects>>> {
        let executed_effects_digests = self.perpetual_tables.executed_effects.multi_get(digests)?;
        let effects = self.multi_get_effects(executed_effects_digests.iter().flatten())?;
        let mut tx_to_effects_map = effects
            .into_iter()
            .flatten()
            .map(|effects| (effects.transaction_digest, effects))
            .collect::<HashMap<_, _>>();
        Ok(digests
            .iter()
            .map(|digest| tx_to_effects_map.remove(digest))
            .collect())
    }

    pub fn is_tx_already_executed(&self, digest: &TransactionDigest) -> SuiResult<bool> {
        Ok(self
            .perpetual_tables
            .executed_effects
            .contains_key(digest)?)
    }

    /// Returns future containing the state hash for the given epoch
    /// once available
    pub async fn notify_read_root_state_hash(
        &self,
        epoch: EpochId,
    ) -> SuiResult<(CheckpointSequenceNumber, Accumulator)> {
        // We need to register waiters _before_ reading from the database to avoid race conditions
        let registration = self.root_state_notify_read.register_one(&epoch);
        let hash = self.perpetual_tables.root_state_hash_by_epoch.get(&epoch)?;

        let result = match hash {
            // Note that Some() clause also drops registration that is already fulfilled
            Some(ready) => Either::Left(futures::future::ready(ready)),
            None => Either::Right(registration),
        }
        .await;

        Ok(result)
    }

    pub fn insert_finalized_transactions(
        &self,
        digests: &[TransactionDigest],
        epoch: EpochId,
        sequence: CheckpointSequenceNumber,
    ) -> SuiResult {
        let batch = self
            .perpetual_tables
            .executed_transactions_to_checkpoint
            .batch();
        let batch = batch.insert_batch(
            &self.perpetual_tables.executed_transactions_to_checkpoint,
            digests.iter().map(|d| (*d, (epoch, sequence))),
        )?;
        batch.write()?;
        debug!("Transactions {digests:?} finalized at checkpoint {sequence} epoch {epoch}");
        Ok(())
    }

    pub fn is_transaction_executed_in_checkpoint(
        &self,
        digest: &TransactionDigest,
    ) -> SuiResult<bool> {
        Ok(self
            .perpetual_tables
            .executed_transactions_to_checkpoint
            .contains_key(digest)?)
    }

    pub fn get_transaction_checkpoint(
        &self,
        digest: &TransactionDigest,
    ) -> SuiResult<Option<(EpochId, CheckpointSequenceNumber)>> {
        Ok(self
            .perpetual_tables
            .executed_transactions_to_checkpoint
            .get(digest)?)
    }

    /// Returns true if there are no objects in the database
    pub fn database_is_empty(&self) -> SuiResult<bool> {
        self.perpetual_tables.database_is_empty()
    }

    /// A function that acquires all locks associated with the objects (in order to avoid deadlocks).
    async fn acquire_locks(&self, input_objects: &[ObjectRef]) -> Vec<LockGuard> {
        self.mutex_table
            .acquire_locks(input_objects.iter().map(|(_, _, digest)| *digest))
            .await
    }

    pub fn get_object_by_key(
        &self,
        object_id: &ObjectID,
        version: VersionNumber,
    ) -> Result<Option<Object>, SuiError> {
        Ok(self
            .perpetual_tables
            .objects
            .get(&ObjectKey(*object_id, version))?)
    }

    /// Read an object and return it, or Ok(None) if the object was not found.
    pub fn get_object(&self, object_id: &ObjectID) -> Result<Option<Object>, SuiError> {
        self.perpetual_tables.as_ref().get_object(object_id)
    }

    /// Get many objects
    pub fn get_objects(&self, objects: &[ObjectID]) -> Result<Vec<Option<Object>>, SuiError> {
        let mut result = Vec::new();
        for id in objects {
            result.push(self.get_object(id)?);
        }
        Ok(result)
    }

    pub fn check_input_objects(
        &self,
        objects: &[InputObjectKind],
    ) -> Result<Vec<Object>, SuiError> {
        let mut result = Vec::new();
        for kind in objects {
            let obj = match kind {
                InputObjectKind::MovePackage(id) | InputObjectKind::SharedMoveObject { id, .. } => {
                    self.get_object(id)?
                }
                InputObjectKind::ImmOrOwnedMoveObject(objref) => {
                    self.get_object_by_key(&objref.0, objref.1)?
                }
            }
            .ok_or_else(|| SuiError::from(kind.object_not_found_error()))?;
            result.push(obj);
        }
        Ok(result)
    }

    /// Gets the input object keys from input object kinds, by determining the versions of owned,
    /// shared and package objects.
    /// When making changes, please see if check_sequenced_input_objects() below needs
    /// similar changes as well.
    pub fn get_input_object_keys(
        &self,
        digest: &TransactionDigest,
        objects: &[InputObjectKind],
        epoch_store: &AuthorityPerEpochStore,
    ) -> Vec<InputKey> {
        let mut shared_locks = HashMap::<ObjectID, SequenceNumber>::new();
        objects
            .iter()
            .map(|kind| {
                match kind {
                    InputObjectKind::SharedMoveObject { id, .. } => {
                        if shared_locks.is_empty() {
                            shared_locks = epoch_store
                                .get_shared_locks(digest)
                                .expect("Read from storage should not fail!")
                                .into_iter()
                                .collect();
                        }
                        // If we can't find the locked version, it means
                        // 1. either we have a bug that skips shared object version assignment
                        // 2. or we have some DB corruption
                        let Some(version) = shared_locks.get(id) else {
                            panic!(
                                "Shared object locks should have been set. tx_digset: {digest:?}, obj \
                                id: {id:?}",
                            )
                        };
                        InputKey(*id, Some(*version))
                    }
                    InputObjectKind::MovePackage(id) => InputKey(*id, None),
                    InputObjectKind::ImmOrOwnedMoveObject(objref) => InputKey(objref.0, Some(objref.1))
                }
            })
            .collect()
    }

    /// Checks if the input object identified by the InputKey exists, with support for non-system
    /// packages i.e. when version is None.
    pub fn input_object_exists(&self, key: &InputKey) -> Result<bool, SuiError> {
        match key.1 {
            Some(version) => Ok(self
                .perpetual_tables
                .objects
                .contains_key(&ObjectKey(key.0, version))?),
            None => match self.get_latest_parent_entry(key.0)? {
                None => Ok(false),
                Some(entry) => Ok(entry.0 .2.is_alive()),
            },
        }
    }

    /// Attempts to acquire execution lock for an executable transaction.
    /// Returns the lock if the transaction is matching current executed epoch
    /// Returns None otherwise
    pub async fn execution_lock_for_executable_transaction(
        &self,
        transaction: &VerifiedExecutableTransaction,
    ) -> SuiResult<ExecutionLockReadGuard> {
        let lock = self.execution_lock.read().await;
        if *lock == transaction.auth_sig().epoch() {
            Ok(lock)
        } else {
            Err(SuiError::WrongEpoch {
                expected_epoch: *lock,
                actual_epoch: transaction.auth_sig().epoch(),
            })
        }
    }

    pub async fn execution_lock_for_reconfiguration(&self) -> ExecutionLockWriteGuard {
        self.execution_lock.write().await
    }

    /// When making changes, please see if get_input_object_keys() above needs
    /// similar changes as well.
    ///
    /// Before this function is invoked, TransactionManager must ensure all depended
    /// objects are present. Thus any missing object will panic.
    pub fn check_sequenced_input_objects(
        &self,
        digest: &TransactionDigest,
        objects: &[InputObjectKind],
        epoch_store: &AuthorityPerEpochStore,
    ) -> Result<Vec<Object>, SuiError> {
        let shared_locks_cell: OnceCell<HashMap<_, _>> = OnceCell::new();

        let mut result = Vec::new();
        for kind in objects {
            let obj = match kind {
                InputObjectKind::SharedMoveObject { id, .. } => {
                    let shared_locks = shared_locks_cell.get_or_try_init(|| {
                        Ok::<HashMap<ObjectID, SequenceNumber>, SuiError>(
                            epoch_store.get_shared_locks(digest)?.into_iter().collect(),
                        )
                    })?;
                    // If we can't find the locked version, it means
                    // 1. either we have a bug that skips shared object version assignment
                    // 2. or we have some DB corruption
                    let version = shared_locks.get(id).unwrap_or_else(|| {
                        panic!(
                        "Shared object locks should have been set. tx_digset: {:?}, obj id: {:?}",
                        digest, id
                    )
                    });
                    self.get_object_by_key(id, *version)?.unwrap_or_else(|| {
                        panic!("All dependencies of tx {:?} should have been executed now, but Shared Object id: {}, version: {} is absent", digest, *id, *version);
                    })
                }
                InputObjectKind::MovePackage(id) => self.get_object(id)?.unwrap_or_else(|| {
                    panic!("All dependencies of tx {:?} should have been executed now, but Move Package id: {} is absent", digest, id);
                }),
                InputObjectKind::ImmOrOwnedMoveObject(objref) => {
                    self.get_object_by_key(&objref.0, objref.1)?.unwrap_or_else(|| {
                        panic!("All dependencies of tx {:?} should have been executed now, but Immutable or Owned Object id: {}, version: {} is absent", digest, objref.0, objref.1);
                    })
                }
            };
            result.push(obj);
        }
        Ok(result)
    }

    /// Read the transactionDigest that is the parent of an object reference
    /// (ie. the transaction that created an object at this version.)
    pub fn parent(&self, object_ref: &ObjectRef) -> Result<Option<TransactionDigest>, SuiError> {
        self.perpetual_tables
            .parent_sync
            .get(object_ref)
            .map_err(|e| e.into())
    }

    /// Batch version of `parent` function.
    pub fn multi_get_parents(
        &self,
        object_refs: &[ObjectRef],
    ) -> Result<Vec<Option<TransactionDigest>>, SuiError> {
        self.perpetual_tables
            .parent_sync
            .multi_get(object_refs)
            .map_err(|e| e.into())
    }

    /// Returns all parents (object_ref and transaction digests) that match an object_id, at
    /// any object version, or optionally at a specific version.
    pub fn get_parent_iterator(
        &self,
        object_id: ObjectID,
        seq: Option<SequenceNumber>,
    ) -> Result<impl Iterator<Item = (ObjectRef, TransactionDigest)> + '_, SuiError> {
        let seq_inner = seq.unwrap_or_else(|| SequenceNumber::from(0));
        let obj_dig_inner = ObjectDigest::new([0; 32]);

        Ok(self
            .perpetual_tables
            .parent_sync
            .iter()
            // The object id [0; 16] is the smallest possible
            .skip_to(&(object_id, seq_inner, obj_dig_inner))?
            .take_while(move |((id, iseq, _digest), _txd)| {
                let mut flag = id == &object_id;
                if let Some(seq_num) = seq {
                    flag &= seq_num == *iseq;
                }
                flag
            }))
    }

    // Methods to mutate the store

    /// Insert a genesis object.
    pub async fn insert_genesis_object(&self, object: Object) -> SuiResult {
        // We only side load objects with a genesis parent transaction.
        debug_assert!(object.previous_transaction == TransactionDigest::genesis());
        let object_ref = object.compute_object_reference();
        self.insert_object_direct(object_ref, &object).await
    }

    /// Insert an object directly into the store, and also update relevant tables
    /// NOTE: does not handle transaction lock.
    /// This is used to insert genesis objects
    async fn insert_object_direct(&self, object_ref: ObjectRef, object: &Object) -> SuiResult {
        let mut write_batch = self.perpetual_tables.objects.batch();

        // Insert object
        write_batch = write_batch.insert_batch(
            &self.perpetual_tables.objects,
            std::iter::once((ObjectKey::from(object_ref), object)),
        )?;

        // Update the index
        if object.get_single_owner().is_some() {
            // Only initialize lock for address owned objects.
            if !object.is_child_object() {
                write_batch = self.initialize_locks_impl(write_batch, &[object_ref], false)?;
            }
        }

        // Update the parent
        write_batch = write_batch.insert_batch(
            &self.perpetual_tables.parent_sync,
            std::iter::once((&object_ref, &object.previous_transaction)),
        )?;

        write_batch.write()?;

        Ok(())
    }

    /// This function should only be used for initializing genesis and should remain private.
    async fn bulk_object_insert(&self, objects: &[&Object]) -> SuiResult<()> {
        let mut batch = self.perpetual_tables.objects.batch();
        let ref_and_objects: Vec<_> = objects
            .iter()
            .map(|o| (o.compute_object_reference(), o))
            .collect();

        batch = batch
            .insert_batch(
                &self.perpetual_tables.objects,
                ref_and_objects
                    .iter()
                    .map(|(oref, o)| (ObjectKey::from(oref), **o)),
            )?
            .insert_batch(
                &self.perpetual_tables.parent_sync,
                ref_and_objects
                    .iter()
                    .map(|(oref, o)| (oref, o.previous_transaction)),
            )?;

        let non_child_object_refs: Vec<_> = ref_and_objects
            .iter()
            .filter(|(_, object)| !object.is_child_object())
            .map(|(oref, _)| *oref)
            .collect();

        batch = self.initialize_locks_impl(
            batch,
            &non_child_object_refs,
            false, // is_force_reset
        )?;

        batch.write()?;

        Ok(())
    }

    /// Updates the state resulting from the execution of a certificate.
    ///
    /// Internally it checks that all locks for active inputs are at the correct
    /// version, and then writes objects, certificates, parents and clean up locks atomically.
    pub async fn update_state(
        &self,
        inner_temporary_store: InnerTemporaryStore,
        transaction: &VerifiedTransaction,
        effects: &TransactionEffects,
    ) -> SuiResult {
        // Extract the new state from the execution
        // TODO: events are already stored in the TxDigest -> TransactionEffects store. Is that enough?
        let mut write_batch = self.perpetual_tables.transactions.batch();

        // Store the certificate indexed by transaction digest
        let transaction_digest = transaction.digest();
        write_batch = write_batch.insert_batch(
            &self.perpetual_tables.transactions,
            iter::once((transaction_digest, transaction.serializable_ref())),
        )?;

        // Add batched writes for objects and locks.
        let effects_digest = effects.digest();
        write_batch = self
            .update_objects_and_locks(
                write_batch,
                inner_temporary_store,
                *transaction_digest,
                UpdateType::Transaction(effects_digest),
            )
            .await?;

        // Store the signed effects of the transaction
        // We can't write this until after sequencing succeeds (which happens in
        // batch_update_objects), as effects_exists is used as a check in many places
        // for "did the tx finish".
        write_batch = write_batch
            .insert_batch(&self.perpetual_tables.effects, [(effects_digest, effects)])?
            .insert_batch(
                &self.perpetual_tables.executed_effects,
                [(transaction_digest, effects_digest)],
            )?;

        // Commit.
        write_batch.write()?;

        self.executed_effects_notify_read
            .notify(transaction_digest, effects);

        Ok(())
    }

    /// Helper function for updating the objects and locks in the state
    async fn update_objects_and_locks(
        &self,
        mut write_batch: DBBatch,
        inner_temporary_store: InnerTemporaryStore,
        transaction_digest: TransactionDigest,
        update_type: UpdateType,
    ) -> SuiResult<DBBatch> {
        let InnerTemporaryStore {
            objects,
            mutable_inputs: active_inputs,
            written,
            deleted,
            events,
        } = inner_temporary_store;
        trace!(written =? written.values().map(|((obj_id, ver, _), _, _)| (obj_id, ver)).collect::<Vec<_>>(),
               "batch_update_objects: temp store written");

        let owned_inputs: Vec<_> = active_inputs
            .iter()
            .filter(|(id, _, _)| objects.get(id).unwrap().is_address_owned())
            .cloned()
            .collect();

        // Index the certificate by the objects mutated
        write_batch = write_batch.insert_batch(
            &self.perpetual_tables.parent_sync,
            written
                .iter()
                .map(|(_, (object_ref, _object, _kind))| (object_ref, transaction_digest)),
        )?;

        // Index the certificate by the objects deleted
        write_batch = write_batch.insert_batch(
            &self.perpetual_tables.parent_sync,
            deleted.iter().map(|(object_id, (version, kind))| {
                (
                    (
                        *object_id,
                        *version,
                        if kind == &DeleteKind::Wrap {
                            ObjectDigest::OBJECT_DIGEST_WRAPPED
                        } else {
                            ObjectDigest::OBJECT_DIGEST_DELETED
                        },
                    ),
                    transaction_digest,
                )
            }),
        )?;

        // Insert each output object into the stores
        write_batch = write_batch.insert_batch(
            &self.perpetual_tables.objects,
            written.iter().map(|(_, (obj_ref, new_object, _kind))| {
                debug!(?obj_ref, "writing object");
                (ObjectKey::from(obj_ref), new_object)
            }),
        )?;

        write_batch =
            write_batch.insert_batch(&self.perpetual_tables.events, [(events.digest(), events)])?;

        let new_locks_to_init: Vec<_> = written
            .iter()
            .filter_map(|(_, (object_ref, new_object, _kind))| {
                if new_object.is_address_owned() {
                    Some(*object_ref)
                } else {
                    None
                }
            })
            .collect();

        if let UpdateType::Transaction(_) = update_type {
            // NOTE: We just check here that locks exist, not that they are locked to a specific TX. Why?
            // 1. Lock existence prevents re-execution of old certs when objects have been upgraded
            // 2. Not all validators lock, just 2f+1, so transaction should proceed regardless
            //    (But the lock should exist which means previous transactions finished)
            // 3. Equivocation possible (different TX) but as long as 2f+1 approves current TX its
            //    fine
            // 4. Locks may have existed when we started processing this tx, but could have since
            //    been deleted by a concurrent tx that finished first. In that case, check if the
            //    tx effects exist.
            self.check_owned_object_locks_exist(&owned_inputs)?;
        }

        write_batch = self.initialize_locks_impl(write_batch, &new_locks_to_init, false)?;
        self.delete_locks(write_batch, &owned_inputs)
    }

    /// Acquires a lock for a transaction on the given objects if they have all been initialized previously
    /// to None state.  It is also OK if they have been set to the same transaction.
    /// The locks are all set to the given transaction digest.
    /// Returns UserInputError::ObjectNotFound if no lock record can be found for one of the objects.
    /// Returns UserInputError::ObjectVersionUnavailableForConsumption if one of the objects is not locked at the given version.
    /// Returns SuiError::ObjectLockConflict if one of the objects is locked by a different transaction in the same epoch.
    /// Returns SuiError::ObjectLockedAtFutureEpoch if one of the objects is locked in a future epoch (bug).
    pub(crate) async fn acquire_transaction_locks(
        &self,
        epoch: EpochId,
        owned_input_objects: &[ObjectRef],
        tx_digest: TransactionDigest,
    ) -> SuiResult {
        // Other writers may be attempting to acquire locks on the same objects, so a mutex is
        // required.
        // TODO: replace with optimistic transactions (i.e. set lock to tx if none)
        let _mutexes = self.acquire_locks(owned_input_objects).await;

        debug!(?owned_input_objects, "acquire_locks");
        let mut locks_to_write = Vec::new();

        let locks = self
            .perpetual_tables
            .owned_object_transaction_locks
            .multi_get(owned_input_objects)?;

        for ((i, lock), obj_ref) in locks.iter().enumerate().zip(owned_input_objects) {
            // The object / version must exist, and therefore lock initialized.
            let lock = lock.as_ref();
            if lock.is_none() {
                let latest_lock = self.get_latest_lock_for_object_id(obj_ref.0)?;
                fp_bail!(UserInputError::ObjectVersionUnavailableForConsumption {
                    provided_obj_ref: *obj_ref,
                    current_version: latest_lock.1
                }
                .into());
            }
            // Safe to unwrap as it is checked above
            let lock = lock.unwrap();

            if let Some(LockDetails {
                epoch: previous_epoch,
                tx_digest: previous_tx_digest,
            }) = lock
            {
                fp_ensure!(
                    &epoch >= previous_epoch,
                    SuiError::ObjectLockedAtFutureEpoch {
                        obj_refs: owned_input_objects.to_vec(),
                        locked_epoch: *previous_epoch,
                        new_epoch: epoch,
                        locked_by_tx: *previous_tx_digest,
                    }
                );
                // Lock already set to different transaction from the same epoch.
                // If the lock is set in a previous epoch, it's ok to override it.
                if previous_epoch == &epoch && previous_tx_digest != &tx_digest {
                    // TODO: add metrics here
                    debug!(prev_tx_digest =? previous_tx_digest,
                          cur_tx_digest =? tx_digest,
                          "Cannot acquire lock: conflicting transaction!");
                    return Err(SuiError::ObjectLockConflict {
                        obj_ref: *obj_ref,
                        pending_transaction: *previous_tx_digest,
                    });
                }
                if &epoch == previous_epoch {
                    // Exactly the same epoch and same transaction, nothing to lock here.
                    continue;
                } else {
                    debug!(prev_epoch =? previous_epoch, cur_epoch =? epoch, "Overriding an old lock from previous epoch");
                    // Fall through and override the old lock.
                }
            }
            let obj_ref = owned_input_objects[i];
            locks_to_write.push((obj_ref, Some(LockDetails { epoch, tx_digest })));
        }

        if !locks_to_write.is_empty() {
            trace!(?locks_to_write, "Writing locks");
            self.perpetual_tables
                .owned_object_transaction_locks
                .batch()
                .insert_batch(
                    &self.perpetual_tables.owned_object_transaction_locks,
                    locks_to_write,
                )?
                .write()?;
        }

        Ok(())
    }

    /// Gets ObjectLockInfo that represents state of lock on an object.
    /// Returns UserInputError::ObjectNotFound if cannot find lock record for this object
    pub(crate) fn get_lock(&self, obj_ref: ObjectRef, epoch_id: EpochId) -> SuiLockResult {
        Ok(
            if let Some(lock_info) = self
                .perpetual_tables
                .owned_object_transaction_locks
                .get(&obj_ref)
                .map_err(SuiError::StorageError)?
            {
                match lock_info {
                    Some(lock_info) => {
                        match Ord::cmp(&lock_info.epoch, &epoch_id) {
                            // If the object was locked in a previous epoch, we can say that it's
                            // no longer locked and is considered as just Initialized.
                            Ordering::Less => ObjectLockStatus::Initialized,
                            Ordering::Equal => ObjectLockStatus::LockedToTx {
                                locked_by_tx: lock_info,
                            },
                            Ordering::Greater => {
                                return Err(SuiError::ObjectLockedAtFutureEpoch {
                                    obj_refs: vec![obj_ref],
                                    locked_epoch: lock_info.epoch,
                                    new_epoch: epoch_id,
                                    locked_by_tx: lock_info.tx_digest,
                                });
                            }
                        }
                    }
                    None => ObjectLockStatus::Initialized,
                }
            } else {
                ObjectLockStatus::LockedAtDifferentVersion {
                    locked_ref: self.get_latest_lock_for_object_id(obj_ref.0)?,
                }
            },
        )
    }

    /// Returns UserInputError::ObjectNotFound if no lock records found for this object.
    fn get_latest_lock_for_object_id(&self, object_id: ObjectID) -> SuiResult<ObjectRef> {
        let mut iterator = self
            .perpetual_tables
            .owned_object_transaction_locks
            .iter()
            // Make the max possible entry for this object ID.
            .skip_prior_to(&(object_id, SequenceNumber::MAX, ObjectDigest::MAX))?;
        Ok(iterator
            .next()
            .and_then(|value| {
                if value.0 .0 == object_id {
                    Some(value)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                SuiError::from(UserInputError::ObjectNotFound {
                    object_id,
                    version: None,
                })
            })?
            .0)
    }

    /// Checks multiple object locks exist.
    /// Returns UserInputError::ObjectNotFound if cannot find lock record for at least one of the objects.
    /// Returns UserInputError::ObjectVersionUnavailableForConsumption if at least one object lock is not initialized
    ///     at the given version.
    pub fn check_owned_object_locks_exist(&self, objects: &[ObjectRef]) -> SuiResult {
        let locks = self
            .perpetual_tables
            .owned_object_transaction_locks
            .multi_get(objects)?;
        for (lock, obj_ref) in locks.into_iter().zip(objects) {
            if lock.is_none() {
                let latest_lock = self.get_latest_lock_for_object_id(obj_ref.0)?;
                fp_bail!(UserInputError::ObjectVersionUnavailableForConsumption {
                    provided_obj_ref: *obj_ref,
                    current_version: latest_lock.1
                }
                .into());
            }
        }
        Ok(())
    }

    /// Initialize a lock to None (but exists) for a given list of ObjectRefs.
    /// Returns SuiError::ObjectLockAlreadyInitialized if the lock already exists and is locked to a transaction
    fn initialize_locks_impl(
        &self,
        write_batch: DBBatch,
        objects: &[ObjectRef],
        is_force_reset: bool,
    ) -> SuiResult<DBBatch> {
        debug!(?objects, "initialize_locks");

        let locks = self
            .perpetual_tables
            .owned_object_transaction_locks
            .multi_get(objects)?;

        if !is_force_reset {
            // If any locks exist and are not None, return errors for them
            let existing_locks: Vec<ObjectRef> = locks
                .iter()
                .zip(objects)
                .filter_map(|(lock_opt, objref)| {
                    lock_opt.clone().flatten().map(|_tx_digest| *objref)
                })
                .collect();
            if !existing_locks.is_empty() {
                info!(
                    ?existing_locks,
                    "Cannot initialize locks because some exist already"
                );
                return Err(SuiError::ObjectLockAlreadyInitialized {
                    refs: existing_locks,
                });
            }
        }

        Ok(write_batch.insert_batch(
            &self.perpetual_tables.owned_object_transaction_locks,
            objects.iter().map(|obj_ref| (obj_ref, None)),
        )?)
    }

    /// Removes locks for a given list of ObjectRefs.
    fn delete_locks(&self, write_batch: DBBatch, objects: &[ObjectRef]) -> SuiResult<DBBatch> {
        debug!(?objects, "delete_locks");
        Ok(write_batch.delete_batch(
            &self.perpetual_tables.owned_object_transaction_locks,
            objects.iter(),
        )?)
    }

    #[cfg(test)]
    pub(crate) fn reset_locks_for_test(
        &self,
        transactions: &[TransactionDigest],
        objects: &[ObjectRef],
        epoch_store: &AuthorityPerEpochStore,
    ) {
        for tx in transactions {
            epoch_store.delete_signed_transaction_for_test(tx);
        }

        self.perpetual_tables
            .owned_object_transaction_locks
            .batch()
            .delete_batch(
                &self.perpetual_tables.owned_object_transaction_locks,
                objects.iter(),
            )
            .unwrap()
            .write()
            .unwrap();

        let write_batch = self.perpetual_tables.owned_object_transaction_locks.batch();

        self.initialize_locks_impl(write_batch, objects, false)
            .unwrap()
            .write()
            .unwrap();
    }

    /// This function is called at the end of epoch for each transaction that's
    /// executed locally on the validator but didn't make to the last checkpoint.
    /// The effects of the execution is reverted here.
    /// The following things are reverted:
    /// 1. Certificate and effects are deleted.
    /// 2. Latest parent_sync entries for each mutated object are deleted.
    /// 3. All new object states are deleted.
    /// 4. owner_index table change is reverted.
    pub async fn revert_state_update(&self, tx_digest: &TransactionDigest) -> SuiResult {
        let Some(effects) = self.get_executed_effects(tx_digest)? else {
            debug!("Not reverting {:?} as it was not executed", tx_digest);
            return Ok(())
        };

        // We should never be reverting shared object transactions.
        assert!(effects.shared_objects.is_empty());

        let mut write_batch = self.perpetual_tables.transactions.batch();
        write_batch = write_batch
            .delete_batch(&self.perpetual_tables.transactions, iter::once(tx_digest))?
            .delete_batch(&self.perpetual_tables.effects, iter::once(effects.digest()))?
            .delete_batch(
                &self.perpetual_tables.executed_effects,
                iter::once(tx_digest),
            )?;

        let all_new_refs = effects
            .mutated
            .iter()
            .chain(effects.created.iter())
            .chain(effects.unwrapped.iter())
            .map(|(r, _)| r)
            .chain(effects.deleted.iter())
            .chain(effects.unwrapped_then_deleted.iter())
            .chain(effects.wrapped.iter());
        write_batch = write_batch.delete_batch(&self.perpetual_tables.parent_sync, all_new_refs)?;

        let all_new_object_keys = effects
            .mutated
            .iter()
            .chain(effects.created.iter())
            .chain(effects.unwrapped.iter())
            .map(|((id, version, _), _)| ObjectKey(*id, *version));
        write_batch = write_batch
            .delete_batch(&self.perpetual_tables.objects, all_new_object_keys.clone())?;

        let modified_object_keys = effects
            .modified_at_versions
            .iter()
            .map(|(id, version)| ObjectKey(*id, *version));

        macro_rules! get_objects_and_locks {
            ($object_keys: expr) => {
                self.perpetual_tables
                    .objects
                    .multi_get($object_keys.clone())?
                    .into_iter()
                    .zip($object_keys)
                    .filter_map(|(obj_opt, key)| {
                        let obj =
                            obj_opt.expect(&format!("Older object version not found: {:?}", key));

                        if obj.is_immutable() {
                            return None;
                        }

                        let obj_ref = obj.compute_object_reference();
                        Some(obj.is_address_owned().then_some(obj_ref))
                    })
            };
        }

        let old_locks = get_objects_and_locks!(modified_object_keys);
        let new_locks = get_objects_and_locks!(all_new_object_keys);

        let old_locks: Vec<_> = old_locks.flatten().collect();

        // Re-create old locks.
        write_batch = self.initialize_locks_impl(write_batch, &old_locks, true)?;

        // Delete new locks
        write_batch = write_batch.delete_batch(
            &self.perpetual_tables.owned_object_transaction_locks,
            new_locks.flatten(),
        )?;

        write_batch.write()?;

        Ok(())
    }

    /// Return the object with version less then or eq to the provided seq number.
    /// This is used by indexer to find the correct version of dynamic field child object.
    /// We do not store the version of the child object, but because of lamport timestamp,
    /// we know the child must have version number less then or eq to the parent.
    pub fn find_object_lt_or_eq_version(
        &self,
        object_id: ObjectID,
        version: SequenceNumber,
    ) -> Option<Object> {
        self.perpetual_tables
            .find_object_lt_or_eq_version(object_id, version)
    }

    /// Returns the last entry we have for this object in the parents_sync index used
    /// to facilitate client and authority sync. In turn the latest entry provides the
    /// latest object_reference, and also the latest transaction that has interacted with
    /// this object.
    ///
    /// This parent_sync index also contains entries for deleted objects (with a digest of
    /// ObjectDigest::deleted()), and provides the transaction digest of the certificate
    /// that deleted the object. Note that a deleted object may re-appear if the deletion
    /// was the result of the object being wrapped in another object.
    ///
    /// If no entry for the object_id is found, return None.
    pub fn get_latest_parent_entry(
        &self,
        object_id: ObjectID,
    ) -> Result<Option<(ObjectRef, TransactionDigest)>, SuiError> {
        self.perpetual_tables.get_latest_parent_entry(object_id)
    }

    pub fn insert_transaction_and_effects(
        &self,
        transaction: &VerifiedTransaction,
        transaction_effects: &TransactionEffects,
    ) -> Result<(), TypedStoreError> {
        let mut write_batch = self.perpetual_tables.transactions.batch();
        write_batch = write_batch
            .insert_batch(
                &self.perpetual_tables.transactions,
                [(transaction.digest(), transaction.serializable_ref())],
            )?
            .insert_batch(
                &self.perpetual_tables.effects,
                [(transaction_effects.digest(), transaction_effects)],
            )?;

        write_batch.write()?;
        Ok(())
    }

    pub fn multi_get_transactions(
        &self,
        tx_digests: &[TransactionDigest],
    ) -> Result<Vec<Option<VerifiedTransaction>>, SuiError> {
        Ok(self
            .perpetual_tables
            .transactions
            .multi_get(tx_digests)
            .map(|v| v.into_iter().map(|v| v.map(|v| v.into())).collect())?)
    }

    pub fn get_transaction(
        &self,
        tx_digest: &TransactionDigest,
    ) -> Result<Option<VerifiedTransaction>, TypedStoreError> {
        self.perpetual_tables
            .transactions
            .get(tx_digest)
            .map(|v| v.map(|v| v.into()))
    }

    // TODO: Transaction Orchestrator also calls this, which is not ideal.
    // Instead of this function use AuthorityEpochStore::epoch_start_configuration() to access this object everywhere
    // besides when we are reading fields for the current epoch
    pub fn get_sui_system_state_object(&self) -> SuiResult<SuiSystemState> {
        get_sui_system_state(self.perpetual_tables.as_ref())
    }

    pub fn iter_live_object_set(&self) -> impl Iterator<Item = ObjectRef> + '_ {
        self.perpetual_tables.iter_live_object_set()
    }
}

impl BackingPackageStore for AuthorityStore {
    fn get_package(&self, package_id: &ObjectID) -> SuiResult<Option<Object>> {
        let package = self.get_object(package_id)?;
        if let Some(obj) = &package {
            fp_ensure!(
                obj.is_package(),
                SuiError::BadObjectType {
                    error: format!("Package expected, Move object found: {package_id}"),
                }
            );
        }
        Ok(package)
    }
}

impl ChildObjectResolver for AuthorityStore {
    fn read_child_object(&self, parent: &ObjectID, child: &ObjectID) -> SuiResult<Option<Object>> {
        let child_object = match self.get_object(child)? {
            None => return Ok(None),
            Some(o) => o,
        };
        let parent = *parent;
        if child_object.owner != Owner::ObjectOwner(parent.into()) {
            return Err(SuiError::InvalidChildObjectAccess {
                object: *child,
                given_parent: parent,
                actual_owner: child_object.owner,
            });
        }
        Ok(Some(child_object))
    }
}

impl ParentSync for AuthorityStore {
    fn get_latest_parent_entry_ref(&self, object_id: ObjectID) -> SuiResult<Option<ObjectRef>> {
        Ok(self
            .get_latest_parent_entry(object_id)?
            .map(|(obj_ref, _)| obj_ref))
    }
}

impl ModuleResolver for AuthorityStore {
    type Error = SuiError;

    // TODO: duplicated code with ModuleResolver for InMemoryStorage in memory_storage.rs.
    fn get_module(&self, module_id: &ModuleId) -> Result<Option<Vec<u8>>, Self::Error> {
        // TODO: We should cache the deserialized modules to avoid
        // fetching from the store / re-deserializing them every time.
        // https://github.com/MystenLabs/sui/issues/809
        Ok(self
            .get_package(&ObjectID::from(*module_id.address()))?
            .and_then(|package| {
                // unwrap safe since get_package() ensures it's a package object.
                package
                    .data
                    .try_as_package()
                    .unwrap()
                    .serialized_module_map()
                    .get(module_id.name().as_str())
                    .cloned()
            }))
    }
}

/// A wrapper to make Orphan Rule happy
pub struct ResolverWrapper<T: ModuleResolver> {
    pub resolver: Arc<T>,
    pub metrics: Arc<ResolverMetrics>,
}

impl<T: ModuleResolver> ResolverWrapper<T> {
    pub fn new(resolver: Arc<T>, metrics: Arc<ResolverMetrics>) -> Self {
        metrics.module_cache_size.set(0);
        ResolverWrapper { resolver, metrics }
    }

    fn inc_cache_size_gauge(&self) {
        // reset the gauge after a restart of the cache
        let current = self.metrics.module_cache_size.get();
        self.metrics.module_cache_size.set(current + 1);
    }
}

impl<T: ModuleResolver> ModuleResolver for ResolverWrapper<T> {
    type Error = T::Error;
    fn get_module(&self, module_id: &ModuleId) -> Result<Option<Vec<u8>>, Self::Error> {
        self.inc_cache_size_gauge();
        self.resolver.get_module(module_id)
    }
}

pub enum UpdateType {
    Transaction(TransactionEffectsDigest),
    Genesis,
}

pub type SuiLockResult = SuiResult<ObjectLockStatus>;

#[derive(Debug, PartialEq, Eq)]
pub enum ObjectLockStatus {
    Initialized,
    LockedToTx { locked_by_tx: LockDetails },
    LockedAtDifferentVersion { locked_ref: ObjectRef },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockDetails {
    pub epoch: EpochId,
    pub tx_digest: TransactionDigest,
}

/// A potential input to a transaction.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InputKey(pub ObjectID, pub Option<SequenceNumber>);
