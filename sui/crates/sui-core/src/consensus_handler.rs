// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::authority::authority_per_epoch_store::{
    AuthorityPerEpochStore, ExecutionIndicesWithHash,
};
use crate::authority::AuthorityMetrics;
use crate::checkpoints::CheckpointService;
use crate::transaction_manager::TransactionManager;
use async_trait::async_trait;
use mysten_metrics::monitored_scope;
use narwhal_executor::{ExecutionIndices, ExecutionState};
use narwhal_types::ConsensusOutput;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use sui_types::base_types::{AuthorityName, EpochId, TransactionDigest};
use sui_types::messages::{
    ConsensusTransaction, ConsensusTransactionKey, ConsensusTransactionKind,
    VerifiedExecutableTransaction, VerifiedTransaction,
};
use sui_types::storage::ParentSync;
use tracing::{debug, error, instrument};

pub struct ConsensusHandler<T> {
    /// A store created for each epoch. ConsensusHandler is recreated each epoch, with the
    /// corresponding store. This store is also used to get the current epoch ID.
    epoch_store: Arc<AuthorityPerEpochStore>,
    last_seen: Mutex<ExecutionIndicesWithHash>,
    checkpoint_service: Arc<CheckpointService>,
    /// transaction_manager is needed to schedule certificates execution received from Narwhal.
    transaction_manager: Arc<TransactionManager>,
    /// parent_sync_store is needed when determining the next version to assign for shared objects.
    parent_sync_store: T,
    // TODO: ConsensusHandler doesn't really share metrics with AuthorityState. We could define
    // a new metrics type here if we want to.
    metrics: Arc<AuthorityMetrics>,
}

impl<T> ConsensusHandler<T> {
    pub fn new(
        epoch_store: Arc<AuthorityPerEpochStore>,
        checkpoint_service: Arc<CheckpointService>,
        transaction_manager: Arc<TransactionManager>,
        parent_sync_store: T,
        metrics: Arc<AuthorityMetrics>,
    ) -> Self {
        let last_seen = Mutex::new(Default::default());
        Self {
            epoch_store,
            last_seen,
            checkpoint_service,
            transaction_manager,
            parent_sync_store,
            metrics,
        }
    }
}

fn update_hash(
    last_seen: &Mutex<ExecutionIndicesWithHash>,
    index: ExecutionIndices,
    v: &[u8],
) -> Option<ExecutionIndicesWithHash> {
    let mut last_seen_guard = last_seen
        .try_lock()
        .expect("Should not have contention on ExecutionState::update_hash");
    if last_seen_guard.index >= index {
        return None;
    }

    let previous_hash = last_seen_guard.hash;
    let mut hasher = DefaultHasher::new();
    previous_hash.hash(&mut hasher);
    v.hash(&mut hasher);
    let hash = hasher.finish();
    // Log hash every 100th transaction of the subdag
    if index.transaction_index % 100 == 0 {
        debug!(
            "Integrity hash for consensus output at subdag {} is {:016x}",
            index.sub_dag_index, hash
        );
    }
    let last_seen = ExecutionIndicesWithHash { index, hash };
    *last_seen_guard = last_seen.clone();
    Some(last_seen)
}

#[async_trait]
impl<T: ParentSync + Send + Sync> ExecutionState for ConsensusHandler<T> {
    /// This function will be called by Narwhal, after Narwhal sequenced this certificate.
    #[instrument(level = "trace", skip_all)]
    async fn handle_consensus_output(
        &self,
        // TODO [2533]: use this once integrating Narwhal reconfiguration
        consensus_output: ConsensusOutput,
    ) {
        let _scope = monitored_scope("HandleConsensusOutput");
        let mut sequenced_transactions = Vec::new();

        let mut bytes = 0usize;
        let round = consensus_output.sub_dag.round();

        /* (serialized, transaction, output_cert) */
        let mut transactions = vec![];

        let prologue_transaction = self.consensus_commit_prologue_transaction(
            consensus_output.sub_dag.round(),
            consensus_output.sub_dag.leader.metadata.created_at,
        );
        transactions.push((
            vec![],
            SequencedConsensusTransactionKind::System(prologue_transaction),
            Arc::new(consensus_output.sub_dag.leader.clone()),
        ));

        for (cert, batches) in consensus_output.batches {
            let author = cert.header.author.clone();
            let output_cert = Arc::new(cert);
            for batch in batches {
                self.metrics.consensus_handler_processed_batches.inc();
                for serialized_transaction in batch.transactions {
                    bytes += serialized_transaction.len();

                    let transaction = match bincode::deserialize::<ConsensusTransaction>(
                        &serialized_transaction,
                    ) {
                        Ok(transaction) => transaction,
                        Err(err) => {
                            // This should be prevented by batch verification, hence `error` log level
                            error!(
                                    "Ignoring unexpected malformed transaction (failed to deserialize) from {}: {}",
                                    author, err
                                );
                            continue;
                        }
                    };
                    self.metrics
                        .consensus_handler_processed
                        .with_label_values(&[classify(&transaction)])
                        .inc();
                    let transaction = SequencedConsensusTransactionKind::External(transaction);
                    transactions.push((serialized_transaction, transaction, output_cert.clone()));
                }
            }
        }

        for (seq, (serialized, transaction, output_cert)) in transactions.into_iter().enumerate() {
            let index = ExecutionIndices {
                last_committed_round: round,
                sub_dag_index: consensus_output.sub_dag.sub_dag_index,
                transaction_index: seq as u64,
            };

            let index_with_hash = match update_hash(&self.last_seen, index, &serialized) {
                Some(i) => i,
                None => {
                    debug!(
                "Ignore consensus transaction at index {:?} as it appear to be already processed",
                index
            );
                    continue;
                }
            };

            sequenced_transactions.push(SequencedConsensusTransaction {
                certificate: output_cert.clone(),
                consensus_index: index_with_hash,
                transaction,
            });
        }

        self.metrics
            .consensus_handler_processed_bytes
            .inc_by(bytes as u64);

        for sequenced_transaction in sequenced_transactions {
            let verified_transaction = match self.epoch_store.verify_consensus_transaction(
                sequenced_transaction,
                &self.metrics.skipped_consensus_txns,
            ) {
                Ok(verified_transaction) => verified_transaction,
                Err(()) => continue,
            };

            self.epoch_store
                .handle_consensus_transaction(
                    verified_transaction,
                    &self.checkpoint_service,
                    &self.transaction_manager,
                    &self.parent_sync_store,
                )
                .await
                .expect("Unrecoverable error in consensus handler");
        }

        self.epoch_store
            .handle_commit_boundary(&consensus_output.sub_dag, &self.checkpoint_service)
            .expect("Unrecoverable error in consensus handler when processing commit boundary")
    }

    async fn last_executed_sub_dag_index(&self) -> u64 {
        let index_with_hash = self
            .epoch_store
            .get_last_consensus_index()
            .expect("Failed to load consensus indices");

        index_with_hash.index.sub_dag_index
    }
}

impl<T> ConsensusHandler<T> {
    #[allow(dead_code)]
    fn consensus_commit_prologue_transaction(
        &self,
        round: u64,
        commit_timestamp_ms: u64,
    ) -> VerifiedExecutableTransaction {
        let transaction = VerifiedTransaction::new_consensus_commit_prologue(
            self.epoch(),
            round,
            commit_timestamp_ms,
        );
        VerifiedExecutableTransaction::new_system(transaction, self.epoch())
    }

    fn epoch(&self) -> EpochId {
        self.epoch_store.epoch()
    }
}

fn classify(transaction: &ConsensusTransaction) -> &'static str {
    match &transaction.kind {
        ConsensusTransactionKind::UserTransaction(certificate) => {
            if certificate.contains_shared_object() {
                "shared_certificate"
            } else {
                "owned_certificate"
            }
        }
        ConsensusTransactionKind::CheckpointSignature(_) => "checkpoint_signature",
        ConsensusTransactionKind::EndOfPublish(_) => "end_of_publish",
        ConsensusTransactionKind::CapabilityNotification(_) => "capability_notification",
    }
}

pub struct SequencedConsensusTransaction {
    pub certificate: Arc<narwhal_types::Certificate>,
    pub consensus_index: ExecutionIndicesWithHash,
    pub transaction: SequencedConsensusTransactionKind,
}

pub enum SequencedConsensusTransactionKind {
    External(ConsensusTransaction),
    System(VerifiedExecutableTransaction),
}

#[derive(Serialize, Deserialize, Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub enum SequencedConsensusTransactionKey {
    External(ConsensusTransactionKey),
    System(TransactionDigest),
}

impl SequencedConsensusTransactionKind {
    pub fn key(&self) -> SequencedConsensusTransactionKey {
        match self {
            SequencedConsensusTransactionKind::External(ext) => {
                SequencedConsensusTransactionKey::External(ext.key())
            }
            SequencedConsensusTransactionKind::System(txn) => {
                SequencedConsensusTransactionKey::System(*txn.digest())
            }
        }
    }

    pub fn get_tracking_id(&self) -> u64 {
        match self {
            SequencedConsensusTransactionKind::External(ext) => ext.get_tracking_id(),
            SequencedConsensusTransactionKind::System(_txn) => 0,
        }
    }

    pub fn is_executable_transaction(&self) -> bool {
        match self {
            SequencedConsensusTransactionKind::External(ext) => ext.is_user_certificate(),
            SequencedConsensusTransactionKind::System(_) => true,
        }
    }
}

impl SequencedConsensusTransaction {
    pub fn sender_authority(&self) -> AuthorityName {
        (&self.certificate.header.author).into()
    }

    pub fn key(&self) -> SequencedConsensusTransactionKey {
        self.transaction.key()
    }
}

pub struct VerifiedSequencedConsensusTransaction(pub SequencedConsensusTransaction);

#[cfg(test)]
impl VerifiedSequencedConsensusTransaction {
    pub fn new_test(transaction: ConsensusTransaction) -> Self {
        Self(SequencedConsensusTransaction::new_test(transaction))
    }
}

#[cfg(test)]
impl SequencedConsensusTransaction {
    pub fn new_test(transaction: ConsensusTransaction) -> Self {
        Self {
            transaction: SequencedConsensusTransactionKind::External(transaction),
            certificate: Default::default(),
            consensus_index: Default::default(),
        }
    }
}

#[test]
pub fn test_update_hash() {
    let index0 = ExecutionIndices {
        sub_dag_index: 0,
        transaction_index: 0,
        last_committed_round: 0,
    };
    let index1 = ExecutionIndices {
        sub_dag_index: 0,
        transaction_index: 1,
        last_committed_round: 0,
    };
    let index2 = ExecutionIndices {
        sub_dag_index: 1,
        transaction_index: 0,
        last_committed_round: 0,
    };

    let last_seen = ExecutionIndicesWithHash {
        index: index1,
        hash: 1000,
    };

    let last_seen = Mutex::new(last_seen);
    let tx = &[0];
    assert!(update_hash(&last_seen, index0, tx).is_none());
    assert!(update_hash(&last_seen, index1, tx).is_none());
    assert!(update_hash(&last_seen, index2, tx).is_some());
}
