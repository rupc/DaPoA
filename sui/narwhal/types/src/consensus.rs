// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::mutable_key_type)]

use crate::{Batch, Certificate, CertificateDigest, Round};
use crypto::PublicKey;
use fastcrypto::hash::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use store::{
    rocks::{DBMap, TypedStoreError},
    traits::Map,
};
use tokio::sync::mpsc;

/// A global sequence number assigned to every CommittedSubDag.
pub type SequenceNumber = u64;

#[derive(Clone, Debug)]
/// The output of Consensus, which includes all the batches for each certificate in the sub dag
/// It is sent to the the ExecutionState handle_consensus_transactions
pub struct ConsensusOutput {
    pub sub_dag: Arc<CommittedSubDag>,
    pub batches: Vec<(Certificate, Vec<Batch>)>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CommittedSubDag {
    /// The sequence of committed certificates.
    pub certificates: Vec<Certificate>,
    /// The leader certificate responsible of committing this sub-dag.
    pub leader: Certificate,
    /// The index associated with this CommittedSubDag
    pub sub_dag_index: SequenceNumber,
}

impl CommittedSubDag {
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn num_batches(&self) -> usize {
        self.certificates
            .iter()
            .map(|x| x.header.payload.len())
            .sum()
    }

    pub fn is_last(&self, output: &Certificate) -> bool {
        self.certificates
            .iter()
            .last()
            .map_or_else(|| false, |x| x == output)
    }

    pub fn round(&self) -> Round {
        self.leader.round()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CommittedSubDagShell {
    /// The sequence of committed certificates' digests.
    pub certificates: Vec<CertificateDigest>,
    /// The leader certificate's digest responsible of committing this sub-dag.
    pub leader: CertificateDigest,
    /// Sequence number of the CommittedSubDag
    pub sub_dag_index: SequenceNumber,
}

impl CommittedSubDagShell {
    pub fn from_sub_dag(sub_dag: &CommittedSubDag) -> Self {
        Self {
            certificates: sub_dag.certificates.iter().map(|x| x.digest()).collect(),
            leader: sub_dag.leader.digest(),
            sub_dag_index: sub_dag.sub_dag_index,
        }
    }
}

/// Shutdown token dropped when a task is properly shut down.
pub type ShutdownToken = mpsc::Sender<()>;

/// Convenience type to propagate store errors.
pub type StoreResult<T> = Result<T, TypedStoreError>;

/// The persistent storage of the sequencer.
pub struct ConsensusStore {
    /// The latest committed round of each validator.
    last_committed: DBMap<PublicKey, Round>,
    /// The global consensus sequence.
    committed_sub_dags_by_index: DBMap<SequenceNumber, CommittedSubDagShell>,
}

impl ConsensusStore {
    /// Create a new consensus store structure by using already loaded maps.
    pub fn new(
        last_committed: DBMap<PublicKey, Round>,
        sequence: DBMap<SequenceNumber, CommittedSubDagShell>,
    ) -> Self {
        Self {
            last_committed,
            committed_sub_dags_by_index: sequence,
        }
    }

    /// Clear the store.
    pub fn clear(&self) -> StoreResult<()> {
        self.last_committed.clear()?;
        self.committed_sub_dags_by_index.clear()?;
        Ok(())
    }

    /// Persist the consensus state.
    pub fn write_consensus_state(
        &self,
        last_committed: &HashMap<PublicKey, Round>,
        sub_dag: &CommittedSubDag,
    ) -> Result<(), TypedStoreError> {
        let shell = CommittedSubDagShell::from_sub_dag(sub_dag);

        let mut write_batch = self.last_committed.batch();
        write_batch = write_batch.insert_batch(&self.last_committed, last_committed.iter())?;
        write_batch = write_batch.insert_batch(
            &self.committed_sub_dags_by_index,
            std::iter::once((sub_dag.sub_dag_index, shell)),
        )?;
        write_batch.write()
    }

    /// Load the last committed round of each validator.
    pub fn read_last_committed(&self) -> HashMap<PublicKey, Round> {
        self.last_committed.iter().collect()
    }

    /// Gets the latest sub dag index from the store
    pub fn get_latest_sub_dag_index(&self) -> SequenceNumber {
        let s = self
            .committed_sub_dags_by_index
            .iter()
            .skip_to_last()
            .next()
            .map(|(seq, _)| seq)
            .unwrap_or_default();
        s
    }

    /// Load all the sub dags committed with sequence number of at least `from`.
    pub fn read_committed_sub_dags_from(
        &self,
        from: &SequenceNumber,
    ) -> StoreResult<Vec<CommittedSubDagShell>> {
        Ok(self
            .committed_sub_dags_by_index
            .iter()
            .skip_to(from)?
            .map(|(_, sub_dag)| sub_dag)
            .collect())
    }
}
