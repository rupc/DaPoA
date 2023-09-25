// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! CheckpointExecutor is a Node component that executes all checkpoints for the
//! given epoch. It acts as a Consumer to StateSync
//! for newly synced checkpoints, taking these checkpoints and
//! scheduling and monitoring their execution. Its primary goal is to allow
//! for catching up to the current checkpoint sequence number of the network
//! as quickly as possible so that a newly joined, or recovering Node can
//! participate in a timely manner. To that end, CheckpointExecutor attempts
//! to saturate the CPU with executor tasks (one per checkpoint), each of which
//! handle scheduling and awaiting checkpoint transaction execution.
//!
//! CheckpointExecutor is made recoverable in the event of Node shutdown by way of a watermark,
//! highest_executed_checkpoint, which is guaranteed to be updated sequentially in order,
//! despite checkpoints themselves potentially being executed nonsequentially and in parallel.
//! CheckpointExecutor parallelizes checkpoints of the same epoch as much as possible.
//! CheckpointExecutor enforces the invariant that if `run` returns successfully, we have reached the
//! end of epoch. This allows us to use it as a signal for reconfig.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use futures::stream::FuturesOrdered;
use itertools::izip;
use mysten_metrics::spawn_monitored_task;
use prometheus::Registry;
use sui_config::node::CheckpointExecutorConfig;
use sui_types::error::SuiResult;
use sui_types::messages::VerifiedExecutableTransaction;
use sui_types::{
    base_types::{ExecutionDigests, TransactionDigest},
    messages::TransactionEffects,
    messages_checkpoint::{CheckpointSequenceNumber, EndOfEpochData, VerifiedCheckpoint},
};
use sui_types::{
    committee::{Committee, EpochId},
    message_envelope::Message,
};
use tap::TapFallible;
use tokio::{
    sync::broadcast::{self, error::RecvError},
    task::JoinHandle,
    time::timeout,
};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, instrument, warn};
use typed_store::Map;

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::authority::AuthorityStore;
use crate::state_accumulator::StateAccumulator;
use crate::transaction_manager::TransactionManager;
use crate::{authority::EffectsNotifyRead, checkpoints::CheckpointStore};

use self::metrics::CheckpointExecutorMetrics;

mod metrics;
#[cfg(test)]
pub(crate) mod tests;

type CheckpointExecutionBuffer = FuturesOrdered<JoinHandle<VerifiedCheckpoint>>;

pub struct CheckpointExecutor {
    mailbox: broadcast::Receiver<VerifiedCheckpoint>,
    checkpoint_store: Arc<CheckpointStore>,
    authority_store: Arc<AuthorityStore>,
    tx_manager: Arc<TransactionManager>,
    accumulator: Arc<StateAccumulator>,
    config: CheckpointExecutorConfig,
    metrics: Arc<CheckpointExecutorMetrics>,
}

impl CheckpointExecutor {
    pub fn new(
        mailbox: broadcast::Receiver<VerifiedCheckpoint>,
        checkpoint_store: Arc<CheckpointStore>,
        authority_store: Arc<AuthorityStore>,
        tx_manager: Arc<TransactionManager>,
        accumulator: Arc<StateAccumulator>,
        config: CheckpointExecutorConfig,
        prometheus_registry: &Registry,
    ) -> Self {
        Self {
            mailbox,
            checkpoint_store,
            authority_store,
            tx_manager,
            accumulator,
            config,
            metrics: CheckpointExecutorMetrics::new(prometheus_registry),
        }
    }

    pub fn new_for_tests(
        mailbox: broadcast::Receiver<VerifiedCheckpoint>,
        checkpoint_store: Arc<CheckpointStore>,
        authority_store: Arc<AuthorityStore>,
        tx_manager: Arc<TransactionManager>,
        accumulator: Arc<StateAccumulator>,
    ) -> Self {
        Self {
            mailbox,
            checkpoint_store,
            authority_store,
            tx_manager,
            accumulator,
            config: Default::default(),
            metrics: CheckpointExecutorMetrics::new_for_tests(),
        }
    }

    /// Ensure that all checkpoints in the current epoch will be executed.
    /// Return the committee of the next epoch.
    /// We don't technically need &mut on self, but passing it to make sure only one instance is
    /// running at one time.
    pub async fn run_epoch(&mut self, epoch_store: Arc<AuthorityPerEpochStore>) -> Committee {
        debug!(
            "Checkpoint executor running for epoch {}",
            epoch_store.epoch(),
        );
        self.metrics
            .checkpoint_exec_epoch
            .set(epoch_store.epoch() as i64);

        // Decide the first checkpoint to schedule for execution.
        // If we haven't executed anything in the past, we schedule checkpoint 0.
        // Otherwise we schedule the one after highest executed.
        let mut highest_executed = self
            .checkpoint_store
            .get_highest_executed_checkpoint()
            .unwrap();
        let mut next_to_schedule = highest_executed
            .as_ref()
            .map(|c| c.sequence_number() + 1)
            .unwrap_or_else(|| {
                // TODO this invariant may no longer hold once we introduce snapshots
                assert_eq!(epoch_store.epoch(), 0);
                0
            });
        let mut pending: CheckpointExecutionBuffer = FuturesOrdered::new();

        let mut now_time = Instant::now();
        let mut now_transaction_num = highest_executed
            .as_ref()
            .map(|c| c.summary.network_total_transactions)
            .unwrap_or(0);

        loop {
            // If we have executed the last checkpoint of the current epoch, stop.
            if let Some(next_epoch_committee) =
                check_epoch_last_checkpoint(epoch_store.epoch(), &highest_executed)
            {
                // be extra careful to ensure we don't have orphans
                assert!(
                    pending.is_empty(),
                    "Pending checkpoint execution buffer should be empty after processing last checkpoint of epoch",
                );
                return next_epoch_committee;
            }
            self.schedule_synced_checkpoints(
                &mut pending,
                // next_to_schedule will be updated to the next checkpoint to schedule.
                // This makes sure we don't re-schedule the same checkpoint multiple times.
                &mut next_to_schedule,
                epoch_store.clone(),
            );
            tokio::select! {
                // Check for completed workers and ratchet the highest_checkpoint_executed
                // watermark accordingly. Note that given that checkpoints are guaranteed to
                // be processed (added to FuturesOrdered) in seq_number order, using FuturesOrdered
                // guarantees that we will also ratchet the watermarks in order.
                Some(Ok(checkpoint)) = pending.next() => {
                    self.process_executed_checkpoint(&checkpoint);
                    highest_executed = Some(checkpoint);

                    // Estimate TPS every 10k transactions or 30 sec
                    let elapsed = now_time.elapsed().as_millis();
                    let current_transaction_num =  highest_executed.as_ref().map(|c| c.summary.network_total_transactions).unwrap_or(0);
                    if current_transaction_num - now_transaction_num > 10_000 || elapsed > 30_000{
                        let tps = (1000.0 * (current_transaction_num - now_transaction_num) as f64 / elapsed as f64) as i32;
                        self.metrics.checkpoint_exec_sync_tps.set(tps as i64);
                        now_time = Instant::now();
                        now_transaction_num = current_transaction_num;
                    }

                }
                // Check for newly synced checkpoints from StateSync.
                received = self.mailbox.recv() => match received {
                    Ok(checkpoint) => {
                        debug!(
                            sequence_number = ?checkpoint.summary.sequence_number,
                            "received checkpoint summary from state sync"
                        );
                        SystemTime::now().duration_since(checkpoint.summary.timestamp())
                            .map(|latency|
                                self.metrics.checkpoint_contents_age_ms.report(latency.as_millis() as u64)
                            )
                            .tap_err(|err| warn!("unable to compute checkpoint age: {}", err))
                            .ok();
                    },
                    // In this case, messages in the mailbox have been overwritten
                    // as a result of lagging too far behind.
                    Err(RecvError::Lagged(num_skipped)) => {
                        debug!(
                            "Checkpoint Execution Recv channel overflowed {:?} messages",
                            num_skipped,
                        );
                    }
                    Err(RecvError::Closed) => {
                        panic!("Checkpoint Execution Sender (StateSync) closed channel unexpectedly");
                    }
                }
            }
        }
    }

    /// Post processing and plumbing after we executed a checkpoint. This function is guaranteed
    /// to be called in the order of checkpoint sequence number.
    fn process_executed_checkpoint(&self, checkpoint: &VerifiedCheckpoint) {
        // Ensure that we are not skipping checkpoints at any point
        let seq = checkpoint.sequence_number();
        if let Some(prev_highest) = self
            .checkpoint_store
            .get_highest_executed_checkpoint_seq_number()
            .unwrap()
        {
            assert_eq!(prev_highest + 1, seq);
        } else {
            assert_eq!(seq, 0);
        }
        debug!("Bumping highest_executed_checkpoint watermark to {:?}", seq,);

        self.checkpoint_store
            .update_highest_executed_checkpoint(checkpoint)
            .unwrap();
        self.metrics.last_executed_checkpoint.set(seq as i64);
    }

    fn schedule_synced_checkpoints(
        &self,
        pending: &mut CheckpointExecutionBuffer,
        next_to_schedule: &mut CheckpointSequenceNumber,
        epoch_store: Arc<AuthorityPerEpochStore>,
    ) {
        let Some(latest_synced_checkpoint) = self
            .checkpoint_store
            .get_highest_synced_checkpoint()
            .expect("Failed to read highest synced checkpoint") else {
            debug!(
                "No checkpoints to schedule, highest synced checkpoint is None",
            );
            return;
        };

        while *next_to_schedule <= latest_synced_checkpoint.sequence_number()
            && pending.len() < self.config.checkpoint_execution_max_concurrency
        {
            let checkpoint = self
                .checkpoint_store
                .get_checkpoint_by_sequence_number(*next_to_schedule)
                .unwrap()
                .unwrap_or_else(|| {
                    panic!(
                        "Checkpoint sequence number {:?} does not exist in checkpoint store",
                        *next_to_schedule
                    )
                });
            if checkpoint.epoch() > epoch_store.epoch() {
                return;
            }

            self.schedule_checkpoint(checkpoint, pending, epoch_store.clone());
            *next_to_schedule += 1;
        }
    }

    fn schedule_checkpoint(
        &self,
        checkpoint: VerifiedCheckpoint,
        pending: &mut CheckpointExecutionBuffer,
        epoch_store: Arc<AuthorityPerEpochStore>,
    ) {
        debug!("Executing checkpoint {:?}", checkpoint.sequence_number());

        // Mismatch between node epoch and checkpoint epoch after startup
        // crash recovery is invalid
        let checkpoint_epoch = checkpoint.epoch();
        assert_eq!(
            checkpoint_epoch,
            epoch_store.epoch(),
            "Epoch mismatch after startup recovery. checkpoint epoch: {:?}, node epoch: {:?}",
            checkpoint_epoch,
            epoch_store.epoch(),
        );

        // Record checkpoint participation for tallying rule.
        epoch_store
            .record_certified_checkpoint_signatures(checkpoint.inner())
            .unwrap();

        let metrics = self.metrics.clone();
        let local_execution_timeout_sec = self.config.local_execution_timeout_sec;
        let authority_store = self.authority_store.clone();
        let checkpoint_store = self.checkpoint_store.clone();
        let tx_manager = self.tx_manager.clone();
        let accumulator = self.accumulator.clone();

        pending.push_back(spawn_monitored_task!(async move {
            let epoch_store = epoch_store.clone();
            while let Err(err) = execute_checkpoint(
                checkpoint.clone(),
                authority_store.clone(),
                checkpoint_store.clone(),
                epoch_store.clone(),
                tx_manager.clone(),
                accumulator.clone(),
                local_execution_timeout_sec,
                &metrics,
            )
            .await
            {
                error!(
                    "Error while executing checkpoint, will retry in 1s: {:?}",
                    err
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                metrics.checkpoint_exec_errors.inc();
            }
            checkpoint
        }));
    }
}

/// Check whether `checkpoint` is the last checkpoint of the current epoch. If so, return the
/// committee of the next epoch.
fn check_epoch_last_checkpoint(
    cur_epoch: EpochId,
    checkpoint: &Option<VerifiedCheckpoint>,
) -> Option<Committee> {
    if let Some(checkpoint) = checkpoint {
        if checkpoint.epoch() == cur_epoch {
            if let Some(EndOfEpochData {
                next_epoch_committee,
                next_epoch_protocol_version,
                ..
            }) = &checkpoint.summary.end_of_epoch_data
            {
                info!(
                    ended_epoch = cur_epoch,
                    ?next_epoch_protocol_version,
                    last_checkpoint = checkpoint.sequence_number(),
                    "Reached end of epoch",
                );
                let next_epoch = cur_epoch + 1;
                return Some(
                    Committee::new(
                        next_epoch,
                        *next_epoch_protocol_version,
                        next_epoch_committee.iter().cloned().collect(),
                    )
                    .expect("Creating new committee object cannot fail"),
                );
            }
        }
    }
    None
}

#[instrument(level = "error", skip_all, fields(seq = ?checkpoint.sequence_number(), epoch = ?epoch_store.epoch()))]
pub async fn execute_checkpoint(
    checkpoint: VerifiedCheckpoint,
    authority_store: Arc<AuthorityStore>,
    checkpoint_store: Arc<CheckpointStore>,
    epoch_store: Arc<AuthorityPerEpochStore>,
    transaction_manager: Arc<TransactionManager>,
    accumulator: Arc<StateAccumulator>,
    local_execution_timeout_sec: u64,
    metrics: &Arc<CheckpointExecutorMetrics>,
) -> SuiResult {
    debug!(
        "Scheduling checkpoint {:?} for execution",
        checkpoint.sequence_number(),
    );
    let txes = checkpoint_store
        .get_checkpoint_contents(&checkpoint.content_digest())?
        .unwrap_or_else(|| {
            panic!(
                "Checkpoint contents for digest {:?} does not exist",
                checkpoint.content_digest()
            )
        })
        .into_inner();

    let tx_count = txes.len();
    debug!(
        epoch=?epoch_store.epoch(),
        checkpoint_sequence=?checkpoint.sequence_number(),
        "Number of transactions in the checkpoint: {:?}",
        tx_count
    );
    metrics.checkpoint_transaction_count.report(tx_count as u64);

    execute_transactions(
        txes,
        authority_store,
        epoch_store,
        transaction_manager,
        local_execution_timeout_sec,
        checkpoint,
        accumulator,
    )
    .await
}

async fn execute_transactions(
    execution_digests: Vec<ExecutionDigests>,
    authority_store: Arc<AuthorityStore>,
    epoch_store: Arc<AuthorityPerEpochStore>,
    transaction_manager: Arc<TransactionManager>,
    log_timeout_sec: u64,
    checkpoint: VerifiedCheckpoint,
    accumulator: Arc<StateAccumulator>,
) -> SuiResult {
    let checkpoint_sequence = checkpoint.sequence_number();
    let all_tx_digests: Vec<TransactionDigest> =
        execution_digests.iter().map(|tx| tx.transaction).collect();

    let executable_txns: Vec<_> = authority_store
        .multi_get_transactions(&all_tx_digests)?
        .into_iter()
        .map(|tx| {
            VerifiedExecutableTransaction::new_from_checkpoint(
                tx.expect("state-sync should have ensured that the transaction exists"),
                epoch_store.epoch(),
                checkpoint_sequence,
            )
        })
        .collect();

    let effects_digests: Vec<_> = execution_digests
        .iter()
        .map(|digest| digest.effects)
        .collect();

    let digest_to_effects: HashMap<TransactionDigest, TransactionEffects> = authority_store
        .perpetual_tables
        .effects
        .multi_get(effects_digests.iter())?
        .into_iter()
        .map(|fx| {
            if fx.is_none() {
                panic!("Transaction effects do not exist in effects table");
            }
            let fx = fx.unwrap();
            (fx.transaction_digest, fx)
        })
        .collect();

    for tx in &executable_txns {
        if tx.contains_shared_object() {
            epoch_store
                .acquire_shared_locks_from_effects(
                    tx,
                    digest_to_effects.get(tx.digest()).unwrap(),
                    &authority_store,
                )
                .await?;
        }
    }

    transaction_manager.enqueue(executable_txns, &epoch_store)?;

    // Once synced_txns have been awaited, all txns should have effects committed.
    let mut periods = 1;
    let log_timeout_sec = Duration::from_secs(log_timeout_sec);

    loop {
        let effects_future = authority_store.notify_read_executed_effects(all_tx_digests.clone());

        match timeout(log_timeout_sec, effects_future).await {
            Err(_elapsed) => {
                let missing_digests: Vec<TransactionDigest> = authority_store
                    .multi_get_executed_effects(&all_tx_digests)?
                    .iter()
                    .zip(all_tx_digests.clone())
                    .filter_map(
                        |(fx, digest)| {
                            if fx.is_none() {
                                Some(digest)
                            } else {
                                None
                            }
                        },
                    )
                    .collect();

                warn!(
                    "Transaction effects for tx digests {:?} checkpoint not present within {:?}. ",
                    missing_digests,
                    log_timeout_sec * periods,
                );
                periods += 1;
            }
            Ok(Err(err)) => return Err(err),
            Ok(Ok(effects)) => {
                let checkpoint_sequence = checkpoint.sequence_number();
                for (tx_digest, expected_digest, actual_effects) in
                    izip!(&all_tx_digests, &execution_digests, &effects)
                {
                    let expected_effects_digest = expected_digest.effects;
                    if expected_effects_digest != actual_effects.digest() {
                        panic!("When executing checkpoint {checkpoint_sequence}, transaction {tx_digest} is expected to have effects digest {expected_effects_digest}, but got {}!", actual_effects.digest());
                    }
                }

                authority_store.insert_finalized_transactions(
                    &all_tx_digests,
                    epoch_store.epoch(),
                    checkpoint_sequence,
                )?;
                accumulator.accumulate_checkpoint(effects, checkpoint_sequence, epoch_store)?;

                return Ok(());
            }
        }
    }
}
