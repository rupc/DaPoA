// Copyright(C) Facebook, Inc. and its affiliates.
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{metrics::PrimaryMetrics, NetworkModel};
use config::{Committee, Epoch, WorkerId};
use crypto::{PublicKey, Signature};
use fastcrypto::{hash::Hash as _, signature_service::SignatureService};
use mysten_metrics::spawn_logged_monitored_task;
use std::collections::BTreeMap;
use std::{cmp::Ordering, sync::Arc};
use storage::ProposerStore;
use tokio::time::{sleep_until, Instant};
use tokio::{
    sync::{oneshot, watch},
    task::JoinHandle,
    time::{sleep, Duration},
};
use tracing::{debug, enabled, error, info};
use types::{
    error::{DagError, DagResult},
    metered_channel::{Receiver, Sender},
    BatchDigest, Certificate, Header, Round, TimestampMs,
};
use types::{now, ConditionalBroadcastReceiver};

/// Messages sent to the proposer about our own batch digests
#[derive(Debug)]
pub struct OurDigestMessage {
    pub digest: BatchDigest,
    pub worker_id: WorkerId,
    pub timestamp: TimestampMs,
    /// A channel to send an () as an ack after this digest is processed by the primary.
    pub ack_channel: oneshot::Sender<()>,
}

#[cfg(test)]
#[path = "tests/proposer_tests.rs"]
pub mod proposer_tests;

const DEFAULT_HEADER_RESEND_TIMEOUT: Duration = Duration::from_secs(60);

/// The proposer creates new headers and send them to the core for broadcasting and further processing.
pub struct Proposer {
    /// The public key of this primary.
    name: PublicKey,
    /// The committee information.
    committee: Committee,
    /// Service to sign headers.
    signature_service: SignatureService<Signature, { crypto::DIGEST_LENGTH }>,
    /// The threshold number of batches that can trigger
    /// a header creation. When there are available at least
    /// `header_num_of_batches_threshold` batches we are ok
    /// to try and propose a header
    header_num_of_batches_threshold: usize,
    /// The maximum number of batches in header.
    max_header_num_of_batches: usize,
    /// The maximum delay to wait for conditions like having leader in parents.
    max_header_delay: Duration,
    /// The minimum delay between generating headers.
    min_header_delay: Duration,
    /// The delay to wait until resending the last proposed header if proposer
    /// hasn't proposed anything new since then. If None is provided then the
    /// default value will be used instead.
    header_resend_timeout: Option<Duration>,
    /// The network model in which the node operates.
    network_model: NetworkModel,

    /// Receiver for shutdown.
    rx_shutdown: ConditionalBroadcastReceiver,
    /// Receives the parents to include in the next header (along with their round number) from core.
    rx_parents: Receiver<(Vec<Certificate>, Round, Epoch)>,
    /// Receives the batches' digests from our workers.
    rx_our_digests: Receiver<OurDigestMessage>,
    /// Sends newly created headers to the `Core`.
    tx_headers: Sender<Header>,

    /// The proposer store for persisting the last header.
    proposer_store: ProposerStore,
    /// The current round of the dag.
    round: Round,
    /// Signals a new narwhal round
    tx_narwhal_round_updates: watch::Sender<Round>,
    /// Holds the certificates' ids waiting to be included in the next header.
    last_parents: Vec<Certificate>,
    /// Holds the certificate of the last leader (if any).
    last_leader: Option<Certificate>,
    /// Holds the batches' digests waiting to be included in the next header.
    digests: Vec<(BatchDigest, WorkerId, TimestampMs)>,

    /// Holds the map of proposed previous round headers, used to ensure that
    /// all batches' digest included will eventually be re-sent.
    proposed_headers: BTreeMap<Round, Header>,
    /// Committed headers channel on which we get updates on which of
    /// our own headers have been committed.
    rx_committed_own_headers: Receiver<(Round, Vec<Round>)>,

    /// Metrics handler
    metrics: Arc<PrimaryMetrics>,
}

impl Proposer {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService<Signature, { crypto::DIGEST_LENGTH }>,
        proposer_store: ProposerStore,
        header_num_of_batches_threshold: usize,
        max_header_num_of_batches: usize,
        max_header_delay: Duration,
        min_header_delay: Duration,
        header_resend_timeout: Option<Duration>,
        network_model: NetworkModel,
        rx_shutdown: ConditionalBroadcastReceiver,
        rx_parents: Receiver<(Vec<Certificate>, Round, Epoch)>,
        rx_our_digests: Receiver<OurDigestMessage>,
        tx_headers: Sender<Header>,
        tx_narwhal_round_updates: watch::Sender<Round>,
        rx_committed_own_headers: Receiver<(Round, Vec<Round>)>,
        metrics: Arc<PrimaryMetrics>,
    ) -> JoinHandle<()> {
        let genesis = Certificate::genesis(&committee);
        spawn_logged_monitored_task!(
            async move {
                Self {
                    name,
                    committee,
                    signature_service,
                    header_num_of_batches_threshold,
                    max_header_num_of_batches,
                    max_header_delay,
                    min_header_delay,
                    header_resend_timeout,
                    network_model,
                    rx_shutdown,
                    rx_parents,
                    rx_our_digests,
                    tx_headers,
                    tx_narwhal_round_updates,
                    proposer_store,
                    round: 0,
                    last_parents: genesis,
                    last_leader: None,
                    digests: Vec::with_capacity(2 * max_header_num_of_batches),
                    proposed_headers: BTreeMap::new(),
                    rx_committed_own_headers,
                    metrics,
                }
                .run()
                .await;
            },
            "ProposerTask"
        )
    }

    /// make_header creates a new Header, persists it to database
    /// and sends it to core for processing. If successful, it returns
    /// the number of batch digests included in header.
    async fn make_header(&mut self) -> DagResult<(Header, usize)> {
        // Make a new header.
        let header = self.create_new_header().await?;

        // Store the last header.
        self.proposer_store.write_last_proposed(&header)?;

        #[cfg(feature = "benchmark")]
        for digest in header.payload.keys() {
            // NOTE: This log entry is used to compute performance.
            info!("Created {} -> {:?}", header, digest);
        }

        let num_of_included_digests = header.payload.len();

        // Send the new header to the `Core` that will broadcast and process it.
        self.tx_headers
            .send(header.clone())
            .await
            .map_err(|_| DagError::ShuttingDown)?;

        Ok((header, num_of_included_digests))
    }

    // Creates a new header. Also the method ensures we are protected against equivocation.
    // If we detect that a different header has been already produced for the same round, then
    // this method returns the earlier header. Otherwise the newly created header will be returned.
    async fn create_new_header(&mut self) -> DagResult<Header> {
        let this_round = self.round;
        let this_epoch = self.committee.epoch();

        // Check if we already have stored a header for this round.
        if let Some(last_header) = self.proposer_store.get_last_proposed()? {
            if last_header.round == this_round && last_header.epoch == this_epoch {
                // We have already produced a header for the current round, idempotent re-send
                debug!("Proposer re-using existing header for round {this_round}");
                self.last_parents.clear(); // Clear parents that are now invalid for next round.
                return Ok(last_header);
            }
        }

        // Make a new header.
        let num_of_digests = self.digests.len().min(self.max_header_num_of_batches);
        let digests: Vec<_> = self.digests.drain(..num_of_digests).collect();
        let parents: Vec<_> = self.last_parents.drain(..).collect();

        // Here we check that the timestamp we will include in the header is consistent with the
        // parents, ie our current time is *after* the timestamp in all the included headers. If
        // not we log an error and hope a kind operator fixes the clock.
        let current_time = now();
        let parent_max_time = parents
            .iter()
            .map(|c| c.header.created_at)
            .max()
            .unwrap_or(0);
        if current_time < parent_max_time {
            error!(
                "Current time {} earlier than max parent time {}",
                current_time, parent_max_time
            );
        }

        let header = Header::new(
            self.name.clone(),
            this_round,
            this_epoch,
            digests
                .iter()
                .map(|(digest, worker_id, created_at)| (*digest, (*worker_id, *created_at)))
                .collect(),
            parents.iter().map(|x| x.digest()).collect(),
            &self.signature_service,
        )
        .await;

        let leader_and_support = if this_round % 2 == 0 {
            let leader_name = self.committee.leader(this_round);
            if self.name == leader_name {
                "even_round_is_leader"
            } else {
                "even_round_not_leader"
            }
        } else {
            let leader_name = self.committee.leader(this_round - 1);
            if parents.iter().any(|c| c.origin() == leader_name) {
                "odd_round_gives_support"
            } else {
                "odd_round_no_support"
            }
        };
        self.metrics
            .headers_proposed
            .with_label_values(&[leader_and_support])
            .inc();
        self.metrics.header_parents.observe(parents.len() as f64);

        if enabled!(tracing::Level::DEBUG) {
            let mut msg = format!("Created header {header:?} with parent certificates:\n");
            for parent in parents.iter() {
                msg.push_str(&format!("{parent:?}\n"));
            }
            debug!(msg);
        }

        // Register the header by the current round, to remember that we need to commit
        // it, or re-include the batch digests that it contains.
        self.proposed_headers.insert(this_round, header.clone());

        // Update metrics related to latency
        let mut total_inclusion_secs = 0.0;
        for (_digest, _worker_id, created_at_timestamp) in digests.clone() {
            let batch_inclusion_secs =
                Duration::from_millis(header.created_at - created_at_timestamp).as_secs_f64();
            total_inclusion_secs += batch_inclusion_secs;

            #[cfg(feature = "benchmark")]
            {
                // NOTE: This log entry is used to compute performance.
                tracing::info!(
                    "Batch {:?} from worker {} took {} seconds from creation to be included in a proposed header",
                    _digest,
                    _worker_id,
                    batch_inclusion_secs
                );
            }

            self.metrics
                .proposer_batch_latency
                .observe(batch_inclusion_secs);
        }

        // NOTE: This log entry is used to compute performance.
        let (header_creation_secs, avg_inclusion_secs) = if let Some(digest) = digests.first() {
            (
                Duration::from_millis(header.created_at - digest.2).as_secs_f64(),
                total_inclusion_secs / digests.len() as f64,
            )
        } else {
            (self.max_header_delay.as_secs_f64(), 0.0)
        };
        debug!(
            "Header {:?} was created in {} seconds. Contains {} batches, with average delay {} seconds.",
            header.digest(),
            header_creation_secs,
            digests.len(),
            avg_inclusion_secs,
        );

        Ok(header)
    }

    fn max_delay(&self) -> Duration {
        match self.network_model {
            // In partial synchrony, if this node is going to be the leader of the next
            // round, we set a lower max timeout value to increase its chance of committing
            // the leader.
            NetworkModel::PartiallySynchronous
                if self.committee.leader(self.round + 1) == self.name =>
            {
                self.max_header_delay / 2
            }

            // Otherwise we keep the default timeout value.
            _ => self.max_header_delay,
        }
    }

    fn min_delay(&self) -> Duration {
        match self.network_model {
            // In partial synchrony, if this node is going to be the leader of the next
            // round and there are more than 1 primary in the committee, we use a lower
            // min delay value to increase the chance of committing the leader.
            NetworkModel::PartiallySynchronous
                if self.committee.size() > 1
                    && self.committee.leader(self.round + 1) == self.name =>
            {
                Duration::ZERO
            }

            // Otherwise we keep the default timeout value.
            _ => self.min_header_delay,
        }
    }

    /// Update the last leader certificate. This is only relevant in partial synchrony.
    fn update_leader(&mut self) -> bool {
        let leader_name = self.committee.leader(self.round);
        self.last_leader = self
            .last_parents
            .iter()
            .find(|x| x.origin() == leader_name)
            .cloned();

        if let Some(leader) = self.last_leader.as_ref() {
            debug!("Got leader {} for round {}", leader.origin(), self.round);
        }

        self.last_leader.is_some()
    }

    /// Check whether if this validator is the leader of the round, or if we have
    /// (i) f+1 votes for the leader, (ii) 2f+1 nodes not voting for the leader,
    /// (iii) there is no leader to vote for. This is only relevant in partial synchrony.
    fn enough_votes(&self) -> bool {
        if self.committee.leader(self.round + 1) == self.name {
            return true;
        }

        let leader = match &self.last_leader {
            Some(x) => x.digest(),
            None => return true,
        };

        let mut votes_for_leader = 0;
        let mut no_votes = 0;
        for certificate in &self.last_parents {
            let stake = self.committee.stake(&certificate.origin());
            if certificate.header.parents.contains(&leader) {
                votes_for_leader += stake;
            } else {
                no_votes += stake;
            }
        }

        let mut enough_votes = votes_for_leader >= self.committee.validity_threshold();
        if enough_votes {
            if let Some(leader) = self.last_leader.as_ref() {
                debug!(
                    "Got enough support for leader {} at round {}",
                    leader.origin(),
                    self.round
                );
            }
        }
        enough_votes |= no_votes >= self.committee.quorum_threshold();
        enough_votes
    }

    /// Whether we can advance the DAG or need to wait for the leader/more votes. This is only relevant in
    /// partial synchrony. Note that if we timeout, we ignore this check and advance anyway.
    fn ready(&mut self) -> bool {
        match self.network_model {
            // In asynchrony we advance immediately.
            NetworkModel::Asynchronous => true,

            // In partial synchrony, we need to wait for the leader or for enough votes.
            NetworkModel::PartiallySynchronous => match self.round % 2 {
                0 => self.update_leader(),
                _ => self.enough_votes(),
            },
        }
    }

    /// Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        debug!("Dag starting at round {}", self.round);
        let mut advance = true;

        let timer_start = Instant::now();
        let max_delay_timer = sleep_until(timer_start + self.max_header_delay);
        let min_delay_timer = sleep_until(timer_start + self.min_header_delay);

        let header_resend_timeout = self
            .header_resend_timeout
            .unwrap_or(DEFAULT_HEADER_RESEND_TIMEOUT);
        let mut header_repeat_timer = Box::pin(sleep(header_resend_timeout));
        let mut opt_latest_header = None;

        tokio::pin!(max_delay_timer);
        tokio::pin!(min_delay_timer);

        info!(
            "Proposer on node {} has started successfully with header resend timeout {:?}.",
            self.name, header_resend_timeout
        );
        loop {
            // Check if we can propose a new header. We propose a new header when we have a quorum of parents
            // and one of the following conditions is met:
            // (i) the timer expired (we timed out on the leader or gave up gather votes for the leader),
            // (ii) we have enough digests (header_num_of_batches_threshold) and we are on the happy path (we can vote for
            // the leader or the leader has enough votes to enable a commit). The latter condition only matters
            // in partially synchrony. We guarantee that no more than max_header_num_of_batches are included in
            let enough_parents = !self.last_parents.is_empty();
            let enough_digests = self.digests.len() >= self.header_num_of_batches_threshold;
            let max_delay_timed_out = max_delay_timer.is_elapsed();
            let min_delay_timed_out = min_delay_timer.is_elapsed();

            if (max_delay_timed_out || ((enough_digests || min_delay_timed_out) && advance))
                && enough_parents
            {
                if max_delay_timed_out
                    && matches!(self.network_model, NetworkModel::PartiallySynchronous)
                {
                    // It is expected that this timer expires from time to time. If it expires too often, it
                    // either means some validators are Byzantine or that the network is experiencing periods
                    // of asynchrony. In practice, the latter scenario means we misconfigured the parameter
                    // called `max_header_delay`.
                    debug!("Timer expired for round {}", self.round);
                }

                // Advance to the next round.
                self.round += 1;
                let _ = self.tx_narwhal_round_updates.send(self.round);
                self.metrics.current_round.set(self.round as i64);
                debug!("Dag moved to round {}", self.round);

                // Make a new header.
                match self.make_header().await {
                    Err(e @ DagError::ShuttingDown) => debug!("{e}"),
                    Err(e) => panic!("Unexpected error: {e}"),
                    Ok((header, digests)) => {
                        let reason = if max_delay_timed_out {
                            "max_timeout"
                        } else if enough_digests {
                            "threshold_size_reached"
                        } else {
                            "min_timeout"
                        };

                        // Save the header
                        opt_latest_header = Some(header);
                        header_repeat_timer = Box::pin(sleep(header_resend_timeout));

                        self.metrics
                            .num_of_batch_digests_in_header
                            .with_label_values(&[reason])
                            .observe(digests as f64);
                    }
                }

                // Reschedule the timer.
                let timer_start = Instant::now();
                max_delay_timer
                    .as_mut()
                    .reset(timer_start + self.max_delay());
                min_delay_timer
                    .as_mut()
                    .reset(timer_start + self.min_delay());
            }

            tokio::select! {

                () = &mut header_repeat_timer => {
                    // If the round has not advanced within header_resend_timeout then try to
                    // re-process our own header.
                    if let Some(header) = &opt_latest_header {
                        debug!("resend header {:?}", header);

                        if let Err(err) = self.tx_headers.send(header.clone()).await.map_err(|_| DagError::ShuttingDown) {
                            error!("failed to resend header {:?} : {:?}", header, err);
                        }

                        // we want to reset the timer only when there is already a previous header
                        // created.
                        header_repeat_timer = Box::pin(sleep(header_resend_timeout));
                    }
                }

                Some((commit_round, commit_headers)) = self.rx_committed_own_headers.recv() => {
                    // Remove committed headers from the list of pending
                    for round in &commit_headers {
                        self.proposed_headers.remove(round);
                    }

                    // Now for any round much below the current commit round we re-insert
                    // the batches into the digests we need to send, effectively re-sending
                    // them
                    let mut digests_to_resend = Vec::new();
                    let mut retransmit_rounds = Vec::new();

                    // Iterate in order of rounds of our own headers.
                    for (round_header, header) in &mut self.proposed_headers {
                        // If we are within 2 rounds of the commit we break
                        if round_header + 2 >= commit_round {
                            break;
                        }

                        digests_to_resend.extend(
                            header.payload.iter().map(|(digest, (worker, created_at))| (*digest, *worker, *created_at))
                        );
                        retransmit_rounds.push(*round_header);
                    }

                    if !retransmit_rounds.is_empty() {
                        // Add the digests to retransmit to the digests for the next header
                        digests_to_resend.extend(&self.digests);
                        self.digests = digests_to_resend;

                        // Now delete the headers with batches we re-transmit
                        for round in &retransmit_rounds {
                            self.proposed_headers.remove(round);
                        }

                        debug!(
                            "Retransmit {} batches in undelivered headers {:?} at commit round {:?}, remaining headers {}",
                            self.digests.len(),
                            retransmit_rounds,
                            commit_round,
                            self.proposed_headers.len()
                        );
                    }
                },

                Some((parents, round, epoch)) = self.rx_parents.recv() => {
                    // If the core already moved to the next epoch we should pull the next
                    // committee as well.

                    match epoch.cmp(&self.committee.epoch()) {
                        Ordering::Equal => {
                            // we can proceed.
                        }
                        _ => continue
                    }

                    // Sanity check: verify provided certs are of the correct round & epoch.
                    for parent in parents.iter() {
                        if parent.round() != round || parent.epoch() != epoch {
                            error!("Proposer received certificate {parent:?} that failed to match expected round {round} or epoch {epoch}. This should not be possible.");
                        }
                    }

                    // Compare the parents' round number with our current round.
                    match round.cmp(&self.round) {
                        Ordering::Greater => {
                            // We accept round bigger than our current round to jump ahead in case we were
                            // late (or just joined the network).
                            self.round = round;
                            let _ = self.tx_narwhal_round_updates.send(self.round);
                            self.last_parents = parents;

                            // we re-calculate the timeout to give the opportunity to the node
                            // to propose earlier if it's a leader for the round
                            // Reschedule the timer.
                            let timer_start = Instant::now();
                            max_delay_timer
                                .as_mut()
                                .reset(timer_start + self.max_delay());
                            min_delay_timer
                                .as_mut()
                                .reset(timer_start + self.min_delay());
                        },
                        Ordering::Less => {
                            // Ignore parents from older rounds.
                            continue;
                        },
                        Ordering::Equal => {
                            // The core gives us the parents the first time they are enough to form a quorum.
                            // Then it keeps giving us all the extra parents.
                            self.last_parents.extend(parents)
                        }
                    }

                    // Check whether we can advance to the next round. Note that if we timeout,
                    // we ignore this check and advance anyway.
                    advance = self.ready();

                    let round_type = if self.round % 2 == 0 {
                        "even"
                    } else {
                        "odd"
                    };

                    self.metrics
                    .proposer_ready_to_advance
                    .with_label_values(&[&advance.to_string(), round_type])
                    .inc();
                }

                // Receive digests from our workers.
                Some(OurDigestMessage {
                    digest,
                    worker_id,
                    timestamp,
                    ack_channel,
                }) = self.rx_our_digests.recv() => {
                    let digest_record = (digest, worker_id, timestamp, );
                    self.digests.push(digest_record);
                    // Signal back to the worker that the batch is recorded on the
                    // primary, and will be tracked until inclusion. This means that
                    // if the primary does not fail it will attempt to send the digest
                    // (and re-send if necessary) until it is sequenced, or the end of
                    // the epoch is reached. For the moment this does not persist primary
                    // crashes and re-starts.
                    let _ = ack_channel.send(());
                }

                // Check whether any timer expired.
                () = &mut max_delay_timer, if !max_delay_timed_out => {
                    // Continue to next iteration of the loop.
                }
                () = &mut min_delay_timer, if !min_delay_timed_out => {
                    // Continue to next iteration of the loop.
                }

                _ = self.rx_shutdown.receiver.recv() => {
                    return
                }
            }

            // update metrics
            self.metrics
                .num_of_pending_batches_in_proposer
                .set(self.digests.len() as i64);
        }
    }
}
