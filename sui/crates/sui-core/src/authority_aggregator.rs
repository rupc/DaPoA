// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::authority_client::{
    make_authority_clients, make_network_authority_client_sets_from_committee,
    make_network_authority_client_sets_from_system_state, AuthorityAPI, NetworkAuthorityClient,
};
use crate::safe_client::{SafeClient, SafeClientMetrics, SafeClientMetricsBase};
use crate::validator_info::make_committee;
use futures::{future::BoxFuture, stream::FuturesUnordered, StreamExt};
use mysten_metrics::monitored_future;
use mysten_network::config::Config;
use std::convert::AsRef;
use sui_config::genesis::Genesis;
use sui_config::NetworkConfig;
use sui_network::{
    default_mysten_network_config, DEFAULT_CONNECT_TIMEOUT_SEC, DEFAULT_REQUEST_TIMEOUT_SEC,
};
use sui_types::crypto::{AuthorityPublicKeyBytes, AuthoritySignInfo};
use sui_types::error::UserInputError;
use sui_types::fp_ensure;
use sui_types::message_envelope::Message;
use sui_types::object::Object;
use sui_types::sui_system_state::SuiSystemState;
use sui_types::{
    base_types::*,
    committee::{Committee, ProtocolVersion},
    error::{SuiError, SuiResult},
    messages::*,
};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn, Instrument};

use prometheus::{
    register_histogram_with_registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, Histogram, IntCounter, IntCounterVec, Registry,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;
use sui_types::committee::{CommitteeWithNetAddresses, StakeUnit};
use tokio::time::{sleep, timeout};

use crate::authority::AuthorityStore;
use crate::epoch::committee_store::CommitteeStore;
use crate::stake_aggregator::{InsertResult, MultiStakeAggregator, StakeAggregator};

pub const DEFAULT_RETRIES: usize = 4;

#[cfg(test)]
#[path = "unit_tests/authority_aggregator_tests.rs"]
pub mod authority_aggregator_tests;

pub type AsyncResult<'a, T, E> = BoxFuture<'a, Result<T, E>>;

#[derive(Clone)]
pub struct TimeoutConfig {
    // Timeout used when making many concurrent requests - ok if it is large because a slow
    // authority won't block other authorities from being contacted.
    pub authority_request_timeout: Duration,
    pub pre_quorum_timeout: Duration,
    pub post_quorum_timeout: Duration,

    // Timeout used when making serial requests. Should be smaller, since we wait to hear from each
    // authority before continuing.
    pub serial_authority_request_timeout: Duration,

    // Timeout used to determine when to start a second "serial" request for
    // quorum_once_with_timeout. This is a latency optimization that prevents us from having
    // to wait an entire serial_authority_request_timeout interval before starting a second
    // request.
    //
    // If this is set to zero, then quorum_once_with_timeout becomes completely parallelized - if
    // it is set to a value greater than serial_authority_request_timeout then it becomes
    // completely serial.
    pub serial_authority_request_interval: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            authority_request_timeout: Duration::from_secs(60),
            pre_quorum_timeout: Duration::from_secs(60),
            post_quorum_timeout: Duration::from_secs(30),
            serial_authority_request_timeout: Duration::from_secs(5),
            serial_authority_request_interval: Duration::from_millis(1000),
        }
    }
}

/// Prometheus metrics which can be displayed in Grafana, queried and alerted on
#[derive(Clone)]
pub struct AuthAggMetrics {
    pub total_tx_certificates_created: IntCounter,
    pub num_signatures: Histogram,
    pub num_good_stake: Histogram,
    pub num_bad_stake: Histogram,
    pub total_quorum_once_timeout: IntCounter,
    pub process_tx_errors: IntCounterVec,
    pub process_cert_errors: IntCounterVec,
}

// Override default Prom buckets for positive numbers in 0-50k range
const POSITIVE_INT_BUCKETS: &[f64] = &[
    1., 2., 5., 10., 20., 50., 100., 200., 500., 1000., 2000., 5000., 10000., 20000., 50000.,
];

impl AuthAggMetrics {
    pub fn new(registry: &prometheus::Registry) -> Self {
        Self {
            total_tx_certificates_created: register_int_counter_with_registry!(
                "total_tx_certificates_created",
                "Total number of certificates made in the authority_aggregator",
                registry,
            )
            .unwrap(),
            // It's really important to use the right histogram buckets for accurate histogram collection.
            // Otherwise values get clipped
            num_signatures: register_histogram_with_registry!(
                "num_signatures_per_tx",
                "Number of signatures collected per transaction",
                POSITIVE_INT_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            num_good_stake: register_histogram_with_registry!(
                "num_good_stake_per_tx",
                "Amount of good stake collected per transaction",
                POSITIVE_INT_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            num_bad_stake: register_histogram_with_registry!(
                "num_bad_stake_per_tx",
                "Amount of bad stake collected per transaction",
                POSITIVE_INT_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            total_quorum_once_timeout: register_int_counter_with_registry!(
                "total_quorum_once_timeout",
                "Total number of timeout when calling quorum_once_with_timeout",
                registry,
            )
            .unwrap(),
            process_tx_errors: register_int_counter_vec_with_registry!(
                "process_tx_errors",
                "Number of errors returned from validators when processing transaction, group by validator name and error type",
                &["name","error"],
                registry,
            )
            .unwrap(),
            process_cert_errors: register_int_counter_vec_with_registry!(
                "process_cert_errors",
                "Number of errors returned from validators when processing certificate, group by validator name and error type",
                &["name", "error"],
                registry,
            )
            .unwrap(),
        }
    }

    pub fn new_for_tests() -> Self {
        let registry = prometheus::Registry::new();
        Self::new(&registry)
    }
}

#[derive(Error, Debug)]
#[error(
    "Failed to execute certificate on a quorum of validators. Validator errors: {:?}",
    errors
)]
pub struct QuorumExecuteCertificateError {
    pub total_stake: StakeUnit,
    pub errors: Vec<(SuiError, Vec<AuthorityName>, StakeUnit)>,
}

#[derive(Error, Debug)]
#[error(
    "Failed to execute transaction on a quorum of validators to form a transaction certificate. Locked objects: {:?}. Validator errors: {:?}",
    conflicting_tx_digests,
    errors,
)]
pub struct QuorumSignTransactionError {
    pub total_stake: StakeUnit,
    pub good_stake: StakeUnit,
    pub errors: Vec<(SuiError, Vec<AuthorityName>, StakeUnit)>,
    pub conflicting_tx_digests:
        BTreeMap<TransactionDigest, (Vec<(AuthorityName, ObjectRef)>, StakeUnit)>,
}

struct ProcessTransactionState {
    // The list of signatures gathered at any point
    tx_signatures: StakeAggregator<AuthoritySignInfo, true>,
    effects_map: MultiStakeAggregator<TransactionEffectsDigest, TransactionEffects, true>,
    // The list of errors gathered at any point
    errors: Vec<(SuiError, Vec<AuthorityName>, StakeUnit)>,
    bad_stake: StakeUnit,
    // If there are conflicting transactions, we note them down and may attempt to retry
    conflicting_tx_digests:
        BTreeMap<TransactionDigest, (Vec<(AuthorityName, ObjectRef)>, StakeUnit)>,
}

impl ProcessTransactionState {
    pub fn good_stake(&self) -> StakeUnit {
        self.tx_signatures.total_votes() + self.effects_map.total_votes()
    }
}

struct ProcessCertificateState {
    // Different authorities could return different effects.  We want at least one effect to come
    // from 2f+1 authorities, which meets quorum and can be considered the approved effect.
    // The map here allows us to count the stake for each unique effect.
    effects_map:
        MultiStakeAggregator<(EpochId, TransactionEffectsDigest), TransactionEffects, true>,
    bad_stake: StakeUnit,
    errors: Vec<(SuiError, Vec<AuthorityName>, StakeUnit)>,
}

#[derive(Debug)]
pub enum ProcessTransactionResult {
    Certified(VerifiedCertificate),
    Executed(VerifiedCertifiedTransactionEffects, TransactionEvents),
}

impl ProcessTransactionResult {
    pub fn into_cert_for_testing(self) -> VerifiedCertificate {
        match self {
            Self::Certified(cert) => cert,
            Self::Executed(..) => panic!("Wrong type"),
        }
    }
}

#[derive(Clone)]
pub struct AuthorityAggregator<A> {
    /// Our Sui committee.
    pub committee: Committee,
    /// How to talk to this committee.
    pub authority_clients: BTreeMap<AuthorityName, SafeClient<A>>,
    /// Metrics
    pub metrics: AuthAggMetrics,
    /// Metric base for the purpose of creating new safe clients during reconfiguration.
    pub safe_client_metrics_base: SafeClientMetricsBase,
    pub timeouts: TimeoutConfig,
    /// Store here for clone during re-config.
    pub committee_store: Arc<CommitteeStore>,
}

impl<A> AuthorityAggregator<A> {
    pub fn new(
        committee: Committee,
        committee_store: Arc<CommitteeStore>,
        authority_clients: BTreeMap<AuthorityName, A>,
        registry: &Registry,
    ) -> Self {
        Self::new_with_timeouts(
            committee,
            committee_store,
            authority_clients,
            registry,
            Default::default(),
        )
    }

    pub fn new_with_timeouts(
        committee: Committee,
        committee_store: Arc<CommitteeStore>,
        authority_clients: BTreeMap<AuthorityName, A>,
        registry: &Registry,
        timeouts: TimeoutConfig,
    ) -> Self {
        let safe_client_metrics_base = SafeClientMetricsBase::new(registry);
        Self {
            committee,
            authority_clients: authority_clients
                .into_iter()
                .map(|(name, api)| {
                    (
                        name,
                        SafeClient::new(
                            api,
                            committee_store.clone(),
                            name,
                            SafeClientMetrics::new(&safe_client_metrics_base, name),
                        ),
                    )
                })
                .collect(),
            metrics: AuthAggMetrics::new(registry),
            safe_client_metrics_base,
            timeouts,
            committee_store,
        }
    }

    pub fn new_with_metrics(
        committee: Committee,
        committee_store: Arc<CommitteeStore>,
        authority_clients: BTreeMap<AuthorityName, A>,
        safe_client_metrics_base: SafeClientMetricsBase,
        auth_agg_metrics: AuthAggMetrics,
    ) -> Self {
        Self {
            committee,
            authority_clients: authority_clients
                .into_iter()
                .map(|(name, api)| {
                    (
                        name,
                        SafeClient::new(
                            api,
                            committee_store.clone(),
                            name,
                            SafeClientMetrics::new(&safe_client_metrics_base, name),
                        ),
                    )
                })
                .collect(),
            metrics: auth_agg_metrics,
            safe_client_metrics_base,
            timeouts: Default::default(),
            committee_store,
        }
    }

    /// This function recreates AuthorityAggregator with the given committee.
    /// It also updates committee store which impacts other of its references.
    /// When disallow_missing_intermediate_committees is true, it requires the
    /// new committee needs to be current epoch + 1.
    /// The function could be used along with `reconfig_from_genesis` to fill in
    /// all previous epoch's committee info.
    pub fn recreate_with_net_addresses(
        &self,
        committee: CommitteeWithNetAddresses,
        network_config: &Config,
        disallow_missing_intermediate_committees: bool,
    ) -> SuiResult<AuthorityAggregator<NetworkAuthorityClient>> {
        let network_clients =
            make_network_authority_client_sets_from_committee(&committee, network_config).map_err(
                |err| SuiError::GenericAuthorityError {
                    error: format!(
                        "Failed to make authority clients from committee {committee}, err: {:?}",
                        err
                    ),
                },
            )?;

        let safe_clients = network_clients
            .into_iter()
            .map(|(name, api)| {
                (
                    name,
                    SafeClient::new(
                        api,
                        self.committee_store.clone(),
                        name,
                        SafeClientMetrics::new(&self.safe_client_metrics_base, name),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();

        // TODO: It's likely safer to do the following operations atomically, in case this function
        // gets called from different threads. It cannot happen today, but worth the caution.
        let new_committee = committee.committee;
        if disallow_missing_intermediate_committees {
            fp_ensure!(
                self.committee.epoch + 1 == new_committee.epoch,
                SuiError::AdvanceEpochError {
                    error: format!(
                        "Trying to advance from epoch {} to epoch {}",
                        self.committee.epoch, new_committee.epoch
                    )
                }
            );
        }
        // This call may return error if this committee is already inserted,
        // which is fine. We should continue to construct the new aggregator.
        // This is because there may be multiple AuthorityAggregators
        // or its containers (e.g. Quorum Drivers)  share the same committee
        // store and all of them need to reconfigure.
        let _ = self.committee_store.insert_new_committee(&new_committee);
        Ok(AuthorityAggregator {
            committee: new_committee,
            authority_clients: safe_clients,
            metrics: self.metrics.clone(),
            timeouts: self.timeouts.clone(),
            safe_client_metrics_base: self.safe_client_metrics_base.clone(),
            committee_store: self.committee_store.clone(),
        })
    }

    pub fn get_client(&self, name: &AuthorityName) -> Option<&SafeClient<A>> {
        self.authority_clients.get(name)
    }

    pub fn clone_client(&self, name: &AuthorityName) -> SafeClient<A>
    where
        A: Clone,
    {
        self.authority_clients[name].clone()
    }

    pub fn clone_inner_clients(&self) -> BTreeMap<AuthorityName, A>
    where
        A: Clone,
    {
        let mut clients = BTreeMap::new();
        for (name, client) in &self.authority_clients {
            clients.insert(*name, client.authority_client().clone());
        }
        clients
    }

    pub fn clone_committee_store(&self) -> Arc<CommitteeStore> {
        self.committee_store.clone()
    }
}

impl AuthorityAggregator<NetworkAuthorityClient> {
    /// Create a new network authority aggregator by reading the committee and
    /// network address information from the system state object on-chain.
    /// This function needs metrics parameters because registry will panic
    /// if we attempt to register already-registered metrics again.
    pub fn new_from_local_system_state(
        store: &Arc<AuthorityStore>,
        committee_store: &Arc<CommitteeStore>,
        safe_client_metrics_base: SafeClientMetricsBase,
        auth_agg_metrics: AuthAggMetrics,
    ) -> anyhow::Result<Self> {
        let sui_system_state = store.get_sui_system_state_object()?;
        Self::new_from_system_state(
            &sui_system_state,
            committee_store,
            safe_client_metrics_base,
            auth_agg_metrics,
        )
    }

    pub fn new_from_system_state(
        sui_system_state: &SuiSystemState,
        committee_store: &Arc<CommitteeStore>,
        safe_client_metrics_base: SafeClientMetricsBase,
        auth_agg_metrics: AuthAggMetrics,
    ) -> anyhow::Result<Self> {
        let net_config = default_mysten_network_config();
        // TODO: the function returns on URL parsing errors. In this case we should
        // tolerate it as long as we have 2f+1 good validators.
        // GH issue: https://github.com/MystenLabs/sui/issues/7019
        let authority_clients =
            make_network_authority_client_sets_from_system_state(sui_system_state, &net_config)?;
        Ok(Self::new_with_metrics(
            sui_system_state.get_current_epoch_committee().committee,
            committee_store.clone(),
            authority_clients,
            safe_client_metrics_base,
            auth_agg_metrics,
        ))
    }
}

pub enum ReduceOutput<R, S> {
    Continue(S),
    ContinueWithTimeout(S, Duration),
    Failed(S),
    Success(R),
}

impl<A> AuthorityAggregator<A>
where
    A: AuthorityAPI + Send + Sync + 'static + Clone,
{
    /// This function takes an initial state, than executes an asynchronous function (FMap) for each
    /// authority, and folds the results as they become available into the state using an async function (FReduce).
    ///
    /// FMap can do io, and returns a result V. An error there may not be fatal, and could be consumed by the
    /// MReduce function to overall recover from it. This is necessary to ensure byzantine authorities cannot
    /// interrupt the logic of this function.
    ///
    /// FReduce returns a result to a ReduceOutput. If the result is Err the function
    /// shortcuts and the Err is returned. An Ok ReduceOutput result can be used to shortcut and return
    /// the resulting state (ReduceOutput::End), continue the folding as new states arrive (ReduceOutput::Continue),
    /// or continue with a timeout maximum waiting time (ReduceOutput::ContinueWithTimeout).
    ///
    /// This function provides a flexible way to communicate with a quorum of authorities, processing and
    /// processing their results into a safe overall result, and also safely allowing operations to continue
    /// past the quorum to ensure all authorities are up to date (up to a timeout).
    pub(crate) async fn quorum_map_then_reduce_with_timeout<'a, S, V, R, FMap, FReduce>(
        &'a self,
        // The initial state that will be used to fold in values from authorities.
        initial_state: S,
        // The async function used to apply to each authority. It takes an authority name,
        // and authority client parameter and returns a Result<V>.
        map_each_authority: FMap,
        // The async function that takes an accumulated state, and a new result for V from an
        // authority and returns a result to a ReduceOutput state.
        reduce_result: FReduce,
        // The initial timeout applied to all
        initial_timeout: Duration,
    ) -> Result<R, S>
    where
        FMap: FnOnce(AuthorityName, &'a SafeClient<A>) -> AsyncResult<'a, V, SuiError> + Clone,
        FReduce: Fn(
            S,
            AuthorityName,
            StakeUnit,
            Result<V, SuiError>,
        ) -> BoxFuture<'a, ReduceOutput<R, S>>,
    {
        self.quorum_map_then_reduce_with_timeout_and_prefs(
            None,
            initial_state,
            map_each_authority,
            reduce_result,
            initial_timeout,
        )
        .await
    }

    pub(crate) async fn quorum_map_then_reduce_with_timeout_and_prefs<'a, S, V, R, FMap, FReduce>(
        &'a self,
        authority_preferences: Option<&BTreeSet<AuthorityName>>,
        initial_state: S,
        map_each_authority: FMap,
        reduce_result: FReduce,
        initial_timeout: Duration,
    ) -> Result<R, S>
    where
        FMap: FnOnce(AuthorityName, &'a SafeClient<A>) -> AsyncResult<'a, V, SuiError> + Clone,
        FReduce: Fn(
            S,
            AuthorityName,
            StakeUnit,
            Result<V, SuiError>,
        ) -> BoxFuture<'a, ReduceOutput<R, S>>,
    {
        let authorities_shuffled = self.committee.shuffle_by_stake(authority_preferences, None);

        // First, execute in parallel for each authority FMap.
        let mut responses: futures::stream::FuturesUnordered<_> = authorities_shuffled
            .iter()
            .map(|name| {
                let client = &self.authority_clients[name];
                let execute = map_each_authority.clone();
                monitored_future!(async move {
                    (
                        *name,
                        execute(*name, client)
                            .instrument(tracing::trace_span!("quorum_map_auth", authority =? name.concise()))
                            .await,
                    )
                })
            })
            .collect();

        let mut current_timeout = initial_timeout;
        let mut accumulated_state = initial_state;
        // Then, as results become available fold them into the state using FReduce.
        while let Ok(Some((authority_name, result))) =
            timeout(current_timeout, responses.next()).await
        {
            let authority_weight = self.committee.weight(&authority_name);
            accumulated_state =
                match reduce_result(accumulated_state, authority_name, authority_weight, result)
                    .await
                {
                    // In the first two cases we are told to continue the iteration.
                    ReduceOutput::Continue(state) => state,
                    ReduceOutput::ContinueWithTimeout(state, duration) => {
                        // Adjust the waiting timeout.
                        current_timeout = duration;
                        state
                    }
                    ReduceOutput::Failed(state) => {
                        return Err(state);
                    }
                    ReduceOutput::Success(result) => {
                        // The reducer tells us that we have the result needed. Just return it.
                        return Ok(result);
                    }
                }
        }
        // If we have exhausted all authorities and still have not returned a result, return
        // error with the accumulated state.
        Err(accumulated_state)
    }

    // Repeatedly calls the provided closure on a randomly selected validator until it succeeds.
    // Once all validators have been attempted, starts over at the beginning. Intended for cases
    // that must eventually succeed as long as the network is up (or comes back up) eventually.
    async fn quorum_once_inner<'a, S, FMap>(
        &'a self,
        // try these authorities first
        preferences: Option<&BTreeSet<AuthorityName>>,
        // only attempt from these authorities.
        restrict_to: Option<&BTreeSet<AuthorityName>>,
        // The async function used to apply to each authority. It takes an authority name,
        // and authority client parameter and returns a Result<V>.
        map_each_authority: FMap,
        timeout_each_authority: Duration,
        authority_errors: &mut HashMap<AuthorityName, SuiError>,
    ) -> Result<S, SuiError>
    where
        FMap: Fn(AuthorityName, SafeClient<A>) -> AsyncResult<'a, S, SuiError> + Send + Clone + 'a,
        S: Send,
    {
        let start = tokio::time::Instant::now();
        let mut delay = Duration::from_secs(1);
        loop {
            let authorities_shuffled = self.committee.shuffle_by_stake(preferences, restrict_to);
            let mut authorities_shuffled = authorities_shuffled.iter();

            type RequestResult<S> = Result<Result<S, SuiError>, tokio::time::error::Elapsed>;

            enum Event<S> {
                StartNext,
                Request(AuthorityName, RequestResult<S>),
            }

            let mut futures = FuturesUnordered::<BoxFuture<'a, Event<S>>>::new();

            let start_req = |name: AuthorityName, client: SafeClient<A>| {
                let map_each_authority = map_each_authority.clone();
                Box::pin(monitored_future!(async move {
                    trace!(name=?name.concise(), now = ?tokio::time::Instant::now() - start, "new request");
                    let map = map_each_authority(name, client);
                    Event::Request(name, timeout(timeout_each_authority, map).await)
                }))
            };

            let schedule_next = || {
                let delay = self.timeouts.serial_authority_request_interval;
                Box::pin(monitored_future!(async move {
                    sleep(delay).await;
                    Event::StartNext
                }))
            };

            // This process is intended to minimize latency in the face of unreliable authorities,
            // without creating undue load on authorities.
            //
            // The fastest possible process from the
            // client's point of view would simply be to issue a concurrent request to every
            // authority and then take the winner - this would create unnecessary load on
            // authorities.
            //
            // The most efficient process from the network's point of view is to do one request at
            // a time, however if the first validator that the client contacts is unavailable or
            // slow, the client must wait for the serial_authority_request_interval period to elapse
            // before starting its next request.
            //
            // So, this process is designed as a compromise between these two extremes.
            // - We start one request, and schedule another request to begin after
            //   serial_authority_request_interval.
            // - Whenever a request finishes, if it succeeded, we return. if it failed, we start a
            //   new request.
            // - If serial_authority_request_interval elapses, we begin a new request even if the
            //   previous one is not finished, and schedule another future request.

            let name = authorities_shuffled.next().ok_or_else(|| {
                error!(
                    ?preferences,
                    ?restrict_to,
                    "Available authorities list is empty."
                );
                SuiError::from("Available authorities list is empty")
            })?;
            futures.push(start_req(*name, self.authority_clients[name].clone()));
            futures.push(schedule_next());

            while let Some(res) = futures.next().await {
                match res {
                    Event::StartNext => {
                        trace!(now = ?tokio::time::Instant::now() - start, "eagerly beginning next request");
                        futures.push(schedule_next());
                    }
                    Event::Request(name, res) => {
                        match res {
                            // timeout
                            Err(_) => {
                                debug!(name=?name.concise(), "authority request timed out");
                                authority_errors.insert(name, SuiError::TimeoutError);
                            }
                            // request completed
                            Ok(inner_res) => {
                                trace!(name=?name.concise(), now = ?tokio::time::Instant::now() - start,
                                       "request completed successfully");
                                match inner_res {
                                    Err(e) => authority_errors.insert(name, e),
                                    Ok(res) => return Ok(res),
                                };
                            }
                        };
                    }
                }

                if let Some(next_authority) = authorities_shuffled.next() {
                    futures.push(start_req(
                        *next_authority,
                        self.authority_clients[next_authority].clone(),
                    ));
                } else {
                    break;
                }
            }

            info!(
                ?authority_errors,
                "quorum_once_with_timeout failed on all authorities, retrying in {:?}", delay
            );
            sleep(delay).await;
            delay = std::cmp::min(delay * 2, Duration::from_secs(5 * 60));
        }
    }

    /// Like quorum_map_then_reduce_with_timeout, but for things that need only a single
    /// successful response, such as fetching a Transaction from some authority.
    /// This is intended for cases in which byzantine authorities can time out or slow-loris, but
    /// can't give a false answer, because e.g. the digest of the response is known, or a
    /// quorum-signed object such as a checkpoint has been requested.
    pub(crate) async fn quorum_once_with_timeout<'a, S, FMap>(
        &'a self,
        // try these authorities first
        preferences: Option<&BTreeSet<AuthorityName>>,
        // only attempt from these authorities.
        restrict_to: Option<&BTreeSet<AuthorityName>>,
        // The async function used to apply to each authority. It takes an authority name,
        // and authority client parameter and returns a Result<V>.
        map_each_authority: FMap,
        timeout_each_authority: Duration,
        // When to give up on the attempt entirely.
        timeout_total: Option<Duration>,
        // The behavior that authorities expect to perform, used for logging and error
        description: String,
    ) -> Result<S, SuiError>
    where
        FMap: Fn(AuthorityName, SafeClient<A>) -> AsyncResult<'a, S, SuiError> + Send + Clone + 'a,
        S: Send,
    {
        let mut authority_errors = HashMap::new();

        let fut = self.quorum_once_inner(
            preferences,
            restrict_to,
            map_each_authority,
            timeout_each_authority,
            &mut authority_errors,
        );

        if let Some(t) = timeout_total {
            timeout(t, fut).await.map_err(|_timeout_error| {
                if authority_errors.is_empty() {
                    self.metrics.total_quorum_once_timeout.inc();
                    SuiError::TimeoutError
                } else {
                    SuiError::TooManyIncorrectAuthorities {
                        errors: authority_errors
                            .iter()
                            .map(|(a, b)| (*a, b.clone()))
                            .collect(),
                        action: description,
                    }
                }
            })?
        } else {
            fut.await
        }
    }

    /// Query the object with highest version number from the authorities.
    /// We stop after receiving responses from 2f+1 validators.
    /// This function is untrusted because we simply assume each response is valid and there are no
    /// byzantine validators.
    /// Because of this, this function should only be used for testing or benchmarking.
    pub async fn get_latest_object_version_for_testing(
        &self,
        object_id: ObjectID,
    ) -> SuiResult<Object> {
        #[derive(Debug, Default)]
        struct State {
            latest_object_version: Option<Object>,
            total_weight: StakeUnit,
        }
        let initial_state = State::default();
        self
            .quorum_map_then_reduce_with_timeout(
                initial_state,
                |_name, client| {
                    Box::pin(async move {
                        let request =
                            ObjectInfoRequest::latest_object_info_request(object_id, None);
                        client.handle_object_info_request(request).await
                    })
                },
                |mut state, name, weight, result| {
                    Box::pin(async move {
                        state.total_weight += weight;
                        match result {
                            Ok(object_info) => {
                                debug!("Received object info response from validator {:?} with version: {:?}", name.concise(), object_info.object.version());
                                if state.latest_object_version.as_ref().map_or(true, |latest| {
                                    object_info.object.version() > latest.version()
                                }) {
                                    state.latest_object_version = Some(object_info.object);
                                }
                            }
                            Err(err) => {
                                debug!("Received error from validator {:?}: {:?}", name.concise(), err);
                            }
                        };
                        if state.total_weight >= self.committee.quorum_threshold() {
                            if let Some(object) = state.latest_object_version {
                                return ReduceOutput::Success(object);
                            } else {
                                return ReduceOutput::Failed(state);
                            }
                        }
                        ReduceOutput::Continue(state)
                    })
                },
                // A long timeout before we hear back from a quorum
                self.timeouts.pre_quorum_timeout,
            )
            .await.map_err(|_state| UserInputError::ObjectNotFound {
                object_id,
                version: None,
            }.into())
    }

    /// Get the latest system state object from the authorities.
    /// This function assumes all validators are honest.
    /// It should only be used for testing or benchmarking.
    pub async fn get_latest_system_state_object_for_testing(
        &self,
    ) -> anyhow::Result<SuiSystemState> {
        #[derive(Debug, Default)]
        struct State {
            latest_system_state: Option<SuiSystemState>,
            total_weight: StakeUnit,
        }
        let initial_state = State::default();
        self.quorum_map_then_reduce_with_timeout(
            initial_state,
            |_name, client| Box::pin(async move { client.handle_system_state_object().await }),
            |mut state, name, weight, result| {
                Box::pin(async move {
                    state.total_weight += weight;
                    match result {
                        Ok(system_state) => {
                            debug!(
                                "Received system state object from validator {:?} with epoch: {:?}",
                                name.concise(),
                                system_state.epoch
                            );
                            if state
                                .latest_system_state
                                .as_ref()
                                .map_or(true, |latest| system_state.epoch > latest.epoch)
                            {
                                state.latest_system_state = Some(system_state);
                            }
                        }
                        Err(err) => {
                            debug!(
                                "Received error from validator {:?}: {:?}",
                                name.concise(),
                                err
                            );
                        }
                    };
                    if state.total_weight >= self.committee.quorum_threshold() {
                        if let Some(system_state) = state.latest_system_state {
                            return ReduceOutput::Success(system_state);
                        } else {
                            return ReduceOutput::Failed(state);
                        }
                    }
                    ReduceOutput::Continue(state)
                })
            },
            // A long timeout before we hear back from a quorum
            self.timeouts.pre_quorum_timeout,
        )
        .await
        .map_err(|_| anyhow::anyhow!("Failed to get latest system state from the authorities"))
    }

    /// Submits the transaction to a quorum of validators to make a certificate.
    pub async fn process_transaction(
        &self,
        transaction: VerifiedTransaction,
    ) -> Result<ProcessTransactionResult, QuorumSignTransactionError> {
        // Now broadcast the transaction to all authorities.
        let tx_digest = transaction.digest();
        debug!(
            tx_digest = ?tx_digest,
            "Broadcasting transaction request to authorities"
        );
        trace!(
            "Transaction data: {:?}",
            transaction.data().intent_message.value
        );

        let committee = Arc::new(self.committee.clone());
        let state = ProcessTransactionState {
            tx_signatures: StakeAggregator::new(committee.clone()),
            effects_map: MultiStakeAggregator::new(committee.clone()),
            errors: vec![],
            bad_stake: 0,
            conflicting_tx_digests: Default::default(),
        };

        let transaction_ref = &transaction;
        let validity_threshold = committee.validity_threshold();
        let result = self
            .quorum_map_then_reduce_with_timeout(
                state,
                |_name, client| {
                    Box::pin(
                        async move { client.handle_transaction(transaction_ref.clone()).await },
                    )
                },
                |mut state, name, weight, response| {
                    Box::pin(async move {
                        match self.handle_process_transaction_response(
                            tx_digest, &mut state, response, name, weight,
                        ) {
                            Ok(Some(result)) => {
                                self.record_process_transaction_metrics(tx_digest, &state);
                                ReduceOutput::Success(result)
                            }
                            Ok(None) => ReduceOutput::Continue(state),
                            Err(err) => {
                                debug!(?tx_digest, name=?name.concise(), weight, "Error processing transaction from validator: {:?}", err);
                                self.metrics
                                    .process_tx_errors
                                    .with_label_values(&[&name.concise().to_string(), err.as_ref()])
                                    .inc();
                                state.bad_stake += weight;
                                state.errors.push((err, vec![name], weight));

                                if state.bad_stake > validity_threshold {
                                    ReduceOutput::Failed(state)
                                } else {
                                    ReduceOutput::Continue(state)
                                }
                            }
                        }
                    })
                },
                // A long timeout before we hear back from a quorum
                self.timeouts.pre_quorum_timeout,
            )
            .await;

        match result {
            Ok(result) => Ok(result),
            Err(state) => {
                self.record_process_transaction_metrics(tx_digest, &state);
                let state = Self::record_non_quorum_effects_maybe(tx_digest, state);
                Err(QuorumSignTransactionError {
                    total_stake: self.committee.total_votes,
                    good_stake: state.good_stake(),
                    errors: state.errors,
                    conflicting_tx_digests: state.conflicting_tx_digests,
                })
            }
        }
    }

    fn record_process_transaction_metrics(
        &self,
        tx_digest: &TransactionDigest,
        state: &ProcessTransactionState,
    ) {
        // TODO: Revisit whether we need these metrics.
        let num_signatures = state.tx_signatures.validator_sig_count();
        self.metrics.num_signatures.observe(num_signatures as f64);
        let good_stake = state.good_stake();
        self.metrics.num_good_stake.observe(good_stake as f64);
        self.metrics.num_bad_stake.observe(state.bad_stake as f64);
        debug!(
            ?tx_digest,
            num_errors = state.errors.iter().map(|e| e.1.len()).sum::<usize>(),
            num_unique_errors = state.errors.len(),
            ?good_stake,
            bad_stake = state.bad_stake,
            ?num_signatures,
            "Received signatures response from validators handle_transaction"
        );
        if !state.errors.is_empty() {
            debug!(?tx_digest, "Errors received: {:?}", state.errors);
        }
    }

    fn handle_process_transaction_response(
        &self,
        tx_digest: &TransactionDigest,
        state: &mut ProcessTransactionState,
        response: SuiResult<VerifiedTransactionInfoResponse>,
        name: AuthorityName,
        weight: StakeUnit,
    ) -> SuiResult<Option<ProcessTransactionResult>> {
        match response {
            Ok(VerifiedTransactionInfoResponse::Signed(signed)) => {
                debug!(?tx_digest, name=?name.concise(), weight, "Received signed transaction from validator handle_transaction");
                self.handle_transaction_response_with_signed(state, signed)
            }
            Ok(VerifiedTransactionInfoResponse::ExecutedWithCert(cert, effects, events)) => {
                debug!(?tx_digest, name=?name.concise(), weight, "Received prev certificate and effects from validator handle_transaction");
                self.handle_transaction_response_with_executed(state, Some(cert), effects, events)
            }
            Ok(VerifiedTransactionInfoResponse::ExecutedWithoutCert(_, effects, events)) => {
                debug!(?tx_digest, name=?name.concise(), weight, "Received prev effects from validator handle_transaction");
                self.handle_transaction_response_with_executed(state, None, effects, events)
            }
            Err(err) => {
                self.record_conflicting_transaction_if_any(state, name, weight, &err);
                Err(err)
            }
        }
    }

    // TODO: This should really be done at higher level such as quorum driver, not here.
    fn record_conflicting_transaction_if_any(
        &self,
        state: &mut ProcessTransactionState,
        name: AuthorityName,
        weight: StakeUnit,
        err: &SuiError,
    ) {
        if let SuiError::ObjectLockConflict {
            obj_ref,
            pending_transaction,
        } = err
        {
            let (lock_records, total_stake) = state
                .conflicting_tx_digests
                .entry(*pending_transaction)
                .or_insert((Vec::new(), 0));
            lock_records.push((name, *obj_ref));
            *total_stake += weight;
        }
    }

    fn handle_transaction_response_with_signed(
        &self,
        state: &mut ProcessTransactionState,
        signed_transaction: VerifiedSignedTransaction,
    ) -> SuiResult<Option<ProcessTransactionResult>> {
        let (data, sig) = signed_transaction.into_inner().into_data_and_sig();
        match state.tx_signatures.insert(sig) {
            InsertResult::NotEnoughVotes => Ok(None),
            InsertResult::Failed { error } => Err(error),
            InsertResult::QuorumReached(cert_sig) => {
                let ct = CertifiedTransaction::new_from_data_and_sig(data, cert_sig);
                Ok(Some(ProcessTransactionResult::Certified(
                    ct.verify(&self.committee)?,
                )))
            }
        }
    }

    fn handle_transaction_response_with_executed(
        &self,
        state: &mut ProcessTransactionState,
        certificate: Option<VerifiedCertificate>,
        signed_effects: VerifiedSignedTransactionEffects,
        events: TransactionEvents,
    ) -> SuiResult<Option<ProcessTransactionResult>> {
        match certificate {
            Some(certificate) if certificate.epoch() == self.committee.epoch => {
                // If we get a certificate in the same epoch, then we use it.
                // A certificate in a past epoch does not guarantee finality
                // and validators may reject to process it.
                Ok(Some(ProcessTransactionResult::Certified(certificate)))
            }
            _ => {
                // If we get 2f+1 effects, it's a proof that the transaction
                // has already been finalized. This works because validators would re-sign effects for transactions
                // that were finalized in previous epochs.
                let (effects, sig) = signed_effects.into_inner().into_data_and_sig();
                match state.effects_map.insert(effects.digest(), &effects, sig) {
                    InsertResult::NotEnoughVotes => Ok(None),
                    InsertResult::Failed { error } => Err(error),
                    InsertResult::QuorumReached(cert_sig) => {
                        let ct =
                            CertifiedTransactionEffects::new_from_data_and_sig(effects, cert_sig);
                        Ok(Some(ProcessTransactionResult::Executed(
                            ct.verify(&self.committee)?,
                            events,
                        )))
                    }
                }
            }
        }
    }

    /// Check if we have some signed TransactionEffects but not a quorum
    fn record_non_quorum_effects_maybe(
        tx_digest: &TransactionDigest,
        mut state: ProcessTransactionState,
    ) -> ProcessTransactionState {
        if state.effects_map.unique_key_count() > 0 {
            let non_quorum_effects = state.effects_map.get_all_unique_values();
            warn!(
                ?tx_digest,
                "Received signed Effects but not with a quorum {:?}", non_quorum_effects
            );

            let mut involved_validators = Vec::new();
            let mut total_stake = 0;
            for (validators, stake) in non_quorum_effects.values() {
                involved_validators.extend_from_slice(validators);
                total_stake += stake;
            }
            // TODO: Instead of pushing a new error, we should add more information about the non-quorum effects
            // in the final error.
            state.errors.push((
                SuiError::QuorumFailedToGetEffectsQuorumWhenProcessingTransaction {
                    effects_map: non_quorum_effects,
                },
                involved_validators,
                total_stake,
            ));
        }
        state
    }

    /// Process a certificate
    pub async fn process_certificate(
        &self,
        certificate: CertifiedTransaction,
    ) -> Result<
        (VerifiedCertifiedTransactionEffects, TransactionEvents),
        QuorumExecuteCertificateError,
    > {
        let state = ProcessCertificateState {
            effects_map: MultiStakeAggregator::new(Arc::new(self.committee.clone())),
            bad_stake: 0,
            errors: vec![],
        };

        let tx_digest = *certificate.digest();
        let timeout_after_quorum = self.timeouts.post_quorum_timeout;

        let cert_ref = &certificate;
        let threshold = self.committee.quorum_threshold();
        let validity = self.committee.validity_threshold();
        debug!(
            ?tx_digest,
            quorum_threshold = threshold,
            validity_threshold = validity,
            ?timeout_after_quorum,
            "Broadcasting certificate to authorities"
        );
        self.quorum_map_then_reduce_with_timeout(
            state,
            |name, client| {
                Box::pin(async move {
                    client
                        .handle_certificate(cert_ref.clone())
                        .instrument(
                            tracing::trace_span!("handle_certificate", authority =? name.concise()),
                        )
                        .await
                })
            },
            |mut state, name, weight, response| {
                Box::pin(async move {
                    // We aggregate the effects response, until we have more than 2f
                    // and return.
                    match self
                        .handle_process_certificate_response(&tx_digest, &mut state, response, name)
                    {
                        Ok(Some(effects)) => ReduceOutput::Success(effects),
                        Ok(None) => ReduceOutput::Continue(state),
                        Err(err) => {
                            let concise_name = name.concise();
                            debug!(?tx_digest, name=?concise_name, "Error processing certificate from validator: {:?}", err);
                            self.metrics
                                .process_cert_errors
                                .with_label_values(&[&concise_name.to_string(), err.as_ref()])
                                .inc();
                            state.errors.push((err, vec![name], weight));
                            state.bad_stake += weight;
                            if state.bad_stake > validity {
                                ReduceOutput::Failed(state)
                            } else {
                                ReduceOutput::Continue(state)
                            }
                        }
                    }
                })
            },
            // A long timeout before we hear back from a quorum
            self.timeouts.pre_quorum_timeout,
        )
        .await
        .map_err(|state| {
            debug!(
                ?tx_digest,
                num_unique_effects = state.effects_map.unique_key_count(),
                bad_stake = state.bad_stake,
                "Received effects responses from validators"
            );
            QuorumExecuteCertificateError {
                total_stake: self.committee.total_votes,
                errors: state.errors,
            }
        })
    }

    fn handle_process_certificate_response(
        &self,
        tx_digest: &TransactionDigest,
        state: &mut ProcessCertificateState,
        response: SuiResult<VerifiedHandleCertificateResponse>,
        name: AuthorityName,
    ) -> SuiResult<Option<(VerifiedCertifiedTransactionEffects, TransactionEvents)>> {
        match response {
            Ok(VerifiedHandleCertificateResponse {
                signed_effects,
                events,
            }) => {
                debug!(
                    ?tx_digest,
                    name = ?name.concise(),
                    "Validator handled certificate successfully",
                );
                let signed_effects = signed_effects.into_inner();
                // Note: here we aggregate votes by the hash of the effects structure
                match state.effects_map.insert(
                    (signed_effects.epoch(), *signed_effects.digest()),
                    signed_effects.data(),
                    signed_effects.auth_sig().clone(),
                ) {
                    InsertResult::NotEnoughVotes => Ok(None),
                    InsertResult::Failed { error } => Err(error),
                    InsertResult::QuorumReached(cert_sig) => {
                        let ct = CertifiedTransactionEffects::new_from_data_and_sig(
                            signed_effects.into_data(),
                            cert_sig,
                        );
                        ct.verify(&self.committee).map(|ct| {
                            debug!(?tx_digest, "Got quorum for validators handle_certificate.");
                            Some((ct, events))
                        })
                    }
                }
            }
            Err(err) => Err(err),
        }
    }

    pub async fn execute_transaction(
        &self,
        transaction: &VerifiedTransaction,
    ) -> Result<VerifiedCertifiedTransactionEffects, anyhow::Error> {
        let result = self
            .process_transaction(transaction.clone())
            .instrument(tracing::debug_span!("process_tx"))
            .await?;
        let cert = match result {
            ProcessTransactionResult::Certified(cert) => cert,
            ProcessTransactionResult::Executed(effects, _) => {
                return Ok(effects);
            }
        };
        self.metrics.total_tx_certificates_created.inc();
        let response = self
            .process_certificate(cert.clone().into())
            .instrument(tracing::debug_span!("process_cert"))
            .await?;

        Ok(response.0)
    }

    /// This function tries to get SignedTransaction OR CertifiedTransaction from
    /// an given list of validators who are supposed to know about it.
    pub async fn handle_transaction_info_request_from_some_validators(
        &self,
        tx_digest: &TransactionDigest,
        // authorities known to have the transaction info we are requesting.
        validators: &BTreeSet<AuthorityName>,
        timeout_total: Option<Duration>,
    ) -> SuiResult<VerifiedTransactionInfoResponse> {
        self.quorum_once_with_timeout(
            None,
            Some(validators),
            |_authority, client| {
                Box::pin(async move {
                    client
                        .handle_transaction_info_request(TransactionInfoRequest {
                            transaction_digest: *tx_digest,
                        })
                        .await
                })
            },
            Duration::from_secs(2),
            timeout_total,
            "handle_transaction_info_request_from_some_validators".to_string(),
        )
        .await
    }
}
pub struct AuthorityAggregatorBuilder<'a> {
    network_config: Option<&'a NetworkConfig>,
    genesis: Option<&'a Genesis>,
    committee_store: Option<Arc<CommitteeStore>>,
    registry: Option<&'a Registry>,
    protocol_version: ProtocolVersion,
}

impl<'a> AuthorityAggregatorBuilder<'a> {
    pub fn from_network_config(config: &'a NetworkConfig) -> Self {
        Self {
            network_config: Some(config),
            genesis: None,
            committee_store: None,
            registry: None,
            protocol_version: ProtocolVersion::MIN,
        }
    }

    pub fn from_genesis(genesis: &'a Genesis) -> Self {
        Self {
            network_config: None,
            genesis: Some(genesis),
            committee_store: None,
            registry: None,
            protocol_version: ProtocolVersion::MIN,
        }
    }

    pub fn with_protocol_version(mut self, new_version: ProtocolVersion) -> Self {
        self.protocol_version = new_version;
        self
    }

    pub fn with_committee_store(mut self, committee_store: Arc<CommitteeStore>) -> Self {
        self.committee_store = Some(committee_store);
        self
    }

    pub fn with_registry(mut self, registry: &'a Registry) -> Self {
        self.registry = Some(registry);
        self
    }

    pub fn build(
        self,
    ) -> anyhow::Result<(
        AuthorityAggregator<NetworkAuthorityClient>,
        BTreeMap<AuthorityPublicKeyBytes, NetworkAuthorityClient>,
    )> {
        let validator_info = if let Some(network_config) = self.network_config {
            network_config.validator_set()
        } else if let Some(genesis) = self.genesis {
            genesis.validator_set()
        } else {
            anyhow::bail!("need either NetworkConfig or Genesis.");
        };
        let committee = make_committee(0, self.protocol_version, &validator_info)?;
        let mut registry = &prometheus::Registry::new();
        if self.registry.is_some() {
            registry = self.registry.unwrap();
        }

        let auth_clients = make_authority_clients(
            &validator_info,
            DEFAULT_CONNECT_TIMEOUT_SEC,
            DEFAULT_REQUEST_TIMEOUT_SEC,
        );
        let committee_store = if let Some(committee_store) = self.committee_store {
            committee_store
        } else {
            Arc::new(CommitteeStore::new_for_testing(&committee))
        };
        Ok((
            AuthorityAggregator::new(committee, committee_store, auth_clients.clone(), registry),
            auth_clients,
        ))
    }
}
