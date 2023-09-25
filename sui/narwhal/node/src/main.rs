// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

use arc_swap::ArcSwap;
use clap::{crate_name, crate_version, App, AppSettings, ArgMatches, SubCommand};
use config::{Committee, Import, Parameters, WorkerCache, WorkerId};
use crypto::{KeyPair, NetworkKeyPair};
use eyre::Context;
use fastcrypto::traits::KeyPair as _;
use mysten_metrics::RegistryService;
use narwhal_node as node;
use narwhal_node::primary_node::PrimaryNode;
use narwhal_node::worker_node::WorkerNode;
use node::{
    execution_state::SimpleExecutionState,
    metrics::{primary_metrics_registry, start_prometheus_server, worker_metrics_registry},
};
use prometheus::Registry;
use std::sync::Arc;
use storage::NodeStorage;
use sui_keys::keypair_file::{
    read_authority_keypair_from_file, read_network_keypair_from_file,
    write_authority_keypair_to_file, write_keypair_to_file,
};
use sui_types::crypto::{get_key_pair_from_rng, AuthorityKeyPair, SuiKeyPair};
use telemetry_subscribers::TelemetryGuards;
use tokio::sync::mpsc::channel;

#[cfg(feature = "benchmark")]
use tracing::subscriber::set_global_default;
use tracing::{info, warn};
#[cfg(feature = "benchmark")]
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use worker::TrivialTransactionValidator;

#[tokio::main]
async fn main() -> Result<(), eyre::Report> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("A research implementation of Narwhal and Tusk.")
        .args_from_usage("-v... 'Sets the level of verbosity'")
        .subcommand(
            SubCommand::with_name("generate_keys")
                .about("Save an encoded bls12381 keypair (Base64 encoded `privkey`) to file")
                .args_from_usage("--filename=<FILE> 'The file where to save the encoded authority key pair'"),
        )
        .subcommand(
            SubCommand::with_name("generate_network_keys")
            .about("Save an encoded ed25519 network keypair (Base64 encoded `flag || privkey`) to file")
            .args_from_usage("--filename=<FILE> 'The file where to save the encoded network key pair'"),
        )
        .subcommand(
            SubCommand::with_name("get_pub_key")
                .about("Get the public key from a keypair file")
                .args_from_usage("--filename=<FILE> 'The file where the keypair is stored'"),
        )
        .subcommand(
            SubCommand::with_name("run")
                .about("Run a node")
                .args_from_usage("--primary-keys=<FILE> 'The file containing the node's primary keys'")
                .args_from_usage("--primary-network-keys=<FILE> 'The file containing the node's primary network keys'")
                .args_from_usage("--worker-keys=<FILE> 'The file containing the node's worker keys'")
                .args_from_usage("--committee=<FILE> 'The file containing committee information'")
                .args_from_usage("--workers=<FILE> 'The file containing worker information'")
                .args_from_usage("--parameters=[FILE] 'The file containing the node parameters'")
                .args_from_usage("--store=<PATH> 'The path where to create the data store'")
                .subcommand(SubCommand::with_name("primary")
                    .about("Run a single primary")
                    .args_from_usage("-d, --consensus-disabled 'Provide this flag to run a primary node without Tusk'")
                )
                .subcommand(
                    SubCommand::with_name("worker")
                        .about("Run a single worker")
                        .args_from_usage("--id=<INT> 'The worker id'"),
                )
                .setting(AppSettings::SubcommandRequiredElseHelp),
        )
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .get_matches();

    let tracing_level = match matches.occurrences_of("v") {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };

    // some of the network is very verbose, so we require more 'v's
    let network_tracing_level = match matches.occurrences_of("v") {
        0 | 1 => "error",
        2 => "warn",
        3 => "info",
        4 => "debug",
        _ => "trace",
    };

    match matches.subcommand() {
        ("generate_keys", Some(sub_matches)) => {
            let _guard = setup_telemetry(tracing_level, network_tracing_level, None);
            let key_file = sub_matches.value_of("filename").unwrap();
            let keypair: AuthorityKeyPair = get_key_pair_from_rng(&mut rand::rngs::OsRng).1;
            write_authority_keypair_to_file(&keypair, key_file).unwrap();
        }
        ("generate_network_keys", Some(sub_matches)) => {
            let _guard = setup_telemetry(tracing_level, network_tracing_level, None);
            let network_key_file = sub_matches.value_of("filename").unwrap();
            let network_keypair: NetworkKeyPair = get_key_pair_from_rng(&mut rand::rngs::OsRng).1;
            write_keypair_to_file(&SuiKeyPair::Ed25519(network_keypair), network_key_file).unwrap();
        }
        ("get_pub_key", Some(sub_matches)) => {
            let _guard = setup_telemetry(tracing_level, network_tracing_level, None);
            let file = sub_matches.value_of("filename").unwrap();
            match read_network_keypair_from_file(file) {
                Ok(keypair) => {
                    // Network keypair file is stored as `flag || privkey`.
                    println!("{:?}", keypair.public())
                }
                Err(_) => {
                    // Authority keypair file is stored as `privkey`.
                    match read_authority_keypair_from_file(file) {
                        Ok(kp) => println!("{:?}", kp.public()),
                        Err(e) => {
                            println!("Failed to read keypair at path {:?} err: {:?}", file, e)
                        }
                    }
                }
            }
        }
        ("run", Some(sub_matches)) => {
            let primary_key_file = sub_matches.value_of("primary-keys").unwrap();
            info!("primary_key_file: {}", primary_key_file);

            let primary_keypair = read_authority_keypair_from_file(primary_key_file)
                .expect("Failed to load the node's primary keypair");
            let primary_network_key_file = sub_matches.value_of("primary-network-keys").unwrap();
            info!("primary_network_key_file: {}", primary_network_key_file);

            let primary_network_keypair = read_network_keypair_from_file(primary_network_key_file)
                .expect("Failed to load the node's primary network keypair");
            let worker_key_file = sub_matches.value_of("worker-keys").unwrap();
            let worker_keypair = read_network_keypair_from_file(worker_key_file)
                .expect("Failed to load the node's worker keypair");
            let registry = match sub_matches.subcommand() {
                ("primary", _) => primary_metrics_registry(primary_keypair.public().clone()),
                ("worker", Some(worker_matches)) => {
                    let id = worker_matches
                        .value_of("id")
                        .unwrap()
                        .parse::<WorkerId>()
                        .context("The worker id must be a positive integer")?;

                    worker_metrics_registry(id, primary_keypair.public().clone())
                }
                _ => unreachable!(),
            };

            // In benchmarks, transactions are not deserializable => many errors at the debug level
            // Moreover, we need RFC 3339 timestamps to parse properly => we use a custom subscriber.
            cfg_if::cfg_if! {
                if #[cfg(feature = "benchmark")] {
                    setup_benchmark_telemetry(tracing_level, network_tracing_level)?;
                } else {
                    let _guard = setup_telemetry(tracing_level, network_tracing_level, Some(&registry));
                }
            }
            run(
                sub_matches,
                primary_keypair,
                primary_network_keypair,
                worker_keypair,
                registry,
            )
            .await?
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn setup_telemetry(
    tracing_level: &str,
    network_tracing_level: &str,
    prom_registry: Option<&Registry>,
) -> TelemetryGuards {
    let log_filter = format!("{tracing_level},h2={network_tracing_level},tower={network_tracing_level},hyper={network_tracing_level},tonic::transport={network_tracing_level},quinn={network_tracing_level}");

    let config = telemetry_subscribers::TelemetryConfig::new()
        // load env variables
        .with_env()
        // load special log filter
        .with_log_level(&log_filter);

    let config = if let Some(reg) = prom_registry {
        config.with_prom_registry(reg)
    } else {
        config
    };

    let (guard, _handle) = config.init();
    guard
}

#[cfg(feature = "benchmark")]
fn setup_benchmark_telemetry(
    tracing_level: &str,
    network_tracing_level: &str,
) -> Result<(), eyre::Report> {
    let custom_directive = "narwhal_executor=info";
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse(format!(
            "{tracing_level},h2={network_tracing_level},tower={network_tracing_level},hyper={network_tracing_level},tonic::transport={network_tracing_level},{custom_directive}"
        ))?;

    let env_filter = EnvFilter::try_from_default_env().unwrap_or(filter);

    let timer = tracing_subscriber::fmt::time::UtcTime::rfc_3339();
    let subscriber_builder = tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(env_filter)
        .with_timer(timer)
        .with_ansi(false);
    let subscriber = subscriber_builder.with_writer(std::io::stderr).finish();
    set_global_default(subscriber).expect("Failed to set subscriber");
    Ok(())
}

// Runs either a worker or a primary.
async fn run(
    matches: &ArgMatches<'_>,
    primary_keypair: KeyPair,
    primary_network_keypair: NetworkKeyPair,
    worker_keypair: NetworkKeyPair,
    registry: Registry,
) -> Result<(), eyre::Report> {
    // Only enabled if failpoints feature flag is set
    let _failpoints_scenario: fail::FailScenario<'_>;
    if fail::has_failpoints() {
        warn!("Failpoints are enabled");
        _failpoints_scenario = fail::FailScenario::setup();
    } else {
        info!("Failpoints are not enabled");
    }

    let committee_file = matches.value_of("committee").unwrap();
    let workers_file = matches.value_of("workers").unwrap();
    let parameters_file = matches.value_of("parameters");
    let store_path = matches.value_of("store").unwrap();

    // Read the committee, workers and node's keypair from file.
    let committee =
        Committee::import(committee_file).context("Failed to load the committee information")?;
    let worker_cache = Arc::new(ArcSwap::from_pointee(
        WorkerCache::import(workers_file).context("Failed to load the worker information")?,
    ));

    // Load default parameters if none are specified.
    let parameters = match parameters_file {
        Some(filename) => {
            Parameters::import(filename).context("Failed to load the node's parameters")?
        }
        None => Parameters::default(),
    };

    // Make the data store.
    let store = NodeStorage::reopen(store_path);

    // The channel returning the result for each transaction's execution.
    // let (_tx_transaction_confirmation, _rx_transaction_confirmation) = channel(100);
    let (_tx_transaction_confirmation, _rx_transaction_confirmation) =
        channel::<ConsensusOutput>(100);

    let registry_service = RegistryService::new(Registry::new());

    // Check whether to run a primary, a worker, or an entire authority.
    let (primary, worker) = match matches.subcommand() {
        // Spawn the primary and consensus core.
        ("primary", Some(sub_matches)) => {
            let primary = PrimaryNode::new(
                parameters.clone(),
                !sub_matches.is_present("consensus-disabled"),
                registry_service,
            );

            primary
                .start(
                    primary_keypair,
                    primary_network_keypair,
                    committee,
                    worker_cache,
                    &store,
                    Arc::new(SimpleExecutionState::new(_tx_transaction_confirmation)),
                )
                .await?;

            (Some(primary), None)
        }

        // Spawn a single worker.
        ("worker", Some(sub_matches)) => {
            let id = sub_matches
                .value_of("id")
                .unwrap()
                .parse::<WorkerId>()
                .context("The worker id must be a positive integer")?;

            let worker = WorkerNode::new(id, parameters.clone(), registry_service);

            worker
                .start(
                    primary_keypair.public().clone(),
                    worker_keypair,
                    committee,
                    worker_cache,
                    &store,
                    TrivialTransactionValidator::default(),
                    None,
                )
                .await?;

            (None, Some(worker))
        }
        _ => unreachable!(),
    };

    // spin up prometheus server exporter
    let prom_address = parameters.prometheus_metrics.socket_addr;
    info!(
        "Starting Prometheus HTTP metrics endpoint at {}",
        prom_address
    );
    let _metrics_server_handle = start_prometheus_server(prom_address, &registry);

    if let Some(primary) = primary {
        // relay the consensus' output.
        let execution_block_type = env::var("EXECUTION_BLOCK_TYPE")
            .expect("Environment EXECUTION_BLOCK_TYPE variable not found");

        relay(_rx_transaction_confirmation, execution_block_type).await;
        primary.wait().await;
    } else if let Some(worker) = worker {
        worker.wait().await;
    }

    // If this expression is reached, the program ends and all other tasks terminate.
    Ok(())
}

use bytes::Bytes;
use tokio::sync::mpsc::Receiver;
use types::{NarwhalGatewayClient, OrderedBlocks};
// use types::{EcBlock};
use types::CommitNotifierClient;
use types::{ConsensusOutput, GatewayConsensusOutput};
// use types::{McHeader,McBlock};

// use serde_json::Result;
// Receives an ordered list of certificates and apply any application-specific logic.

async fn _hello_msg(mut client: NarwhalGatewayClient<tonic::transport::Channel>) {
    let hello_sub_dag = Bytes::from("hello");
    let mut hello_batches: Vec<bytes::Bytes> = Vec::new();
    hello_batches.push(Bytes::from("hello"));
    hello_batches.push(Bytes::from("gateway"));
    let hello_digest = Bytes::from("hello_digest");
    // use types::CommittedSubDag;

    // let ser_sub_dag = Bytes::from(bincode::serialize(&consensus_output.sub_dag).unwrap());
    // let ser_sub_dag = Bytes::from(bincode::serialize(&consensus_output.sub_dag).unwrap());

    let request: tonic::Request<GatewayConsensusOutput> =
        tonic::Request::new(GatewayConsensusOutput {
            sub_dag: hello_sub_dag.clone(),
            batches: hello_batches.clone(),
            leader_header_digest: hello_digest,
        });

    // Send Hello Message to Gateway for testing-purpose
    let _response: Result<tonic::Response<types::DeliverConsensusOutputResponse>, tonic::Status> =
        client.deliver_consensus_output(request).await;
    info!("Successfully connected to Gateway!, tested by sending HelloRequest");
}

use prost::Message;
use std::env;
use std::future::Future;
use std::pin::Pin;
use types::Proposal;

// type HandleBlock = fn(&mut NarwhalGatewayClient<tonic::transport::Channel>, ConsensusOutput);

async fn handle_ethereum_block(
    client: &mut NarwhalGatewayClient<tonic::transport::Channel>,
    consensus_output: ConsensusOutput,
) {
    // NOTE: Notify the user that its transaction has been processed.
    info!(
        "Get ConsensusOutput #Seq:{} from Executor!",
        &consensus_output.sub_dag.sub_dag_index
    );

    // Make sure that ConsensusOutput is delivered to gateway server only when it's not empty!
    if consensus_output.batches.len() == 0 {
        info!("Executor skips Empty batches");
        return;
        // continue;
    }

    // let batches = consensus_output.batches;
    let mut header_batches: Vec<bytes::Bytes> = Vec::new();
    for (_, batches) in consensus_output.batches {
        for _batch in batches {
            for _transaction in _batch.transactions.into_iter() {
                // Assumes that _transactions are a Ethereum Block and Header
                let data = Proposal::decode(_transaction.as_ref()).unwrap();
                header_batches.push(bytes::Bytes::from(data.ethereum_header));
            }
        }
    }

    // info!(
    //     "Processed ConsensusOutput: out:{}, batch:{}, tx:{}, headers:{}",
    //     cnt_out,
    //     cnt_batch,
    //     cnt_tx,
    //     header_batches.len(),
    // );
    // let subdag_json = serde_json::to_string(&consensus_output.sub_dag).unwrap();
    // info!("subdag_json: {}", subdag_json);

    let ser_sub_dag = Bytes::from(bincode::serialize(&consensus_output.sub_dag).unwrap());
    let ser_leader_digest =
        Bytes::from(bincode::serialize(&consensus_output.sub_dag.leader.header.digest()).unwrap());

    let request: tonic::Request<GatewayConsensusOutput> =
        tonic::Request::new(GatewayConsensusOutput {
            sub_dag: ser_sub_dag.clone(),
            // batches: consensus_output.batches,
            batches: header_batches,
            leader_header_digest: ser_leader_digest.clone(),
        });

    let _response: Result<tonic::Response<types::DeliverConsensusOutputResponse>, tonic::Status> =
        client.deliver_consensus_output(request).await;
    info!("Deliver ConsensusOutput to Gateway!");
}

async fn handle_fabric_block(
    client: &mut CommitNotifierClient<tonic::transport::Channel>,
    consensus_output: ConsensusOutput,
) {
    // ordered_blocks contains a list of EcBlocks, a transaction unit in narwhal.
    let mut ordered_blocks: Vec<bytes::Bytes> = Vec::new();
    // let mut ordered_blocks: Vec<bytes::Bytes> = Vec::with_capacity(consensus_ouput.);
    
    if consensus_output.batches.is_empty() {
        warn!("handle_fabric_block is obviosuly invoked, but the consensus_output.batches is empty!");
        return;
    }

    for (_, batches) in consensus_output.batches {
        for _batch in batches {
            for _transaction in _batch.transactions.into_iter() {
                ordered_blocks.push(Bytes::from(_transaction));
            }
        }
    }
    if ordered_blocks.is_empty() {
        warn!("handle_fabric_block is obviosuly invoked, but the ordered_blocks is empty WTF is that?!");
        return;
    }

    let req = OrderedBlocks {
        sequence_number: consensus_output.sub_dag.sub_dag_index,
        blocks: ordered_blocks
    };

    info!("Send ConsensusOutput[seq:{}, num_ecblocks:{}] to Executor!", req.sequence_number, req.blocks.len());
    let _resp = client.process_ordered_blocks(req).await;
    match _resp {
        Ok(response) => {
            info!("Received response: {:?}", response);
        }
        Err(e) => {
            info!("An error occurred: {:?}", e);
        }
    }
}
use std::time::Duration;
use tokio::time::sleep;

// Future와 Send 트레잇을 구현하는 동적 디스패치를 위한 타입 별칭
type AsyncFnPointer = Pin<Box<dyn Future<Output = ()> + Send>>;

// 공통 인터페이스를 위한 트레잇 정의
trait Relayer {
    fn relay(&self, rx_output: Receiver<types::ConsensusOutput>) -> AsyncFnPointer;
}

struct EthRelayer;
struct FabRelayer;
struct NoopRelayer;

impl Relayer for EthRelayer {
    fn relay(&self, rx_output: Receiver<types::ConsensusOutput>) -> AsyncFnPointer {
        Box::pin(relay_eth(rx_output))
    }
}

impl Relayer for FabRelayer {
    fn relay(&self, rx_output: Receiver<types::ConsensusOutput>) -> AsyncFnPointer {
        Box::pin(relay_fab(rx_output))
    }
}

impl Relayer for NoopRelayer {
    fn relay(&self, rx_output: Receiver<types::ConsensusOutput>) -> AsyncFnPointer {
        Box::pin(relay_noop(rx_output))
    }
}

async fn relay(mut _rx_output: Receiver<types::ConsensusOutput>, execution_block_type: String) {
    // Get appropriate relayer based on execution_block_type
    let relayer: Box<dyn Relayer> = match execution_block_type.as_str() {
        "ethereum" => Box::new(EthRelayer),
        "hyperledger_fabric" => Box::new(FabRelayer),
        _ => Box::new(NoopRelayer),
    };

    info!("execution_block_type: {}", execution_block_type);

    // Start relaying depending on execution_block_type
    relayer.relay(_rx_output).await;

    // relay_eth(rx_output);
    // relay_fab(rx_output).await;
}

async fn relay_eth(mut rx_output: Receiver<types::ConsensusOutput>) {
    let gateway_url = "http://0.0.0.0:50051";
    let mut client: NarwhalGatewayClient<tonic::transport::Channel> =
        NarwhalGatewayClient::connect(gateway_url).await.unwrap();
    // _hello_msg(client.clone()).await;

    while let Some(consensus_output) = rx_output.recv().await {
        // Uncomment, below handle_ethereum_block, for demoing
        handle_ethereum_block(&mut client, consensus_output).await;
    }
}

async fn relay_noop(mut rx_output: Receiver<types::ConsensusOutput>) {
    while let Some(_consensus_output) = rx_output.recv().await {
    }
}

async fn relay_fab(mut rx_output: Receiver<types::ConsensusOutput>) {
    // We infer corresponding shard index from validator #id from env, which #id is used as a shard index
    let validator_id =
        env::var("VALIDATOR_ID").expect("Environment VALIDATOR_ID variable not found");
    // bsp0.executor.edgechain0:10000
    // "/dns/worker_0/tcp/4001/http
    // let deliver_address = format!("executor0.edgechain{}.com:10000", validator_id);
    let deliver_address = format!("http://bsp0.executor.edgechain{}:10000", validator_id);
    // "transactions": "/dns/worker_0/tcp/4001/http",

    // let deliver_address = format!("/dns/bsp0.executor.edgechain{}/tcp/10000/http", validator_id);
    // let deliver_address = format!("executor0.edgechain{}.com:10000", validator_id);
    // let deliver_address = format!("executor0_edgechain{}_com:10000", validator_id);
    info!(
        "Connecting to BSP Executor[addr:{}, validator:{}]",
        deliver_address, validator_id
    );
    
    // get fabric client (for bsp executor)
    let mut client = get_fab_client(deliver_address).await.unwrap();

    while let Some(_consensus_output) = rx_output.recv().await {
        info!("Received Fabric Block!");
        handle_fabric_block(&mut client, _consensus_output).await;
        info!("Handled Fabric Block22!");
    }
}

async fn get_fab_client(
    deliver_address: String,
) -> Result<CommitNotifierClient<tonic::transport::Channel>, Box<dyn std::error::Error>> {
    const MAX_RETRIES: usize = 500; // 최대 시도 횟수
    const RETRY_DELAY: Duration = Duration::from_secs(2); // 다음 재시도까지의 지연 시간
    const TIMEOUT: Duration = Duration::from_secs(2); // 연결 시도 타임아웃
    // Narwhal Failed to connect to BSP Executor[addr:executor0_edgechain0_com:10000]. Retrying...
    let mut retries = 0;
    
    // This loop ensures client have connection to Executor
    loop {
        let result = tonic::transport::Channel::builder(deliver_address.parse()?)
            .timeout(TIMEOUT)
            .connect()
            .await;

        match result {
            Ok(channel) => {
                println!("Successfully connected to BSP Executor server.");
                return Ok(CommitNotifierClient::new(channel));
                // Ok(client)
                // break;
            }
            Err(_e) => {
                retries += 1;
                if retries >= MAX_RETRIES {
                    println!("Reached max retries. Exiting.");
                    // return Err(Box::new(e));
                } else {
                    println!("Narwhal Failed to connect to BSP Executor[addr:{}]. Retrying...", deliver_address);
                    sleep(RETRY_DELAY).await;
                }
            }
        }
    }
    // return client;
}
