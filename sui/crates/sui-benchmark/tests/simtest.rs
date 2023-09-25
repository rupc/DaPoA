// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[cfg(msim)]
mod test {

    use rand::{thread_rng, Rng};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use sui_benchmark::benchmark_setup::ProxyGasAndCoin;
    use sui_benchmark::system_state_observer::SystemStateObserver;
    use sui_benchmark::workloads::workload_configuration::configure_combined_mode;
    use sui_benchmark::{
        drivers::{bench_driver::BenchDriver, driver::Driver, Interval},
        util::get_ed25519_keypair_from_keystore,
        LocalValidatorAggregatorProxy, ValidatorProxy,
    };
    use sui_config::{AUTHORITIES_DB_NAME, SUI_KEYSTORE_FILENAME};
    use sui_core::checkpoints::{CheckpointStore, CheckpointWatermark};
    use sui_macros::{register_fail_points, sim_test};
    use sui_simulator::{configs::*, SimConfig};
    use sui_types::object::Owner;
    use test_utils::messages::get_sui_gas_object_with_wallet_context;
    use test_utils::network::{TestCluster, TestClusterBuilder};
    use tracing::info;
    use typed_store::traits::Map;

    fn test_config() -> SimConfig {
        env_config(
            uniform_latency_ms(10..20),
            [
                (
                    "regional_high_variance",
                    bimodal_latency_ms(30..40, 300..800, 0.005),
                ),
                (
                    "global_high_variance",
                    bimodal_latency_ms(60..80, 500..1500, 0.01),
                ),
            ],
        )
    }

    fn get_var<T: FromStr>(name: &str, default: T) -> T
    where
        <T as FromStr>::Err: std::fmt::Debug,
    {
        std::env::var(name)
            .ok()
            .map(|v| v.parse().unwrap())
            .unwrap_or(default)
    }

    #[sim_test(config = "test_config()")]
    async fn test_simulated_load_with_reconfig() {
        sui_protocol_config::ProtocolConfig::poison_get_for_min_version();
        let test_cluster = build_test_cluster(4, 1000).await;
        test_simulated_load(test_cluster, 60).await;
    }

    #[sim_test(config = "test_config()")]
    async fn test_simulated_load_basic() {
        sui_protocol_config::ProtocolConfig::poison_get_for_min_version();
        let test_cluster = build_test_cluster(7, 0).await;
        test_simulated_load(test_cluster, 15).await;
    }

    #[sim_test(config = "test_config()")]
    #[ignore]
    async fn test_simulated_load_restarts() {
        sui_protocol_config::ProtocolConfig::poison_get_for_min_version();
        let test_cluster = build_test_cluster(4, 0).await;
        let node_restarter = test_cluster
            .random_node_restarter()
            .with_kill_interval_secs(5, 15)
            .with_restart_delay_secs(1, 10);
        node_restarter.run();
        test_simulated_load(test_cluster, 120).await;
    }

    #[sim_test(config = "test_config()")]
    #[ignore]
    async fn test_simulated_load_reconfig_restarts() {
        sui_protocol_config::ProtocolConfig::poison_get_for_min_version();
        let test_cluster = build_test_cluster(4, 1000).await;
        let node_restarter = test_cluster
            .random_node_restarter()
            .with_kill_interval_secs(5, 15)
            .with_restart_delay_secs(1, 10);
        node_restarter.run();
        test_simulated_load(test_cluster, 120).await;
    }

    #[sim_test(config = "test_config()")]
    #[ignore]
    async fn test_simulated_load_reconfig_crashes() {
        sui_protocol_config::ProtocolConfig::poison_get_for_min_version();
        let test_cluster = build_test_cluster(4, 1000).await;

        struct DeadValidator {
            node_id: sui_simulator::task::NodeId,
            dead_until: std::time::Instant,
        }
        let dead_validator: Arc<Mutex<Option<DeadValidator>>> = Default::default();

        let client_node = sui_simulator::runtime::NodeHandle::current().id();
        register_fail_points(
            &["batch-write", "transaction-commit", "put-cf"],
            move || {
                let mut dead_validator = dead_validator.lock().unwrap();
                let cur_node = sui_simulator::runtime::NodeHandle::current().id();

                // never kill the client node (which is running the test)
                if cur_node == client_node {
                    return;
                }

                // do not fail multiple nodes at a time.
                if let Some(dead) = &*dead_validator {
                    if dead.node_id != cur_node && dead.dead_until > Instant::now() {
                        return;
                    }
                }

                // otherwise, possibly fail the current node
                let mut rng = thread_rng();
                if rng.gen_range(0.0..1.0) < 0.01 {
                    let restart_after = Duration::from_millis(rng.gen_range(10000..20000));

                    *dead_validator = Some(DeadValidator {
                        node_id: cur_node,
                        dead_until: Instant::now() + restart_after,
                    });

                    // must manually release lock before calling kill_current_node, which panics
                    // and would poison the lock.
                    drop(dead_validator);

                    sui_simulator::task::kill_current_node(Some(restart_after));
                }
            },
        );

        test_simulated_load(test_cluster, 120).await;
    }

    // TODO add this back once flakiness is resolved
    #[ignore]
    #[sim_test(config = "test_config()")]
    async fn test_simulated_load_pruning() {
        let epoch_duration_ms = 5000;
        let test_cluster = build_test_cluster(4, epoch_duration_ms).await;
        test_simulated_load(test_cluster.clone(), 30).await;

        let swarm_dir = test_cluster.swarm.dir().join(AUTHORITIES_DB_NAME);
        let validator_path = std::fs::read_dir(swarm_dir).unwrap().next().unwrap();

        let db_path = validator_path.unwrap().path().join("checkpoints");
        let store = CheckpointStore::open_readonly(&db_path);
        let (pruned, digest) = store
            .watermarks
            .get(&CheckpointWatermark::HighestPruned)
            .unwrap()
            .unwrap();
        assert!(pruned > 0);
        let pruned_epoch = store
            .checkpoint_by_digest
            .get(&digest)
            .unwrap()
            .unwrap()
            .epoch();
        let expected_checkpoint = store
            .epoch_last_checkpoint_map
            .get(&pruned_epoch)
            .unwrap()
            .unwrap();
        assert_eq!(expected_checkpoint, pruned);
    }

    async fn build_test_cluster(
        default_num_validators: usize,
        default_epoch_duration_ms: u64,
    ) -> Arc<TestCluster> {
        let mut builder = TestClusterBuilder::new().with_num_validators(get_var(
            "SIM_STRESS_TEST_NUM_VALIDATORS",
            default_num_validators,
        ));
        if std::env::var("CHECKPOINTS_PER_EPOCH").is_ok() {
            eprintln!("CHECKPOINTS_PER_EPOCH env var is deprecated, use EPOCH_DURATION_MS");
        }
        let epoch_duration_ms = get_var("EPOCH_DURATION_MS", default_epoch_duration_ms);
        if epoch_duration_ms > 0 {
            builder = builder.with_epoch_duration_ms(epoch_duration_ms);
        }

        Arc::new(builder.build().await.unwrap())
    }

    async fn test_simulated_load(test_cluster: Arc<TestCluster>, test_duration_secs: u64) {
        let swarm = &test_cluster.swarm;
        let context = &test_cluster.wallet;
        let sender = test_cluster.get_address_0();

        let keystore_path = swarm.dir().join(SUI_KEYSTORE_FILENAME);
        let ed25519_keypair =
            Arc::new(get_ed25519_keypair_from_keystore(keystore_path, &sender).unwrap());
        let all_gas = get_sui_gas_object_with_wallet_context(context, &sender).await;
        let (_, gas) = all_gas.get(0).unwrap();
        let (move_struct, pay_coin) = all_gas.get(1).unwrap();
        let primary_gas = (
            gas.clone(),
            Owner::AddressOwner(sender),
            ed25519_keypair.clone(),
        );
        let pay_coin = (
            pay_coin.clone(),
            Owner::AddressOwner(sender),
            ed25519_keypair.clone(),
        );
        let pay_coin_type_tag = move_struct.type_params[0].clone();

        let registry = prometheus::Registry::new();
        let proxy: Arc<dyn ValidatorProxy + Send + Sync> = Arc::new(
            LocalValidatorAggregatorProxy::from_network_config(swarm.config(), &registry, None)
                .await,
        );

        let proxy_gas_and_coins = vec![ProxyGasAndCoin {
            primary_gas,
            pay_coin,
            pay_coin_type_tag,
            proxy: proxy.clone(),
        }];

        let system_state_observer = {
            let mut system_state_observer = SystemStateObserver::new(proxy.clone());
            if let Ok(_) = system_state_observer.reference_gas_price.changed().await {
                info!("Got the reference gas price from system state object");
            }
            Arc::new(system_state_observer)
        };
        // The default test parameters are somewhat conservative in order to keep the running time
        // of the test reasonable in CI.
        let target_qps = get_var("SIM_STRESS_TEST_QPS", 10);
        let num_workers = get_var("SIM_STRESS_TEST_WORKERS", 10);
        let in_flight_ratio = get_var("SIM_STRESS_TEST_IFR", 2);
        let shared_counter_weight = 1;
        let transfer_object_weight = 1;
        let num_transfer_accounts = 2;
        let delegation_weight = 1;
        let shared_counter_hotness_factor = 50;

        let proxy_workloads = configure_combined_mode(
            num_workers,
            num_transfer_accounts,
            shared_counter_weight,
            transfer_object_weight,
            delegation_weight,
            shared_counter_hotness_factor,
            target_qps,
            in_flight_ratio,
            proxy_gas_and_coins,
            system_state_observer.clone(),
            1000,
        )
        .await
        .unwrap();

        let driver = BenchDriver::new(5, false);

        // Use 0 for unbounded
        let test_duration_secs = get_var("SIM_STRESS_TEST_DURATION_SECS", test_duration_secs);
        let test_duration = if test_duration_secs == 0 {
            Duration::MAX
        } else {
            Duration::from_secs(test_duration_secs)
        };
        let interval = Interval::Time(test_duration);

        let show_progress = interval.is_unbounded();
        let (benchmark_stats, _) = driver
            .run(
                proxy_workloads,
                system_state_observer,
                &registry,
                show_progress,
                interval,
            )
            .await
            .unwrap();

        assert_eq!(benchmark_stats.num_error, 0);

        tracing::info!("end of test {:?}", benchmark_stats);
    }
}
