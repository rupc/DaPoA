// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::genesis;
use crate::p2p::P2pConfig;
use crate::Config;
use anyhow::Result;
use multiaddr::Multiaddr;
use narwhal_config::Parameters as ConsensusParameters;
use once_cell::sync::OnceCell;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::usize;
use sui_keys::keypair_file::{read_authority_keypair_from_file, read_keypair_from_file};
use sui_protocol_config::SupportedProtocolVersions;
use sui_types::base_types::SuiAddress;
use sui_types::crypto::AuthorityPublicKeyBytes;
use sui_types::crypto::KeypairTraits;
use sui_types::crypto::NetworkKeyPair;
use sui_types::crypto::NetworkPublicKey;
use sui_types::crypto::PublicKey as AccountsPublicKey;
use sui_types::crypto::SuiKeyPair;
use sui_types::crypto::{get_key_pair_from_rng, AccountKeyPair, AuthorityKeyPair};

// Default max number of concurrent requests served
pub const DEFAULT_GRPC_CONCURRENCY_LIMIT: usize = 20000000000;

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct NodeConfig {
    #[serde(default = "default_authority_key_pair")]
    pub protocol_key_pair: AuthorityKeyPairWithPath,
    #[serde(default = "default_key_pair")]
    pub worker_key_pair: KeyPairWithPath,
    #[serde(default = "default_key_pair")]
    pub account_key_pair: KeyPairWithPath,
    #[serde(default = "default_key_pair")]
    pub network_key_pair: KeyPairWithPath,

    pub db_path: PathBuf,
    #[serde(default = "default_grpc_address")]
    pub network_address: Multiaddr,
    #[serde(default = "default_json_rpc_address")]
    pub json_rpc_address: SocketAddr,

    #[serde(default = "default_metrics_address")]
    pub metrics_address: SocketAddr,
    #[serde(default = "default_admin_interface_port")]
    pub admin_interface_port: u16,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub consensus_config: Option<ConsensusConfig>,

    #[serde(default)]
    pub enable_event_processing: bool,

    // TODO: It will be removed down the road.
    /// Epoch duration in ms.
    /// u64::MAX means reconfiguration is disabled
    /// Exposing this in config to allow easier testing with shorter epoch.
    #[serde(default = "default_epoch_duration_ms")]
    pub epoch_duration_ms: u64,

    #[serde(default)]
    pub grpc_load_shed: Option<bool>,

    #[serde(default = "default_concurrency_limit")]
    pub grpc_concurrency_limit: Option<usize>,

    #[serde(default)]
    pub p2p_config: P2pConfig,

    pub genesis: Genesis,

    #[serde(default = "default_authority_store_pruning_config")]
    pub authority_store_pruning_config: AuthorityStorePruningConfig,

    /// Size of the broadcast channel used for notifying other systems of end of epoch.
    ///
    /// If unspecified, this will default to `128`.
    #[serde(default = "default_end_of_epoch_broadcast_channel_capacity")]
    pub end_of_epoch_broadcast_channel_capacity: usize,

    #[serde(default)]
    pub checkpoint_executor_config: CheckpointExecutorConfig,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsConfig>,

    /// In a `sui-node` binary, this is set to SupportedProtocolVersions::SYSTEM_DEFAULT
    /// in sui-node/src/main.rs. It is present in the config so that it can be changed by tests in
    /// order to test protocol upgrades.
    #[serde(skip)]
    pub supported_protocol_versions: Option<SupportedProtocolVersions>,
}

fn default_authority_store_pruning_config() -> AuthorityStorePruningConfig {
    AuthorityStorePruningConfig::default()
}

fn default_grpc_address() -> Multiaddr {
    use multiaddr::multiaddr;
    multiaddr!(Ip4([0, 0, 0, 0]), Tcp(8080u16))
}
fn default_authority_key_pair() -> AuthorityKeyPairWithPath {
    AuthorityKeyPairWithPath::new(get_key_pair_from_rng::<AuthorityKeyPair, _>(&mut OsRng).1)
}

fn default_key_pair() -> KeyPairWithPath {
    KeyPairWithPath::new(
        get_key_pair_from_rng::<AccountKeyPair, _>(&mut OsRng)
            .1
            .into(),
    )
}

fn default_metrics_address() -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9184)
}

pub fn default_admin_interface_port() -> u16 {
    1337
}

pub fn default_json_rpc_address() -> SocketAddr {
    use std::net::{IpAddr, Ipv4Addr};
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9000)
}

pub fn default_websocket_address() -> Option<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr};
    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9001))
}

pub fn default_concurrency_limit() -> Option<usize> {
    Some(DEFAULT_GRPC_CONCURRENCY_LIMIT)
}

pub fn default_epoch_duration_ms() -> u64 {
    // 24 Hrs
    24 * 60 * 60 * 1000
}

pub fn default_end_of_epoch_broadcast_channel_capacity() -> usize {
    128
}

pub fn bool_true() -> bool {
    true
}

impl Config for NodeConfig {}

impl NodeConfig {
    pub fn protocol_key_pair(&self) -> &AuthorityKeyPair {
        self.protocol_key_pair.authority_keypair()
    }

    pub fn worker_key_pair(&self) -> &NetworkKeyPair {
        match self.worker_key_pair.keypair() {
            SuiKeyPair::Ed25519(kp) => kp,
            other => panic!(
                "Invalid keypair type: {:?}, only Ed25519 is allowed for worker key",
                other
            ),
        }
    }

    pub fn network_key_pair(&self) -> &NetworkKeyPair {
        match self.network_key_pair.keypair() {
            SuiKeyPair::Ed25519(kp) => kp,
            other => panic!(
                "Invalid keypair type: {:?}, only Ed25519 is allowed for network key",
                other
            ),
        }
    }

    pub fn account_key_pair(&self) -> &SuiKeyPair {
        self.account_key_pair.keypair()
    }

    pub fn protocol_public_key(&self) -> AuthorityPublicKeyBytes {
        self.protocol_key_pair().public().into()
    }

    pub fn sui_address(&self) -> SuiAddress {
        (&self.account_key_pair().public()).into()
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn network_address(&self) -> &Multiaddr {
        &self.network_address
    }

    pub fn consensus_config(&self) -> Option<&ConsensusConfig> {
        self.consensus_config.as_ref()
    }

    pub fn genesis(&self) -> Result<&genesis::Genesis> {
        self.genesis.genesis()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConsensusConfig {
    pub address: Multiaddr,
    pub db_path: PathBuf,

    // Optional alternative address preferentially used by a primary to talk to its own worker.
    // For example, this could be used to connect to co-located workers over a private LAN address.
    pub internal_worker_address: Option<Multiaddr>,

    // Timeout to retry sending transaction to consensus internally.
    // Default to 60s.
    pub timeout_secs: Option<u64>,

    pub narwhal_config: ConsensusParameters,
}

impl ConsensusConfig {
    pub fn address(&self) -> &Multiaddr {
        &self.address
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn narwhal_config(&self) -> &ConsensusParameters {
        &self.narwhal_config
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CheckpointExecutorConfig {
    /// Upper bound on the number of checkpoints that can be concurrently executed
    ///
    /// If unspecified, this will default to `200`
    #[serde(default = "default_checkpoint_execution_max_concurrency")]
    pub checkpoint_execution_max_concurrency: usize,

    /// Number of seconds to wait for effects of a batch of transactions
    /// before logging a warning. Note that we will continue to retry
    /// indefinitely
    ///
    /// If unspecified, this will default to `10`.
    #[serde(default = "default_local_execution_timeout_sec")]
    pub local_execution_timeout_sec: u64,
}

fn default_checkpoint_execution_max_concurrency() -> usize {
    200
}

fn default_local_execution_timeout_sec() -> u64 {
    10
}

impl Default for CheckpointExecutorConfig {
    fn default() -> Self {
        Self {
            checkpoint_execution_max_concurrency: default_checkpoint_execution_max_concurrency(),
            local_execution_timeout_sec: default_local_execution_timeout_sec(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AuthorityStorePruningConfig {
    pub objects_num_latest_versions_to_retain: u64,
    pub objects_pruning_period_secs: u64,
    pub objects_pruning_initial_delay_secs: u64,
    pub num_latest_epoch_dbs_to_retain: usize,
    pub epoch_db_pruning_period_secs: u64,
    pub num_epochs_to_retain: u64,
}

impl Default for AuthorityStorePruningConfig {
    fn default() -> Self {
        Self {
            objects_num_latest_versions_to_retain: u64::MAX,
            objects_pruning_period_secs: 24 * 60 * 60,
            objects_pruning_initial_delay_secs: 60 * 60,
            num_latest_epoch_dbs_to_retain: usize::MAX,
            epoch_db_pruning_period_secs: u64::MAX,
            num_epochs_to_retain: u64::MAX,
        }
    }
}

impl AuthorityStorePruningConfig {
    pub fn validator_config() -> Self {
        Self {
            // TODO: Temporarily disable the pruner, since we are not sure if it properly maintains
            // most recent 2 versions with lamport versioning.
            objects_num_latest_versions_to_retain: 2,
            objects_pruning_period_secs: 24 * 60 * 60,
            objects_pruning_initial_delay_secs: 60 * 60,
            num_latest_epoch_dbs_to_retain: 3,
            epoch_db_pruning_period_secs: 60 * 60,
            num_epochs_to_retain: if cfg!(msim) { 1 } else { u64::MAX },
        }
    }
    pub fn fullnode_config() -> Self {
        Self {
            objects_num_latest_versions_to_retain: 5,
            objects_pruning_period_secs: 24 * 60 * 60,
            objects_pruning_initial_delay_secs: 60 * 60,
            num_latest_epoch_dbs_to_retain: 3,
            epoch_db_pruning_period_secs: 60 * 60,
            num_epochs_to_retain: if cfg!(msim) { 1 } else { u64::MAX },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MetricsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_interval_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_url: Option<String>,
}

/// Publicly known information about a validator
/// TODO read most of this from on-chain
#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct ValidatorInfo {
    pub name: String,
    pub account_key: AccountsPublicKey,
    pub protocol_key: AuthorityPublicKeyBytes,
    pub worker_key: NetworkPublicKey,
    pub network_key: NetworkPublicKey,
    pub gas_price: u64,
    pub commission_rate: u64,
    pub network_address: Multiaddr,
    pub p2p_address: Multiaddr,
    pub narwhal_primary_address: Multiaddr,
    pub narwhal_worker_address: Multiaddr,
    pub description: String,
    pub image_url: String,
    pub project_url: String,
}

impl ValidatorInfo {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn sui_address(&self) -> SuiAddress {
        self.account_key().into()
    }

    pub fn protocol_key(&self) -> AuthorityPublicKeyBytes {
        self.protocol_key
    }

    pub fn worker_key(&self) -> &NetworkPublicKey {
        &self.worker_key
    }

    pub fn network_key(&self) -> &NetworkPublicKey {
        &self.network_key
    }

    pub fn account_key(&self) -> &AccountsPublicKey {
        &self.account_key
    }

    pub fn gas_price(&self) -> u64 {
        self.gas_price
    }

    pub fn commission_rate(&self) -> u64 {
        self.commission_rate
    }

    pub fn network_address(&self) -> &Multiaddr {
        &self.network_address
    }

    pub fn narwhal_primary_address(&self) -> &Multiaddr {
        &self.narwhal_primary_address
    }

    pub fn narwhal_worker_address(&self) -> &Multiaddr {
        &self.narwhal_worker_address
    }

    pub fn p2p_address(&self) -> &Multiaddr {
        &self.p2p_address
    }

    //TODO remove this
    pub fn voting_rights(validator_set: &[Self]) -> BTreeMap<AuthorityPublicKeyBytes, u64> {
        validator_set
            .iter()
            .map(|validator| (validator.protocol_key(), 1))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Eq)]
pub struct Genesis {
    #[serde(flatten)]
    location: GenesisLocation,

    #[serde(skip)]
    genesis: once_cell::sync::OnceCell<genesis::Genesis>,
}

impl Genesis {
    pub fn new(genesis: genesis::Genesis) -> Self {
        Self {
            location: GenesisLocation::InPlace { genesis },
            genesis: Default::default(),
        }
    }

    pub fn new_from_file<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            location: GenesisLocation::File {
                genesis_file_location: path.into(),
            },
            genesis: Default::default(),
        }
    }

    pub fn genesis(&self) -> Result<&genesis::Genesis> {
        match &self.location {
            GenesisLocation::InPlace { genesis } => Ok(genesis),
            GenesisLocation::File {
                genesis_file_location,
            } => self
                .genesis
                .get_or_try_init(|| genesis::Genesis::load(genesis_file_location)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Eq)]
#[serde(untagged)]
enum GenesisLocation {
    InPlace {
        genesis: genesis::Genesis,
    },
    File {
        #[serde(rename = "genesis-file-location")]
        genesis_file_location: PathBuf,
    },
}

/// Wrapper struct for SuiKeyPair that can be deserialized from a file path. Used by network, worker, and account keypair.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyPairWithPath {
    #[serde(flatten)]
    location: KeyPairLocation,

    #[serde(skip)]
    keypair: OnceCell<Arc<SuiKeyPair>>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Eq)]
#[serde_as]
#[serde(untagged)]
enum KeyPairLocation {
    InPlace {
        #[serde_as(as = "Arc<KeyPairBase64>")]
        value: Arc<SuiKeyPair>,
    },
    File {
        #[serde(rename = "path")]
        path: PathBuf,
    },
}

impl KeyPairWithPath {
    pub fn new(kp: SuiKeyPair) -> Self {
        let cell: OnceCell<Arc<SuiKeyPair>> = OnceCell::new();
        let arc_kp = Arc::new(kp);
        // OK to unwrap panic because authority should not start without all keypairs loaded.
        cell.set(arc_kp.clone()).expect("Failed to set keypair");
        Self {
            location: KeyPairLocation::InPlace { value: arc_kp },
            keypair: cell,
        }
    }

    pub fn new_from_path(path: PathBuf) -> Self {
        let cell: OnceCell<Arc<SuiKeyPair>> = OnceCell::new();
        // OK to unwrap panic because authority should not start without all keypairs loaded.
        cell.set(Arc::new(read_keypair_from_file(&path).unwrap_or_else(
            |e| panic!("Invalid keypair file at path {:?}: {e}", &path),
        )))
        .expect("Failed to set keypair");
        Self {
            location: KeyPairLocation::File { path },
            keypair: cell,
        }
    }

    pub fn keypair(&self) -> &SuiKeyPair {
        self.keypair
            .get_or_init(|| match &self.location {
                KeyPairLocation::InPlace { value } => value.clone(),
                KeyPairLocation::File { path } => {
                    // OK to unwrap panic because authority should not start without all keypairs loaded.
                    Arc::new(
                        read_keypair_from_file(path).unwrap_or_else(|e| {
                            panic!("Invalid keypair file at path {:?}: {e}", path)
                        }),
                    )
                }
            })
            .as_ref()
    }
}

/// Wrapper struct for AuthorityKeyPair that can be deserialized from a file path.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct AuthorityKeyPairWithPath {
    #[serde(flatten)]
    location: AuthorityKeyPairLocation,

    #[serde(skip)]
    keypair: OnceCell<Arc<AuthorityKeyPair>>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize, Eq)]
#[serde_as]
#[serde(untagged)]
enum AuthorityKeyPairLocation {
    InPlace { value: Arc<AuthorityKeyPair> },
    File { path: PathBuf },
}

impl AuthorityKeyPairWithPath {
    pub fn new(kp: AuthorityKeyPair) -> Self {
        let cell: OnceCell<Arc<AuthorityKeyPair>> = OnceCell::new();
        let arc_kp = Arc::new(kp);
        // OK to unwrap panic because authority should not start without all keypairs loaded.
        cell.set(arc_kp.clone())
            .expect("Failed to set authority keypair");
        Self {
            location: AuthorityKeyPairLocation::InPlace { value: arc_kp },
            keypair: cell,
        }
    }

    pub fn new_from_path(path: PathBuf) -> Self {
        let cell: OnceCell<Arc<AuthorityKeyPair>> = OnceCell::new();
        // OK to unwrap panic because authority should not start without all keypairs loaded.
        cell.set(Arc::new(
            read_authority_keypair_from_file(&path)
                .unwrap_or_else(|_| panic!("Invalid authority keypair file at path {:?}", &path)),
        ))
        .expect("Failed to set authority keypair");
        Self {
            location: AuthorityKeyPairLocation::File { path },
            keypair: cell,
        }
    }

    pub fn authority_keypair(&self) -> &AuthorityKeyPair {
        self.keypair
            .get_or_init(|| match &self.location {
                AuthorityKeyPairLocation::InPlace { value } => value.clone(),
                AuthorityKeyPairLocation::File { path } => {
                    // OK to unwrap panic because authority should not start without all keypairs loaded.
                    Arc::new(
                        read_authority_keypair_from_file(path).unwrap_or_else(|_| {
                            panic!("Invalid authority keypair file {:?}", &path)
                        }),
                    )
                }
            })
            .as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use fastcrypto::traits::KeyPair;
    use rand::{rngs::StdRng, SeedableRng};
    use sui_keys::keypair_file::{write_authority_keypair_to_file, write_keypair_to_file};
    use sui_types::crypto::{
        get_key_pair_from_rng, AccountKeyPair, AuthorityKeyPair, NetworkKeyPair, SuiKeyPair,
    };

    use super::Genesis;
    use crate::NodeConfig;

    #[test]
    fn serialize_genesis_config_from_file() {
        let g = Genesis::new_from_file("path/to/file");

        let s = serde_yaml::to_string(&g).unwrap();
        assert_eq!("---\ngenesis-file-location: path/to/file\n", s);
        let loaded_genesis: Genesis = serde_yaml::from_str(&s).unwrap();
        assert_eq!(g, loaded_genesis);
    }

    #[test]
    fn serialize_genesis_config_in_place() {
        let dir = tempfile::TempDir::new().unwrap();
        let network_config = crate::builder::ConfigBuilder::new(&dir).build();
        let genesis = network_config.genesis;

        let g = Genesis::new(genesis);

        let mut s = serde_yaml::to_string(&g).unwrap();
        let loaded_genesis: Genesis = serde_yaml::from_str(&s).unwrap();
        assert_eq!(g, loaded_genesis);

        // If both in-place and file location are provided, prefer the in-place variant
        s.push_str("\ngenesis-file-location: path/to/file");
        let loaded_genesis: Genesis = serde_yaml::from_str(&s).unwrap();
        assert_eq!(g, loaded_genesis);
    }

    #[test]
    fn load_genesis_config_from_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let genesis_config = Genesis::new_from_file(file.path());

        let dir = tempfile::TempDir::new().unwrap();
        let network_config = crate::builder::ConfigBuilder::new(&dir).build();
        let genesis = network_config.genesis;
        genesis.save(file.path()).unwrap();

        let loaded_genesis = genesis_config.genesis().unwrap();
        assert_eq!(&genesis, loaded_genesis);
    }

    #[test]
    fn fullnode_template() {
        const TEMPLATE: &str = include_str!("../data/fullnode-template.yaml");

        let _template: NodeConfig = serde_yaml::from_str(TEMPLATE).unwrap();
    }

    #[test]
    fn load_key_pairs_to_node_config() {
        let protocol_key_pair: AuthorityKeyPair =
            get_key_pair_from_rng(&mut StdRng::from_seed([0; 32])).1;
        let worker_key_pair: NetworkKeyPair =
            get_key_pair_from_rng(&mut StdRng::from_seed([0; 32])).1;
        let account_key_pair: SuiKeyPair =
            get_key_pair_from_rng::<AccountKeyPair, _>(&mut StdRng::from_seed([0; 32]))
                .1
                .into();
        let network_key_pair: NetworkKeyPair =
            get_key_pair_from_rng(&mut StdRng::from_seed([0; 32])).1;

        write_authority_keypair_to_file(&protocol_key_pair, PathBuf::from("protocol.key")).unwrap();
        write_keypair_to_file(
            &SuiKeyPair::Ed25519(worker_key_pair.copy()),
            PathBuf::from("worker.key"),
        )
        .unwrap();
        write_keypair_to_file(
            &SuiKeyPair::Ed25519(network_key_pair.copy()),
            PathBuf::from("network.key"),
        )
        .unwrap();
        write_keypair_to_file(&account_key_pair, PathBuf::from("account.key")).unwrap();

        const TEMPLATE: &str = include_str!("../data/fullnode-template-with-path.yaml");
        let template: NodeConfig = serde_yaml::from_str(TEMPLATE).unwrap();
        assert_eq!(
            template.protocol_key_pair().public(),
            protocol_key_pair.public()
        );
        assert_eq!(
            template.network_key_pair().public(),
            network_key_pair.public()
        );
        assert_eq!(
            template.account_key_pair().public(),
            account_key_pair.public()
        );
        assert_eq!(
            template.worker_key_pair().public(),
            worker_key_pair.public()
        );
    }
}
