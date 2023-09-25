// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::Node;
use anyhow::Result;
use futures::future::try_join_all;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::{
    mem, ops,
    path::{Path, PathBuf},
};
use sui_config::builder::{
    CommitteeConfig, ConfigBuilder, ProtocolVersionsConfig, SupportedProtocolVersionsCallback,
};
use sui_config::genesis_config::{GenesisConfig, ValidatorConfigInfo};
use sui_config::NetworkConfig;
use sui_protocol_config::SupportedProtocolVersions;
use sui_types::base_types::AuthorityName;
use sui_types::object::Object;
use tempfile::TempDir;

pub struct SwarmBuilder<R = OsRng> {
    rng: R,
    // template: NodeConfig,
    dir: Option<PathBuf>,
    committee: CommitteeConfig,
    initial_accounts_config: Option<GenesisConfig>,
    additional_objects: Vec<Object>,
    fullnode_count: usize,
    fullnode_rpc_addr: Option<SocketAddr>,
    with_event_store: bool,
    epoch_duration_ms: Option<u64>,
    supported_protocol_versions_config: ProtocolVersionsConfig,
}

impl SwarmBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            rng: OsRng,
            dir: None,
            committee: CommitteeConfig::Size(NonZeroUsize::new(1).unwrap()),
            initial_accounts_config: None,
            additional_objects: vec![],
            fullnode_count: 0,
            fullnode_rpc_addr: None,
            with_event_store: false,
            epoch_duration_ms: None,
            supported_protocol_versions_config: ProtocolVersionsConfig::Default,
        }
    }
}

impl<R> SwarmBuilder<R> {
    pub fn rng<N: rand::RngCore + rand::CryptoRng>(self, rng: N) -> SwarmBuilder<N> {
        SwarmBuilder {
            rng,
            dir: self.dir,
            committee: self.committee,
            initial_accounts_config: self.initial_accounts_config,
            additional_objects: self.additional_objects,
            fullnode_count: self.fullnode_count,
            fullnode_rpc_addr: self.fullnode_rpc_addr,
            with_event_store: false,
            epoch_duration_ms: None,
            supported_protocol_versions_config: ProtocolVersionsConfig::Default,
        }
    }

    /// Set the directory that should be used by the Swarm for any on-disk data.
    ///
    /// If a directory is provided, it will not be cleaned up when the Swarm is dropped.
    ///
    /// Defaults to using a temporary directory that will be cleaned up when the Swarm is dropped.
    pub fn dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.dir = Some(dir.into());
        self
    }

    /// Set the committee size (the number of validators in the validator set).
    ///
    /// Defaults to 1.
    pub fn committee_size(mut self, committee_size: NonZeroUsize) -> Self {
        self.committee = CommitteeConfig::Size(committee_size);
        self
    }

    pub fn with_validators(mut self, validators: Vec<ValidatorConfigInfo>) -> Self {
        self.committee = CommitteeConfig::Validators(validators);
        self
    }

    pub fn initial_accounts_config(mut self, initial_accounts_config: GenesisConfig) -> Self {
        self.initial_accounts_config = Some(initial_accounts_config);
        self
    }

    pub fn with_objects<I: IntoIterator<Item = Object>>(mut self, objects: I) -> Self {
        self.additional_objects.extend(objects);
        self
    }

    pub fn with_fullnode_count(mut self, fullnode_count: usize) -> Self {
        self.fullnode_count = fullnode_count;
        self
    }

    pub fn with_fullnode_rpc_addr(mut self, fullnode_rpc_addr: SocketAddr) -> Self {
        self.fullnode_rpc_addr = Some(fullnode_rpc_addr);
        self
    }

    pub fn with_epoch_duration_ms(mut self, epoch_duration_ms: u64) -> Self {
        self.epoch_duration_ms = Some(epoch_duration_ms);
        self
    }

    pub fn with_supported_protocol_versions(mut self, c: SupportedProtocolVersions) -> Self {
        self.supported_protocol_versions_config = ProtocolVersionsConfig::Global(c);
        self
    }

    pub fn with_supported_protocol_version_callback(
        mut self,
        func: SupportedProtocolVersionsCallback,
    ) -> Self {
        self.supported_protocol_versions_config = ProtocolVersionsConfig::PerValidator(func);
        self
    }

    pub fn with_supported_protocol_versions_config(mut self, c: ProtocolVersionsConfig) -> Self {
        self.supported_protocol_versions_config = c;
        self
    }
}

impl<R: rand::RngCore + rand::CryptoRng> SwarmBuilder<R> {
    /// Create the configured Swarm.
    pub fn build(self) -> Swarm {
        let dir = if let Some(dir) = self.dir {
            SwarmDirectory::Persistent(dir)
        } else {
            SwarmDirectory::Temporary(TempDir::new().unwrap())
        };

        let mut config_builder = ConfigBuilder::new(dir.as_ref());

        if let Some(initial_accounts_config) = self.initial_accounts_config {
            config_builder = config_builder.initial_accounts_config(initial_accounts_config);
        }

        if let Some(epoch_duration_ms) = self.epoch_duration_ms {
            config_builder = config_builder.with_epoch_duration(epoch_duration_ms);
        }

        let network_config = config_builder
            .committee(self.committee)
            .with_swarm()
            .rng(self.rng)
            .with_objects(self.additional_objects)
            .with_supported_protocol_versions_config(
                self.supported_protocol_versions_config.clone(),
            )
            .build();

        let validators = network_config
            .validator_configs()
            .iter()
            .map(|config| (config.protocol_public_key(), Node::new(config.to_owned())))
            .collect();

        let mut fullnodes = HashMap::new();

        if self.fullnode_count > 0 {
            (0..self.fullnode_count).for_each(|_| {
                let spvc = self.supported_protocol_versions_config.clone();
                //let spvc = spvc.clone();
                let mut config = network_config
                    .fullnode_config_builder()
                    .with_supported_protocol_versions_config(spvc)
                    .with_random_dir()
                    .build()
                    .unwrap();

                if let Some(fullnode_rpc_addr) = self.fullnode_rpc_addr {
                    config.json_rpc_address = fullnode_rpc_addr;
                }
                fullnodes.insert(config.protocol_public_key(), Node::new(config));
            });
        }
        Swarm {
            dir,
            network_config,
            validators,
            fullnodes,
        }
    }

    pub fn with_event_store(mut self) -> Self {
        self.with_event_store = true;
        self
    }

    pub fn from_network_config(self, dir: PathBuf, network_config: NetworkConfig) -> Swarm {
        let dir = SwarmDirectory::Persistent(dir);

        let validators = network_config
            .validator_configs()
            .iter()
            .map(|config| (config.protocol_public_key(), Node::new(config.to_owned())))
            .collect();

        let fullnodes = if let Some(fullnode_rpc_addr) = self.fullnode_rpc_addr {
            let mut config = network_config
                .fullnode_config_builder()
                .with_supported_protocol_versions_config(self.supported_protocol_versions_config)
                .set_event_store(self.with_event_store)
                .with_random_dir()
                .build()
                .unwrap();
            config.json_rpc_address = fullnode_rpc_addr;
            HashMap::from([(config.protocol_public_key(), Node::new(config))])
        } else {
            Default::default()
        };

        Swarm {
            dir,
            network_config,
            validators,
            fullnodes,
        }
    }
}

/// A handle to an in-memory Sui Network.
#[derive(Debug)]
pub struct Swarm {
    dir: SwarmDirectory,
    network_config: NetworkConfig,
    validators: HashMap<AuthorityName, Node>,
    fullnodes: HashMap<AuthorityName, Node>,
}

impl Drop for Swarm {
    fn drop(&mut self) {
        self.nodes_iter_mut().for_each(|node| node.stop());
    }
}

impl Swarm {
    /// Return a new Builder
    pub fn builder() -> SwarmBuilder {
        SwarmBuilder::new()
    }

    fn nodes_iter_mut(&mut self) -> impl Iterator<Item = &mut Node> {
        self.validators
            .values_mut()
            .chain(self.fullnodes.values_mut())
    }

    /// Start all of the Validators associated with this Swarm
    pub async fn launch(&mut self) -> Result<()> {
        try_join_all(self.nodes_iter_mut().map(|node| node.start())).await?;

        Ok(())
    }

    /// Return the path to the directory where this Swarm's on-disk data is kept.
    pub fn dir(&self) -> &Path {
        self.dir.as_ref()
    }

    /// Ensure that the Swarm data directory will persist and not be cleaned up when this Swarm is
    /// dropped.
    pub fn persist_dir(&mut self) {
        self.dir.persist();
    }

    /// Return a reference to this Swarm's `NetworkConfig`.
    pub fn config(&self) -> &NetworkConfig {
        &self.network_config
    }

    /// Return a mutable reference to this Swarm's `NetworkConfig`.
    pub fn config_mut(&mut self) -> &mut NetworkConfig {
        &mut self.network_config
    }

    /// Attempt to lookup and return a shared reference to the Validator with the provided `name`.
    pub fn validator(&self, name: AuthorityName) -> Option<&Node> {
        self.validators.get(&name)
    }

    /// Return an iterator over shared references of all Validators.
    pub fn validators(&self) -> impl Iterator<Item = &Node> {
        self.validators.values()
    }

    /// Attempt to lookup and return a shared reference to the Fullnode with the provided `name`.
    pub fn fullnode(&self, name: AuthorityName) -> Option<&Node> {
        self.fullnodes.get(&name)
    }

    /// Return an iterator over shared references of all Fullnodes.
    pub fn fullnodes(&self) -> impl Iterator<Item = &Node> {
        self.fullnodes.values()
    }
}

#[derive(Debug)]
enum SwarmDirectory {
    Persistent(PathBuf),
    Temporary(TempDir),
}

impl SwarmDirectory {
    fn persist(&mut self) {
        match self {
            SwarmDirectory::Persistent(_) => {}
            SwarmDirectory::Temporary(_) => {
                let mut temp = SwarmDirectory::Persistent(PathBuf::new());
                mem::swap(self, &mut temp);
                let _ = mem::replace(self, temp.into_persistent());
            }
        }
    }

    fn into_persistent(self) -> Self {
        match self {
            SwarmDirectory::Temporary(tempdir) => SwarmDirectory::Persistent(tempdir.into_path()),
            SwarmDirectory::Persistent(dir) => SwarmDirectory::Persistent(dir),
        }
    }
}

impl ops::Deref for SwarmDirectory {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        match self {
            SwarmDirectory::Persistent(dir) => dir.deref(),
            SwarmDirectory::Temporary(dir) => dir.path(),
        }
    }
}

impl AsRef<Path> for SwarmDirectory {
    fn as_ref(&self) -> &Path {
        match self {
            SwarmDirectory::Persistent(dir) => dir.as_ref(),
            SwarmDirectory::Temporary(dir) => dir.as_ref(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::Swarm;
    use std::num::NonZeroUsize;

    #[tokio::test]
    async fn launch() {
        telemetry_subscribers::init_for_testing();
        let mut swarm = Swarm::builder()
            .committee_size(NonZeroUsize::new(4).unwrap())
            .with_fullnode_count(1)
            .build();

        swarm.launch().await.unwrap();

        for validator in swarm.validators() {
            validator.health_check(true).await.unwrap();
        }

        for fullnode in swarm.fullnodes() {
            fullnode.health_check(false).await.unwrap();
        }
    }
}
