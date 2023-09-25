// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{server::Server, Discovery, DiscoveryEventLoop, DiscoveryServer, State};
use anemo::codegen::InboundRequestLayer;
use anemo_tower::rate_limit;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use sui_config::p2p::P2pConfig;
use tap::Pipe;
use tokio::{sync::oneshot, task::JoinSet};

/// Discovery Service Builder.
pub struct Builder {
    config: Option<P2pConfig>,
}

impl Builder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self { config: None }
    }

    pub fn config(mut self, config: P2pConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn build(self) -> (UnstartedDiscovery, DiscoveryServer<impl Discovery>) {
        let discovery_config = self
            .config
            .clone()
            .and_then(|config| config.discovery)
            .unwrap_or_default();
        let (builder, server) = self.build_internal();
        let mut discovery_server = DiscoveryServer::new(server);

        // Apply rate limits from configuration as needed.
        if let Some(limit) = discovery_config.get_known_peers_rate_limit {
            discovery_server = discovery_server.add_layer_for_get_known_peers(
                InboundRequestLayer::new(rate_limit::RateLimitLayer::new(
                    governor::Quota::per_second(limit),
                    rate_limit::WaitMode::Block,
                )),
            );
        }
        (builder, discovery_server)
    }

    pub(super) fn build_internal(self) -> (UnstartedDiscovery, Server) {
        let Builder { config } = self;
        let config = config.unwrap();
        let (sender, receiver) = oneshot::channel();

        let handle = Handle {
            _shutdown_handle: Arc::new(sender),
        };

        let state = State {
            our_info: None,
            connected_peers: HashMap::default(),
            known_peers: HashMap::default(),
        }
        .pipe(RwLock::new)
        .pipe(Arc::new);

        let server = Server {
            state: state.clone(),
        };

        (
            UnstartedDiscovery {
                handle,
                config,
                shutdown_handle: receiver,
                state,
            },
            server,
        )
    }
}

/// Handle to an unstarted discovery system
pub struct UnstartedDiscovery {
    pub(super) handle: Handle,
    pub(super) config: P2pConfig,
    pub(super) shutdown_handle: oneshot::Receiver<()>,
    pub(super) state: Arc<RwLock<State>>,
}

impl UnstartedDiscovery {
    pub(super) fn build(self, network: anemo::Network) -> (DiscoveryEventLoop, Handle) {
        let Self {
            handle,
            config,
            shutdown_handle,
            state,
        } = self;

        let discovery_config = config.discovery.clone().unwrap_or_default();

        (
            DiscoveryEventLoop {
                config,
                discovery_config,
                network,
                tasks: JoinSet::new(),
                pending_dials: Default::default(),
                dial_seed_peers_task: None,
                shutdown_handle,
                state,
            },
            handle,
        )
    }

    pub fn start(self, network: anemo::Network) -> Handle {
        let (event_loop, handle) = self.build(network);
        tokio::spawn(event_loop.start());

        handle
    }
}

/// A Handle to the Discovery subsystem. The Discovery system will be shutdown once its Handle has
/// been dropped.
pub struct Handle {
    _shutdown_handle: Arc<oneshot::Sender<()>>,
}
