// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crypto::PublicKey;
use mysten_metrics::spawn_logged_monitored_task;
use tap::TapFallible;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
use types::{
    metered_channel::{Receiver, Sender},
    Certificate, ConditionalBroadcastReceiver, Round,
};

/// Receives the highest round reached by consensus and update it for all tasks.
pub struct StateHandler {
    /// The public key of this authority.
    name: PublicKey,
    /// Receives the ordered certificates from consensus.
    rx_committed_certificates: Receiver<(Round, Vec<Certificate>)>,
    /// Channel to signal committee changes.
    rx_shutdown: ConditionalBroadcastReceiver,
    /// A channel to update the committed rounds
    tx_commited_own_headers: Option<Sender<(Round, Vec<Round>)>>,

    network: anemo::Network,
}

impl StateHandler {
    #[must_use]
    pub fn spawn(
        name: PublicKey,
        rx_committed_certificates: Receiver<(Round, Vec<Certificate>)>,
        rx_shutdown: ConditionalBroadcastReceiver,
        tx_commited_own_headers: Option<Sender<(Round, Vec<Round>)>>,
        network: anemo::Network,
    ) -> JoinHandle<()> {
        spawn_logged_monitored_task!(
            async move {
                Self {
                    name,
                    rx_committed_certificates,
                    rx_shutdown,
                    tx_commited_own_headers,
                    network,
                }
                .run()
                .await;
            },
            "StateHandlerTask"
        )
    }

    async fn handle_sequenced(&mut self, commit_round: Round, certificates: Vec<Certificate>) {
        // Now we are going to signal which of our own batches have been committed.
        let own_rounds_committed: Vec<_> = certificates
            .iter()
            .filter_map(|cert| {
                if cert.header.author == self.name {
                    Some(cert.header.round)
                } else {
                    None
                }
            })
            .collect();
        debug!(
            "Own committed rounds {:?} at round {:?}",
            own_rounds_committed, commit_round
        );

        // If a reporting channel is available send the committed own
        // headers to it.
        if let Some(sender) = &self.tx_commited_own_headers {
            let _ = sender.send((commit_round, own_rounds_committed)).await;
        }
    }

    async fn run(mut self) {
        info!(
            "StateHandler on node {} has started successfully.",
            self.name
        );
        loop {
            tokio::select! {
                Some((commit_round, certificates)) = self.rx_committed_certificates.recv() => {
                    self.handle_sequenced(commit_round, certificates).await;
                },

                _ = self.rx_shutdown.receiver.recv() => {
                    // shutdown network
                    let _ = self.network.shutdown().await.tap_err(|err|{
                        error!("Error while shutting down network: {err}")
                    });

                    warn!("Network has shutdown");

                    return;
                }
            }
        }
    }
}
