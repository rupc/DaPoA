// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::NUM_SHUTDOWN_RECEIVERS;
use test_utils::{batch, test_network, CommitteeFixture, WorkerToWorkerMockServer};
use types::PreSubscribedBroadcastSender;

#[tokio::test]
async fn wait_for_quorum() {
    let (tx_message, rx_message) = test_utils::test_channel!(1);
    let fixture = CommitteeFixture::builder().randomize_ports(true).build();
    let committee = fixture.committee();
    let worker_cache = fixture.shared_worker_cache();
    let my_primary = fixture.authorities().next().unwrap().public_key();
    let myself = fixture.authorities().next().unwrap().worker(0);

    let mut tx_shutdown = PreSubscribedBroadcastSender::new(NUM_SHUTDOWN_RECEIVERS);

    // setup network
    let network = test_network(myself.keypair(), &myself.info().worker_address);
    // Spawn a `QuorumWaiter` instance.
    let _quorum_waiter_handler = QuorumWaiter::spawn(
        my_primary.clone(),
        /* worker_id */ 0,
        committee.clone(),
        worker_cache.clone(),
        tx_shutdown.subscribe(),
        rx_message,
        network.clone(),
    );

    // Make a batch.
    let batch = batch();
    let message = WorkerBatchMessage {
        batch: batch.clone(),
    };

    // Spawn enough listeners to acknowledge our batches.
    let mut listener_handles = Vec::new();
    for worker in fixture.authorities().skip(1).map(|a| a.worker(0)) {
        let handle =
            WorkerToWorkerMockServer::spawn(worker.keypair(), worker.info().worker_address.clone());
        listener_handles.push(handle);

        // ensure that the networks are connected
        network
            .connect(network::multiaddr_to_address(&worker.info().worker_address).unwrap())
            .await
            .unwrap();
    }

    // Forward the batch along with the handlers to the `QuorumWaiter`.
    let (s, r) = tokio::sync::oneshot::channel();
    tx_message.send((batch.clone(), Some(s))).await.unwrap();

    // Wait for the `QuorumWaiter` to gather enough acknowledgements and output the batch.
    r.await.unwrap();

    // Ensure the other listeners correctly received the batch.
    for (mut handle, _network) in listener_handles {
        assert_eq!(handle.recv().await.unwrap(), message);
    }
}

#[tokio::test]
async fn pipeline_for_quorum() {
    let (tx_message, rx_message) = test_utils::test_channel!(1);
    let fixture = CommitteeFixture::builder().randomize_ports(true).build();
    let committee = fixture.committee();
    let worker_cache = fixture.shared_worker_cache();
    let my_primary = fixture.authorities().next().unwrap().public_key();
    let myself = fixture.authorities().next().unwrap().worker(0);

    let mut tx_shutdown = PreSubscribedBroadcastSender::new(NUM_SHUTDOWN_RECEIVERS);

    // setup network
    let network = test_network(myself.keypair(), &myself.info().worker_address);
    // Spawn a `QuorumWaiter` instance.
    let _quorum_waiter_handler = QuorumWaiter::spawn(
        my_primary.clone(),
        /* worker_id */ 0,
        committee.clone(),
        worker_cache.clone(),
        tx_shutdown.subscribe(),
        rx_message,
        network.clone(),
    );

    // Make a batch.
    let batch = batch();
    let message = WorkerBatchMessage {
        batch: batch.clone(),
    };

    // Spawn enough listeners to acknowledge our batches.
    let mut listener_handles = Vec::new();
    for worker in fixture.authorities().skip(1).map(|a| a.worker(0)) {
        let handle =
            WorkerToWorkerMockServer::spawn(worker.keypair(), worker.info().worker_address.clone());
        listener_handles.push(handle);

        // ensure that the networks are connected
        network
            .connect(network::multiaddr_to_address(&worker.info().worker_address).unwrap())
            .await
            .unwrap();
    }

    // Forward the batch along with the handlers to the `QuorumWaiter`.
    let (s0, r0) = tokio::sync::oneshot::channel();
    tx_message.send((batch.clone(), Some(s0))).await.unwrap();

    // Forward the batch along with the handlers to the `QuorumWaiter`.
    let (s1, r1) = tokio::sync::oneshot::channel();
    tx_message.send((batch.clone(), Some(s1))).await.unwrap();

    // Wait for the `QuorumWaiter` to gather enough acknowledgements and output the batch.
    r0.await.unwrap();

    // Ensure the other listeners correctly received the batch.
    for (mut handle, _network) in listener_handles {
        assert_eq!(handle.recv().await.unwrap(), message);
        assert_eq!(handle.recv().await.unwrap(), message);
    }

    r1.await.unwrap();
}
