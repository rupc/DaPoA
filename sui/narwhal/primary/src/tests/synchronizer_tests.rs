// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    common::create_db_stores, metrics::PrimaryMetrics, synchronizer::Synchronizer,
    NUM_SHUTDOWN_RECEIVERS,
};
use consensus::{dag::Dag, metrics::ConsensusMetrics};
use fastcrypto::{hash::Hash, traits::KeyPair};
use futures::{stream::FuturesUnordered, StreamExt};
use itertools::Itertools;
use prometheus::Registry;
use std::{
    collections::{BTreeSet, HashMap},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};
use test_utils::{make_optimal_signed_certificates, CommitteeFixture};
use tokio::sync::{oneshot, watch};
use types::{error::DagError, Certificate, PreSubscribedBroadcastSender};

#[tokio::test]
async fn accept_certificates() {
    let fixture = CommitteeFixture::builder().randomize_ports(true).build();
    let committee = fixture.committee();
    let worker_cache = fixture.shared_worker_cache();
    let primary = fixture.authorities().last().unwrap();
    let network_key = primary.network_keypair().copy().private().0.to_bytes();
    let name = primary.public_key();
    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));

    let (tx_certificate_fetcher, _rx_certificate_fetcher) = test_utils::test_channel!(1);
    let (tx_new_certificates, mut rx_new_certificates) = test_utils::test_channel!(3);
    let (tx_parents, mut rx_parents) = test_utils::test_channel!(4);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);
    let (tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();

    // Create test stores.
    let (_, certificate_store, payload_store) = create_db_stores();

    // Make a synchronizer.
    let synchronizer = Arc::new(Synchronizer::new(
        name.clone(),
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 50,
        certificate_store.clone(),
        payload_store.clone(),
        tx_certificate_fetcher,
        tx_new_certificates.clone(),
        tx_parents.clone(),
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        None,
        metrics.clone(),
    ));

    let own_address = network::multiaddr_to_address(&committee.primary(&name).unwrap()).unwrap();
    let network = anemo::Network::bind(own_address)
        .server_name("narwhal")
        .private_key(network_key)
        .start(anemo::Router::new())
        .unwrap();
    let _ = tx_synchronizer_network.send(network.clone());

    // Send 3 certificates to the Synchronizer.
    let certificates: Vec<_> = fixture
        .headers()
        .iter()
        .take(3)
        .map(|h| fixture.certificate(h))
        .collect();
    for cert in certificates.clone() {
        synchronizer
            .try_accept_certificate(cert, &network)
            .await
            .unwrap();
    }

    // Ensure the Synchronizer sends the parents of the certificates to the proposer.
    //
    // The first messages are the Synchronizer letting us know about the round of parent certificates
    for _i in 0..3 {
        let received = rx_parents.recv().await.unwrap();
        assert_eq!(received, (vec![], 0, 0));
    }
    // the next message actually contains the parents
    let received = rx_parents.recv().await.unwrap();
    assert_eq!(received, (certificates.clone(), 1, 0));

    // Ensure the Synchronizer sends the certificates to the consensus.
    for x in certificates.clone() {
        let received = rx_new_certificates.recv().await.unwrap();
        assert_eq!(received, x);
    }

    // Ensure the certificates are stored.
    for x in &certificates {
        let stored = certificate_store.read(x.digest()).unwrap();
        assert_eq!(stored, Some(x.clone()));
    }

    let mut m = HashMap::new();
    m.insert("source", "other");
    assert_eq!(
        metrics
            .certificates_processed
            .get_metric_with(&m)
            .unwrap()
            .get(),
        3
    );
}

#[tokio::test]
async fn accept_suspended_certificates() {
    const NUM_AUTHORITIES: usize = 4;
    telemetry_subscribers::init_for_testing();
    let fixture = CommitteeFixture::builder()
        .randomize_ports(true)
        .committee_size(NonZeroUsize::new(NUM_AUTHORITIES).unwrap())
        .build();
    let worker_cache = fixture.shared_worker_cache();
    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));
    let primary = fixture.authorities().next().unwrap();
    let name = primary.public_key();
    let network = test_utils::test_network(primary.network_keypair(), primary.address());

    let (_header_store, certificate_store, payload_store) = create_db_stores();
    let (tx_certificate_fetcher, _rx_certificate_fetcher) = test_utils::test_channel!(100);
    let (tx_new_certificates, _rx_new_certificates) = test_utils::test_channel!(100);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(100);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(1u64);
    let (_tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();

    let synchronizer = Arc::new(Synchronizer::new(
        name.clone(),
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 50,
        certificate_store.clone(),
        payload_store.clone(),
        tx_certificate_fetcher,
        tx_new_certificates,
        tx_parents,
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        None,
        metrics.clone(),
    ));

    // Make fake certificates.
    let committee = fixture.committee();
    let genesis = Certificate::genesis(&committee)
        .iter()
        .map(|x| x.digest())
        .collect::<BTreeSet<_>>();
    let keys: Vec<_> = fixture.authorities().map(|a| a.keypair().copy()).collect();
    let (certificates, _next_parents) =
        make_optimal_signed_certificates(1..=5, &genesis, &committee, keys.as_slice());
    let certificates = certificates.into_iter().collect_vec();

    // Try to aceept certificates from round 2 and above. All of them should be suspended.
    let accept = FuturesUnordered::new();
    for cert in &certificates[NUM_AUTHORITIES..] {
        match synchronizer
            .try_accept_certificate(cert.clone(), &network)
            .await
        {
            Ok(()) => panic!("Unexpected acceptance of {cert:?}"),
            Err(DagError::Suspended(notify)) => {
                let notify = notify.lock().unwrap().take();
                accept.push(async move { notify.unwrap().recv().await.unwrap() });
                continue;
            }
            Err(e) => panic!("Unexpected error {e}"),
        }
    }

    // Try to aceept certificates from round 1. All of them should be accepted.
    for cert in &certificates[..NUM_AUTHORITIES] {
        match synchronizer
            .try_accept_certificate(cert.clone(), &network)
            .await
        {
            Ok(()) => continue,
            Err(e) => panic!("Unexpected error {e}"),
        }
    }

    // Wait for all notifications to arrive.
    accept.collect::<Vec<()>>().await;

    // Try to aceept certificates from round 2 and above again. All of them should be accepted.
    for cert in &certificates[NUM_AUTHORITIES..] {
        match synchronizer
            .try_accept_certificate(cert.clone(), &network)
            .await
        {
            Ok(()) => continue,
            Err(e) => panic!("Unexpected error {e}"),
        }
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn synchronizer_recover_basic() {
    let fixture = CommitteeFixture::builder().randomize_ports(true).build();
    let committee = fixture.committee();
    let worker_cache = fixture.shared_worker_cache();
    let primary = fixture.authorities().last().unwrap();
    let network_key = primary.network_keypair().copy().private().0.to_bytes();
    let name = primary.public_key();
    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));

    let (tx_certificate_fetcher, _rx_certificate_fetcher) = test_utils::test_channel!(1);
    let (tx_new_certificates, _rx_new_certificates) = test_utils::test_channel!(3);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(4);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);
    let (tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();

    // Create test stores.
    let (_, certificate_store, payload_store) = create_db_stores();

    // Make Synchronizer.
    let synchronizer = Arc::new(Synchronizer::new(
        name.clone(),
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 50,
        certificate_store.clone(),
        payload_store.clone(),
        tx_certificate_fetcher,
        tx_new_certificates,
        tx_parents,
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        None,
        metrics.clone(),
    ));

    let own_address = network::multiaddr_to_address(&committee.primary(&name).unwrap()).unwrap();
    let network = anemo::Network::bind(own_address)
        .server_name("narwhal")
        .private_key(network_key)
        .start(anemo::Router::new())
        .unwrap();
    let _ = tx_synchronizer_network.send(network.clone());

    // Send 3 certificates to Synchronizer.
    let certificates: Vec<_> = fixture
        .headers()
        .iter()
        .take(3)
        .map(|h| fixture.certificate(h))
        .collect();
    for cert in certificates.clone() {
        synchronizer
            .try_accept_certificate(cert, &network)
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Shutdown Synchronizer.
    drop(synchronizer);

    // Restart Synchronizer.
    let (tx_certificate_fetcher, _rx_certificate_fetcher) = test_utils::test_channel!(1);
    let (tx_new_certificates, _rx_new_certificates) = test_utils::test_channel!(3);
    let (tx_parents, mut rx_parents) = test_utils::test_channel!(4);
    let (tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();

    let _synchronizer = Arc::new(Synchronizer::new(
        name.clone(),
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 50,
        certificate_store.clone(),
        payload_store.clone(),
        tx_certificate_fetcher,
        tx_new_certificates,
        tx_parents,
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        None,
        metrics.clone(),
    ));
    let _ = tx_synchronizer_network.send(network.clone());

    // Ensure the Synchronizer sends the parent certificates to the proposer.

    // the recovery flow sends message that contains the parents
    let received = rx_parents.recv().await.unwrap();
    assert_eq!(received.1, 1);
    assert_eq!(received.2, 0);
    assert_eq!(received.0.len(), certificates.len());
    for c in &certificates {
        assert!(received.0.contains(c));
    }

    // Ensure the certificates are stored.
    for x in &certificates {
        let stored = certificate_store.read(x.digest()).unwrap();
        assert_eq!(stored, Some(x.clone()));
    }

    let mut m = HashMap::new();
    m.insert("source", "other");
    assert_eq!(
        metrics
            .certificates_processed
            .get_metric_with(&m)
            .unwrap()
            .get(),
        3
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn synchronizer_recover_partial_certs() {
    let fixture = CommitteeFixture::builder().randomize_ports(true).build();
    let committee = fixture.committee();
    let worker_cache = fixture.shared_worker_cache();
    let primary = fixture.authorities().last().unwrap();
    let network_key = primary.network_keypair().copy().private().0.to_bytes();
    let name = primary.public_key();
    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));

    let (tx_certificate_fetcher, _rx_certificate_fetcher) = test_utils::test_channel!(1);
    let (tx_new_certificates, _rx_new_certificates) = test_utils::test_channel!(3);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(4);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);
    let (tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();

    // Create test stores.
    let (_, certificate_store, payload_store) = create_db_stores();

    // Make a synchronizer.
    let synchronizer = Arc::new(Synchronizer::new(
        name.clone(),
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 50,
        certificate_store.clone(),
        payload_store.clone(),
        tx_certificate_fetcher,
        tx_new_certificates.clone(),
        tx_parents.clone(),
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        None,
        metrics.clone(),
    ));

    let own_address = network::multiaddr_to_address(&committee.primary(&name).unwrap()).unwrap();
    let network = anemo::Network::bind(own_address)
        .server_name("narwhal")
        .private_key(network_key)
        .start(anemo::Router::new())
        .unwrap();
    let _ = tx_synchronizer_network.send(network.clone());

    // Send 1 certificate.
    let certificates: Vec<Certificate> = fixture
        .headers()
        .iter()
        .take(3)
        .map(|h| fixture.certificate(h))
        .collect();
    let last_cert = certificates.clone().into_iter().last().unwrap();
    synchronizer
        .try_accept_certificate(last_cert, &network)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Shutdown Synchronizer.
    drop(synchronizer);

    // Restart Synchronizer.
    let (tx_certificate_fetcher, _rx_certificate_fetcher) = test_utils::test_channel!(1);
    let (tx_new_certificates, _rx_new_certificates) = test_utils::test_channel!(3);
    let (tx_parents, mut rx_parents) = test_utils::test_channel!(4);
    let (tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();

    let synchronizer = Arc::new(Synchronizer::new(
        name.clone(),
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 50,
        certificate_store.clone(),
        payload_store.clone(),
        tx_certificate_fetcher,
        tx_new_certificates,
        tx_parents,
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        None,
        metrics.clone(),
    ));
    let _ = tx_synchronizer_network.send(network.clone());

    // Send remaining 2f certs.
    for cert in certificates.clone().into_iter().take(2) {
        synchronizer
            .try_accept_certificate(cert, &network)
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_secs(5)).await;

    for _ in 0..2 {
        let received = rx_parents.recv().await.unwrap();
        assert_eq!(received, (vec![], 0, 0));
    }

    // the recovery flow sends message that contains the parents
    let received = rx_parents.recv().await.unwrap();
    assert_eq!(received.1, 1);
    assert_eq!(received.2, 0);
    assert_eq!(received.0.len(), certificates.len());
    for c in &certificates {
        assert!(received.0.contains(c));
    }
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn synchronizer_recover_previous_round() {
    let fixture = CommitteeFixture::builder().randomize_ports(true).build();
    let committee = fixture.committee();
    let worker_cache = fixture.shared_worker_cache();
    let primary = fixture.authorities().last().unwrap();
    let network_key = primary.network_keypair().copy().private().0.to_bytes();
    let name = primary.public_key();
    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));

    let (tx_certificate_fetcher, _rx_certificate_fetcher) = test_utils::test_channel!(1);
    let (tx_new_certificates, _rx_new_certificates) = test_utils::test_channel!(6);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(10);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);
    let (tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();

    // Create test stores.
    let (_, certificate_store, payload_store) = create_db_stores();

    // Make a synchronizer.
    let synchronizer = Arc::new(Synchronizer::new(
        name.clone(),
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 50,
        certificate_store.clone(),
        payload_store.clone(),
        tx_certificate_fetcher,
        tx_new_certificates.clone(),
        tx_parents.clone(),
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        None,
        metrics.clone(),
    ));

    let own_address = network::multiaddr_to_address(&committee.primary(&name).unwrap()).unwrap();
    let network = anemo::Network::bind(own_address)
        .server_name("narwhal")
        .private_key(network_key)
        .start(anemo::Router::new())
        .unwrap();
    let _ = tx_synchronizer_network.send(network.clone());

    // Send 3 certificates from round 1, and 2 certificates from round 2 to Synchronizer.
    let genesis_certs = Certificate::genesis(&committee);
    let genesis = genesis_certs
        .iter()
        .map(|x| x.digest())
        .collect::<BTreeSet<_>>();
    let keys = fixture
        .authorities()
        .map(|a| a.keypair().copy())
        .take(3)
        .collect::<Vec<_>>();
    let (all_certificates, _next_parents) =
        make_optimal_signed_certificates(1..=2, &genesis, &committee, &keys);
    let all_certificates: Vec<_> = all_certificates.into_iter().collect();
    let round_1_certificates = all_certificates[0..3].to_vec();
    let round_2_certificates = all_certificates[3..5].to_vec();
    for cert in round_1_certificates
        .iter()
        .chain(round_2_certificates.iter())
    {
        synchronizer
            .try_accept_certificate(cert.clone(), &network)
            .await
            .unwrap();
    }

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Shutdown Synchronizer.
    drop(synchronizer);

    // Restart Synchronizer.
    let (tx_certificate_fetcher, _rx_certificate_fetcher) = test_utils::test_channel!(1);
    let (tx_new_certificates, _rx_new_certificates) = test_utils::test_channel!(6);
    let (tx_parents, mut rx_parents) = test_utils::test_channel!(10);
    let (tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();

    let _synchronizer = Arc::new(Synchronizer::new(
        name.clone(),
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 50,
        certificate_store.clone(),
        payload_store.clone(),
        tx_certificate_fetcher,
        tx_new_certificates,
        tx_parents,
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        None,
        metrics.clone(),
    ));
    let _ = tx_synchronizer_network.send(network.clone());

    // the recovery flow sends message that contains the parents for the last round for which we
    // have a quorum of certificates, in this case is round 1.
    let received = rx_parents.recv().await.unwrap();
    assert_eq!(received.0.len(), round_1_certificates.len());
    assert_eq!(received.1, 1);
    assert_eq!(received.2, 0);
    for c in &round_1_certificates {
        assert!(received.0.contains(c));
    }
}

#[tokio::test]
async fn deliver_certificate_using_dag() {
    let fixture = CommitteeFixture::builder().build();
    let name = fixture.authorities().next().unwrap().public_key();
    let committee = fixture.committee();
    let worker_cache = fixture.shared_worker_cache();
    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));

    let (_, certificates_store, payload_store) = create_db_stores();
    let (tx_certificate_fetcher, _rx_certificate_fetcher) = test_utils::test_channel!(1);
    let (tx_new_certificates, _rx_new_certificates) = test_utils::test_channel!(100);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(100);
    let (_tx_consensus, rx_consensus) = test_utils::test_channel!(1);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);
    let (_tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();
    let mut tx_shutdown = PreSubscribedBroadcastSender::new(NUM_SHUTDOWN_RECEIVERS);

    let consensus_metrics = Arc::new(ConsensusMetrics::new(&Registry::new()));
    let dag = Arc::new(
        Dag::new(
            &committee,
            rx_consensus,
            consensus_metrics,
            tx_shutdown.subscribe(),
        )
        .1,
    );

    let synchronizer = Synchronizer::new(
        name,
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 50,
        certificates_store,
        payload_store,
        tx_certificate_fetcher,
        tx_new_certificates,
        tx_parents,
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        Some(dag.clone()),
        metrics.clone(),
    );

    // create some certificates in a complete DAG form
    let genesis_certs = Certificate::genesis(&committee);
    let genesis = genesis_certs
        .iter()
        .map(|x| x.digest())
        .collect::<BTreeSet<_>>();

    let keys = fixture
        .authorities()
        .map(|a| a.keypair().copy())
        .take(3)
        .collect::<Vec<_>>();
    let (mut certificates, _next_parents) =
        make_optimal_signed_certificates(1..=4, &genesis, &committee, &keys);

    // insert the certificates in the DAG
    for certificate in certificates.clone() {
        dag.insert(certificate).await.unwrap();
    }

    // take the last one (top) and test for parents
    let test_certificate = certificates.pop_back().unwrap();

    // ensure that the certificate parents are found
    let parents_available = synchronizer
        .get_missing_parents(&test_certificate)
        .await
        .unwrap()
        .is_empty();
    assert!(parents_available);
}

#[tokio::test]
async fn deliver_certificate_using_store() {
    let fixture = CommitteeFixture::builder().build();
    let name = fixture.authorities().next().unwrap().public_key();
    let committee = fixture.committee();
    let worker_cache = fixture.shared_worker_cache();
    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));

    let (_, certificates_store, payload_store) = create_db_stores();
    let (tx_certificate_fetcher, _rx_certificate_fetcher) = test_utils::test_channel!(1);
    let (tx_new_certificates, _rx_new_certificates) = test_utils::test_channel!(100);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(100);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);
    let (_tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();

    let synchronizer = Synchronizer::new(
        name,
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 50,
        certificates_store.clone(),
        payload_store.clone(),
        tx_certificate_fetcher,
        tx_new_certificates,
        tx_parents,
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        None,
        metrics.clone(),
    );

    // create some certificates in a complete DAG form
    let genesis_certs = Certificate::genesis(&committee);
    let genesis = genesis_certs
        .iter()
        .map(|x| x.digest())
        .collect::<BTreeSet<_>>();

    let keys = fixture
        .authorities()
        .map(|a| a.keypair().copy())
        .take(3)
        .collect::<Vec<_>>();
    let (mut certificates, _next_parents) =
        make_optimal_signed_certificates(1..=4, &genesis, &committee, &keys);

    // insert the certificates in the DAG
    for certificate in certificates.clone() {
        certificates_store.write(certificate).unwrap();
    }

    // take the last one (top) and test for parents
    let test_certificate = certificates.pop_back().unwrap();

    // ensure that the certificate parents are found
    let parents_available = synchronizer
        .get_missing_parents(&test_certificate)
        .await
        .unwrap()
        .is_empty();
    assert!(parents_available);
}

#[tokio::test]
async fn deliver_certificate_not_found_parents() {
    let fixture = CommitteeFixture::builder().build();
    let name = fixture.authorities().next().unwrap().public_key();
    let committee = fixture.committee();
    let worker_cache = fixture.shared_worker_cache();
    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));

    let (_, certificates_store, payload_store) = create_db_stores();
    let (tx_certificate_fetcher, mut rx_certificate_fetcher) = test_utils::test_channel!(1);
    let (tx_new_certificates, _rx_new_certificates) = test_utils::test_channel!(100);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(100);
    let (_tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(0u64);
    let (_tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();

    let synchronizer = Synchronizer::new(
        name,
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 50,
        certificates_store,
        payload_store,
        tx_certificate_fetcher,
        tx_new_certificates,
        tx_parents,
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        None,
        metrics.clone(),
    );

    // create some certificates in a complete DAG form
    let genesis_certs = Certificate::genesis(&committee);
    let genesis = genesis_certs
        .iter()
        .map(|x| x.digest())
        .collect::<BTreeSet<_>>();

    let keys = fixture
        .authorities()
        .map(|a| a.keypair().copy())
        .take(3)
        .collect::<Vec<_>>();
    let (mut certificates, _next_parents) =
        make_optimal_signed_certificates(1..=4, &genesis, &committee, &keys);

    // take the last one (top) and test for parents
    let test_certificate = certificates.pop_back().unwrap();

    // we try to find the certificate's parents
    let parents_available = synchronizer
        .get_missing_parents(&test_certificate)
        .await
        .unwrap()
        .is_empty();

    // and we should fail
    assert!(!parents_available);

    let certificate = rx_certificate_fetcher.recv().await.unwrap();

    assert_eq!(certificate, test_certificate);
}

#[tokio::test]
async fn sync_batches_drops_old() {
    telemetry_subscribers::init_for_testing();
    let fixture = CommitteeFixture::builder()
        .randomize_ports(true)
        .committee_size(NonZeroUsize::new(4).unwrap())
        .build();
    let worker_cache = fixture.shared_worker_cache();
    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));
    let primary = fixture.authorities().next().unwrap();
    let name = primary.public_key();
    let author = fixture.authorities().nth(2).unwrap();
    let network = test_utils::test_network(primary.network_keypair(), primary.address());

    let (_header_store, certificate_store, payload_store) = create_db_stores();
    let (tx_certificate_fetcher, _rx_certificate_fetcher) = test_utils::test_channel!(1);
    let (tx_new_certificates, _rx_new_certificates) = test_utils::test_channel!(100);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(100);
    let (tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(1u64);
    let (_tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();

    let synchronizer = Arc::new(Synchronizer::new(
        name.clone(),
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 50,
        certificate_store.clone(),
        payload_store.clone(),
        tx_certificate_fetcher,
        tx_new_certificates,
        tx_parents,
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        None,
        metrics.clone(),
    ));

    let mut certificates = HashMap::new();
    for _ in 0..3 {
        let header = author
            .header_builder(&fixture.committee())
            .with_payload_batch(test_utils::fixture_batch_with_transactions(10), 0, 0)
            .build(author.keypair())
            .unwrap();

        let certificate = fixture.certificate(&header);
        let digest = certificate.clone().digest();

        certificates.insert(digest, certificate.clone());
        certificate_store.write(certificate.clone()).unwrap();
        for (digest, (worker_id, _)) in certificate.header.payload {
            payload_store.async_write((digest, worker_id), 1).await;
        }
    }
    let test_header = author
        .header_builder(&fixture.committee())
        .round(2)
        .parents(certificates.keys().cloned().collect())
        .with_payload_batch(test_utils::fixture_batch_with_transactions(10), 1, 0)
        .build(author.keypair())
        .unwrap();

    tokio::task::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = tx_consensus_round_updates.send(30);
    });
    match synchronizer
        .sync_batches(&test_header, network.clone(), 10)
        .await
    {
        Err(DagError::TooOld(_, _, _)) => (),
        result => panic!("unexpected result {result:?}"),
    }
}

#[tokio::test]
async fn gc_suspended_certificates() {
    const NUM_AUTHORITIES: usize = 4;
    telemetry_subscribers::init_for_testing();
    let fixture = CommitteeFixture::builder()
        .randomize_ports(true)
        .committee_size(NonZeroUsize::new(NUM_AUTHORITIES).unwrap())
        .build();
    let worker_cache = fixture.shared_worker_cache();
    let metrics = Arc::new(PrimaryMetrics::new(&Registry::new()));
    let primary = fixture.authorities().next().unwrap();
    let name = primary.public_key();
    let network = test_utils::test_network(primary.network_keypair(), primary.address());

    let (_header_store, certificate_store, payload_store) = create_db_stores();
    let (tx_certificate_fetcher, _rx_certificate_fetcher) = test_utils::test_channel!(100);
    let (tx_new_certificates, mut rx_new_certificates) = test_utils::test_channel!(100);
    let (tx_parents, _rx_parents) = test_utils::test_channel!(100);
    let (tx_consensus_round_updates, rx_consensus_round_updates) = watch::channel(1u64);
    let (_tx_synchronizer_network, rx_synchronizer_network) = oneshot::channel();

    let synchronizer = Arc::new(Synchronizer::new(
        name.clone(),
        fixture.committee(),
        worker_cache.clone(),
        /* gc_depth */ 5,
        certificate_store.clone(),
        payload_store.clone(),
        tx_certificate_fetcher,
        tx_new_certificates,
        tx_parents,
        rx_consensus_round_updates.clone(),
        rx_synchronizer_network,
        None,
        metrics.clone(),
    ));

    // Make fake certificates.
    let committee = fixture.committee();
    let genesis = Certificate::genesis(&committee)
        .iter()
        .map(|x| x.digest())
        .collect::<BTreeSet<_>>();
    let keys: Vec<_> = fixture.authorities().map(|a| a.keypair().copy()).collect();
    let (certificates, _next_parents) =
        make_optimal_signed_certificates(1..=5, &genesis, &committee, keys.as_slice());
    let certificates = certificates.into_iter().collect_vec();

    // Try to aceept certificates from round 2 and above. All of them should be suspended.
    let accept = FuturesUnordered::new();
    for cert in &certificates[NUM_AUTHORITIES..] {
        match synchronizer
            .try_accept_certificate(cert.clone(), &network)
            .await
        {
            Ok(()) => panic!("Unexpected acceptance of {cert:?}"),
            Err(DagError::Suspended(notify)) => {
                let mut notify = notify.lock().unwrap().take().unwrap();
                accept.push(async move { notify.recv().await.unwrap() });
                continue;
            }
            Err(e) => panic!("Unexpected error {e}"),
        }
    }

    // Re-insertion of missing certificate as fetched certificates should be ok.
    for cert in &certificates[NUM_AUTHORITIES * 2..NUM_AUTHORITIES * 4] {
        match synchronizer
            .try_accept_fetched_certificate(cert.clone(), &network)
            .await
        {
            Ok(()) => panic!("Unexpected acceptance of {cert:?}"),
            Err(DagError::Suspended(_)) => {
                continue;
            }
            Err(e) => panic!("Unexpected error {e}"),
        }
    }

    // At commit round 8, round 3 becomes the GC round. Round 4 and 5 will be accepted.
    let _ = tx_consensus_round_updates.send(8);

    // Wait for all notifications to arrive.
    accept.collect::<Vec<()>>().await;

    // Compare received and expected certificates.
    let mut received_certificates = HashMap::new();
    for _ in 0..NUM_AUTHORITIES * 2 {
        let cert = rx_new_certificates.try_recv().unwrap();
        received_certificates.insert(cert.digest(), cert);
    }
    let expected_certificates: HashMap<_, _> = certificates[NUM_AUTHORITIES * 3..]
        .iter()
        .map(|cert| (cert.digest(), cert.clone()))
        .collect();
    assert_eq!(received_certificates, expected_certificates);
}
