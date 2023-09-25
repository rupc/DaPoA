// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use async_trait::async_trait;
use executor::ExecutionState;
use tokio::sync::mpsc::Sender;
use types::ConsensusOutput;
// use types::GatewayConsensusOutput;
// use types::NarwhalGatewayClient;
// use tonic::transport::Channel;
// use bytes::Bytes;


// use types::{GatewayConsensusOutput, NarwhalGatewayClient, Proposal};

// use tracing::info;
/// A simple/dumb execution engine.
pub struct SimpleExecutionState {
    tx_transaction_confirmation: Sender<types::ConsensusOutput>,
    // cnt_consensusoutput: i32,
    // cnt_batch: i32,
    // cnt_tx: i32,
    // gateway_client: NarwhalGatewayClient<Channel>,
    // gateway_client: NarwhalGatewayClient,
}

impl SimpleExecutionState {
    pub fn new(tx_transaction_confirmation: Sender<types::ConsensusOutput>) -> Self {
        // let mut client = NarwhalGatewayClient::connect("http://[::1]:50051");
            // .await
            // .unwrap();

        // let sub_dag = Bytes::from("hello");
        // let batches = Bytes::from("gateway");
        // let request: tonic::Request<GatewayConsensusOutput> = tonic::Request::new(GatewayConsensusOutput { sub_dag, batches });

        // let _response = client.deliver_consensus_output(request).await;
        // info!("Successfully connected to Gateway!, tested by sending Request");

        Self {
            tx_transaction_confirmation,
            // cnt_consensusoutput: 0,
            // cnt_batch: 0,
            // cnt_tx: 0,
            // gateway_client: client,
        }
    }
}
// use std::sync::Once;

#[async_trait]
impl ExecutionState for SimpleExecutionState {
    async fn handle_consensus_output(&self, consensus_output: ConsensusOutput) {

        // info!("Handle ConsensusOutput");
        if let Err(err) = self.tx_transaction_confirmation.send(consensus_output).await {
            eprintln!("Failed to send txn in SimpleExecutionState: {}", err);
        }
        // static START: Once = Once::new();

        // START.call_once(|| async {
        // // run initialization here
        //     self.
        // });


        // info!("cnt:consensusoutput{}", self.cnt_consensusoutput);
        // let mut cnt_batch =0;
        // let mut cnt_tx =0 ;
        // // let mut _cnt_output = 0;
        // // self.cnt_batch +=1;


        // for (_, batches) in consensus_output.batches {
        //     for batch in batches {
        //         // info!("cnt:batch{}", cnt_batch);
        //         // cnt_batch += 1;

        //         for transaction in batch.transactions.into_iter() {
        //             if let Err(err) = self.tx_transaction_confirmation.send(transaction).await {
        //                 eprintln!("Failed to send txn in SimpleExecutionState: {}", err);
        //             }
        //             // info!("cnt:tx{}", cnt_tx);
        //             // cnt_tx+=1;
        //         }
        //     }
        // }
        // self.cnt_consensusoutput += 1;
    }

    async fn last_executed_sub_dag_index(&self) -> u64 {
        0
    }
}
