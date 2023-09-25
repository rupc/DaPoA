use bytes::Bytes;
use tokio::sync::mpsc;

use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, warn};

use eyre::Context;
use narwhal_gateway::narwhal_gateway_server::{NarwhalGateway, NarwhalGatewayServer};
use narwhal_gateway::{
    DeliverConsensusOutputResponse, GatewayConsensusOutput, /* Batch , */ Proposal,
    ProposalResponse, SubscribeConsensusOutputRequest, SubscribeConsensusOutputResponse,DagProof
};

use narwhal_gateway::NarwhalCommitEvent;

use types::CommittedSubDag;
use types::{TransactionProto, TransactionsClient};
use url::Url;

// use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// use fastcrypto::{
//     hash::{Digest, Hash, HashFunction},
//     // signature_service::SignatureService,
//     // traits::{AggregateAuthenticator, EncodeDecodeBase64, InsecureDefault, Signer, VerifyingKey},
// };
// type Db = Arc<Mutex<HashMap<u64, Vec<u8>>>>;
use prost::Message;

pub mod narwhal_gateway {
    tonic::include_proto!("narwhal_gateway");
}

#[derive(Debug)]
pub struct MyNarwhalGatewayServer {
    cnt_deliver_output: Mutex<i32>,
    tx_co: Arc<Mutex<mpsc::Sender<GatewayConsensusOutput>>>,
    // consensusoutput_db: Db,
}

#[tonic::async_trait]
impl NarwhalGateway for MyNarwhalGatewayServer {
    type SubscribeConsensusOutputStream =
        ReceiverStream<Result<SubscribeConsensusOutputResponse, Status>>;

    async fn submit_transaction(
        &self,
        request: Request<Proposal>,
    ) -> Result<Response<ProposalResponse>, Status> {
        println!("Got a request:");

        let narwhal_client = NarwhalClient {
            target: Url::parse("http://127.0.0.1:3009").unwrap(),
        };

        let mut resp = ProposalResponse {
            success_or_fail: String::from("empty"),
        };

        // use hex::ToHex;
        // use prost::Message;
        // info!("[Before] encode_to_vec: {}", hex_str);
        // let header = request.into_inner().ethereum_header.clone();

        // let ethereum_header_proposal = request.into_inner().ethereum_header.clone();
        
        // let ethereum_header_proposal = request.into_inner().ethereum_header.clone().encode_to_vec();
        // let hex_str: String = ethereum_header_proposal.encode_hex();

        let mut proposal_bytes = vec![];
        let request_inner = request.into_inner();
        request_inner.encode(&mut proposal_bytes).unwrap();

        println!("total_bytes: {}, block:{}, header: {}", proposal_bytes.len(), 
        request_inner.ethereum_block.clone().len(),
        request_inner.ethereum_header.clone().len());

        // println!("rust gateway header:vec::Vec<u8> --> Vec<u8>{}", hex_str);

        // Forward Ethereum Block as TX to NarwhalClient
        match narwhal_client
            .submit_transaction(proposal_bytes)
            .await
        {
            Ok(result) => {
                info!("Transaction submitted: {}", result);
                println!("Transaction submitted: {}", result);
                resp.success_or_fail = "success".to_string();
            }
            Err(err) => {
                warn!("Failed to submit transaction: {}", err);
                println!("Failed to submit transaction: {}", err);
                resp.success_or_fail = "fail".to_string();
            }
        };

        // Wait for a corresponding ConsensusOutput
        // self.rx_co.recv()

        //

        Ok(Response::new(resp))
    }

    // async fn wait_for_output(&mut self) {
    //     println("hello");
    // }

    async fn deliver_consensus_output(
        &self,
        request: Request<GatewayConsensusOutput>, // Accept request of type HelloRequest
    ) -> Result<Response<DeliverConsensusOutputResponse>, Status> {
        // Return an instance of type HelloReply
        println!("Got a DeliverConsensusOutput: ");

        let mut mutex_changer = self.cnt_deliver_output.lock().await;
        *mutex_changer += 1;

        // let my_ch = Arc::clone(&self.tx_co);
        let locked_tx_co = &self.tx_co.lock().await;

        match locked_tx_co.send(request.into_inner()).await {
            Err(e) => println!("Failed send ConsensusOutput to Ch: Err{:?}", e),
            Ok(()) => println!("Successfully send request to internal channel"),
        }

        let reply = narwhal_gateway::DeliverConsensusOutputResponse {
            resp: format!("deliver {}-th consensus output response !", mutex_changer).into(), // We must use .into_inner() as the fields of gRPC requests and responses are private
        };

        std::mem::drop(mutex_changer);
        Ok(Response::new(reply)) // Send back our formatted greeting

        // send(request.into_inner()).await;
        // if let Err(_) =  {
        //     // println!("receiver dropped");
        // }
        // 876:                match RoaringBitmap::deserialize_from(&mut &serialized[..]) {
        // let cnt_tx = 0;
        // for (_, batches) in request.into_inner().batches {
        //     for batch in batches {
        //         // info!("cnt:batch{}", cnt_batch);
        //         // cnt_batch += 1;
        //         for transaction in batch.transactions.into_iter() {
        //             // if let Err(err) = self.tx_transaction_confirmation.send(transaction).await {
        //             // eprintln!("Failed to send txn in SimpleExecutionState: {}", err);
        //             // }
        //             // info!("cnt:tx{}", cnt_tx);
        //             // cnt_tx+=1;
        //             cnt_tx += 1;
        //         }
        //     }
        // }
        // let msg = SubscribeConsensusOutputResponse {
        //     narwhal_sequence_number: narwhal_sequence_number,
        //     eth_sequence_numbers: vec![1, 2, 34],
        //     eth_header_digest: vec![vec![1, 2], vec![1, 2]],
        // };
        // self.consensusoutput_db
        //     .lock()
        //     .unwrap()
        //     .insert(narwhal_sequence_number, vec![1, 2, 3]);
    }

    async fn subscribe_consensus_output(
        &self,
        request: Request<SubscribeConsensusOutputRequest>, // Accept request of type HelloRequest
    ) -> Result<Response<Self::SubscribeConsensusOutputStream>, Status> {
        // Return an instance of type HelloReply
        println!(
            "Start ConsensusOutput Delivery for requester GethID:{}",
            request.into_inner().requestor_id
        );

        let (_tx, rx) = mpsc::channel(1000);

        // tokio::spawn(async move {
        //     // let batch_size = 5;
        //     let consensus_output = SubscribeConsensusOutputResponse {
        //         narwhal_sequence_number: 0,
        //         eth_sequence_numbers: vec![1, 2, 34],
        //         eth_header_digest: vec![vec![1, 2], vec![1, 2]],
        //     };

        //     use tokio::time::{sleep, Duration};
        //     let sleep_time = 1;
        //     let mut cnt = 0;
        //     loop {
        //         if cnt == 5 {
        //             break;
        //         }
        //         println!("Confirmed");
        //         sleep(Duration::from_secs(sleep_time)).await;
        //         tx.send(Ok(consensus_output.clone())).await.unwrap();
        //         cnt += 1;
        //     }
        // });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

struct NarwhalClient {
    target: Url,
}

impl NarwhalClient {
    pub async fn submit_transaction(&self, payload: Vec<u8>) -> Result<String, eyre::Report> {
        let mut client = TransactionsClient::connect(self.target.as_str().to_owned())
            .await
            .wrap_err(format!("failed to connect to {}", self.target))?;

        let tx = TransactionProto {
            transaction: Bytes::from(payload.clone()),
        };

        info!("received payload {}", payload.len());

        if let Err(e) = client.submit_transaction(tx).await {
            warn!("Failed to send transaction: {e}");
            return Err(eyre::eyre!("Failed to send transaction"));
        }
        Ok("Success".to_owned())
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let addr = "[::1]:50051".parse()?;
    let addr = "0.0.0.0:50051".parse()?;
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    
    health_reporter.set_serving::<NarwhalGatewayServer<MyNarwhalGatewayServer>>()
        .await;


    // Define channels for ConsensusOutput communication
    let (tx_co, mut rx_co) = mpsc::channel(500);

    // let db = Arc::new(Mutex::new(HashMap::new()));

    let ng = MyNarwhalGatewayServer {
        cnt_deliver_output: Mutex::new(0),
        tx_co: Arc::new(Mutex::new(tx_co)),
        // consensusoutput_db: db,
    };
    // let subdag_json = serde_json::to_string(&consensus_output.sub_dag).unwrap();
        // info!("subdag_json: {}", subdag_json);

    tokio::spawn(async move {
        use narwhal_gateway::commit_notifier_client::CommitNotifierClient;
        let narwhal_adapter_addr = "http://0.0.0.0:60000";

        while let Some(_consensus_output) = rx_co.recv().await {
            let client = CommitNotifierClient::connect(narwhal_adapter_addr).await;
            println!(
                "Received Confirmed from TX Channel, len(headers): {:}",
                _consensus_output.batches.len()
            );

            let subdag: CommittedSubDag =
                bincode::deserialize(&mut _consensus_output.clone().sub_dag).unwrap();

            let _subdag_json = serde_json::to_string(&subdag).unwrap();
            let signed_authorities = subdag.clone().leader.signed_authorities;
            let leader_header_digest = _consensus_output.leader_header_digest;
            // from_str
            // println!("subdag_json: {}", subdag_json);
            println!("num_of_certificate: {}", subdag.certificates.len());
            println!("num_of_batches: {}", _consensus_output.batches.len());
            println!("subdag.index: {}", subdag.sub_dag_index);
            println!("signed_authorities: {:?}", signed_authorities);
            println!("leader_header_digest: {:?}", leader_header_digest);

            for au in signed_authorities {
                println!("Bit {} is set", au);
            }
            // subdag.certificates.

        //     for subdag.certificates
        //             // Check the signature.
        // let digest: Digest<{ crypto::DIGEST_LENGTH }> = Digest::from(self.digest());
        // self.author
        //     .verify(digest.as_ref(), &self.signature)
        //     .map_err(|_| DagError::InvalidSignature)


            let mut headers: Vec<Vec<u8>> = Vec::new();
            // let mut eth_sequence_numbers: Vec<u64> = Vec::new();
            for h in _consensus_output.batches {
                headers.push(h);
            }

            // let converted_digest:  Digest<64> = subdag.leader.header.digest().into();
            let header_digest: String = format!("{:?}", subdag.leader.header.digest());

            // let leader_certificate = serde_json::to_vec(&subdag.leader).unwrap();
            let dag_proof = DagProof{
                header_digest: header_digest.into_bytes(),
                leader_certificate: serde_json::to_vec(&subdag.leader).unwrap(),
            };
            
            let narwhal_commit_evt = tonic::Request::new(NarwhalCommitEvent {
                narwhal_sequence_number: subdag.sub_dag_index,
                eth_sequence_numbers: vec![1, 2, 3],
                eth_header_digest: headers,
                extensions: _consensus_output.sub_dag,
                dag_proof: Some(dag_proof),
            });

            // Send Notification to Geth that his transaction has been confirmed!
            let _response = client.unwrap().notify(narwhal_commit_evt).await;
            info!(
                "Successfully sent Notification Event to Geth; {:?}",
                _response
            );
        }
    });

    health_reporter.set_serving::<NarwhalGatewayServer<MyNarwhalGatewayServer>>()
        .await;
    
    println!("Start Narwhal Gateway Server!");
    Server::builder()
        .add_service(NarwhalGatewayServer::new(ng))
        .add_service(health_service)
        .serve(addr)
        .await?;

    Ok(())
}


// impl Default for mpsc::Sender<GatewayConsensusOutput> {
//     fn default() -> Self {}
// }
