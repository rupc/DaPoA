// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, SuiRpcResult};
use crate::{RpcClient, WAIT_FOR_TX_TIMEOUT_SEC};
use fastcrypto::encoding::Base64;
use futures::stream;
use futures_core::Stream;
use jsonrpsee::core::client::Subscription;
use std::collections::BTreeMap;
use std::future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sui_json_rpc::api::GovernanceReadApiClient;
use sui_json_rpc_types::{
    Balance, Checkpoint, CheckpointId, Coin, CoinPage, DryRunTransactionResponse, DynamicFieldPage,
    EventPage, GetObjectDataResponse, GetPastObjectDataResponse, GetRawObjectDataResponse,
    SuiCoinMetadata, SuiEventEnvelope, SuiEventFilter, SuiMoveNormalizedModule, SuiObjectInfo,
    SuiTransactionResponse, TransactionsPage,
};
use sui_types::balance::Supply;
use sui_types::base_types::{
    ObjectID, SequenceNumber, SuiAddress, TransactionDigest, TxSequenceNumber,
};
use sui_types::committee::EpochId;
use sui_types::error::TRANSACTION_NOT_FOUND_MSG_PREFIX;
use sui_types::event::EventID;
use sui_types::messages::{
    CommitteeInfoResponse, ExecuteTransactionRequestType, TransactionData, VerifiedTransaction,
};
use sui_types::messages_checkpoint::{CheckpointSequenceNumber, CheckpointSummary};
use sui_types::query::{EventQuery, TransactionQuery};
use sui_types::sui_system_state::{SuiSystemState, ValidatorMetadata};

use futures::StreamExt;
use sui_json_rpc::api::{CoinReadApiClient, EventReadApiClient, ReadApiClient, WriteApiClient};
use sui_types::governance::DelegatedStake;

#[derive(Debug)]
pub struct ReadApi {
    api: Arc<RpcClient>,
}

impl ReadApi {
    pub(crate) fn new(api: Arc<RpcClient>) -> Self {
        Self { api }
    }

    pub async fn get_objects_owned_by_address(
        &self,
        address: SuiAddress,
    ) -> SuiRpcResult<Vec<SuiObjectInfo>> {
        Ok(self.api.http.get_objects_owned_by_address(address).await?)
    }

    pub async fn get_dynamic_fields(
        &self,
        object_id: ObjectID,
        cursor: Option<ObjectID>,
        limit: Option<usize>,
    ) -> SuiRpcResult<DynamicFieldPage> {
        Ok(self
            .api
            .http
            .get_dynamic_fields(object_id, cursor, limit)
            .await?)
    }

    pub async fn get_parsed_object(
        &self,
        object_id: ObjectID,
    ) -> SuiRpcResult<GetObjectDataResponse> {
        Ok(self.api.http.get_object(object_id).await?)
    }

    pub async fn try_get_parsed_past_object(
        &self,
        object_id: ObjectID,
        version: SequenceNumber,
    ) -> SuiRpcResult<GetPastObjectDataResponse> {
        Ok(self
            .api
            .http
            .try_get_past_object(object_id, version)
            .await?)
    }

    pub async fn get_object(&self, object_id: ObjectID) -> SuiRpcResult<GetRawObjectDataResponse> {
        Ok(self.api.http.get_raw_object(object_id).await?)
    }

    pub async fn get_total_transaction_number(&self) -> SuiRpcResult<u64> {
        Ok(self.api.http.get_total_transaction_number().await?)
    }

    pub async fn get_transactions_in_range(
        &self,
        start: TxSequenceNumber,
        end: TxSequenceNumber,
    ) -> SuiRpcResult<Vec<TransactionDigest>> {
        Ok(self.api.http.get_transactions_in_range(start, end).await?)
    }

    pub async fn get_transaction(
        &self,
        digest: TransactionDigest,
    ) -> SuiRpcResult<SuiTransactionResponse> {
        Ok(self.api.http.get_transaction(digest).await?)
    }

    pub async fn get_committee_info(
        &self,
        epoch: Option<EpochId>,
    ) -> SuiRpcResult<CommitteeInfoResponse> {
        Ok(self.api.http.get_committee_info(epoch).await?)
    }

    pub async fn get_transactions(
        &self,
        query: TransactionQuery,
        cursor: Option<TransactionDigest>,
        limit: Option<usize>,
        descending_order: bool,
    ) -> SuiRpcResult<TransactionsPage> {
        Ok(self
            .api
            .http
            .get_transactions(query, cursor, limit, Some(descending_order))
            .await?)
    }

    /// Return a checkpoint
    pub async fn get_checkpoint(&self, id: CheckpointId) -> SuiRpcResult<Checkpoint> {
        Ok(self.api.http.get_checkpoint(id).await?)
    }

    /// Return a checkpoint summary based on a checkpoint sequence number
    pub async fn get_checkpoint_summary(
        &self,
        seq_number: CheckpointSequenceNumber,
    ) -> SuiRpcResult<CheckpointSummary> {
        Ok(self.api.http.get_checkpoint_summary(seq_number).await?)
    }

    /// Return the sequence number of the latest checkpoint that has been executed
    pub async fn get_latest_checkpoint_sequence_number(
        &self,
    ) -> SuiRpcResult<CheckpointSequenceNumber> {
        Ok(self
            .api
            .http
            .get_latest_checkpoint_sequence_number()
            .await?)
    }

    pub fn get_transactions_stream(
        &self,
        query: TransactionQuery,
        cursor: Option<TransactionDigest>,
        descending_order: bool,
    ) -> impl Stream<Item = TransactionDigest> + '_ {
        stream::unfold(
            (vec![], cursor, true, query),
            move |(mut data, cursor, first, query)| async move {
                if let Some(item) = data.pop() {
                    Some((item, (data, cursor, false, query)))
                } else if (cursor.is_none() && first) || cursor.is_some() {
                    let page = self
                        .get_transactions(query.clone(), cursor, Some(100), descending_order)
                        .await
                        .ok()?;
                    let mut data = page.data;
                    data.reverse();
                    data.pop()
                        .map(|item| (item, (data, page.next_cursor, false, query)))
                } else {
                    None
                }
            },
        )
    }

    pub async fn get_normalized_move_modules_by_package(
        &self,
        package: ObjectID,
    ) -> SuiRpcResult<BTreeMap<String, SuiMoveNormalizedModule>> {
        Ok(self
            .api
            .http
            .get_normalized_move_modules_by_package(package)
            .await?)
    }

    pub async fn get_sui_system_state(&self) -> SuiRpcResult<SuiSystemState> {
        Ok(self.api.http.get_sui_system_state().await?)
    }

    pub async fn get_reference_gas_price(&self) -> SuiRpcResult<u64> {
        Ok(self.api.http.get_reference_gas_price().await?)
    }

    pub async fn dry_run_transaction(
        &self,
        tx: TransactionData,
    ) -> SuiRpcResult<DryRunTransactionResponse> {
        Ok(self
            .api
            .http
            .dry_run_transaction(Base64::from_bytes(&bcs::to_bytes(&tx)?))
            .await?)
    }
}

#[derive(Debug, Clone)]
pub struct CoinReadApi {
    api: Arc<RpcClient>,
}

impl CoinReadApi {
    pub(crate) fn new(api: Arc<RpcClient>) -> Self {
        Self { api }
    }

    pub async fn get_coins(
        &self,
        owner: SuiAddress,
        coin_type: Option<String>,
        cursor: Option<ObjectID>,
        limit: Option<usize>,
    ) -> SuiRpcResult<CoinPage> {
        Ok(self
            .api
            .http
            .get_coins(owner, coin_type, cursor, limit)
            .await?)
    }

    pub async fn get_all_coins(
        &self,
        owner: SuiAddress,
        cursor: Option<ObjectID>,
        limit: Option<usize>,
    ) -> SuiRpcResult<CoinPage> {
        Ok(self.api.http.get_all_coins(owner, cursor, limit).await?)
    }

    pub fn get_coins_stream(
        &self,
        owner: SuiAddress,
        coin_type: Option<String>,
    ) -> impl Stream<Item = Coin> + '_ {
        stream::unfold(
            (vec![], None, true, coin_type),
            move |(mut data, cursor, first, coin_type)| async move {
                if let Some(item) = data.pop() {
                    Some((item, (data, cursor, false, coin_type)))
                } else if (cursor.is_none() && first) || cursor.is_some() {
                    let page = self
                        .get_coins(owner, coin_type.clone(), cursor, Some(100))
                        .await
                        .ok()?;
                    let mut data = page.data;
                    data.reverse();
                    data.pop()
                        .map(|item| (item, (data, page.next_cursor, false, coin_type)))
                } else {
                    None
                }
            },
        )
    }

    pub async fn select_coins(
        &self,
        address: SuiAddress,
        coin_type: Option<String>,
        amount: u128,
        locked_until_epoch: Option<EpochId>,
        exclude: Vec<ObjectID>,
    ) -> SuiRpcResult<Vec<Coin>> {
        let mut total = 0u128;
        let coins = self
            .get_coins_stream(address, coin_type)
            .filter(|coin: &Coin| {
                future::ready(
                    locked_until_epoch == coin.locked_until_epoch
                        && !exclude.contains(&coin.coin_object_id),
                )
            })
            .take_while(|coin: &Coin| {
                let ready = future::ready(total < amount);
                total += coin.balance as u128;
                ready
            })
            .collect::<Vec<_>>()
            .await;

        if total < amount {
            return Err(Error::InsufficientFund { address, amount });
        }
        Ok(coins)
    }

    pub async fn get_balance(
        &self,
        owner: SuiAddress,
        coin_type: Option<String>,
    ) -> SuiRpcResult<Balance> {
        Ok(self.api.http.get_balance(owner, coin_type).await?)
    }

    pub async fn get_all_balances(&self, owner: SuiAddress) -> SuiRpcResult<Vec<Balance>> {
        Ok(self.api.http.get_all_balances(owner).await?)
    }

    pub async fn get_coin_metadata(&self, coin_type: String) -> SuiRpcResult<SuiCoinMetadata> {
        Ok(self.api.http.get_coin_metadata(coin_type).await?)
    }

    pub async fn get_total_supply(&self, coin_type: String) -> SuiRpcResult<Supply> {
        Ok(self.api.http.get_total_supply(coin_type).await?)
    }
}

#[derive(Clone)]
pub struct EventApi {
    api: Arc<RpcClient>,
}

impl EventApi {
    pub(crate) fn new(api: Arc<RpcClient>) -> Self {
        Self { api }
    }

    pub async fn subscribe_event(
        &self,
        filter: SuiEventFilter,
    ) -> SuiRpcResult<impl Stream<Item = SuiRpcResult<SuiEventEnvelope>>> {
        match &self.api.ws {
            Some(c) => {
                let subscription: Subscription<SuiEventEnvelope> =
                    c.subscribe_event(filter).await?;
                Ok(subscription.map(|item| Ok(item?)))
            }
            _ => Err(Error::Subscription(
                "Subscription only supported by WebSocket client.".to_string(),
            )),
        }
    }

    pub async fn get_events(
        &self,
        query: EventQuery,
        cursor: Option<EventID>,
        limit: Option<usize>,
        descending_order: bool,
    ) -> SuiRpcResult<EventPage> {
        Ok(self
            .api
            .http
            .get_events(query, cursor, limit, Some(descending_order))
            .await?)
    }

    pub fn get_events_stream(
        &self,
        query: EventQuery,
        cursor: Option<EventID>,
        descending_order: bool,
    ) -> impl Stream<Item = SuiEventEnvelope> + '_ {
        stream::unfold(
            (vec![], cursor, true, query),
            move |(mut data, cursor, first, query)| async move {
                if let Some(item) = data.pop() {
                    Some((item, (data, cursor, false, query)))
                } else if (cursor.is_none() && first) || cursor.is_some() {
                    let page = self
                        .get_events(query.clone(), cursor, Some(100), descending_order)
                        .await
                        .ok()?;
                    let mut data = page.data;
                    data.reverse();
                    data.pop()
                        .map(|item| (item, (data, page.next_cursor, false, query)))
                } else {
                    None
                }
            },
        )
    }
}

#[derive(Clone)]
pub struct QuorumDriver {
    api: Arc<RpcClient>,
}

impl QuorumDriver {
    pub(crate) fn new(api: Arc<RpcClient>) -> Self {
        Self { api }
    }

    /// Execute a transaction with a FullNode client. `request_type`
    /// defaults to `ExecuteTransactionRequestType::WaitForLocalExecution`.
    /// When `ExecuteTransactionRequestType::WaitForLocalExecution` is used,
    /// but returned `confirmed_local_execution` is false, the client polls
    /// the fullnode until the fullnode recognizes this transaction, or
    /// until times out (see WAIT_FOR_TX_TIMEOUT_SEC). If it times out, an
    /// error is returned from this call.
    pub async fn execute_transaction(
        &self,
        tx: VerifiedTransaction,
        request_type: Option<ExecuteTransactionRequestType>,
    ) -> SuiRpcResult<SuiTransactionResponse> {
        let (tx_bytes, signatures) = tx.to_tx_bytes_and_signatures();
        let request_type =
            request_type.unwrap_or(ExecuteTransactionRequestType::WaitForLocalExecution);
        let mut response: SuiTransactionResponse = self
            .api
            .http
            .submit_transaction(tx_bytes, signatures, request_type.clone())
            .await?;

        Ok(match request_type {
            ExecuteTransactionRequestType::WaitForEffectsCert => response,
            ExecuteTransactionRequestType::WaitForLocalExecution => {
                if let Some(confirmed_local_execution) = response.confirmed_local_execution {
                    if !confirmed_local_execution {
                        Self::wait_until_fullnode_sees_tx(
                            &self.api,
                            response.effects.transaction_digest,
                        )
                        .await?;
                    }
                }
                response.confirmed_local_execution = Some(true);
                response
            }
        })
    }

    async fn wait_until_fullnode_sees_tx(
        c: &RpcClient,
        tx_digest: TransactionDigest,
    ) -> SuiRpcResult<()> {
        let start = Instant::now();
        loop {
            let resp = ReadApiClient::get_transaction(&c.http, tx_digest).await;
            if let Err(err) = resp {
                if err.to_string().contains(TRANSACTION_NOT_FOUND_MSG_PREFIX) {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                } else {
                    // immediately return on other types of errors
                    return Err(Error::TransactionConfirmationError(tx_digest, err));
                }
            } else {
                return Ok(());
            }
            if start.elapsed().as_secs() >= WAIT_FOR_TX_TIMEOUT_SEC {
                return Err(Error::FailToConfirmTransactionStatus(
                    tx_digest,
                    WAIT_FOR_TX_TIMEOUT_SEC,
                ));
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct GovernanceApi {
    api: Arc<RpcClient>,
}

impl GovernanceApi {
    pub(crate) fn new(api: Arc<RpcClient>) -> Self {
        Self { api }
    }

    /// Return all [DelegatedStake].
    pub async fn get_delegated_stakes(
        &self,
        owner: SuiAddress,
    ) -> SuiRpcResult<Vec<DelegatedStake>> {
        Ok(self.api.http.get_delegated_stakes(owner).await?)
    }

    /// Return all validators available for stake delegation.
    pub async fn get_validators(&self) -> SuiRpcResult<Vec<ValidatorMetadata>> {
        Ok(self.api.http.get_validators().await?)
    }

    /// Return the committee information for the asked `epoch`.
    /// `epoch`: The epoch of interest. If None, default to the latest epoch
    pub async fn get_committee_info(
        &self,
        epoch: Option<EpochId>,
    ) -> SuiRpcResult<CommitteeInfoResponse> {
        Ok(self.api.http.get_committee_info(epoch).await?)
    }

    /// Return [SuiSystemState]
    pub async fn get_sui_system_state(&self) -> SuiRpcResult<SuiSystemState> {
        Ok(self.api.http.get_sui_system_state().await?)
    }
}
