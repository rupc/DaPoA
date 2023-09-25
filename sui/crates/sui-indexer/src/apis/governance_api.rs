// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use jsonrpsee::core::RpcResult;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::RpcModule;
use sui_json_rpc::api::{GovernanceReadApiClient, GovernanceReadApiServer};
use sui_json_rpc::SuiRpcModule;
use sui_open_rpc::Module;
use sui_types::base_types::{EpochId, SuiAddress};
use sui_types::governance::DelegatedStake;
use sui_types::messages::CommitteeInfoResponse;
use sui_types::sui_system_state::{SuiSystemState, ValidatorMetadata};

pub(crate) struct GovernanceReadApi {
    fullnode: HttpClient,
}

impl GovernanceReadApi {
    pub fn new(fullnode_client: HttpClient) -> Self {
        Self {
            fullnode: fullnode_client,
        }
    }
}

#[async_trait]
impl GovernanceReadApiServer for GovernanceReadApi {
    async fn get_delegated_stakes(&self, owner: SuiAddress) -> RpcResult<Vec<DelegatedStake>> {
        self.fullnode.get_delegated_stakes(owner).await
    }

    async fn get_validators(&self) -> RpcResult<Vec<ValidatorMetadata>> {
        self.fullnode.get_validators().await
    }

    async fn get_committee_info(&self, epoch: Option<EpochId>) -> RpcResult<CommitteeInfoResponse> {
        self.fullnode.get_committee_info(epoch).await
    }

    async fn get_sui_system_state(&self) -> RpcResult<SuiSystemState> {
        self.fullnode.get_sui_system_state().await
    }

    async fn get_reference_gas_price(&self) -> RpcResult<u64> {
        self.fullnode.get_reference_gas_price().await
    }
}

impl SuiRpcModule for GovernanceReadApi {
    fn rpc(self) -> RpcModule<Self> {
        self.into_rpc()
    }

    fn rpc_doc_module() -> Module {
        sui_json_rpc::api::GovernanceReadApiOpenRpc::module_doc()
    }
}
