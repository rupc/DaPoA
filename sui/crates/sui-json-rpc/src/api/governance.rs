// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use jsonrpsee::core::RpcResult;
use jsonrpsee_proc_macros::rpc;

use sui_open_rpc_macros::open_rpc;
use sui_types::base_types::SuiAddress;

use sui_types::committee::EpochId;
use sui_types::governance::DelegatedStake;
use sui_types::messages::CommitteeInfoResponse;

use sui_types::sui_system_state::{SuiSystemState, ValidatorMetadata};

#[open_rpc(namespace = "sui", tag = "Governance Read API")]
#[rpc(server, client, namespace = "sui")]
pub trait GovernanceReadApi {
    /// Return all [DelegatedStake].
    #[method(name = "getDelegatedStakes")]
    async fn get_delegated_stakes(&self, owner: SuiAddress) -> RpcResult<Vec<DelegatedStake>>;

    /// Return all validators available for stake delegation.
    #[method(name = "getValidators")]
    async fn get_validators(&self) -> RpcResult<Vec<ValidatorMetadata>>;

    /// Return the committee information for the asked `epoch`.
    #[method(name = "getCommitteeInfo")]
    async fn get_committee_info(
        &self,
        /// The epoch of interest. If None, default to the latest epoch
        epoch: Option<EpochId>,
    ) -> RpcResult<CommitteeInfoResponse>;

    /// Return [SuiSystemState]
    #[method(name = "getSuiSystemState")]
    async fn get_sui_system_state(&self) -> RpcResult<SuiSystemState>;

    /// Return the reference gas price for the network
    #[method(name = "getReferenceGasPrice")]
    async fn get_reference_gas_price(&self) -> RpcResult<u64>;
}
