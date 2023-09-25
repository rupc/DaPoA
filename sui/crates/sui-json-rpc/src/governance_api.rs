// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use jsonrpsee::core::RpcResult;
use std::collections::HashMap;
use std::sync::Arc;

use crate::api::GovernanceReadApiServer;
use crate::error::Error;
use crate::SuiRpcModule;
use async_trait::async_trait;
use jsonrpsee::RpcModule;
use sui_core::authority::AuthorityState;
use sui_open_rpc::Module;
use sui_types::base_types::SuiAddress;
use sui_types::committee::EpochId;
use sui_types::governance::{DelegatedStake, Delegation, DelegationStatus, StakedSui};
use sui_types::messages::{CommitteeInfoRequest, CommitteeInfoResponse};
use sui_types::sui_system_state::{SuiSystemState, ValidatorMetadata};

pub struct GovernanceReadApi {
    state: Arc<AuthorityState>,
}

impl GovernanceReadApi {
    pub fn new(state: Arc<AuthorityState>) -> Self {
        Self { state }
    }

    async fn get_staked_sui(&self, owner: SuiAddress) -> Result<Vec<StakedSui>, Error> {
        Ok(self
            .state
            .get_move_objects(owner, &StakedSui::type_())
            .await?)
    }
    async fn get_delegations(&self, owner: SuiAddress) -> Result<Vec<Delegation>, Error> {
        Ok(self
            .state
            .get_move_objects(owner, &Delegation::type_())
            .await?)
    }
}

#[async_trait]
impl GovernanceReadApiServer for GovernanceReadApi {
    async fn get_delegated_stakes(&self, owner: SuiAddress) -> RpcResult<Vec<DelegatedStake>> {
        let delegation = self
            .get_delegations(owner)
            .await?
            .into_iter()
            .map(|d| (d.staked_sui_id.bytes, d))
            .collect::<HashMap<_, _>>();

        Ok(self
            .get_staked_sui(owner)
            .await?
            .into_iter()
            .map(|staked_sui| {
                let id = staked_sui.id();
                DelegatedStake {
                    staked_sui,
                    delegation_status: delegation
                        .get(&id)
                        .cloned()
                        .map_or(DelegationStatus::Pending, DelegationStatus::Active),
                }
            })
            .collect())
    }

    async fn get_validators(&self) -> RpcResult<Vec<ValidatorMetadata>> {
        // TODO: include pending validators as well when the necessary changes are made in move.
        Ok(self
            .get_sui_system_state()
            .await?
            .validators
            .active_validators
            .into_iter()
            .map(|v| v.metadata)
            .collect())
    }

    async fn get_committee_info(&self, epoch: Option<EpochId>) -> RpcResult<CommitteeInfoResponse> {
        Ok(self
            .state
            .handle_committee_info_request(&CommitteeInfoRequest { epoch })
            .map_err(Error::from)?)
    }

    async fn get_sui_system_state(&self) -> RpcResult<SuiSystemState> {
        Ok(self
            .state
            .database
            .get_sui_system_state_object()
            .map_err(Error::from)?)
    }

    async fn get_reference_gas_price(&self) -> RpcResult<u64> {
        Ok(self.get_sui_system_state().await?.reference_gas_price)
    }
}

impl SuiRpcModule for GovernanceReadApi {
    fn rpc(self) -> RpcModule<Self> {
        self.into_rpc()
    }

    fn rpc_doc_module() -> Module {
        crate::api::GovernanceReadApiOpenRpc::module_doc()
    }
}
