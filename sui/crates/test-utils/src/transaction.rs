// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tracing::{debug, info};

use sui::client_commands::WalletContext;
use sui::client_commands::{SuiClientCommandResult, SuiClientCommands};
use sui_config::ValidatorInfo;
use sui_core::authority_client::AuthorityAPI;
pub use sui_core::test_utils::{compile_basics_package, wait_for_all_txes, wait_for_tx};
use sui_json_rpc_types::{SuiObjectRead, SuiTransactionResponse};
use sui_keys::keystore::AccountKeystore;
use sui_sdk::json::SuiJsonValue;
use sui_types::base_types::ObjectRef;
use sui_types::base_types::{ObjectID, SuiAddress, TransactionDigest};
use sui_types::committee::Committee;
use sui_types::crypto::{deterministic_random_account_key, AuthorityKeyPair};
use sui_types::error::SuiResult;
use sui_types::intent::Intent;
use sui_types::message_envelope::Message;
use sui_types::messages::{
    CallArg, ObjectArg, ObjectInfoRequest, ObjectInfoResponse, Transaction, TransactionData,
    TransactionEffects, TransactionEvents, VerifiedTransaction,
};
use sui_types::messages::{ExecuteTransactionRequestType, HandleCertificateResponse};
use sui_types::object::{Object, Owner};
use sui_types::SUI_FRAMEWORK_OBJECT_ID;

use crate::authority::get_client;
use crate::messages::{
    create_publish_move_package_transaction, get_account_and_gas_coins,
    get_gas_object_with_wallet_context, make_tx_certs_and_signed_effects,
    make_tx_certs_and_signed_effects_with_committee, MAX_GAS,
};

const GAS_BUDGET: u64 = 5000;

pub fn make_publish_package(gas_object: Object, path: PathBuf) -> VerifiedTransaction {
    let (sender, keypair) = deterministic_random_account_key();
    create_publish_move_package_transaction(
        gas_object.compute_object_reference(),
        path,
        sender,
        &keypair,
        None,
    )
}

pub async fn publish_package(
    gas_object: Object,
    path: PathBuf,
    configs: &[ValidatorInfo],
) -> ObjectRef {
    let (effects, _) = publish_package_for_effects(gas_object, path, configs).await;
    parse_package_ref(&effects.created).unwrap()
}

pub async fn publish_package_for_effects(
    gas_object: Object,
    path: PathBuf,
    configs: &[ValidatorInfo],
) -> (TransactionEffects, TransactionEvents) {
    submit_single_owner_transaction(make_publish_package(gas_object, path), configs).await
}

/// Helper function to publish the move package of a simple shared counter.
pub async fn publish_counter_package(gas_object: Object, configs: &[ValidatorInfo]) -> ObjectRef {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../sui_programmability/examples/basics");
    publish_package(gas_object, path, configs).await
}

/// Helper function to publish basic package.
pub async fn publish_basics_package(context: &WalletContext, sender: SuiAddress) -> ObjectRef {
    publish_package_with_wallet(
        context,
        sender,
        compile_basics_package().get_package_bytes(/* with_unpublished_deps */ false),
    )
    .await
}

/// Returns the published package's ObjectRef.
pub async fn publish_package_with_wallet(
    context: &WalletContext,
    sender: SuiAddress,
    all_module_bytes: Vec<Vec<u8>>,
) -> ObjectRef {
    let client = context.get_client().await.unwrap();
    let transaction = {
        let data = client
            .transaction_builder()
            .publish(sender, all_module_bytes, None, GAS_BUDGET)
            .await
            .unwrap();

        let signature = context
            .config
            .keystore
            .sign_secure(&sender, &data, Intent::default())
            .unwrap();
        Transaction::from_data(data, Intent::default(), vec![signature])
            .verify()
            .unwrap()
    };

    let resp = client
        .quorum_driver()
        .execute_transaction(
            transaction,
            Some(ExecuteTransactionRequestType::WaitForLocalExecution),
        )
        .await
        .unwrap();

    assert!(resp.confirmed_local_execution.unwrap());
    resp.effects
        .created
        .iter()
        .find(|obj_ref| obj_ref.owner == Owner::Immutable)
        .unwrap()
        .reference
        .to_object_ref()
}

/// A helper function to submit a move transaction
pub async fn submit_move_transaction(
    context: &WalletContext,
    module: &'static str,
    function: &'static str,
    package_id: ObjectID,
    arguments: Vec<SuiJsonValue>,
    sender: SuiAddress,
    gas_object: Option<ObjectID>,
) -> SuiTransactionResponse {
    debug!(?package_id, ?arguments, "move_transaction");
    let client = context.get_client().await.unwrap();
    let data = client
        .transaction_builder()
        .move_call(
            sender,
            package_id,
            module,
            function,
            vec![], // type_args
            arguments,
            gas_object,
            GAS_BUDGET,
        )
        .await
        .unwrap();

    let signature = context
        .config
        .keystore
        .sign_secure(&sender, &data, Intent::default())
        .unwrap();

    let tx = Transaction::from_data(data, Intent::default(), vec![signature])
        .verify()
        .unwrap();
    let tx_digest = tx.digest();
    debug!(?tx_digest, "submitting move transaction");

    let resp = client
        .quorum_driver()
        .execute_transaction(
            tx,
            Some(ExecuteTransactionRequestType::WaitForLocalExecution),
        )
        .await
        .unwrap();
    assert!(resp.confirmed_local_execution.unwrap());
    resp
}

/// A helper function to publish the basics package and make counter objects
pub async fn publish_basics_package_and_make_counter(
    context: &WalletContext,
    sender: SuiAddress,
) -> (ObjectRef, ObjectRef) {
    let package_ref = publish_basics_package(context, sender).await;

    debug!(?package_ref);

    let response = submit_move_transaction(
        context,
        "counter",
        "create",
        package_ref.0,
        vec![],
        sender,
        None,
    )
    .await;

    let counter_ref = response
        .effects
        .created
        .iter()
        .find(|obj_ref| matches!(obj_ref.owner, Owner::Shared { .. }))
        .unwrap()
        .reference
        .to_object_ref();
    debug!(?counter_ref);
    (package_ref, counter_ref)
}

pub async fn increment_counter(
    context: &WalletContext,
    sender: SuiAddress,
    gas_object: Option<ObjectID>,
    package_id: ObjectID,
    counter_id: ObjectID,
) -> SuiTransactionResponse {
    submit_move_transaction(
        context,
        "counter",
        "increment",
        package_id,
        vec![SuiJsonValue::new(json!(counter_id.to_hex_literal())).unwrap()],
        sender,
        gas_object,
    )
    .await
}

pub async fn create_devnet_nft(
    context: &mut WalletContext,
) -> Result<(SuiAddress, ObjectID, TransactionDigest), anyhow::Error> {
    let (sender, gas_objects) = get_account_and_gas_coins(context).await?.swap_remove(0);
    let gas_object = gas_objects.get(0).unwrap().id();

    let res = SuiClientCommands::CreateExampleNFT {
        name: Some("example_nft_name".into()),
        description: Some("example_nft_desc".into()),
        url: Some("https://sui.io/_nuxt/img/sui-logo.8d3c44e.svg".into()),
        gas: Some(*gas_object),
        gas_budget: Some(GAS_BUDGET),
    }
    .execute(context)
    .await?;

    let (object_id, digest) = if let SuiClientCommandResult::CreateExampleNFT(
        SuiObjectRead::Exists(obj),
    ) = res
    {
        (obj.reference.object_id, obj.previous_transaction)
    } else {
        panic!("CreateExampleNFT command did not return WalletCommandResult::CreateExampleNFT(SuiObjectRead::Exists, got {:?}", res);
    };

    Ok((sender, object_id, digest))
}

pub async fn transfer_sui(
    context: &mut WalletContext,
    sender: Option<SuiAddress>,
    receiver: Option<SuiAddress>,
) -> Result<(ObjectID, SuiAddress, SuiAddress, TransactionDigest), anyhow::Error> {
    let sender = match sender {
        None => context.config.keystore.addresses().get(0).cloned().unwrap(),
        Some(addr) => addr,
    };
    let receiver = match receiver {
        None => context.config.keystore.addresses().get(1).cloned().unwrap(),
        Some(addr) => addr,
    };
    let gas_ref = get_gas_object_with_wallet_context(context, &sender)
        .await
        .unwrap();

    let res = SuiClientCommands::TransferSui {
        to: receiver,
        amount: None,
        sui_coin_object_id: gas_ref.0,
        gas_budget: GAS_BUDGET,
    }
    .execute(context)
    .await?;

    let digest = if let SuiClientCommandResult::TransferSui(response) = res {
        response.effects.transaction_digest
    } else {
        panic!("transfer command did not return WalletCommandResult::TransferSui");
    };

    Ok((gas_ref.0, sender, receiver, digest))
}

pub async fn transfer_coin(
    context: &mut WalletContext,
) -> Result<
    (
        ObjectID,
        SuiAddress,
        SuiAddress,
        TransactionDigest,
        ObjectRef,
        u64,
    ),
    anyhow::Error,
> {
    let sender = context.config.keystore.addresses().get(0).cloned().unwrap();
    let receiver = context.config.keystore.addresses().get(1).cloned().unwrap();
    let client = context.get_client().await.unwrap();
    let object_refs = client
        .read_api()
        .get_objects_owned_by_address(sender)
        .await?;
    let object_to_send = object_refs.get(1).unwrap().object_id;

    // Send an object
    info!(
        "transferring coin {:?} from {:?} -> {:?}",
        object_to_send, sender, receiver
    );
    let res = SuiClientCommands::Transfer {
        to: receiver,
        object_id: object_to_send,
        gas: None,
        gas_budget: GAS_BUDGET,
    }
    .execute(context)
    .await?;

    let (digest, gas, gas_used) = if let SuiClientCommandResult::Transfer(_, response) = res {
        (
            response.effects.transaction_digest,
            response.transaction.data.gas_data.payment,
            response.effects.gas_used.computation_cost + response.effects.gas_used.storage_cost
                - response.effects.gas_used.storage_rebate,
        )
    } else {
        panic!("transfer command did not return WalletCommandResult::Transfer");
    };

    Ok((
        object_to_send,
        sender,
        receiver,
        digest,
        gas.to_object_ref(),
        gas_used,
    ))
}

pub async fn split_coin_with_wallet_context(context: &mut WalletContext, coin_id: ObjectID) {
    SuiClientCommands::SplitCoin {
        coin_id,
        amounts: None,
        count: Some(2),
        gas: None,
        gas_budget: MAX_GAS,
    }
    .execute(context)
    .await
    .unwrap();
}

pub async fn delete_devnet_nft(
    context: &mut WalletContext,
    sender: &SuiAddress,
    nft_to_delete: ObjectRef,
) -> SuiTransactionResponse {
    let gas = get_gas_object_with_wallet_context(context, sender)
        .await
        .unwrap_or_else(|| panic!("Expect {sender} to have at least one gas object"));
    let data = TransactionData::new_move_call_with_dummy_gas_price(
        *sender,
        SUI_FRAMEWORK_OBJECT_ID,
        "devnet_nft".parse().unwrap(),
        "burn".parse().unwrap(),
        Vec::new(),
        gas,
        vec![CallArg::Object(ObjectArg::ImmOrOwnedObject(nft_to_delete))],
        MAX_GAS,
    );

    let signature = context
        .config
        .keystore
        .sign_secure(sender, &data, Intent::default())
        .unwrap();

    let tx = Transaction::from_data(data, Intent::default(), vec![signature])
        .verify()
        .unwrap();
    let client = context.get_client().await.unwrap();
    let resp = client
        .quorum_driver()
        .execute_transaction(
            tx,
            Some(ExecuteTransactionRequestType::WaitForLocalExecution),
        )
        .await
        .unwrap();

    assert!(resp.confirmed_local_execution.unwrap());
    resp
}

/// Submit a certificate containing only owned-objects to all authorities.
pub async fn submit_single_owner_transaction(
    transaction: VerifiedTransaction,
    configs: &[ValidatorInfo],
) -> (TransactionEffects, TransactionEvents) {
    let certificate = make_tx_certs_and_signed_effects(vec![transaction])
        .0
        .pop()
        .unwrap();
    let mut responses = Vec::new();
    for config in configs {
        let client = get_client(config);
        let reply = client
            .handle_certificate(certificate.clone().into())
            .await
            .unwrap();
        responses.push(reply);
    }
    get_unique_effects(responses)
}

/// Keep submitting the certificates of a shared-object transaction until it is sequenced by
/// at least one consensus node. We use the loop since some consensus protocols (like Tusk)
/// may drop transactions. The certificate is submitted to every Sui authority.
pub async fn submit_shared_object_transaction(
    transaction: VerifiedTransaction,
    configs: &[ValidatorInfo],
) -> SuiResult<(TransactionEffects, TransactionEvents)> {
    let (committee, key_pairs) = Committee::new_simple_test_committee();
    submit_shared_object_transaction_with_committee(transaction, configs, &committee, &key_pairs)
        .await
}

/// Keep submitting the certificates of a shared-object transaction until it is sequenced by
/// at least one consensus node. We use the loop since some consensus protocols (like Tusk)
/// may drop transactions. The certificate is submitted to every Sui authority.
pub async fn submit_shared_object_transaction_with_committee(
    transaction: VerifiedTransaction,
    configs: &[ValidatorInfo],
    committee: &Committee,
    key_pairs: &[AuthorityKeyPair],
) -> SuiResult<(TransactionEffects, TransactionEvents)> {
    let certificate =
        make_tx_certs_and_signed_effects_with_committee(vec![transaction], committee, key_pairs)
            .0
            .pop()
            .unwrap();

    let replies = loop {
        let futures: Vec<_> = configs
            .iter()
            .map(|config| {
                let client = get_client(config);
                let cert = certificate.clone();
                async move { client.handle_certificate(cert.into()).await }
            })
            .collect();

        let replies: Vec<_> = futures::future::join_all(futures)
            .await
            .into_iter()
            // Remove all `FailedToHearBackFromConsensus` replies. Note that the original Sui error type
            // `SuiError::FailedToHearBackFromConsensus(..)` is lost when the message is sent through the
            // network (it is replaced by `RpcError`). As a result, the following filter doesn't work:
            // `.filter(|result| !matches!(result, Err(SuiError::FailedToHearBackFromConsensus(..))))`.
            .filter(|result| match result {
                Err(e) => !e.to_string().contains("deadline has elapsed"),
                _ => true,
            })
            .collect();

        if !replies.is_empty() {
            break replies;
        }
    };
    let replies: SuiResult<Vec<_>> = replies.into_iter().collect();
    replies.map(get_unique_effects)
}

pub fn get_unique_effects(
    replies: Vec<HandleCertificateResponse>,
) -> (TransactionEffects, TransactionEvents) {
    let mut all_effects = HashMap::new();
    let mut all_events = HashMap::new();
    for reply in replies {
        let effects = reply.signed_effects.into_data();
        all_effects.insert(effects.digest(), effects);
        all_events.insert(reply.events.digest(), reply.events);
    }
    assert_eq!(all_effects.len(), 1);
    assert_eq!(all_events.len(), 1);
    (
        all_effects.into_values().next().unwrap(),
        all_events.into_values().next().unwrap(),
    )
}

/// Extract the package reference from a transaction effect. This is useful to deduce the
/// authority-created package reference after attempting to publish a new Move package.
pub fn parse_package_ref(created_objs: &[(ObjectRef, Owner)]) -> Option<ObjectRef> {
    created_objs
        .iter()
        .find(|(_, owner)| matches!(owner, Owner::Immutable))
        .map(|(reference, _)| *reference)
}

/// Get the framework object
pub async fn get_framework_object(configs: &[ValidatorInfo]) -> Object {
    let mut responses = Vec::new();
    for config in configs {
        let client = get_client(config);
        let reply = client
            .handle_object_info_request(ObjectInfoRequest::latest_object_info_request(
                SUI_FRAMEWORK_OBJECT_ID,
                None,
            ))
            .await
            .unwrap();
        responses.push(reply);
    }
    extract_obj(responses)
}

pub fn extract_obj(replies: Vec<ObjectInfoResponse>) -> Object {
    let mut all_objects = HashSet::new();
    for reply in replies {
        all_objects.insert(reply.object);
    }
    assert_eq!(all_objects.len(), 1);
    all_objects.into_iter().next().unwrap()
}
