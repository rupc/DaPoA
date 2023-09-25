// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::authority::authority_per_epoch_store::AuthorityPerEpochStore;
use crate::authority::AuthorityStore;
use std::collections::HashSet;
use sui_protocol_config::ProtocolConfig;
use sui_types::base_types::ObjectRef;
use sui_types::error::{SuiError, UserInputError, UserInputResult};
use sui_types::gas::SuiCostTable;
use sui_types::messages::{TransactionKind, VerifiedExecutableTransaction};
use sui_types::{
    base_types::{SequenceNumber, SuiAddress},
    error::SuiResult,
    fp_ensure,
    gas::{self, SuiGasStatus},
    messages::{InputObjectKind, InputObjects, SingleTransactionKind, TransactionData},
    object::{Object, Owner},
};
use sui_types::{SUI_CLOCK_OBJECT_ID, SUI_CLOCK_OBJECT_SHARED_VERSION};
use tracing::instrument;

async fn get_gas_status(
    store: &AuthorityStore,
    epoch_store: &AuthorityPerEpochStore,
    transaction: &TransactionData,
) -> SuiResult<SuiGasStatus<'static>> {
    let tx_kind = &transaction.kind;
    let gas_object_ref = transaction.gas_payment_object_ref();
    let gas_object_refs = match tx_kind {
        TransactionKind::Single(SingleTransactionKind::PaySui(p)) => p.coins.clone(),
        TransactionKind::Single(SingleTransactionKind::PayAllSui(p)) => p.coins.clone(),
        _ => vec![],
    };
    let extra_gas_object_refs = gas_object_refs.into_iter().skip(1).collect();

    check_gas(
        store,
        epoch_store,
        gas_object_ref,
        transaction.gas_budget(),
        transaction.gas_price(),
        &transaction.kind,
        extra_gas_object_refs,
    )
    .await
}

#[instrument(level = "trace", skip_all)]
pub async fn check_transaction_input(
    store: &AuthorityStore,
    epoch_store: &AuthorityPerEpochStore,
    transaction: &TransactionData,
) -> SuiResult<(SuiGasStatus<'static>, InputObjects)> {
    transaction.validity_check(epoch_store.protocol_config())?;
    let gas_status = get_gas_status(store, epoch_store, transaction).await?;
    let input_objects = transaction.input_objects()?;
    let objects = store.check_input_objects(&input_objects)?;
    let input_objects = check_objects(transaction, input_objects, objects).await?;
    Ok((gas_status, input_objects))
}

/// WARNING! This should only be used for the dev-inspect transaction. This transaction type
/// bypasses many of the normal object checks
pub(crate) async fn check_dev_inspect_input(
    store: &AuthorityStore,
    config: &ProtocolConfig,
    kind: &TransactionKind,
    gas_object: Object,
) -> Result<(ObjectRef, InputObjects), anyhow::Error> {
    let gas_object_ref = gas_object.compute_object_reference();
    TransactionData::validity_check_impl(config, kind, &gas_object_ref)?;
    for k in kind.single_transactions() {
        match k {
            SingleTransactionKind::TransferObject(_)
            | SingleTransactionKind::Call(_)
            | SingleTransactionKind::TransferSui(_)
            | SingleTransactionKind::Pay(_)
            | SingleTransactionKind::PaySui(_)
            | SingleTransactionKind::PayAllSui(_) => (),
            SingleTransactionKind::Publish(_)
            | SingleTransactionKind::ChangeEpoch(_)
            | SingleTransactionKind::Genesis(_)
            | SingleTransactionKind::ConsensusCommitPrologue(_)
            | SingleTransactionKind::ProgrammableTransaction(_) => {
                anyhow::bail!("Transaction kind {} is not supported in dev-inspect", k)
            }
        }
    }
    let mut input_objects = kind.input_objects()?;
    let mut objects = store.check_input_objects(&input_objects)?;
    let mut used_objects: HashSet<SuiAddress> = HashSet::new();
    for object in &objects {
        if !object.is_immutable() {
            fp_ensure!(
                used_objects.insert(object.id().into()),
                UserInputError::MutableObjectUsedMoreThanOnce {
                    object_id: object.id()
                }
                .into()
            );
        }
    }
    input_objects.push(InputObjectKind::ImmOrOwnedMoveObject(gas_object_ref));
    objects.push(gas_object);
    let input_objects = InputObjects::new(input_objects.into_iter().zip(objects).collect());
    Ok((gas_object_ref, input_objects))
}

pub async fn check_certificate_input(
    store: &AuthorityStore,
    epoch_store: &AuthorityPerEpochStore,
    cert: &VerifiedExecutableTransaction,
) -> SuiResult<(SuiGasStatus<'static>, InputObjects)> {
    let tx_data = &cert.data().intent_message.value;
    let gas_status = get_gas_status(store, epoch_store, tx_data).await?;
    let input_object_kinds = tx_data.input_objects()?;
    let input_object_data = if tx_data.kind.is_change_epoch_tx() {
        // When changing the epoch, we update a the system object, which is shared, without going
        // through sequencing, so we must bypass the sequence checks here.
        store.check_input_objects(&input_object_kinds)?
    } else {
        store.check_sequenced_input_objects(cert.digest(), &input_object_kinds, epoch_store)?
    };
    let input_objects = check_objects(tx_data, input_object_kinds, input_object_data).await?;
    Ok((gas_status, input_objects))
}

/// Checking gas budget by fetching the gas object only from the store,
/// and check whether the balance and budget satisfies the miminum requirement.
/// Returns the gas object (to be able to reuse it latter) and a gas status
/// that will be used in the entire lifecycle of the transaction execution.
#[instrument(level = "trace", skip_all)]
async fn check_gas(
    store: &AuthorityStore,
    epoch_store: &AuthorityPerEpochStore,
    gas_payment: &ObjectRef,
    gas_budget: u64,
    computation_gas_price: u64,
    tx_kind: &TransactionKind,
    additional_objects_for_gas_payment: Vec<ObjectRef>,
) -> SuiResult<SuiGasStatus<'static>> {
    if tx_kind.is_system_tx() {
        Ok(SuiGasStatus::new_unmetered())
    } else {
        let gas_object = store.get_object_by_key(&gas_payment.0, gas_payment.1)?;
        let gas_object = gas_object.ok_or_else(|| {
            SuiError::from(UserInputError::ObjectNotFound {
                object_id: gas_payment.0,
                version: Some(gas_payment.1),
            })
        })?;

        // If the transaction is TransferSui, we ensure that the gas balance is enough to cover
        // both gas budget and the transfer amount.
        let extra_amount = match tx_kind {
            TransactionKind::Single(SingleTransactionKind::TransferSui(t)) => {
                t.amount.unwrap_or_default()
            }
            TransactionKind::Single(SingleTransactionKind::PaySui(t)) => t.amounts.iter().sum(),
            _ => 0,
        };
        let reference_gas_price = epoch_store.reference_gas_price();
        if computation_gas_price < reference_gas_price {
            return Err(UserInputError::GasPriceUnderRGP {
                gas_price: computation_gas_price,
                reference_gas_price,
            }
            .into());
        }
        let protocol_config = epoch_store.protocol_config();
        let cost_table = SuiCostTable::new(protocol_config);
        let storage_gas_price = protocol_config.storage_gas_price();

        // TODO: We should revisit how we compute gas price and compare to gas budget.
        let gas_price = std::cmp::max(computation_gas_price, storage_gas_price);

        if tx_kind.is_pay_sui_tx() {
            let mut additional_objs = vec![];
            for obj_ref in additional_objects_for_gas_payment.iter() {
                let obj = store.get_object_by_key(&obj_ref.0, obj_ref.1)?;
                let obj = obj.ok_or(UserInputError::ObjectNotFound {
                    object_id: obj_ref.0,
                    version: Some(obj_ref.1),
                })?;
                additional_objs.push(obj);
            }
            gas::check_gas_balance(
                &gas_object,
                gas_budget,
                gas_price,
                extra_amount,
                additional_objs,
                &cost_table,
            )?;
        } else {
            gas::check_gas_balance(
                &gas_object,
                gas_budget,
                gas_price,
                extra_amount,
                vec![],
                &cost_table,
            )?;
        }

        gas::start_gas_metering(
            gas_budget,
            computation_gas_price,
            storage_gas_price,
            cost_table,
        )
        .map_err(|e| e.into())
    }
}

/// Check all the objects used in the transaction against the database, and ensure
/// that they are all the correct version and number.
#[instrument(level = "trace", skip_all)]
async fn check_objects(
    transaction: &TransactionData,
    input_objects: Vec<InputObjectKind>,
    objects: Vec<Object>,
) -> UserInputResult<InputObjects> {
    // We require that mutable objects cannot show up more than once.
    // In [`SingleTransactionKind::input_objects`] we checked that there is no
    // duplicate objects in the same SingleTransactionKind. However for a Batch
    // Transaction, we still need to make sure that the same mutable object don't show
    // up in more than one SingleTransactionKind.
    // TODO: We should be able to allow the same shared object to show up
    // in more than one SingleTransactionKind. We need to ensure that their
    // version number only increases once at the end of the Batch execution.
    let mut used_objects: HashSet<SuiAddress> = HashSet::new();
    for object in objects.iter() {
        if !object.is_immutable() {
            fp_ensure!(
                used_objects.insert(object.id().into()),
                UserInputError::MutableObjectUsedMoreThanOnce {
                    object_id: object.id()
                }
            );
        }
    }

    // Gather all objects and errors.
    let mut all_objects = Vec::with_capacity(input_objects.len());
    let transfer_object_ids: HashSet<_> = transaction
        .kind
        .single_transactions()
        .filter_map(|s| {
            if let SingleTransactionKind::TransferObject(t) = s {
                Some(t.object_ref.0)
            } else {
                None
            }
        })
        .collect();

    for (object_kind, object) in input_objects.into_iter().zip(objects) {
        if transfer_object_ids.contains(&object.id()) {
            object.ensure_public_transfer_eligible().map_err(|_e| {
                UserInputError::TransferObjectWithoutPublicTransferError {
                    object_id: object.id(),
                }
            })?;
        }
        // For Gas Object, we check the object is owned by gas owner
        let owner_address = if object.id() == transaction.gas_payment_object_ref().0 {
            transaction.gas_owner()
        } else {
            transaction.sender()
        };
        // Check if the object contents match the type of lock we need for
        // this object.
        let system_transaction = transaction.kind.is_system_tx();
        check_one_object(&owner_address, object_kind, &object, system_transaction)?;
        all_objects.push((object_kind, object));
    }
    if !transaction.kind.is_genesis_tx() && all_objects.is_empty() {
        return Err(UserInputError::ObjectInputArityViolation);
    }

    Ok(InputObjects::new(all_objects))
}

/// Check one object against a reference
fn check_one_object(
    owner: &SuiAddress,
    object_kind: InputObjectKind,
    object: &Object,
    system_transaction: bool,
) -> UserInputResult {
    match object_kind {
        InputObjectKind::MovePackage(package_id) => {
            fp_ensure!(
                object.data.try_as_package().is_some(),
                UserInputError::MoveObjectAsPackage {
                    object_id: package_id
                }
            );
        }
        InputObjectKind::ImmOrOwnedMoveObject((object_id, sequence_number, object_digest)) => {
            fp_ensure!(
                !object.is_package(),
                UserInputError::MovePackageAsObject { object_id }
            );
            fp_ensure!(
                sequence_number < SequenceNumber::MAX,
                UserInputError::InvalidSequenceNumber
            );

            // This is an invariant - we just load the object with the given ID and version.
            assert_eq!(
                object.version(),
                sequence_number,
                "The fetched object version {} does not match the requested version {}, object id: {}",
                object.version(),
                sequence_number,
                object.id(),
            );

            // Check the digest matches - user could give a mismatched ObjectDigest
            let expected_digest = object.digest();
            fp_ensure!(
                expected_digest == object_digest,
                UserInputError::InvalidObjectDigest {
                    object_id,
                    expected_digest
                }
            );

            match object.owner {
                Owner::Immutable => {
                    // Nothing else to check for Immutable.
                }
                Owner::AddressOwner(actual_owner) => {
                    // Check the owner is correct.
                    fp_ensure!(
                        owner == &actual_owner,
                        UserInputError::IncorrectUserSignature {
                            error: format!("Object {:?} is owned by account address {:?}, but given owner/signer address is {:?}", object_id, actual_owner, owner),
                        }
                    );
                }
                Owner::ObjectOwner(owner) => {
                    return Err(UserInputError::InvalidChildObjectArgument {
                        child_id: object.id(),
                        parent_id: owner.into(),
                    });
                }
                Owner::Shared { .. } => {
                    // This object is a mutable shared object. However the transaction
                    // specifies it as an owned object. This is inconsistent.
                    return Err(UserInputError::NotSharedObjectError);
                }
            };
        }
        InputObjectKind::SharedMoveObject {
            id: SUI_CLOCK_OBJECT_ID,
            initial_shared_version: SUI_CLOCK_OBJECT_SHARED_VERSION,
            mutable: true,
        } => {
            // Only system transactions can accept the Clock
            // object as a mutable parameter.
            if system_transaction {
                return Ok(());
            } else {
                return Err(UserInputError::ImmutableParameterExpectedError {
                    object_id: SUI_CLOCK_OBJECT_ID,
                });
            }
        }
        InputObjectKind::SharedMoveObject {
            initial_shared_version: input_initial_shared_version,
            ..
        } => {
            fp_ensure!(
                object.version() < SequenceNumber::MAX,
                UserInputError::InvalidSequenceNumber
            );

            match object.owner {
                Owner::AddressOwner(_) | Owner::ObjectOwner(_) | Owner::Immutable => {
                    // When someone locks an object as shared it must be shared already.
                    return Err(UserInputError::NotSharedObjectError);
                }
                Owner::Shared {
                    initial_shared_version: actual_initial_shared_version,
                } => {
                    fp_ensure!(
                        input_initial_shared_version == actual_initial_shared_version,
                        UserInputError::SharedObjectStartingVersionMismatch
                    )
                }
            }
        }
    };
    Ok(())
}
