// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{UserInputError, UserInputResult};
use crate::messages::TransactionEffects;
use crate::{
    error::{ExecutionError, ExecutionErrorKind},
    gas_coin::GasCoin,
    object::{Object, Owner},
};
use itertools::MultiUnzip;
use move_core_types::{
    gas_algebra::{GasQuantity, InternalGas, InternalGasPerByte, NumBytes, UnitDiv},
    vm_status::StatusCode,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    ops::{Add, Deref, Mul},
};
use sui_cost_tables::{
    bytecode_tables::{GasStatus, INITIAL_COST_SCHEDULE},
    units_types::GasUnit,
};
use sui_protocol_config::*;

pub type GasUnits = GasQuantity<GasUnit>;
pub enum GasPriceUnit {}
pub enum SuiGasUnit {}

pub type ComputeGasPricePerUnit = GasQuantity<UnitDiv<GasUnit, GasUnit>>;

pub type GasPrice = GasQuantity<GasPriceUnit>;
pub type SuiGas = GasQuantity<SuiGasUnit>;

macro_rules! ok_or_gas_balance_error {
    ($balance:expr, $budget:expr) => {
        if $balance < $budget {
            Err(UserInputError::GasBalanceTooLowToCoverGasBudget {
                gas_balance: $balance,
                gas_budget: $budget,
            })
        } else {
            Ok(())
        }
    };
}

#[derive(Eq, PartialEq, Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct GasCostSummary {
    pub computation_cost: u64,
    pub storage_cost: u64,
    pub storage_rebate: u64,
}

impl GasCostSummary {
    pub fn new(computation_cost: u64, storage_cost: u64, storage_rebate: u64) -> GasCostSummary {
        GasCostSummary {
            computation_cost,
            storage_cost,
            storage_rebate,
        }
    }

    pub fn gas_used(&self) -> u64 {
        self.computation_cost + self.storage_cost
    }

    /// Portion of the storage rebate that gets passed on to the transaction sender. The remainder
    /// will be burned, then re-minted + added to the storage fund at the next epoch change
    pub fn sender_rebate(&self, storage_rebate_rate: u64) -> u64 {
        // we round storage rebate such that `>= x.5` goes to x+1 (rounds up) and
        // `< x.5` goes to x (truncates). We replicate `f32/64::round()`
        const BASIS_POINTS: u128 = 10000;
        (((self.storage_rebate as u128 * storage_rebate_rate as u128)
            + (BASIS_POINTS / 2)) // integer rounding adds half of the BASIS_POINTS (denominator)
            / BASIS_POINTS) as u64
    }

    /// Portion of the storage rebate that flows back into the storage fund.
    /// This will be burned, then re-minted + added to the storage fund at the next epoch change.
    /// Note: these funds are not accounted for in the `storage_refund` field of any Sui object
    pub fn storage_fund_rebate_inflow(&self, storage_rebate_rate: u64) -> u64 {
        self.storage_rebate - self.sender_rebate(storage_rebate_rate)
    }

    /// Get net gas usage, positive number means used gas; negative number means refund.
    pub fn net_gas_usage(&self) -> i64 {
        self.gas_used() as i64 - self.storage_rebate as i64
    }

    pub fn new_from_txn_effects<'a>(
        transactions: impl Iterator<Item = &'a TransactionEffects>,
    ) -> GasCostSummary {
        let (storage_costs, computation_costs, storage_rebates): (Vec<u64>, Vec<u64>, Vec<u64>) =
            transactions
                .map(|e| {
                    (
                        e.gas_used.storage_cost,
                        e.gas_used.computation_cost,
                        e.gas_used.storage_rebate,
                    )
                })
                .multiunzip();

        GasCostSummary {
            storage_cost: storage_costs.iter().sum(),
            computation_cost: computation_costs.iter().sum(),
            storage_rebate: storage_rebates.iter().sum(),
        }
    }
}

// Fixed cost type
#[derive(Clone)]
pub struct FixedCost(InternalGas);
impl FixedCost {
    pub fn new(x: u64) -> Self {
        FixedCost(InternalGas::new(x))
    }
}
impl Deref for FixedCost {
    type Target = InternalGas;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// ComputationCostPerByte is a newtype wrapper of InternalGas
/// to ensure a value of this type is used specifically for computation cost.
/// Anything that does not change the amount of bytes stored in the authority data store
/// will charge ComputationCostPerByte.
pub struct ComputationCostPerByte(InternalGasPerByte);

impl ComputationCostPerByte {
    pub fn new(x: u64) -> Self {
        ComputationCostPerByte(InternalGasPerByte::new(x))
    }
}

impl Deref for ComputationCostPerByte {
    type Target = InternalGasPerByte;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// StorageCostPerByte is a newtype wrapper of InternalGas
/// to ensure a value of this type is used specifically for storage cost.
/// Anything that changes the amount of bytes stored in the authority data store
/// will charge StorageCostPerByte.
pub struct StorageCostPerByte(InternalGasPerByte);

impl Deref for StorageCostPerByte {
    type Target = InternalGasPerByte;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl StorageCostPerByte {
    pub fn new(x: u64) -> Self {
        StorageCostPerByte(InternalGasPerByte::new(x))
    }
}

/// A list of constant costs of various operations in Sui.
pub struct SuiCostTable {
    /// A flat fee charged for every transaction. This is also the mimmum amount of
    /// gas charged for a transaction.
    pub min_transaction_cost: FixedCost,
    /// Maximum allowable budget for a transaction.
    pub max_gas_budget: u64,
    /// Computation cost per byte charged for package publish. This cost is primarily
    /// determined by the cost to verify and link a package. Note that this does not
    /// include the cost of writing the package to the store.
    pub package_publish_per_byte_cost: ComputationCostPerByte,
    /// Per byte cost to read objects from the store. This is computation cost instead of
    /// storage cost because it does not change the amount of data stored on the db.
    pub object_read_per_byte_cost: ComputationCostPerByte,
    /// Per byte cost to write objects to the store. This is computation cost instead of
    /// storage cost because it does not change the amount of data stored on the db.
    pub object_mutation_per_byte_cost: ComputationCostPerByte,
    /// Unit cost of a byte in the storage. This will be used both for charging for
    /// new storage as well as rebating for deleting storage. That is, we expect users to
    /// get full refund on the object storage when it's deleted.
    /// TODO: We should introduce a flat fee on storage that does not get refunded even
    /// when objects are deleted. This cost covers the cost of storing transaction metadata
    /// which will always be there even after the objects are deleted.
    pub storage_per_byte_cost: StorageCostPerByte,
}

impl std::fmt::Debug for SuiCostTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: dump the fields.
        write!(f, "SuiCostTable(...)")
    }
}

impl SuiCostTable {
    pub fn new(c: &ProtocolConfig) -> Self {
        Self {
            min_transaction_cost: FixedCost::new(c.base_tx_cost_fixed()),
            max_gas_budget: c.max_tx_gas(),
            package_publish_per_byte_cost: ComputationCostPerByte::new(
                c.package_publish_cost_per_byte(),
            ),
            object_read_per_byte_cost: ComputationCostPerByte::new(
                c.obj_access_cost_read_per_byte(),
            ),
            object_mutation_per_byte_cost: ComputationCostPerByte::new(
                c.obj_access_cost_mutate_per_byte(),
            ),
            storage_per_byte_cost: StorageCostPerByte::new(c.obj_data_cost_refundable()),
        }
    }

    pub fn new_for_testing() -> Self {
        Self::new(&ProtocolConfig::get_for_max_version())
    }

    fn unmetered() -> Self {
        Self {
            min_transaction_cost: FixedCost::new(0),
            max_gas_budget: u64::MAX,
            package_publish_per_byte_cost: ComputationCostPerByte::new(0),
            object_read_per_byte_cost: ComputationCostPerByte::new(0),
            object_mutation_per_byte_cost: ComputationCostPerByte::new(0),
            storage_per_byte_cost: StorageCostPerByte::new(0),
        }
    }

    pub fn min_gas_budget_external(&self) -> u64 {
        u64::from(to_external(*self.min_transaction_cost))
    }
}

fn to_external(internal_units: InternalGas) -> GasUnits {
    InternalGas::to_unit_round_down(internal_units)
}

fn to_internal(external_units: GasUnits) -> InternalGas {
    GasUnits::to_unit(external_units)
}

#[derive(Debug)]
pub struct SuiGasStatus<'a> {
    gas_status: GasStatus<'a>,
    init_budget: GasUnits,
    charge: bool,
    computation_gas_unit_price: ComputeGasPricePerUnit,
    storage_gas_unit_price: ComputeGasPricePerUnit,
    /// storage_cost is the total storage gas units charged so far, due to writes into storage.
    /// It will be multiplied by the storage gas unit price in the end to obtain the Sui cost.
    storage_gas_units: GasUnits,
    /// storage_rebate is the total storage rebate (in Sui) accumulated in this transaction.
    /// It's directly coming from each mutated object's storage rebate field, which
    /// was the storage cost paid when the object was last mutated. It is not affected
    /// by the current storage gas unit price.
    storage_rebate: SuiGas,

    cost_table: SuiCostTable,
}

impl<'a> SuiGasStatus<'a> {
    pub fn new_with_budget(
        gas_budget: u64,
        computation_gas_unit_price: GasPrice,
        storage_gas_unit_price: GasPrice,
        cost_table: SuiCostTable,
    ) -> SuiGasStatus<'a> {
        let gas_price: u64 = computation_gas_unit_price.into();
        let budget_in_unit = gas_budget / gas_price; // truncate the value and move to units
        Self::new(
            GasStatus::new(&INITIAL_COST_SCHEDULE, GasUnits::new(budget_in_unit)),
            budget_in_unit,
            true,
            computation_gas_unit_price,
            storage_gas_unit_price.into(),
            cost_table,
        )
    }

    pub fn new_unmetered() -> SuiGasStatus<'a> {
        Self::new(
            GasStatus::new_unmetered(),
            0,
            false,
            0.into(),
            0,
            SuiCostTable::unmetered(),
        )
    }

    pub fn is_unmetered(&self) -> bool {
        !self.charge
    }

    pub fn max_gax_budget_in_balance(&self) -> u64 {
        let max_gas_unit_price =
            std::cmp::max(self.computation_gas_unit_price, self.storage_gas_unit_price);
        self.init_budget.mul(max_gas_unit_price).into()
    }

    pub fn create_move_gas_status(&mut self) -> &mut GasStatus<'a> {
        &mut self.gas_status
    }

    pub fn charge_vm_gas(&mut self) -> Result<(), ExecutionError> {
        // Disable flat fee for now
        // self.deduct_computation_cost(&VM_FLAT_FEE.to_unit())
        Ok(())
    }

    /// Try to charge the minimal amount of gas from the gas object.
    /// This function is called in tx signing phase to make sure
    /// the gas object has enough balance to cover minimal transaction cost.
    pub fn charge_min_tx_gas(&mut self) -> UserInputResult {
        let cost = self.cost_table.min_transaction_cost.clone();
        self.deduct_computation_cost(cost.deref())
            .map_err(|_e| UserInputError::InsufficientBalanceToCoverMinimalGas)
    }

    pub fn charge_publish_package(&mut self, size: usize) -> Result<(), ExecutionError> {
        let computation_cost =
            NumBytes::new(size as u64).mul(*self.cost_table.package_publish_per_byte_cost);

        self.deduct_computation_cost(&computation_cost)
    }

    pub fn charge_storage_read(&mut self, size: usize) -> Result<(), ExecutionError> {
        let cost = NumBytes::new(size as u64).mul(*self.cost_table.object_read_per_byte_cost);
        self.deduct_computation_cost(&cost)
    }

    pub fn charge_storage_mutation(
        &mut self,
        old_size: usize,
        new_size: usize,
        storage_rebate: SuiGas,
    ) -> Result<u64, ExecutionError> {
        if self.is_unmetered() {
            return Ok(0);
        }

        // Computation cost of a mutation is charged based on the sum of the old and new size.
        // This is because to update an object in the store, we have to erase the old one and
        // write a new one.
        let cost = NumBytes::new((old_size + new_size) as u64)
            .mul(*self.cost_table.object_mutation_per_byte_cost);
        self.deduct_computation_cost(&cost)?;

        self.storage_rebate += storage_rebate;

        let storage_cost =
            NumBytes::new(new_size as u64).mul(*self.cost_table.storage_per_byte_cost);

        self.deduct_storage_cost(&storage_cost).map(|q| q.into())
    }

    /// This function is only called during testing, where we need to mock
    /// Move VM charging gas.
    pub fn charge_vm_exec_test_only(&mut self, cost: u64) -> Result<(), ExecutionError> {
        self.gas_status
            .deduct_gas(InternalGas::new(cost))
            .map_err(|e| {
                debug_assert_eq!(e.major_status(), StatusCode::OUT_OF_GAS);
                ExecutionErrorKind::InsufficientGas.into()
            })
    }

    /// Returns the final (computation cost, storage cost, storage rebate) of the gas meter.
    /// We use initial budget, combined with remaining gas and storage cost to derive
    /// computation cost.
    pub fn summary(&self, succeeded: bool) -> GasCostSummary {
        let remaining_gas = self.gas_status.remaining_gas();
        let storage_cost = self.storage_gas_units;
        // TODO: handle underflow how?
        let computation_cost = self
            .init_budget
            .checked_sub(remaining_gas)
            .expect("Subtraction overflowed")
            .checked_sub(storage_cost)
            .expect("Subtraction overflowed");
        let computation_cost_in_sui = computation_cost.mul(self.computation_gas_unit_price).into();
        if succeeded {
            GasCostSummary {
                computation_cost: computation_cost_in_sui,
                storage_cost: storage_cost.mul(self.storage_gas_unit_price).into(),
                storage_rebate: self.storage_rebate.into(),
            }
        } else {
            // If execution failed, no storage creation/deletion will materialize in the store.
            // Hence they should be 0.
            GasCostSummary {
                computation_cost: computation_cost_in_sui,
                storage_cost: 0,
                storage_rebate: 0,
            }
        }
    }

    fn new(
        move_gas_status: GasStatus<'a>,
        gas_budget: u64,
        charge: bool,
        computation_gas_unit_price: GasPrice,
        storage_gas_unit_price: u64,
        cost_table: SuiCostTable,
    ) -> SuiGasStatus<'a> {
        SuiGasStatus {
            gas_status: move_gas_status,
            init_budget: GasUnits::new(gas_budget),
            charge,
            computation_gas_unit_price: ComputeGasPricePerUnit::new(
                computation_gas_unit_price.into(),
            ),
            storage_gas_unit_price: ComputeGasPricePerUnit::new(storage_gas_unit_price),
            storage_gas_units: GasUnits::new(0),
            storage_rebate: 0.into(),
            cost_table,
        }
    }

    fn deduct_computation_cost(&mut self, cost: &InternalGas) -> Result<(), ExecutionError> {
        self.gas_status.deduct_gas(*cost).map_err(|e| {
            debug_assert_eq!(e.major_status(), StatusCode::OUT_OF_GAS);
            ExecutionErrorKind::InsufficientGas.into()
        })
    }

    fn deduct_storage_cost(&mut self, cost: &InternalGas) -> Result<GasUnits, ExecutionError> {
        if self.is_unmetered() {
            return Ok(0.into());
        }
        let ext_cost = to_external(NumBytes::new(1).mul(InternalGasPerByte::new(u64::from(*cost))));
        let charge_amount = to_internal(ext_cost);
        let remaining_gas = self.gas_status.remaining_gas();
        if self.gas_status.deduct_gas(charge_amount).is_err() {
            debug_assert_eq!(u64::from(self.gas_status.remaining_gas()), 0);
            // Even when we run out of gas, we still keep track of the storage_cost change,
            // so that at the end, we could still use it to accurately derive the
            // computation cost.
            self.storage_gas_units = self.storage_gas_units.add(remaining_gas);
            Err(ExecutionErrorKind::InsufficientGas.into())
        } else {
            self.storage_gas_units = self.storage_gas_units.add(ext_cost);
            Ok(ext_cost.mul(self.storage_gas_unit_price))
        }
    }
}

/// Check whether the given gas_object and gas_budget is legit:
/// 1. If the gas object has an address owner.
/// 2. If it's enough to pay the flat minimum transaction fee
/// 3. If it's less than the max gas budget allowed
/// 4. If the gas_object actually has enough balance to pay for the budget
/// 5. If total balance in gas object and extra input objects is sufficient
/// to pay total amount of gas budget and extra amount to pay, extra input objects
/// and extra amount to pay are only relevant in SUI payment transactions.
pub fn check_gas_balance(
    gas_object: &Object,
    gas_budget: u64,
    gas_price: u64,
    extra_amount: u64,
    extra_objs: Vec<Object>,
    cost_table: &SuiCostTable,
) -> UserInputResult {
    if !(matches!(gas_object.owner, Owner::AddressOwner(_))) {
        return Err(UserInputError::GasObjectNotOwnedObject {
            owner: gas_object.owner,
        });
    }

    let max_gas_budget = cost_table.max_gas_budget as u128 * gas_price as u128;
    let min_gas_budget = cost_table.min_gas_budget_external() as u128 * gas_price as u128;

    if (gas_budget as u128) > max_gas_budget {
        return Err(UserInputError::GasBudgetTooHigh {
            gas_budget,
            max_budget: cost_table.max_gas_budget,
        });
    }

    if (gas_budget as u128) < min_gas_budget {
        return Err(UserInputError::GasBudgetTooLow {
            gas_budget,
            min_budget: cost_table.min_gas_budget_external(),
        });
    }

    // TODO: remove this check if gas payment with multiple coins is supported.
    // This check is necessary now because, when transactions failed due to execution error,
    // balance of gas budget will be reverted to pre-transaction state.
    // Meanwhile we need to make sure that the pre-transaction balance is sufficient
    // to pay for gas cost before execution error occurs.
    let gas_balance = get_gas_balance(gas_object)?;

    ok_or_gas_balance_error!(gas_balance as u128, gas_budget as u128)?;

    let mut total_balance = gas_balance as u128;
    for extra_obj in extra_objs {
        total_balance += get_gas_balance(&extra_obj)? as u128;
    }

    let total_amount = (gas_budget as u128) + (extra_amount as u128);
    ok_or_gas_balance_error!(total_balance, total_amount)
}

/// Create a new gas status with the given `gas_budget`, and charge the transaction flat fee.
pub fn start_gas_metering(
    gas_budget: u64,
    computation_gas_unit_price: u64,
    storage_gas_unit_price: u64,
    cost_table: SuiCostTable,
) -> UserInputResult<SuiGasStatus<'static>> {
    let mut gas_status = SuiGasStatus::new_with_budget(
        gas_budget,
        computation_gas_unit_price.into(),
        storage_gas_unit_price.into(),
        cost_table,
    );
    // Charge the flat transaction fee.
    gas_status.charge_min_tx_gas()?;
    Ok(gas_status)
}

/// Subtract the gas balance of \p gas_object by \p amount.
/// This function should never fail, since we checked that the budget is always
/// less than balance, and the amount is capped at the budget.
pub fn deduct_gas(gas_object: &mut Object, deduct_amount: u64, rebate_amount: u64) {
    // The object must be a gas coin as we have checked in transaction handle phase.
    let gas_coin = GasCoin::try_from(&*gas_object).unwrap();
    let balance = gas_coin.value();
    assert!(balance >= deduct_amount);
    let new_gas_coin = GasCoin::new(*gas_coin.id(), balance + rebate_amount - deduct_amount);
    let move_object = gas_object.data.try_as_move_mut().unwrap();
    // unwrap safe because GasCoin is guaranteed to serialize
    let new_contents = bcs::to_bytes(&new_gas_coin).unwrap();
    assert_eq!(move_object.contents().len(), new_contents.len());
    move_object.update_coin_contents(new_contents);
}

pub fn refund_gas(gas_object: &mut Object, amount: u64) {
    // The object must be a gas coin as we have checked in transaction handle phase.
    let gas_coin = GasCoin::try_from(&*gas_object).unwrap();
    let balance = gas_coin.value();
    let new_gas_coin = GasCoin::new(*gas_coin.id(), balance + amount);
    let move_object = gas_object.data.try_as_move_mut().unwrap();
    // unwrap safe because GasCoin is guaranteed to serialize
    let new_contents = bcs::to_bytes(&new_gas_coin).unwrap();
    // unwrap because safe gas object cannot exceed max object size
    move_object.update_coin_contents(new_contents);
}

pub fn get_gas_balance(gas_object: &Object) -> UserInputResult<u64> {
    Ok(GasCoin::try_from(gas_object)
        .map_err(|_e| UserInputError::InvalidGasObject {
            object_id: gas_object.id(),
        })?
        .value())
}
