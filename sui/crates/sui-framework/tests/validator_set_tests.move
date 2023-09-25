// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module sui::validator_set_tests {
    use sui::balance;
    use sui::coin;
    use sui::tx_context::{Self, TxContext};
    use sui::validator::{Self, Validator};
    use sui::validator_set::{Self, ValidatorSet};
    use sui::test_scenario;
    use sui::vec_map;
    use std::ascii;
    use std::option;
    use sui::test_utils::assert_eq;

    #[test]
    fun test_validator_set_flow() {
        let scenario = test_scenario::begin(@0x1);
        let ctx1 = test_scenario::ctx(&mut scenario);

        // Create 4 validators, with stake 100, 200, 300, 400.
        let validator1 = create_validator(@0x1, 1, ctx1);
        let validator2 = create_validator(@0x2, 2, ctx1);
        let validator3 = create_validator(@0x3, 3, ctx1);
        let validator4 = create_validator(@0x4, 4, ctx1);

        // Create a validator set with only the first validator in it.
        let validator_set = validator_set::new(vector[validator1], ctx1);
        assert!(validator_set::total_stake(&validator_set) == 100, 0);

        // Add the other 3 validators one by one.
        validator_set::request_add_validator(
            &mut validator_set,
            validator2,
        );
        // Adding validator during the epoch should not affect stake and quorum threshold.
        assert!(validator_set::total_stake(&validator_set) == 100, 0);

        validator_set::request_add_validator(
            &mut validator_set,
            validator3,
        );

        test_scenario::next_tx(&mut scenario, @0x1);
        {
            let ctx1 = test_scenario::ctx(&mut scenario);
            validator_set::request_add_delegation(
                &mut validator_set,
                @0x1,
                coin::into_balance(coin::mint_for_testing(500, ctx1)),
                option::none(),
                ctx1,
            );
            // Adding stake to existing active validator during the epoch
            // should not change total stake.
            assert!(validator_set::total_stake(&validator_set) == 100, 0);
        };

        test_scenario::next_tx(&mut scenario, @0x1);
        {
            validator_set::request_add_validator(
                &mut validator_set,
                validator4,
            );
        };

        test_scenario::next_tx(&mut scenario, @0x1);
        {
            let ctx1 = test_scenario::ctx(&mut scenario);
            advance_epoch_with_dummy_rewards(&mut validator_set, ctx1);
            // Total stake for these should be the starting stake + the 500 delegated to validator 1 in addition to the starting stake.
            assert!(validator_set::total_stake(&validator_set) == 1500, 0);

            validator_set::request_remove_validator(
                &mut validator_set,
                ctx1,
            );
            // Total validator candidate count changes, but total stake remains during epoch.
            assert!(validator_set::total_stake(&validator_set) == 1500, 0);
            advance_epoch_with_dummy_rewards(&mut validator_set, ctx1);
            // Validator1 is gone. This removes its stake (100) + the stake delegated to it (500).
            assert!(validator_set::total_stake(&validator_set) == 900, 0);
        };

        validator_set::destroy_for_testing(validator_set);
        test_scenario::end(scenario);
    }

    #[test]
    fun test_reference_gas_price_derivation() {
        let scenario = test_scenario::begin(@0x1);
        let ctx1 = test_scenario::ctx(&mut scenario);
        // Create 5 validators with different stakes and different gas prices.
        let v1 = create_validator_with_gas_price(@0x1, 1, 45, ctx1);
        let v2 = create_validator_with_gas_price(@0x2, 2, 42, ctx1);
        let v3 = create_validator_with_gas_price(@0x3, 3, 40, ctx1);
        let v4 = create_validator_with_gas_price(@0x4, 4, 41, ctx1);
        let v5 = create_validator_with_gas_price(@0x5, 10, 43, ctx1);

        // Create a validator set with only the first validator in it.
        let validator_set = validator_set::new(vector[v1], ctx1);

        assert_eq(validator_set::derive_reference_gas_price(&validator_set), 45);

        validator_set::request_add_validator(
            &mut validator_set,
            v2,
        );
        advance_epoch_with_dummy_rewards(&mut validator_set, ctx1);

        assert_eq(validator_set::derive_reference_gas_price(&validator_set), 45);

        validator_set::request_add_validator(
            &mut validator_set,
            v3,
        );
        advance_epoch_with_dummy_rewards(&mut validator_set, ctx1);

        assert_eq(validator_set::derive_reference_gas_price(&validator_set), 42);

        validator_set::request_add_validator(
            &mut validator_set,
            v4,
        );
        advance_epoch_with_dummy_rewards(&mut validator_set, ctx1);

        assert_eq(validator_set::derive_reference_gas_price(&validator_set), 42);

        validator_set::request_add_validator(
            &mut validator_set,
            v5,
        );
        advance_epoch_with_dummy_rewards(&mut validator_set, ctx1);

        assert_eq(validator_set::derive_reference_gas_price(&validator_set), 43);

        validator_set::destroy_for_testing(validator_set);
        test_scenario::end(scenario);
    }

    fun create_validator(addr: address, hint: u8, ctx: &mut TxContext): Validator {
        let stake_value = (hint as u64) * 100;
        let init_stake = coin::mint_for_testing(stake_value, ctx);
        let init_stake = coin::into_balance(init_stake);
        let name = hint_to_ascii(hint);
        let validator = validator::new_for_testing(
            addr,
            vector[hint],
            vector[hint],
            vector[hint],
            vector[hint],
            copy name,
            copy name,
            copy name,
            name,
            vector[hint],
            vector[hint],
            vector[hint],
            vector[hint],
            init_stake,
            option::none(),
            1,
            0,
            0,
            ctx
        );
        validator
    }

    fun create_validator_with_gas_price(addr: address, hint: u8, gas_price: u64, ctx: &mut TxContext): Validator {
        let stake_value = (hint as u64) * 100;
        let init_stake = coin::mint_for_testing(stake_value, ctx);
        let init_stake = coin::into_balance(init_stake);
        let name = hint_to_ascii(hint);
        let validator = validator::new_for_testing(
            addr,
            vector[hint],
            vector[hint],
            vector[hint],
            vector[hint],
            copy name,
            copy name,
            copy name,
            name,
            vector[hint],
            vector[hint],
            vector[hint],
            vector[hint],
            init_stake,
            option::none(),
            gas_price,
            0,
            0,
            ctx
        );
        validator
    }

    fun hint_to_ascii(hint: u8): vector<u8> {
        let ascii_bytes = vector[hint / 100 + 65, hint % 100 / 10 + 65, hint % 10 + 65];
        ascii::into_bytes(ascii::string(ascii_bytes))
    }

    fun advance_epoch_with_dummy_rewards(validator_set: &mut ValidatorSet, ctx: &mut TxContext) {
        let dummy_computation_reward = balance::zero();
        let dummy_storage_fund_reward = balance::zero();

        tx_context::increment_epoch_number(ctx);

        validator_set::advance_epoch(
            validator_set,
            &mut dummy_computation_reward,
            &mut dummy_storage_fund_reward,
            vec_map::empty(),
            0,
            ctx
        );

        balance::destroy_zero(dummy_computation_reward);
        balance::destroy_zero(dummy_storage_fund_reward);
    }
}
