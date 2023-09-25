
<a name="0x2_staking_pool"></a>

# Module `0x2::staking_pool`



-  [Resource `StakingPool`](#0x2_staking_pool_StakingPool)
-  [Struct `PoolTokenExchangeRate`](#0x2_staking_pool_PoolTokenExchangeRate)
-  [Resource `InactiveStakingPool`](#0x2_staking_pool_InactiveStakingPool)
-  [Struct `PendingWithdrawEntry`](#0x2_staking_pool_PendingWithdrawEntry)
-  [Resource `StakedSui`](#0x2_staking_pool_StakedSui)
-  [Constants](#@Constants_0)
-  [Function `new`](#0x2_staking_pool_new)
-  [Function `request_add_delegation`](#0x2_staking_pool_request_add_delegation)
-  [Function `request_withdraw_delegation`](#0x2_staking_pool_request_withdraw_delegation)
-  [Function `withdraw_from_principal`](#0x2_staking_pool_withdraw_from_principal)
-  [Function `unwrap_staked_sui`](#0x2_staking_pool_unwrap_staked_sui)
-  [Function `deposit_rewards`](#0x2_staking_pool_deposit_rewards)
-  [Function `process_pending_delegation_withdraws`](#0x2_staking_pool_process_pending_delegation_withdraws)
-  [Function `process_pending_delegation`](#0x2_staking_pool_process_pending_delegation)
-  [Function `withdraw_rewards_and_burn_pool_tokens`](#0x2_staking_pool_withdraw_rewards_and_burn_pool_tokens)
-  [Function `deactivate_staking_pool`](#0x2_staking_pool_deactivate_staking_pool)
-  [Function `sui_balance`](#0x2_staking_pool_sui_balance)
-  [Function `pool_id`](#0x2_staking_pool_pool_id)
-  [Function `staked_sui_amount`](#0x2_staking_pool_staked_sui_amount)
-  [Function `delegation_activation_epoch`](#0x2_staking_pool_delegation_activation_epoch)
-  [Function `pool_token_exchange_rate_at_epoch`](#0x2_staking_pool_pool_token_exchange_rate_at_epoch)
-  [Function `pending_stake_amount`](#0x2_staking_pool_pending_stake_amount)
-  [Function `pending_principal_withdrawal_amounts`](#0x2_staking_pool_pending_principal_withdrawal_amounts)
-  [Function `new_pending_withdraw_entry`](#0x2_staking_pool_new_pending_withdraw_entry)
-  [Function `get_sui_amount`](#0x2_staking_pool_get_sui_amount)
-  [Function `get_token_amount`](#0x2_staking_pool_get_token_amount)
-  [Function `check_balance_invariants`](#0x2_staking_pool_check_balance_invariants)


<pre><code><b>use</b> <a href="">0x1::option</a>;
<b>use</b> <a href="balance.md#0x2_balance">0x2::balance</a>;
<b>use</b> <a href="coin.md#0x2_coin">0x2::coin</a>;
<b>use</b> <a href="epoch_time_lock.md#0x2_epoch_time_lock">0x2::epoch_time_lock</a>;
<b>use</b> <a href="locked_coin.md#0x2_locked_coin">0x2::locked_coin</a>;
<b>use</b> <a href="math.md#0x2_math">0x2::math</a>;
<b>use</b> <a href="object.md#0x2_object">0x2::object</a>;
<b>use</b> <a href="sui.md#0x2_sui">0x2::sui</a>;
<b>use</b> <a href="table.md#0x2_table">0x2::table</a>;
<b>use</b> <a href="table_vec.md#0x2_table_vec">0x2::table_vec</a>;
<b>use</b> <a href="transfer.md#0x2_transfer">0x2::transfer</a>;
<b>use</b> <a href="tx_context.md#0x2_tx_context">0x2::tx_context</a>;
</code></pre>



<a name="0x2_staking_pool_StakingPool"></a>

## Resource `StakingPool`

A staking pool embedded in each validator struct in the system state object.


<pre><code><b>struct</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a> <b>has</b> store, key
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>id: <a href="object.md#0x2_object_UID">object::UID</a></code>
</dt>
<dd>

</dd>
<dt>
<code>starting_epoch: u64</code>
</dt>
<dd>
 The epoch at which this pool started operating. Should be the epoch at which the validator became active.
</dd>
<dt>
<code>sui_balance: u64</code>
</dt>
<dd>
 The total number of SUI tokens in this pool, including the SUI in the rewards_pool, as well as in all the principal
 in the <code><a href="staking_pool.md#0x2_staking_pool_StakedSui">StakedSui</a></code> object, updated at epoch boundaries.
</dd>
<dt>
<code>rewards_pool: <a href="balance.md#0x2_balance_Balance">balance::Balance</a>&lt;<a href="sui.md#0x2_sui_SUI">sui::SUI</a>&gt;</code>
</dt>
<dd>
 The epoch delegation rewards will be added here at the end of each epoch.
</dd>
<dt>
<code>pool_token_balance: u64</code>
</dt>
<dd>
 Total number of pool tokens issued by the pool.
</dd>
<dt>
<code>exchange_rates: <a href="table.md#0x2_table_Table">table::Table</a>&lt;u64, <a href="staking_pool.md#0x2_staking_pool_PoolTokenExchangeRate">staking_pool::PoolTokenExchangeRate</a>&gt;</code>
</dt>
<dd>
 Exchange rate history of previous epochs. Key is the epoch number.
 The entries start from the <code>starting_epoch</code> of this pool and contain exchange rates at the beginning of each epoch,
 i.e., right after the rewards for the previous epoch have been deposited into the pool.
</dd>
<dt>
<code>pending_delegation: u64</code>
</dt>
<dd>
 Pending delegation amount for this epoch.
</dd>
<dt>
<code>pending_withdraws: <a href="table_vec.md#0x2_table_vec_TableVec">table_vec::TableVec</a>&lt;<a href="staking_pool.md#0x2_staking_pool_PendingWithdrawEntry">staking_pool::PendingWithdrawEntry</a>&gt;</code>
</dt>
<dd>
 Delegation withdraws requested during the current epoch. Similar to new delegation, the withdraws are processed
 at epoch boundaries. Rewards are withdrawn and distributed after the rewards for the current epoch have come in.
</dd>
</dl>


</details>

<a name="0x2_staking_pool_PoolTokenExchangeRate"></a>

## Struct `PoolTokenExchangeRate`

Struct representing the exchange rate of the delegation pool token to SUI.


<pre><code><b>struct</b> <a href="staking_pool.md#0x2_staking_pool_PoolTokenExchangeRate">PoolTokenExchangeRate</a> <b>has</b> <b>copy</b>, drop, store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>sui_amount: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>pool_token_amount: u64</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x2_staking_pool_InactiveStakingPool"></a>

## Resource `InactiveStakingPool`

An inactive staking pool associated with an inactive validator.
Only withdraws can be made from this pool.


<pre><code><b>struct</b> <a href="staking_pool.md#0x2_staking_pool_InactiveStakingPool">InactiveStakingPool</a> <b>has</b> key
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>id: <a href="object.md#0x2_object_UID">object::UID</a></code>
</dt>
<dd>

</dd>
<dt>
<code>pool: <a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a></code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x2_staking_pool_PendingWithdrawEntry"></a>

## Struct `PendingWithdrawEntry`

Struct representing a pending delegation withdraw.


<pre><code><b>struct</b> <a href="staking_pool.md#0x2_staking_pool_PendingWithdrawEntry">PendingWithdrawEntry</a> <b>has</b> store
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>delegator: <b>address</b></code>
</dt>
<dd>

</dd>
<dt>
<code>principal_withdraw_amount: u64</code>
</dt>
<dd>

</dd>
<dt>
<code>pool_token_withdraw_amount: u64</code>
</dt>
<dd>

</dd>
</dl>


</details>

<a name="0x2_staking_pool_StakedSui"></a>

## Resource `StakedSui`

A self-custodial object holding the staked SUI tokens.


<pre><code><b>struct</b> <a href="staking_pool.md#0x2_staking_pool_StakedSui">StakedSui</a> <b>has</b> key
</code></pre>



<details>
<summary>Fields</summary>


<dl>
<dt>
<code>id: <a href="object.md#0x2_object_UID">object::UID</a></code>
</dt>
<dd>

</dd>
<dt>
<code>pool_id: <a href="object.md#0x2_object_ID">object::ID</a></code>
</dt>
<dd>
 ID of the staking pool we are staking with.
</dd>
<dt>
<code>validator_address: <b>address</b></code>
</dt>
<dd>

</dd>
<dt>
<code>delegation_activation_epoch: u64</code>
</dt>
<dd>
 The epoch at which the delegation becomes active.
</dd>
<dt>
<code>principal: <a href="balance.md#0x2_balance_Balance">balance::Balance</a>&lt;<a href="sui.md#0x2_sui_SUI">sui::SUI</a>&gt;</code>
</dt>
<dd>
 The staked SUI tokens.
</dd>
<dt>
<code>sui_token_lock: <a href="_Option">option::Option</a>&lt;<a href="epoch_time_lock.md#0x2_epoch_time_lock_EpochTimeLock">epoch_time_lock::EpochTimeLock</a>&gt;</code>
</dt>
<dd>
 If the stake comes from a Coin<SUI>, this field is None. If it comes from a LockedCoin<SUI>, this
 field will record the original lock expiration epoch, to be used when unstaking.
</dd>
</dl>


</details>

<a name="@Constants_0"></a>

## Constants


<a name="0x2_staking_pool_EDestroyNonzeroBalance"></a>



<pre><code><b>const</b> <a href="staking_pool.md#0x2_staking_pool_EDestroyNonzeroBalance">EDestroyNonzeroBalance</a>: u64 = 5;
</code></pre>



<a name="0x2_staking_pool_EInsufficientPoolTokenBalance"></a>



<pre><code><b>const</b> <a href="staking_pool.md#0x2_staking_pool_EInsufficientPoolTokenBalance">EInsufficientPoolTokenBalance</a>: u64 = 0;
</code></pre>



<a name="0x2_staking_pool_EInsufficientRewardsPoolBalance"></a>



<pre><code><b>const</b> <a href="staking_pool.md#0x2_staking_pool_EInsufficientRewardsPoolBalance">EInsufficientRewardsPoolBalance</a>: u64 = 4;
</code></pre>



<a name="0x2_staking_pool_EInsufficientSuiTokenBalance"></a>



<pre><code><b>const</b> <a href="staking_pool.md#0x2_staking_pool_EInsufficientSuiTokenBalance">EInsufficientSuiTokenBalance</a>: u64 = 3;
</code></pre>



<a name="0x2_staking_pool_EPendingDelegationDoesNotExist"></a>



<pre><code><b>const</b> <a href="staking_pool.md#0x2_staking_pool_EPendingDelegationDoesNotExist">EPendingDelegationDoesNotExist</a>: u64 = 8;
</code></pre>



<a name="0x2_staking_pool_ETokenBalancesDoNotMatchExchangeRate"></a>



<pre><code><b>const</b> <a href="staking_pool.md#0x2_staking_pool_ETokenBalancesDoNotMatchExchangeRate">ETokenBalancesDoNotMatchExchangeRate</a>: u64 = 9;
</code></pre>



<a name="0x2_staking_pool_ETokenTimeLockIsSome"></a>



<pre><code><b>const</b> <a href="staking_pool.md#0x2_staking_pool_ETokenTimeLockIsSome">ETokenTimeLockIsSome</a>: u64 = 6;
</code></pre>



<a name="0x2_staking_pool_EWithdrawAmountCannotBeZero"></a>



<pre><code><b>const</b> <a href="staking_pool.md#0x2_staking_pool_EWithdrawAmountCannotBeZero">EWithdrawAmountCannotBeZero</a>: u64 = 2;
</code></pre>



<a name="0x2_staking_pool_EWithdrawalInSameEpoch"></a>



<pre><code><b>const</b> <a href="staking_pool.md#0x2_staking_pool_EWithdrawalInSameEpoch">EWithdrawalInSameEpoch</a>: u64 = 10;
</code></pre>



<a name="0x2_staking_pool_EWrongDelegation"></a>



<pre><code><b>const</b> <a href="staking_pool.md#0x2_staking_pool_EWrongDelegation">EWrongDelegation</a>: u64 = 7;
</code></pre>



<a name="0x2_staking_pool_EWrongPool"></a>



<pre><code><b>const</b> <a href="staking_pool.md#0x2_staking_pool_EWrongPool">EWrongPool</a>: u64 = 1;
</code></pre>



<a name="0x2_staking_pool_new"></a>

## Function `new`

Create a new, empty staking pool.


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_new">new</a>(starting_epoch: u64, ctx: &<b>mut</b> <a href="tx_context.md#0x2_tx_context_TxContext">tx_context::TxContext</a>): <a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_new">new</a>(starting_epoch: u64, ctx: &<b>mut</b> TxContext) : <a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a> {
    <b>let</b> exchange_rates = <a href="table.md#0x2_table_new">table::new</a>(ctx);
    <a href="table.md#0x2_table_add">table::add</a>(
        &<b>mut</b> exchange_rates,
        starting_epoch,
        <a href="staking_pool.md#0x2_staking_pool_PoolTokenExchangeRate">PoolTokenExchangeRate</a> { sui_amount: 0, pool_token_amount: 0 }
    );
    <a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a> {
        id: <a href="object.md#0x2_object_new">object::new</a>(ctx),
        starting_epoch,
        sui_balance: 0,
        rewards_pool: <a href="balance.md#0x2_balance_zero">balance::zero</a>(),
        pool_token_balance: 0,
        exchange_rates,
        pending_delegation: 0,
        pending_withdraws: <a href="table_vec.md#0x2_table_vec_empty">table_vec::empty</a>(ctx),
    }
}
</code></pre>



</details>

<a name="0x2_staking_pool_request_add_delegation"></a>

## Function `request_add_delegation`

Request to delegate to a staking pool. The delegation starts counting at the beginning of the next epoch,


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_request_add_delegation">request_add_delegation</a>(pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>, stake: <a href="balance.md#0x2_balance_Balance">balance::Balance</a>&lt;<a href="sui.md#0x2_sui_SUI">sui::SUI</a>&gt;, sui_token_lock: <a href="_Option">option::Option</a>&lt;<a href="epoch_time_lock.md#0x2_epoch_time_lock_EpochTimeLock">epoch_time_lock::EpochTimeLock</a>&gt;, validator_address: <b>address</b>, delegator: <b>address</b>, delegation_activation_epoch: u64, ctx: &<b>mut</b> <a href="tx_context.md#0x2_tx_context_TxContext">tx_context::TxContext</a>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_request_add_delegation">request_add_delegation</a>(
    pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>,
    stake: Balance&lt;SUI&gt;,
    sui_token_lock: Option&lt;EpochTimeLock&gt;,
    validator_address: <b>address</b>,
    delegator: <b>address</b>,
    delegation_activation_epoch: u64,
    ctx: &<b>mut</b> TxContext
) {
    <b>let</b> sui_amount = <a href="balance.md#0x2_balance_value">balance::value</a>(&stake);
    <b>assert</b>!(sui_amount &gt; 0, 0);
    <b>let</b> staked_sui = <a href="staking_pool.md#0x2_staking_pool_StakedSui">StakedSui</a> {
        id: <a href="object.md#0x2_object_new">object::new</a>(ctx),
        pool_id: <a href="object.md#0x2_object_id">object::id</a>(pool),
        validator_address,
        delegation_activation_epoch,
        principal: stake,
        sui_token_lock,
    };
    pool.pending_delegation = pool.pending_delegation + sui_amount;
    <a href="transfer.md#0x2_transfer_transfer">transfer::transfer</a>(staked_sui, delegator);
}
</code></pre>



</details>

<a name="0x2_staking_pool_request_withdraw_delegation"></a>

## Function `request_withdraw_delegation`

Request to withdraw <code>principal_withdraw_amount</code> of stake plus rewards from a staking pool.
This amount of principal in SUI is withdrawn and transferred to the delegator. A proportional amount
of pool tokens will be later burnt.
The rewards portion will be withdrawn at the end of the epoch, after the rewards have come in so we
can use the new exchange rate to calculate the rewards.


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_request_withdraw_delegation">request_withdraw_delegation</a>(pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>, staked_sui: <a href="staking_pool.md#0x2_staking_pool_StakedSui">staking_pool::StakedSui</a>, ctx: &<b>mut</b> <a href="tx_context.md#0x2_tx_context_TxContext">tx_context::TxContext</a>): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_request_withdraw_delegation">request_withdraw_delegation</a>(
    pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>,
    staked_sui: <a href="staking_pool.md#0x2_staking_pool_StakedSui">StakedSui</a>,
    ctx: &<b>mut</b> TxContext
) : u64 {
    <b>let</b> (pool_token_withdraw_amount, principal_withdraw, time_lock) =
        <a href="staking_pool.md#0x2_staking_pool_withdraw_from_principal">withdraw_from_principal</a>(pool, staked_sui);
    <b>let</b> delegator = <a href="tx_context.md#0x2_tx_context_sender">tx_context::sender</a>(ctx);
    <b>let</b> principal_withdraw_amount = <a href="balance.md#0x2_balance_value">balance::value</a>(&principal_withdraw);
    <a href="table_vec.md#0x2_table_vec_push_back">table_vec::push_back</a>(&<b>mut</b> pool.pending_withdraws, <a href="staking_pool.md#0x2_staking_pool_PendingWithdrawEntry">PendingWithdrawEntry</a> {
        delegator, principal_withdraw_amount, pool_token_withdraw_amount });

    // TODO: implement withdraw bonding period here.
    <b>if</b> (<a href="_is_some">option::is_some</a>(&time_lock)) {
        <a href="locked_coin.md#0x2_locked_coin_new_from_balance">locked_coin::new_from_balance</a>(principal_withdraw, <a href="_destroy_some">option::destroy_some</a>(time_lock), delegator, ctx);
    } <b>else</b> {
        <a href="transfer.md#0x2_transfer_transfer">transfer::transfer</a>(<a href="coin.md#0x2_coin_from_balance">coin::from_balance</a>(principal_withdraw, ctx), delegator);
        <a href="_destroy_none">option::destroy_none</a>(time_lock);
    };
    principal_withdraw_amount
}
</code></pre>



</details>

<a name="0x2_staking_pool_withdraw_from_principal"></a>

## Function `withdraw_from_principal`

Withdraw the principal SUI stored in the StakedSui object, and calculate the corresponding amount of pool
tokens using exchange rate at delegation epoch.
Returns values are amount of pool tokens withdrawn, withdrawn principal portion of SUI, and its
time lock if applicable.


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_withdraw_from_principal">withdraw_from_principal</a>(pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>, staked_sui: <a href="staking_pool.md#0x2_staking_pool_StakedSui">staking_pool::StakedSui</a>): (u64, <a href="balance.md#0x2_balance_Balance">balance::Balance</a>&lt;<a href="sui.md#0x2_sui_SUI">sui::SUI</a>&gt;, <a href="_Option">option::Option</a>&lt;<a href="epoch_time_lock.md#0x2_epoch_time_lock_EpochTimeLock">epoch_time_lock::EpochTimeLock</a>&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_withdraw_from_principal">withdraw_from_principal</a>(
    pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>,
    staked_sui: <a href="staking_pool.md#0x2_staking_pool_StakedSui">StakedSui</a>,
) : (u64, Balance&lt;SUI&gt;, Option&lt;EpochTimeLock&gt;) {

    // Check that the delegation information matches the pool.
    <b>assert</b>!(staked_sui.pool_id == <a href="object.md#0x2_object_id">object::id</a>(pool), <a href="staking_pool.md#0x2_staking_pool_EWrongPool">EWrongPool</a>);

    <b>let</b> exchange_rate_at_staking_epoch = <a href="staking_pool.md#0x2_staking_pool_pool_token_exchange_rate_at_epoch">pool_token_exchange_rate_at_epoch</a>(pool, staked_sui.delegation_activation_epoch);
    <b>let</b> (principal_withdraw, time_lock) = <a href="staking_pool.md#0x2_staking_pool_unwrap_staked_sui">unwrap_staked_sui</a>(staked_sui);
    <b>let</b> pool_token_withdraw_amount = <a href="staking_pool.md#0x2_staking_pool_get_token_amount">get_token_amount</a>(&exchange_rate_at_staking_epoch, <a href="balance.md#0x2_balance_value">balance::value</a>(&principal_withdraw));

    (
        pool_token_withdraw_amount,
        principal_withdraw,
        time_lock
    )
}
</code></pre>



</details>

<a name="0x2_staking_pool_unwrap_staked_sui"></a>

## Function `unwrap_staked_sui`



<pre><code><b>fun</b> <a href="staking_pool.md#0x2_staking_pool_unwrap_staked_sui">unwrap_staked_sui</a>(staked_sui: <a href="staking_pool.md#0x2_staking_pool_StakedSui">staking_pool::StakedSui</a>): (<a href="balance.md#0x2_balance_Balance">balance::Balance</a>&lt;<a href="sui.md#0x2_sui_SUI">sui::SUI</a>&gt;, <a href="_Option">option::Option</a>&lt;<a href="epoch_time_lock.md#0x2_epoch_time_lock_EpochTimeLock">epoch_time_lock::EpochTimeLock</a>&gt;)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="staking_pool.md#0x2_staking_pool_unwrap_staked_sui">unwrap_staked_sui</a>(staked_sui: <a href="staking_pool.md#0x2_staking_pool_StakedSui">StakedSui</a>): (Balance&lt;SUI&gt;, Option&lt;EpochTimeLock&gt;) {
    <b>let</b> <a href="staking_pool.md#0x2_staking_pool_StakedSui">StakedSui</a> {
        id,
        pool_id: _,
        validator_address: _,
        delegation_activation_epoch: _,
        principal,
        sui_token_lock
    } = staked_sui;
    <a href="object.md#0x2_object_delete">object::delete</a>(id);
    (principal, sui_token_lock)
}
</code></pre>



</details>

<a name="0x2_staking_pool_deposit_rewards"></a>

## Function `deposit_rewards`

Called at epoch advancement times to add rewards (in SUI) to the staking pool.


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_deposit_rewards">deposit_rewards</a>(pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>, rewards: <a href="balance.md#0x2_balance_Balance">balance::Balance</a>&lt;<a href="sui.md#0x2_sui_SUI">sui::SUI</a>&gt;, new_epoch: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_deposit_rewards">deposit_rewards</a>(pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>, rewards: Balance&lt;SUI&gt;, new_epoch: u64) {
    pool.sui_balance = pool.sui_balance + <a href="balance.md#0x2_balance_value">balance::value</a>(&rewards);
    <a href="balance.md#0x2_balance_join">balance::join</a>(&<b>mut</b> pool.rewards_pool, rewards);
    <a href="table.md#0x2_table_add">table::add</a>(
        &<b>mut</b> pool.exchange_rates,
        new_epoch,
        <a href="staking_pool.md#0x2_staking_pool_PoolTokenExchangeRate">PoolTokenExchangeRate</a> { sui_amount: pool.sui_balance, pool_token_amount: pool.pool_token_balance },
    );
}
</code></pre>



</details>

<a name="0x2_staking_pool_process_pending_delegation_withdraws"></a>

## Function `process_pending_delegation_withdraws`

Called at epoch boundaries to process pending delegation withdraws requested during the epoch.
For each pending withdraw entry, we withdraw the rewards from the pool at the new exchange rate and burn the pool
tokens.


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_process_pending_delegation_withdraws">process_pending_delegation_withdraws</a>(pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>, ctx: &<b>mut</b> <a href="tx_context.md#0x2_tx_context_TxContext">tx_context::TxContext</a>): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_process_pending_delegation_withdraws">process_pending_delegation_withdraws</a>(pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>, ctx: &<b>mut</b> TxContext) : u64 {
    <b>let</b> total_reward_withdraw = 0;
    <b>let</b> new_epoch = <a href="tx_context.md#0x2_tx_context_epoch">tx_context::epoch</a>(ctx) + 1;

    <b>while</b> (!<a href="table_vec.md#0x2_table_vec_is_empty">table_vec::is_empty</a>(&pool.pending_withdraws)) {
        <b>let</b> <a href="staking_pool.md#0x2_staking_pool_PendingWithdrawEntry">PendingWithdrawEntry</a> {
            delegator, principal_withdraw_amount, pool_token_withdraw_amount
        } = <a href="table_vec.md#0x2_table_vec_pop_back">table_vec::pop_back</a>(&<b>mut</b> pool.pending_withdraws);
        <b>let</b> reward_withdraw = <a href="staking_pool.md#0x2_staking_pool_withdraw_rewards_and_burn_pool_tokens">withdraw_rewards_and_burn_pool_tokens</a>(
            pool, principal_withdraw_amount, pool_token_withdraw_amount, new_epoch);
        total_reward_withdraw = total_reward_withdraw + <a href="balance.md#0x2_balance_value">balance::value</a>(&reward_withdraw);
        <a href="transfer.md#0x2_transfer_transfer">transfer::transfer</a>(<a href="coin.md#0x2_coin_from_balance">coin::from_balance</a>(reward_withdraw, ctx), delegator);
    };
    total_reward_withdraw
}
</code></pre>



</details>

<a name="0x2_staking_pool_process_pending_delegation"></a>

## Function `process_pending_delegation`

Called at epoch boundaries to process the pending delegation.


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_process_pending_delegation">process_pending_delegation</a>(pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>, new_epoch: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_process_pending_delegation">process_pending_delegation</a>(pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>, new_epoch: u64) {
    <b>let</b> new_epoch_exchange_rate = <a href="staking_pool.md#0x2_staking_pool_pool_token_exchange_rate_at_epoch">pool_token_exchange_rate_at_epoch</a>(pool, new_epoch);
    pool.sui_balance = pool.sui_balance + pool.pending_delegation;
    pool.pool_token_balance = <a href="staking_pool.md#0x2_staking_pool_get_token_amount">get_token_amount</a>(&new_epoch_exchange_rate, pool.sui_balance);
    pool.pending_delegation = 0;
    <a href="staking_pool.md#0x2_staking_pool_check_balance_invariants">check_balance_invariants</a>(pool, new_epoch);
}
</code></pre>



</details>

<a name="0x2_staking_pool_withdraw_rewards_and_burn_pool_tokens"></a>

## Function `withdraw_rewards_and_burn_pool_tokens`

This function does the following:
1. Calculates the total amount of SUI (including principal and rewards) that the provided pool tokens represent
at the current exchange rate.
2. Using the above number and the given <code>principal_withdraw_amount</code>, calculates the rewards portion of the
delegation we should withdraw.
3. Withdraws the rewards portion from the rewards pool at the current exchange rate. We only withdraw the rewards
portion because the principal portion was already taken out of the delegator's self custodied StakedSui at request
time in <code>request_withdraw_stake</code>.
4. Since SUI tokens are withdrawn, we need to burn the corresponding pool tokens to keep the exchange rate the same.
5. Updates the SUI balance amount of the pool.


<pre><code><b>fun</b> <a href="staking_pool.md#0x2_staking_pool_withdraw_rewards_and_burn_pool_tokens">withdraw_rewards_and_burn_pool_tokens</a>(pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>, principal_withdraw_amount: u64, pool_token_withdraw_amount: u64, new_epoch: u64): <a href="balance.md#0x2_balance_Balance">balance::Balance</a>&lt;<a href="sui.md#0x2_sui_SUI">sui::SUI</a>&gt;
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="staking_pool.md#0x2_staking_pool_withdraw_rewards_and_burn_pool_tokens">withdraw_rewards_and_burn_pool_tokens</a>(
    pool: &<b>mut</b> <a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>,
    principal_withdraw_amount: u64,
    pool_token_withdraw_amount: u64,
    new_epoch: u64,
) : Balance&lt;SUI&gt; {
    <b>let</b> new_epoch_exchange_rate = <a href="staking_pool.md#0x2_staking_pool_pool_token_exchange_rate_at_epoch">pool_token_exchange_rate_at_epoch</a>(pool, new_epoch);
    <b>let</b> total_sui_withdraw_amount = <a href="staking_pool.md#0x2_staking_pool_get_sui_amount">get_sui_amount</a>(&new_epoch_exchange_rate, pool_token_withdraw_amount);
    <b>let</b> reward_withdraw_amount =
        <b>if</b> (total_sui_withdraw_amount &gt;= principal_withdraw_amount)
            total_sui_withdraw_amount - principal_withdraw_amount
        <b>else</b> 0;
    // This may happen when we are withdrawing everything from the pool and
    // the rewards pool <a href="balance.md#0x2_balance">balance</a> may be less than reward_withdraw_amount.
    // TODO: FIGURE OUT EXACTLY WHY THIS CAN HAPPEN.
    reward_withdraw_amount = <a href="math.md#0x2_math_min">math::min</a>(reward_withdraw_amount, <a href="balance.md#0x2_balance_value">balance::value</a>(&pool.rewards_pool));
    pool.sui_balance = pool.sui_balance - (principal_withdraw_amount + reward_withdraw_amount);
    pool.pool_token_balance = pool.pool_token_balance - pool_token_withdraw_amount;
    <a href="balance.md#0x2_balance_split">balance::split</a>(&<b>mut</b> pool.rewards_pool, reward_withdraw_amount)
}
</code></pre>



</details>

<a name="0x2_staking_pool_deactivate_staking_pool"></a>

## Function `deactivate_staking_pool`

Deactivate a staking pool by wrapping it in an <code><a href="staking_pool.md#0x2_staking_pool_InactiveStakingPool">InactiveStakingPool</a></code> and sharing this newly created object.
After this pool deactivation, the pool stops earning rewards. Only delegation withdraws can be made to the pool.


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_deactivate_staking_pool">deactivate_staking_pool</a>(pool: <a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>, ctx: &<b>mut</b> <a href="tx_context.md#0x2_tx_context_TxContext">tx_context::TxContext</a>)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_deactivate_staking_pool">deactivate_staking_pool</a>(pool: <a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>, ctx: &<b>mut</b> TxContext) {
    <b>let</b> inactive_pool = <a href="staking_pool.md#0x2_staking_pool_InactiveStakingPool">InactiveStakingPool</a> { id: <a href="object.md#0x2_object_new">object::new</a>(ctx), pool};
    <a href="transfer.md#0x2_transfer_share_object">transfer::share_object</a>(inactive_pool);
}
</code></pre>



</details>

<a name="0x2_staking_pool_sui_balance"></a>

## Function `sui_balance`



<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_sui_balance">sui_balance</a>(pool: &<a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_sui_balance">sui_balance</a>(pool: &<a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>) : u64 { pool.sui_balance }
</code></pre>



</details>

<a name="0x2_staking_pool_pool_id"></a>

## Function `pool_id`



<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_pool_id">pool_id</a>(staked_sui: &<a href="staking_pool.md#0x2_staking_pool_StakedSui">staking_pool::StakedSui</a>): <a href="object.md#0x2_object_ID">object::ID</a>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_pool_id">pool_id</a>(staked_sui: &<a href="staking_pool.md#0x2_staking_pool_StakedSui">StakedSui</a>) : ID { staked_sui.pool_id }
</code></pre>



</details>

<a name="0x2_staking_pool_staked_sui_amount"></a>

## Function `staked_sui_amount`



<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_staked_sui_amount">staked_sui_amount</a>(staked_sui: &<a href="staking_pool.md#0x2_staking_pool_StakedSui">staking_pool::StakedSui</a>): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_staked_sui_amount">staked_sui_amount</a>(staked_sui: &<a href="staking_pool.md#0x2_staking_pool_StakedSui">StakedSui</a>): u64 { <a href="balance.md#0x2_balance_value">balance::value</a>(&staked_sui.principal) }
</code></pre>



</details>

<a name="0x2_staking_pool_delegation_activation_epoch"></a>

## Function `delegation_activation_epoch`



<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_delegation_activation_epoch">delegation_activation_epoch</a>(staked_sui: &<a href="staking_pool.md#0x2_staking_pool_StakedSui">staking_pool::StakedSui</a>): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_delegation_activation_epoch">delegation_activation_epoch</a>(staked_sui: &<a href="staking_pool.md#0x2_staking_pool_StakedSui">StakedSui</a>): u64 {
    staked_sui.delegation_activation_epoch
}
</code></pre>



</details>

<a name="0x2_staking_pool_pool_token_exchange_rate_at_epoch"></a>

## Function `pool_token_exchange_rate_at_epoch`



<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_pool_token_exchange_rate_at_epoch">pool_token_exchange_rate_at_epoch</a>(pool: &<a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>, epoch: u64): <a href="staking_pool.md#0x2_staking_pool_PoolTokenExchangeRate">staking_pool::PoolTokenExchangeRate</a>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_pool_token_exchange_rate_at_epoch">pool_token_exchange_rate_at_epoch</a>(pool: &<a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>, epoch: u64): <a href="staking_pool.md#0x2_staking_pool_PoolTokenExchangeRate">PoolTokenExchangeRate</a> {
    *<a href="table.md#0x2_table_borrow">table::borrow</a>(&pool.exchange_rates, epoch)
}
</code></pre>



</details>

<a name="0x2_staking_pool_pending_stake_amount"></a>

## Function `pending_stake_amount`

Calculate the total value of the pending staking requests for this staking pool.


<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_pending_stake_amount">pending_stake_amount</a>(<a href="staking_pool.md#0x2_staking_pool">staking_pool</a>: &<a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_pending_stake_amount">pending_stake_amount</a>(<a href="staking_pool.md#0x2_staking_pool">staking_pool</a>: &<a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>): u64 {
    <a href="staking_pool.md#0x2_staking_pool">staking_pool</a>.pending_delegation
}
</code></pre>



</details>

<a name="0x2_staking_pool_pending_principal_withdrawal_amounts"></a>

## Function `pending_principal_withdrawal_amounts`

Calculate the current the total withdrawal requests (in terms of principal) for the staking pool


<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_pending_principal_withdrawal_amounts">pending_principal_withdrawal_amounts</a>(<a href="staking_pool.md#0x2_staking_pool">staking_pool</a>: &<a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b> <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_pending_principal_withdrawal_amounts">pending_principal_withdrawal_amounts</a>(<a href="staking_pool.md#0x2_staking_pool">staking_pool</a>: &<a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>): u64 {
    <b>let</b> sum = 0;
    <b>let</b> len = <a href="table_vec.md#0x2_table_vec_length">table_vec::length</a>(&<a href="staking_pool.md#0x2_staking_pool">staking_pool</a>.pending_withdraws);
    <b>let</b> i = 0;
    <b>while</b> (i &lt; len) {
        <b>let</b> pending_withdraw = <a href="table_vec.md#0x2_table_vec_borrow">table_vec::borrow</a>(&<a href="staking_pool.md#0x2_staking_pool">staking_pool</a>.pending_withdraws, i);
        sum = sum + pending_withdraw.principal_withdraw_amount;
        i = i + 1;
    };
    sum
}
</code></pre>



</details>

<a name="0x2_staking_pool_new_pending_withdraw_entry"></a>

## Function `new_pending_withdraw_entry`

Create a new pending withdraw entry.


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_new_pending_withdraw_entry">new_pending_withdraw_entry</a>(delegator: <b>address</b>, principal_withdraw_amount: u64, pool_token_withdraw_amount: u64): <a href="staking_pool.md#0x2_staking_pool_PendingWithdrawEntry">staking_pool::PendingWithdrawEntry</a>
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>public</b>(<b>friend</b>) <b>fun</b> <a href="staking_pool.md#0x2_staking_pool_new_pending_withdraw_entry">new_pending_withdraw_entry</a>(
    delegator: <b>address</b>,
    principal_withdraw_amount: u64,
    pool_token_withdraw_amount: u64,
) : <a href="staking_pool.md#0x2_staking_pool_PendingWithdrawEntry">PendingWithdrawEntry</a> {
    <a href="staking_pool.md#0x2_staking_pool_PendingWithdrawEntry">PendingWithdrawEntry</a> { delegator, principal_withdraw_amount, pool_token_withdraw_amount }
}
</code></pre>



</details>

<a name="0x2_staking_pool_get_sui_amount"></a>

## Function `get_sui_amount`



<pre><code><b>fun</b> <a href="staking_pool.md#0x2_staking_pool_get_sui_amount">get_sui_amount</a>(exchange_rate: &<a href="staking_pool.md#0x2_staking_pool_PoolTokenExchangeRate">staking_pool::PoolTokenExchangeRate</a>, token_amount: u64): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="staking_pool.md#0x2_staking_pool_get_sui_amount">get_sui_amount</a>(exchange_rate: &<a href="staking_pool.md#0x2_staking_pool_PoolTokenExchangeRate">PoolTokenExchangeRate</a>, token_amount: u64): u64 {
    <b>if</b> (exchange_rate.pool_token_amount == 0) {
        <b>return</b> token_amount
    };
    <b>let</b> res = (exchange_rate.sui_amount <b>as</b> u128)
            * (token_amount <b>as</b> u128)
            / (exchange_rate.pool_token_amount <b>as</b> u128);
    (res <b>as</b> u64)
}
</code></pre>



</details>

<a name="0x2_staking_pool_get_token_amount"></a>

## Function `get_token_amount`



<pre><code><b>fun</b> <a href="staking_pool.md#0x2_staking_pool_get_token_amount">get_token_amount</a>(exchange_rate: &<a href="staking_pool.md#0x2_staking_pool_PoolTokenExchangeRate">staking_pool::PoolTokenExchangeRate</a>, sui_amount: u64): u64
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="staking_pool.md#0x2_staking_pool_get_token_amount">get_token_amount</a>(exchange_rate: &<a href="staking_pool.md#0x2_staking_pool_PoolTokenExchangeRate">PoolTokenExchangeRate</a>, sui_amount: u64): u64 {
    <b>if</b> (exchange_rate.sui_amount == 0) {
        <b>return</b> sui_amount
    };
    <b>let</b> res = (exchange_rate.pool_token_amount <b>as</b> u128)
            * (sui_amount <b>as</b> u128)
            / (exchange_rate.sui_amount <b>as</b> u128);
    (res <b>as</b> u64)
}
</code></pre>



</details>

<a name="0x2_staking_pool_check_balance_invariants"></a>

## Function `check_balance_invariants`



<pre><code><b>fun</b> <a href="staking_pool.md#0x2_staking_pool_check_balance_invariants">check_balance_invariants</a>(pool: &<a href="staking_pool.md#0x2_staking_pool_StakingPool">staking_pool::StakingPool</a>, epoch: u64)
</code></pre>



<details>
<summary>Implementation</summary>


<pre><code><b>fun</b> <a href="staking_pool.md#0x2_staking_pool_check_balance_invariants">check_balance_invariants</a>(pool: &<a href="staking_pool.md#0x2_staking_pool_StakingPool">StakingPool</a>, epoch: u64) {
    <b>let</b> exchange_rate = <a href="staking_pool.md#0x2_staking_pool_pool_token_exchange_rate_at_epoch">pool_token_exchange_rate_at_epoch</a>(pool, epoch);
    // check that the pool token <a href="balance.md#0x2_balance">balance</a> and <a href="sui.md#0x2_sui">sui</a> <a href="balance.md#0x2_balance">balance</a> ratio matches the exchange rate stored.
    <b>let</b> expected = <a href="staking_pool.md#0x2_staking_pool_get_token_amount">get_token_amount</a>(&exchange_rate, pool.sui_balance);
    <b>let</b> actual = pool.pool_token_balance;
    <b>assert</b>!(expected == actual, <a href="staking_pool.md#0x2_staking_pool_ETokenBalancesDoNotMatchExchangeRate">ETokenBalancesDoNotMatchExchangeRate</a>)
}
</code></pre>



</details>
