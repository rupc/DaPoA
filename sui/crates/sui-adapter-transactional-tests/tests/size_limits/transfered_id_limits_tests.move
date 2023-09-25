// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test limts on number of transferd IDs 

//# init --addresses Test=0x0

//# publish

/// Test transfered id limits enforced
/// Right now, we should never be able to hit the transfer limit because we will hit the create limit first
module Test::M1 {
    use sui::tx_context::{TxContext, Self};
    use sui::object::{Self, UID};
    use sui::transfer;

    struct Obj has key, store {
        id: UID
    }

    public entry fun transfer_n_ids(n: u64, ctx: &mut TxContext) {
        let i = 0;
        while (i < n) {
            transfer::transfer(
                Obj {
                    id: object::new(ctx)
                },
                tx_context::sender(ctx),
            );
            i = i + 1;
        };
    }
}

// transfer below transfer count limit should succeed
//# run Test::M1::transfer_n_ids --args 1

// transfer below transfer count limit should succeed
//# run Test::M1::transfer_n_ids --args 256

// run at run count limit should succeed
//# run Test::M1::transfer_n_ids --args 2048

// run above run count limit should fail
//# run Test::M1::transfer_n_ids --args 2049

// run above run count limit should fail
//# run Test::M1::transfer_n_ids --args 4096

