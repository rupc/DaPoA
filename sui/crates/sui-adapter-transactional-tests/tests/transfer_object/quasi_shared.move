// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// tests TransferObject should fail for a quasi-shared object

//# init --accounts A B --addresses test=0x0

//# publish

module test::m {
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    struct S has key { id: UID }
    struct Child has key, store { id: UID }

    public entry fun mint_s(ctx: &mut TxContext) {
        let id = object::new(ctx);
        transfer::share_object(S { id })
    }

    public entry fun mint_child(s: &mut S, ctx: &mut TxContext) {
        let id = object::new(ctx);
        sui::dynamic_object_field::add(&mut s.id, 0, Child { id });
    }
}

//# run test::m::mint_s

//# run test::m::mint_child --args object(108)

//# view-object 110

//# transfer-object 110 --sender A --recipient B

//# view-object 110
