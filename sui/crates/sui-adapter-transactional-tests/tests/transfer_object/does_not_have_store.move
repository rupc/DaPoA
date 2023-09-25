// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// tests TransferObject should fail for an object _without_ public transfer

//# init --accounts A B --addresses test=0x0

//# publish

module test::m {
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    struct S has key { id: UID }
    struct Cup<phantom T> has key { id: UID }

    public entry fun mint_s(ctx: &mut TxContext) {
        let id = object::new(ctx);
        transfer::transfer(S { id }, tx_context::sender(ctx))
    }

    public entry fun mint_cup<T>(ctx: &mut TxContext) {
        let id = object::new(ctx);
        transfer::transfer(Cup<T> { id }, tx_context::sender(ctx))
    }
}

// Mint S to A. Fail to transfer S from A to B, which should fail

//# run test::m::mint_s --sender A

//# view-object 108

//# transfer-object 108 --sender A --recipient B

//# view-object 108


// Mint Cup<S> to A. Fail to transfer Cup<S> from A to B

//# run test::m::mint_cup --type-args test::m::S --sender A

//# view-object 111

//# transfer-object 111 --sender A --recipient B

//# view-object 111
