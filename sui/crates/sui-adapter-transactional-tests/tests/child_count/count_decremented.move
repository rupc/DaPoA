// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// DEPRECATED child count no longer tracked
// tests various ways of "removing" a child decrements the count

//# init --addresses test=0x0 --accounts A B

//# publish

module test::m {
    use sui::tx_context::{Self, TxContext};
    use sui::dynamic_object_field as ofield;

    struct S has key, store {
        id: sui::object::UID,
    }

    struct R has key, store {
        id: sui::object::UID,
        s: S,
    }

    public entry fun mint(ctx: &mut TxContext) {
        let id = sui::object::new(ctx);
        sui::transfer::transfer(S { id }, tx_context::sender(ctx))
    }

    public entry fun add(parent: &mut S, idx: u64, ctx: &mut TxContext) {
        let child = S { id: sui::object::new(ctx) };
        ofield::add(&mut parent.id, idx, child);
    }

    public entry fun remove(parent: &mut S, idx: u64) {
        let S { id } = ofield::remove(&mut parent.id, idx);
        sui::object::delete(id)
    }

    public entry fun remove_and_add(parent: &mut S, idx: u64) {
        let child: S = ofield::remove(&mut parent.id, idx);
        ofield::add(&mut parent.id, idx, child)
    }

    public entry fun remove_and_wrap(parent: &mut S, idx: u64, ctx: &mut TxContext) {
        let child: S = ofield::remove(&mut parent.id, idx);
        ofield::add(&mut parent.id, idx, R { id: sui::object::new(ctx), s: child })
    }
}

//
// Test remove
//

//# run test::m::mint --sender A

//# view-object 108

//# run test::m::add --sender A --args object(108) 1

//# run test::m::remove --sender A --args object(108) 1

//# view-object 108

//
// Test remove and add
//

//# run test::m::mint --sender A

//# view-object 114

//# run test::m::add --sender A --args object(114) 1

//# run test::m::remove_and_add --sender A --args object(114) 1

//# view-object 114

//
// Test remove and wrap
//

//# run test::m::mint --sender A

//# view-object 120

//# run test::m::add --sender A --args object(120) 1

//# run test::m::remove_and_wrap --sender A --args object(120) 1

//# view-object 120
