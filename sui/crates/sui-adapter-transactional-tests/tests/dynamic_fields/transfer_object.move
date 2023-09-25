// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// similar to dynamic_object_field_tests but over multiple transactions,
// as this uses a different code path
// test transferring an object from one parent to another

//# init --addresses a=0x0 --accounts A

//# publish
module a::m {

use sui::dynamic_object_field::{add, borrow, borrow_mut, remove};
use sui::object::{Self, UID};
use sui::tx_context::{sender, TxContext};

struct Obj has key, store {
    id: UID,
}

struct Counter has key, store {
    id: UID,
    count: u64,
}

fun new(id: UID): Counter {
    Counter { id, count: 0 }
}

fun count(counter: &Counter): u64 {
    counter.count
}

fun bump(counter: &mut Counter): &mut Counter {
    counter.count = counter.count + 1;
    counter
}

fun destroy(counter: Counter): u64 {
    let Counter { id, count } = counter;
    object::delete(id);
    count
}

entry fun create(ctx: &mut TxContext) {
    let id = object::new(ctx);
    sui::transfer::transfer(Obj { id }, sender(ctx))
}

entry fun add_counter(obj: &mut Obj, ctx: &mut TxContext) {
    add(&mut obj.id, 0, new(object::new(ctx)))
}

entry fun obj_bump(obj: &mut Obj) {
    bump(borrow_mut(&mut obj.id, 0));
}

entry fun assert_count(obj: &Obj, target: u64) {
    assert!(count(borrow(&obj.id, 0)) == target, 0)
}

entry fun transfer(o1: &mut Obj, o2: &mut Obj) {
    let c: Counter = remove(&mut o1.id, 0);
    add(&mut o2.id, 0, c)
}

}

//# run a::m::create --sender A

//# run a::m::create --sender A

//# run a::m::add_counter --sender A --args object(107)

//# run a::m::obj_bump --sender A --args object(107)

//# run a::m::assert_count --sender A --args object(107) 1

//# run a::m::transfer --sender A --args object(107) object(109)

//# run a::m::obj_bump --sender A --args object(109)

//# run a::m::assert_count --sender A --args object(109) 2

//# run a::m::obj_bump --sender A --args object(107)
