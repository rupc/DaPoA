// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// tests that shared objects must be newly created

//# init --addresses t=0x0 --accounts A

//# publish

module t::m {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{sender, TxContext};

    struct Obj has key, store {
        id: UID,
    }

    public entry fun create(ctx: &mut TxContext) {
        let o = Obj { id: object::new(ctx) };
        sui::dynamic_field::add(&mut o.id, 0, Obj { id: object::new(ctx) });
        sui::dynamic_object_field::add(&mut o.id, 0, Obj { id: object::new(ctx) });
        transfer::transfer(o, sender(ctx))
    }

    public entry fun share(o: Obj) {
        transfer::share_object(o)
    }

    public entry fun share_wrapped(o: &mut Obj) {
        let inner: Obj = sui::dynamic_field::remove(&mut o.id, 0);
        transfer::share_object(inner)
    }

    public entry fun share_child(o: &mut Obj) {
        let inner: Obj = sui::dynamic_object_field::remove(&mut o.id, 0);
        transfer::share_object(inner)
    }

}

//# run t::m::create --sender A

//# view-object 110

//# run t::m::share --args object(110) --sender A

//# run t::m::share_wrapped --args object(110) --sender A

//# run t::m::share_child --args object(110) --sender A
