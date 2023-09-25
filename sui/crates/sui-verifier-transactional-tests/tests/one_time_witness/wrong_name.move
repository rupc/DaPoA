// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// invalid, wrong one-time witness type name

//# init --addresses test=0x0

//# publish
module test::m {

    struct OneTimeWitness has drop { }

    fun init(_: OneTimeWitness, _ctx: &mut sui::tx_context::TxContext) {
    }
}
