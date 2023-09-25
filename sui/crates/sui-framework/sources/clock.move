// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// APIs for accessing time from move calls, via the `Clock`: a unique
/// shared object that is created at 0x6 during genesis.
module sui::clock {
    use sui::object::{Self, UID};
    use sui::transfer;

    friend sui::genesis;
    friend sui::sui_system;

    /// Singleton shared object that exposes time to Move calls.  This
    /// object is found at address 0x6, and can only be read (accessed
    /// via an immutable reference) by entry functions.
    ///
    /// Entry Functions that attempt to accept `Clock` by mutable
    /// reference or value will fail to verify, and honest validators
    /// will not sign or execute transactions that use `Clock` as an
    /// input parameter, unless it is passed by immutable reference.
    struct Clock has key {
        id: UID,
        /// The clock's timestamp, which is set automatically by a
        /// system transaction every time consensus commits a
        /// schedule, or by `sui::clock::increment_for_testing` during
        /// testing.
        timestamp_ms: u64,
    }

    /// The `clock`'s current timestamp as a running total of
    /// milliseconds since an arbitrary point in the past.
    public fun timestamp_ms(clock: &Clock): u64 {
        clock.timestamp_ms
    }

    /// Create and share the singleton Clock -- this function is
    /// called exactly once, during genesis.
    public(friend) fun create() {
        transfer::share_object(Clock {
            id: object::clock(),
            // Initialised to zero, but set to a real timestamp by a
            // system transaction before it can be witnessed by a move
            // call.
            timestamp_ms: 0,
        })
    }

    /// Set the Clock's timestamp -- this function should only be called by
    /// `sui::system_state::consensus_commit_prologue`.
    public(friend) fun set_timestamp(clock: &mut Clock, timestamp_ms: u64) {
        clock.timestamp_ms = timestamp_ms
    }

    #[test_only]
    public fun increment_for_testing(clock: &mut Clock, tick: u64) {
        clock.timestamp_ms = clock.timestamp_ms + tick;
    }
}
