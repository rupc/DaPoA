// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use mysten_metrics::histogram::Histogram;
use prometheus::{
    register_int_counter_with_registry, register_int_gauge_with_registry, IntCounter, IntGauge,
    Registry,
};
use std::sync::Arc;

pub struct CheckpointExecutorMetrics {
    pub checkpoint_exec_sync_tps: IntGauge,
    pub last_executed_checkpoint: IntGauge,
    pub checkpoint_exec_errors: IntCounter,
    pub checkpoint_exec_epoch: IntGauge,
    pub checkpoint_transaction_count: Histogram,
    pub checkpoint_contents_age_ms: Histogram,
}

impl CheckpointExecutorMetrics {
    pub fn new(registry: &Registry) -> Arc<Self> {
        let this = Self {
            checkpoint_exec_sync_tps: register_int_gauge_with_registry!(
                "checkpoint_exec_sync_tps",
                "Checkpoint sync estimated transactions per second",
                registry
            )
            .unwrap(),
            last_executed_checkpoint: register_int_gauge_with_registry!(
                "last_executed_checkpoint",
                "Last executed checkpoint",
                registry
            )
            .unwrap(),
            checkpoint_exec_errors: register_int_counter_with_registry!(
                "checkpoint_exec_errors",
                "Checkpoint execution errors count",
                registry
            )
            .unwrap(),
            checkpoint_exec_epoch: register_int_gauge_with_registry!(
                "checkpoint_exec_epoch",
                "Current epoch number in the checkpoint executor",
                registry
            )
            .unwrap(),
            checkpoint_transaction_count: Histogram::new_in_registry(
                "checkpoint_transaction_count",
                "Number of transactions in the checkpoint",
                registry,
            ),
            checkpoint_contents_age_ms: Histogram::new_in_registry(
                "checkpoint_contents_age_ms",
                "Age of checkpoints when they arrive for execution",
                registry,
            ),
        };
        Arc::new(this)
    }

    pub fn new_for_tests() -> Arc<Self> {
        Self::new(&Registry::new())
    }
}
