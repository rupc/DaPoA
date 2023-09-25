// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use clap::{Parser, ValueEnum};
use eyre::eyre;
use rocksdb::MultiThreaded;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use strum_macros::EnumString;
use sui_core::authority::authority_per_epoch_store::AuthorityEpochTables;
use sui_core::authority::authority_store_tables::AuthorityPerpetualTables;
use sui_core::epoch::committee_store::CommitteeStore;
use sui_storage::default_db_options;
use sui_storage::write_ahead_log::DBWriteAheadLogTables;
use sui_storage::IndexStoreTables;
use sui_types::base_types::{EpochId, ObjectID};
use sui_types::messages::{SignedTransactionEffects, TrustedCertificate};
use sui_types::object::Data;
use sui_types::temporary_store::InnerTemporaryStore;
use typed_store::rocks::MetricConf;
use typed_store::traits::{Map, TableSummary};

#[derive(EnumString, Clone, Parser, Debug, ValueEnum)]
pub enum StoreName {
    Validator,
    Index,
    Wal,
    Epoch,
    // TODO: Add the new checkpoint v2 tables.
}
impl std::fmt::Display for StoreName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn list_tables(path: PathBuf) -> anyhow::Result<Vec<String>> {
    rocksdb::DBWithThreadMode::<MultiThreaded>::list_cf(
        &default_db_options(None, None).0.options,
        path,
    )
    .map_err(|e| e.into())
    .map(|q| {
        q.iter()
            .filter_map(|s| {
                // The `default` table is not used
                if s != "default" {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect()
    })
}

pub fn table_summary(
    store_name: StoreName,
    epoch: Option<EpochId>,
    db_path: PathBuf,
    table_name: &str,
) -> anyhow::Result<TableSummary> {
    match store_name {
        StoreName::Validator => {
            let epoch_tables = AuthorityEpochTables::describe_tables();
            if epoch_tables.contains_key(table_name) {
                let epoch = epoch.ok_or_else(|| anyhow!("--epoch is required"))?;
                AuthorityEpochTables::open_readonly(epoch, &db_path).table_summary(table_name)
            } else {
                AuthorityPerpetualTables::open_readonly(&db_path).table_summary(table_name)
            }
        }
        StoreName::Index => {
            IndexStoreTables::get_read_only_handle(db_path, None, None, MetricConf::default())
                .table_summary(table_name)
        }
        StoreName::Wal => {
            DBWriteAheadLogTables::<
                TrustedCertificate,
                (InnerTemporaryStore, SignedTransactionEffects),
            >::get_read_only_handle(db_path, None, None, MetricConf::default())
            .table_summary(table_name)
        }
        StoreName::Epoch => {
            CommitteeStore::get_read_only_handle(db_path, None, None, MetricConf::default())
                .table_summary(table_name)
        }
    }
    .map_err(|err| anyhow!(err.to_string()))
}

pub fn duplicate_objects_summary(db_path: PathBuf) -> (usize, usize, usize, usize) {
    let perpetual_tables = AuthorityPerpetualTables::open_readonly(&db_path);
    let iter = perpetual_tables.objects.iter();
    let mut total_count = 0;
    let mut duplicate_count = 0;
    let mut total_bytes = 0;
    let mut duplicated_bytes = 0;

    let mut object_id: ObjectID = ObjectID::random();
    let mut data: HashMap<Vec<u8>, usize> = HashMap::new();

    for (key, value) in iter {
        if let Data::Move(object) = value.data {
            if object_id != key.0 {
                for (k, cnt) in data.iter() {
                    total_bytes += k.len() * cnt;
                    duplicated_bytes += k.len() * (cnt - 1);
                    total_count += cnt;
                    duplicate_count += cnt - 1;
                }
                object_id = key.0;
                data.clear();
            }
            *data.entry(object.contents().to_vec()).or_default() += 1;
        }
    }
    (total_count, duplicate_count, total_bytes, duplicated_bytes)
}

// TODO: condense this using macro or trait dyn skills
pub fn dump_table(
    store_name: StoreName,
    epoch: Option<EpochId>,
    db_path: PathBuf,
    table_name: &str,
    page_size: u16,
    page_number: usize,
) -> anyhow::Result<BTreeMap<String, String>> {
    match store_name {
        StoreName::Validator => {
            let epoch_tables = AuthorityEpochTables::describe_tables();
            if epoch_tables.contains_key(table_name) {
                let epoch = epoch.ok_or_else(|| anyhow!("--epoch is required"))?;
                AuthorityEpochTables::open_readonly(epoch, &db_path).dump(
                    table_name,
                    page_size,
                    page_number,
                )
            } else {
                AuthorityPerpetualTables::open_readonly(&db_path).dump(
                    table_name,
                    page_size,
                    page_number,
                )
            }
        }
        StoreName::Index => {
            IndexStoreTables::get_read_only_handle(db_path, None, None, MetricConf::default()).dump(
                table_name,
                page_size,
                page_number,
            )
        }
        StoreName::Wal => Err(eyre!(
            "Dumping WAL not yet supported. It requires kmowing the value type"
        )),
        StoreName::Epoch => {
            CommitteeStore::get_read_only_handle(db_path, None, None, MetricConf::default()).dump(
                table_name,
                page_size,
                page_number,
            )
        }
    }
    .map_err(|err| anyhow!(err.to_string()))
}

#[cfg(test)]
mod test {
    use sui_core::authority::authority_per_epoch_store::AuthorityEpochTables;
    use sui_core::authority::authority_store_tables::AuthorityPerpetualTables;

    use crate::db_tool::db_dump::{dump_table, list_tables, StoreName};

    #[tokio::test]
    async fn db_dump_population() -> Result<(), anyhow::Error> {
        let primary_path = tempfile::tempdir()?.into_path();

        // Open the DB for writing
        let _: AuthorityEpochTables = AuthorityEpochTables::open(0, &primary_path, None);
        let _: AuthorityPerpetualTables = AuthorityPerpetualTables::open(&primary_path, None);

        // Get all the tables for AuthorityEpochTables
        let tables = {
            let mut epoch_tables =
                list_tables(AuthorityEpochTables::path(0, &primary_path)).unwrap();
            let mut perpetual_tables =
                list_tables(AuthorityPerpetualTables::path(&primary_path)).unwrap();
            epoch_tables.append(&mut perpetual_tables);
            epoch_tables
        };

        let mut missing_tables = vec![];
        for t in tables {
            println!("{}", t);
            if dump_table(
                StoreName::Validator,
                Some(0),
                primary_path.clone(),
                &t,
                0,
                0,
            )
            .is_err()
            {
                missing_tables.push(t);
            }
        }
        if missing_tables.is_empty() {
            return Ok(());
        }
        panic!(
            "{}",
            format!(
                "Missing {} table(s) from DB dump registration function: {:?} \n Update the dump function.",
                missing_tables.len(),
                missing_tables
            )
        );
    }
}
