// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
mod errors;
pub(crate) mod iter;
pub(crate) mod keys;
pub(crate) mod values;

use crate::{
    metrics::{DBMetrics, RocksDBPerfContext, SamplingInterval},
    traits::{Map, TableSummary},
};
use bincode::Options;
use collectable::TryExtend;
use rocksdb::checkpoint::Checkpoint;
use rocksdb::{
    properties, AsColumnFamilyRef, CStrLike, ColumnFamilyDescriptor, DBWithThreadMode, Error,
    ErrorKind, IteratorMode, MultiThreaded, OptimisticTransactionOptions, ReadOptions, Transaction,
    WriteBatch, WriteBatchWithTransaction, WriteOptions,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    borrow::Borrow,
    collections::BTreeMap,
    env,
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tap::TapFallible;
use tokio::sync::oneshot;
use tracing::{debug, error, info, instrument};

use self::{iter::Iter, keys::Keys, values::Values};
pub use errors::TypedStoreError;
use sui_macros::{fail_point, nondeterministic};

// Write buffer size per RocksDB instance can be set via the env var below.
// If the env var is not set, use the default value in MiB.
const ENV_VAR_DB_WRITE_BUFFER_SIZE: &str = "MYSTEN_DB_WRITE_BUFFER_SIZE_MB";
const DEFAULT_DB_WRITE_BUFFER_SIZE: usize = 512;

// Write ahead log size per RocksDB instance can be set via the env var below.
// If the env var is not set, use the default value in MiB.
const ENV_VAR_DB_WAL_SIZE: &str = "MYSTEN_DB_WAL_SIZE_MB";
const DEFAULT_DB_WAL_SIZE: usize = 1024;

#[cfg(test)]
mod tests;

/// A helper macro to reopen multiple column families. The macro returns
/// a tuple of DBMap structs in the same order that the column families
/// are defined.
///
/// # Arguments
///
/// * `db` - a reference to a rocks DB object
/// * `cf;<ty,ty>` - a comma separated list of column families to open. For each
/// column family a concatenation of column family name (cf) and Key-Value <ty, ty>
/// should be provided.
///
/// # Examples
///
/// We successfully open two different column families.
/// ```
/// use typed_store::reopen;
/// use typed_store::rocks::*;
/// use tempfile::tempdir;
/// use prometheus::Registry;
/// use std::sync::Arc;
/// use typed_store::metrics::DBMetrics;
/// use core::fmt::Error;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Error> {
/// const FIRST_CF: &str = "First_CF";
/// const SECOND_CF: &str = "Second_CF";
///
///
/// /// Create the rocks database reference for the desired column families
/// let rocks = open_cf(tempdir().unwrap(), None, MetricConf::default(), &[FIRST_CF, SECOND_CF]).unwrap();
///
/// /// Now simply open all the column families for their expected Key-Value types
/// let (db_map_1, db_map_2) = reopen!(&rocks, FIRST_CF;<i32, String>, SECOND_CF;<i32, String>);
/// Ok(())
/// }
/// ```
///
#[macro_export]
macro_rules! reopen {
    ( $db:expr, $($cf:expr;<$K:ty, $V:ty>),*) => {
        (
            $(
                DBMap::<$K, $V>::reopen($db, Some($cf), &ReadWriteOptions::default()).expect(&format!("Cannot open {} CF.", $cf)[..])
            ),*
        )
    };
}

/// Repeatedly attempt an OptimisiticTransaction until it succeeds.
/// Since many callsites (e.g. the consensus handler) cannot proceed in the case of failed writes,
/// this will loop forever until the transaction succeeds.
#[macro_export]
macro_rules! retry_transaction {
    ($transaction:expr) => {
        retry_transaction!($transaction, Some(20))
    };

    (
        $transaction:expr,
        $max_retries:expr // should be an Option<int type>, None for unlimited
        $(,)?

    ) => {{
        use rand::{
            distributions::{Distribution, Uniform},
            rngs::ThreadRng,
        };
        use tokio::time::{sleep, Duration};
        use tracing::{error, info};

        let mut retries = 0;
        let max_retries = $max_retries;
        loop {
            let status = $transaction;
            match status {
                Err(TypedStoreError::RetryableTransactionError) => {
                    retries += 1;
                    // Randomized delay to help racing transactions get out of each other's way.
                    let delay = {
                        let mut rng = ThreadRng::default();
                        Duration::from_millis(Uniform::new(0, 50).sample(&mut rng))
                    };
                    if let Some(max_retries) = max_retries {
                        if retries > max_retries {
                            error!(?max_retries, "max retries exceeded");
                            break status;
                        }
                    }
                    if retries > 10 {
                        // TODO: monitoring needed?
                        error!(?delay, ?retries, "excessive transaction retries...");
                    } else {
                        info!(
                            ?delay,
                            ?retries,
                            "transaction write conflict detected, sleeping"
                        );
                    }
                    sleep(delay).await;
                }
                _ => break status,
            }
        }
    }};
}

#[macro_export]
macro_rules! retry_transaction_forever {
    ($transaction:expr) => {
        $crate::retry_transaction!($transaction, None)
    };
}

#[derive(Debug)]
pub struct DBWithThreadModeWrapper {
    pub underlying: rocksdb::DBWithThreadMode<MultiThreaded>,
    pub metric_conf: MetricConf,
}

#[derive(Debug)]
pub struct OptimisticTransactionDBWrapper {
    pub underlying: rocksdb::OptimisticTransactionDB<MultiThreaded>,
    pub metric_conf: MetricConf,
}

/// Thin wrapper to unify interface across different db types
#[derive(Debug)]
pub enum RocksDB {
    DBWithThreadMode(DBWithThreadModeWrapper),
    OptimisticTransactionDB(OptimisticTransactionDBWrapper),
}

macro_rules! delegate_call {
    ($self:ident.$method:ident($($args:ident),*)) => {
        match $self {
            Self::DBWithThreadMode(d) => d.underlying.$method($($args),*),
            Self::OptimisticTransactionDB(d) => d.underlying.$method($($args),*),
        }
    }
}

impl Drop for RocksDB {
    fn drop(&mut self) {
        delegate_call!(self.cancel_all_background_work(/* wait */ true))
    }
}

impl RocksDB {
    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        delegate_call!(self.get(key))
    }

    pub fn multi_get_cf<'a, 'b: 'a, K, I, W>(
        &'a self,
        keys: I,
        readopts: &ReadOptions,
    ) -> Vec<Result<Option<Vec<u8>>, rocksdb::Error>>
    where
        K: AsRef<[u8]>,
        I: IntoIterator<Item = (&'b W, K)>,
        W: 'b + AsColumnFamilyRef,
    {
        delegate_call!(self.multi_get_cf_opt(keys, readopts))
    }

    pub fn property_int_value_cf(
        &self,
        cf: &impl AsColumnFamilyRef,
        name: impl CStrLike,
    ) -> Result<Option<u64>, rocksdb::Error> {
        delegate_call!(self.property_int_value_cf(cf, name))
    }

    pub fn get_pinned_cf<K: AsRef<[u8]>>(
        &self,
        cf: &impl AsColumnFamilyRef,
        key: K,
        readopts: &ReadOptions,
    ) -> Result<Option<rocksdb::DBPinnableSlice<'_>>, rocksdb::Error> {
        delegate_call!(self.get_pinned_cf_opt(cf, key, readopts))
    }

    pub fn cf_handle(&self, name: &str) -> Option<Arc<rocksdb::BoundColumnFamily<'_>>> {
        delegate_call!(self.cf_handle(name))
    }

    pub fn create_cf<N: AsRef<str>>(
        &self,
        name: N,
        opts: &rocksdb::Options,
    ) -> Result<(), rocksdb::Error> {
        delegate_call!(self.create_cf(name, opts))
    }

    pub fn drop_cf(&self, name: &str) -> Result<(), rocksdb::Error> {
        delegate_call!(self.drop_cf(name))
    }

    pub fn delete_cf<K: AsRef<[u8]>>(
        &self,
        cf: &impl AsColumnFamilyRef,
        key: K,
        writeopts: &WriteOptions,
    ) -> Result<(), rocksdb::Error> {
        delegate_call!(self.delete_cf_opt(cf, key, writeopts))
    }

    pub fn path(&self) -> &Path {
        delegate_call!(self.path())
    }

    pub fn put_cf<K, V>(
        &self,
        cf: &impl AsColumnFamilyRef,
        key: K,
        value: V,
        writeopts: &WriteOptions,
    ) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        fail_point!("put-cf");
        delegate_call!(self.put_cf_opt(cf, key, value, writeopts))
    }

    pub fn key_may_exist_cf<K: AsRef<[u8]>>(
        &self,
        cf: &impl AsColumnFamilyRef,
        key: K,
        readopts: &ReadOptions,
    ) -> bool {
        delegate_call!(self.key_may_exist_cf_opt(cf, key, readopts))
    }

    pub fn try_catch_up_with_primary(&self) -> Result<(), rocksdb::Error> {
        delegate_call!(self.try_catch_up_with_primary())
    }

    pub fn write(&self, batch: RocksDBBatch) -> Result<(), TypedStoreError> {
        fail_point!("batch-write");
        match (self, batch) {
            (RocksDB::DBWithThreadMode(db), RocksDBBatch::Regular(batch)) => {
                db.underlying.write(batch)?;
                Ok(())
            }
            (RocksDB::OptimisticTransactionDB(db), RocksDBBatch::Transactional(batch)) => {
                db.underlying.write(batch)?;
                Ok(())
            }
            _ => Err(TypedStoreError::RocksDBError(
                "using invalid batch type for the database".to_string(),
            )),
        }
    }

    pub fn transaction_without_snapshot(
        &self,
    ) -> Result<Transaction<'_, rocksdb::OptimisticTransactionDB>, TypedStoreError> {
        match self {
            Self::OptimisticTransactionDB(db) => Ok(db.underlying.transaction()),
            Self::DBWithThreadMode(_) => Err(TypedStoreError::RocksDBError(
                "operation not supported".to_string(),
            )),
        }
    }

    pub fn transaction(
        &self,
    ) -> Result<Transaction<'_, rocksdb::OptimisticTransactionDB>, TypedStoreError> {
        match self {
            Self::OptimisticTransactionDB(db) => {
                let mut tx_opts = OptimisticTransactionOptions::new();
                tx_opts.set_snapshot(true);

                Ok(db
                    .underlying
                    .transaction_opt(&WriteOptions::default(), &tx_opts))
            }
            Self::DBWithThreadMode(_) => Err(TypedStoreError::RocksDBError(
                "operation not supported".to_string(),
            )),
        }
    }

    pub fn raw_iterator_cf<'a: 'b, 'b>(
        &'a self,
        cf_handle: &impl AsColumnFamilyRef,
        readopts: ReadOptions,
    ) -> RocksDBRawIter<'b> {
        match self {
            Self::DBWithThreadMode(db) => {
                RocksDBRawIter::DB(db.underlying.raw_iterator_cf_opt(cf_handle, readopts))
            }
            Self::OptimisticTransactionDB(db) => RocksDBRawIter::OptimisticTransactionDB(
                db.underlying.raw_iterator_cf_opt(cf_handle, readopts),
            ),
        }
    }

    pub fn iterator_cf<'a: 'b, 'b>(
        &'a self,
        cf_handle: &impl AsColumnFamilyRef,
        readopts: ReadOptions,
        mode: IteratorMode<'_>,
    ) -> RocksDBIter<'b> {
        match self {
            Self::DBWithThreadMode(db) => {
                RocksDBIter::DB(db.underlying.iterator_cf_opt(cf_handle, readopts, mode))
            }
            Self::OptimisticTransactionDB(db) => RocksDBIter::OptimisticTransactionDB(
                db.underlying.iterator_cf_opt(cf_handle, readopts, mode),
            ),
        }
    }

    pub fn compact_range_cf<K: AsRef<[u8]>>(
        &self,
        cf: &impl AsColumnFamilyRef,
        start: Option<K>,
        end: Option<K>,
    ) {
        delegate_call!(self.compact_range_cf(cf, start, end))
    }

    pub fn flush(&self) -> Result<(), rocksdb::Error> {
        delegate_call!(self.flush())
    }

    pub fn checkpoint(&self, path: &Path) -> Result<(), rocksdb::Error> {
        match self {
            Self::DBWithThreadMode(d) => {
                let checkpoint = Checkpoint::new(&d.underlying)?;
                checkpoint.create_checkpoint(path)?;
            }
            Self::OptimisticTransactionDB(d) => {
                let checkpoint = Checkpoint::new(&d.underlying)?;
                checkpoint.create_checkpoint(path)?;
            }
        }
        Ok(())
    }

    pub fn flush_cf(&self, cf: &impl AsColumnFamilyRef) -> Result<(), rocksdb::Error> {
        delegate_call!(self.flush_cf(cf))
    }

    pub fn set_options_cf(
        &self,
        cf: &impl AsColumnFamilyRef,
        opts: &[(&str, &str)],
    ) -> Result<(), rocksdb::Error> {
        delegate_call!(self.set_options_cf(cf, opts))
    }

    pub fn read_sampling_interval(&self) -> SamplingInterval {
        match self {
            Self::DBWithThreadMode(d) => d.metric_conf.read_sample_interval.clone(),
            Self::OptimisticTransactionDB(d) => d.metric_conf.read_sample_interval.clone(),
        }
    }

    pub fn write_sampling_interval(&self) -> SamplingInterval {
        match self {
            Self::DBWithThreadMode(d) => d.metric_conf.write_sample_interval.clone(),
            Self::OptimisticTransactionDB(d) => d.metric_conf.write_sample_interval.clone(),
        }
    }

    pub fn iter_latency_sampling_interval(&self) -> SamplingInterval {
        match self {
            Self::DBWithThreadMode(d) => d.metric_conf.iter_latency_sample_interval.clone(),
            Self::OptimisticTransactionDB(d) => d.metric_conf.iter_latency_sample_interval.clone(),
        }
    }

    pub fn iter_bytes_sampling_interval(&self) -> SamplingInterval {
        match self {
            Self::DBWithThreadMode(d) => d.metric_conf.iter_bytes_sample_interval.clone(),
            Self::OptimisticTransactionDB(d) => d.metric_conf.iter_bytes_sample_interval.clone(),
        }
    }

    pub fn db_name(&self) -> String {
        match self {
            Self::DBWithThreadMode(d) => d
                .metric_conf
                .db_name_override
                .clone()
                .unwrap_or_else(|| self.default_db_name()),
            Self::OptimisticTransactionDB(d) => d
                .metric_conf
                .db_name_override
                .clone()
                .unwrap_or_else(|| self.default_db_name()),
        }
    }

    fn default_db_name(&self) -> String {
        self.path()
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown")
            .to_string()
    }
}

pub enum RocksDBBatch {
    Regular(rocksdb::WriteBatch),
    Transactional(rocksdb::WriteBatchWithTransaction<true>),
}

macro_rules! delegate_batch_call {
    ($self:ident.$method:ident($($args:ident),*)) => {
        match $self {
            Self::Regular(b) => b.$method($($args),*),
            Self::Transactional(b) => b.$method($($args),*),
        }
    }
}

impl RocksDBBatch {
    fn size_in_bytes(&self) -> usize {
        delegate_batch_call!(self.size_in_bytes())
    }

    pub fn delete_cf<K: AsRef<[u8]>>(&mut self, cf: &impl AsColumnFamilyRef, key: K) {
        delegate_batch_call!(self.delete_cf(cf, key))
    }

    pub fn put_cf<K, V>(&mut self, cf: &impl AsColumnFamilyRef, key: K, value: V)
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        delegate_batch_call!(self.put_cf(cf, key, value))
    }

    pub fn delete_range_cf<K: AsRef<[u8]>>(
        &mut self,
        cf: &impl AsColumnFamilyRef,
        from: K,
        to: K,
    ) -> Result<(), TypedStoreError> {
        match self {
            Self::Regular(batch) => {
                batch.delete_range_cf(cf, from, to);
                Ok(())
            }
            Self::Transactional(_) => Err(TypedStoreError::RocksDBError(
                "operation not supported".to_string(),
            )),
        }
    }
}

#[derive(Debug, Default)]
pub struct MetricConf {
    pub db_name_override: Option<String>,
    pub read_sample_interval: SamplingInterval,
    pub write_sample_interval: SamplingInterval,
    pub iter_latency_sample_interval: SamplingInterval,
    pub iter_bytes_sample_interval: SamplingInterval,
}

impl MetricConf {
    pub fn with_db_name(db_name: &str) -> Self {
        Self {
            db_name_override: Some(db_name.to_string()),
            read_sample_interval: SamplingInterval::default(),
            write_sample_interval: SamplingInterval::default(),
            iter_latency_sample_interval: SamplingInterval::default(),
            iter_bytes_sample_interval: SamplingInterval::default(),
        }
    }
    pub fn with_sampling(read_interval: SamplingInterval) -> Self {
        Self {
            db_name_override: None,
            read_sample_interval: read_interval,
            write_sample_interval: SamplingInterval::default(),
            iter_latency_sample_interval: SamplingInterval::default(),
            iter_bytes_sample_interval: SamplingInterval::default(),
        }
    }
}
const CF_METRICS_REPORT_PERIOD_MILLIS: u64 = 1000;
const METRICS_ERROR: i64 = -1;

/// An interface to a rocksDB database, keyed by a columnfamily
#[derive(Clone, Debug)]
pub struct DBMap<K, V> {
    pub rocksdb: Arc<RocksDB>,
    _phantom: PhantomData<fn(K) -> V>,
    // the rocksDB ColumnFamily under which the map is stored
    cf: String,
    opts: ReadWriteOptions,
    db_metrics: Arc<DBMetrics>,
    read_sample_interval: SamplingInterval,
    write_sample_interval: SamplingInterval,
    iter_latency_sample_interval: SamplingInterval,
    iter_bytes_sample_interval: SamplingInterval,
    _metrics_task_cancel_handle: Arc<oneshot::Sender<()>>,
}

unsafe impl<K: Send, V: Send> Send for DBMap<K, V> {}

impl<K, V> DBMap<K, V> {
    pub(crate) fn new(db: Arc<RocksDB>, opts: &ReadWriteOptions, opt_cf: &str) -> Self {
        let db_cloned = db.clone();
        let db_metrics = DBMetrics::get();
        let db_metrics_cloned = db_metrics.clone();
        let cf = opt_cf.to_string();
        let (sender, mut recv) = tokio::sync::oneshot::channel();
        tokio::task::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_millis(CF_METRICS_REPORT_PERIOD_MILLIS));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let db = db_cloned.clone();
                        let cf = cf.clone();
                        let db_metrics = db_metrics.clone();
                        if let Err(e) = tokio::task::spawn_blocking(move || {
                            Self::report_metrics(&db, &cf, &db_metrics);
                        }).await {
                            error!("Failed to log metrics with error: {}", e);
                        }
                    }
                    _ = &mut recv => break,
                }
            }
            info!("Returning the cf metric logging task for DBMap: {}", &cf);
        });
        DBMap {
            rocksdb: db.clone(),
            opts: opts.clone(),
            _phantom: PhantomData,
            cf: opt_cf.to_string(),
            db_metrics: db_metrics_cloned,
            _metrics_task_cancel_handle: Arc::new(sender),
            read_sample_interval: db.read_sampling_interval(),
            write_sample_interval: db.write_sampling_interval(),
            iter_bytes_sample_interval: db.iter_bytes_sampling_interval(),
            iter_latency_sample_interval: db.iter_latency_sampling_interval(),
        }
    }

    /// Opens a database from a path, with specific options and an optional column family.
    ///
    /// This database is used to perform operations on single column family, and parametrizes
    /// all operations in `DBBatch` when writing across column families.
    #[instrument(level="debug", skip_all, fields(path = ?path.as_ref(), cf = ?opt_cf), err)]
    pub fn open<P: AsRef<Path>>(
        path: P,
        metric_conf: MetricConf,
        db_options: Option<rocksdb::Options>,
        opt_cf: Option<&str>,
        rw_options: &ReadWriteOptions,
    ) -> Result<Self, TypedStoreError> {
        let cf_key = opt_cf.unwrap_or(rocksdb::DEFAULT_COLUMN_FAMILY_NAME);
        let cfs = vec![cf_key];
        let rocksdb = open_cf(path, db_options, metric_conf, &cfs)?;
        Ok(DBMap::new(rocksdb, rw_options, cf_key))
    }

    /// Reopens an open database as a typed map operating under a specific column family.
    /// if no column family is passed, the default column family is used.
    ///
    /// ```
    ///    use typed_store::rocks::*;
    ///    use typed_store::metrics::DBMetrics;
    ///    use tempfile::tempdir;
    ///    use prometheus::Registry;
    ///    use std::sync::Arc;
    ///    use core::fmt::Error;
    ///    #[tokio::main]
    ///    async fn main() -> Result<(), Error> {
    ///    /// Open the DB with all needed column families first.
    ///    let rocks = open_cf(tempdir().unwrap(), None, MetricConf::default(), &["First_CF", "Second_CF"]).unwrap();
    ///    /// Attach the column families to specific maps.
    ///    let db_cf_1 = DBMap::<u32,u32>::reopen(&rocks, Some("First_CF"), &ReadWriteOptions::default()).expect("Failed to open storage");
    ///    let db_cf_2 = DBMap::<u32,u32>::reopen(&rocks, Some("Second_CF"), &ReadWriteOptions::default()).expect("Failed to open storage");
    ///    Ok(())
    ///    }
    /// ```
    #[instrument(level = "debug", skip(db), err)]
    pub fn reopen(
        db: &Arc<RocksDB>,
        opt_cf: Option<&str>,
        rw_options: &ReadWriteOptions,
    ) -> Result<Self, TypedStoreError> {
        let cf_key = opt_cf
            .unwrap_or(rocksdb::DEFAULT_COLUMN_FAMILY_NAME)
            .to_owned();

        db.cf_handle(&cf_key)
            .ok_or_else(|| TypedStoreError::UnregisteredColumn(cf_key.clone()))?;

        Ok(DBMap::new(db.clone(), rw_options, &cf_key))
    }

    pub fn batch(&self) -> DBBatch {
        let batch = match *self.rocksdb {
            RocksDB::DBWithThreadMode(_) => RocksDBBatch::Regular(WriteBatch::default()),
            RocksDB::OptimisticTransactionDB(_) => {
                RocksDBBatch::Transactional(WriteBatchWithTransaction::<true>::default())
            }
        };
        DBBatch::new(
            &self.rocksdb,
            batch,
            &self.db_metrics,
            &self.write_sample_interval,
        )
    }

    pub fn compact_range<J: Serialize>(&self, start: &J, end: &J) -> Result<(), TypedStoreError> {
        let from_buf = be_fix_int_ser(start.borrow())?;
        let to_buf = be_fix_int_ser(end.borrow())?;
        self.rocksdb
            .compact_range_cf(&self.cf(), Some(from_buf), Some(to_buf));
        Ok(())
    }

    pub fn cf(&self) -> Arc<rocksdb::BoundColumnFamily<'_>> {
        self.rocksdb
            .cf_handle(&self.cf)
            .expect("Map-keying column family should have been checked at DB creation")
    }

    pub fn iterator_cf(&self) -> RocksDBIter<'_> {
        self.rocksdb
            .iterator_cf(&self.cf(), self.opts.readopts(), IteratorMode::Start)
    }

    pub fn flush(&self) -> Result<(), rocksdb::Error> {
        self.rocksdb.flush_cf(&self.cf())
    }

    pub fn set_options(&self, opts: &[(&str, &str)]) -> Result<(), rocksdb::Error> {
        self.rocksdb.set_options_cf(&self.cf(), opts)
    }

    fn get_int_property(
        rocksdb: &RocksDB,
        cf: &impl AsColumnFamilyRef,
        property_name: &'static std::ffi::CStr,
    ) -> Result<i64, TypedStoreError> {
        match rocksdb.property_int_value_cf(cf, property_name) {
            Ok(Some(value)) => Ok(value.try_into().unwrap()),
            Ok(None) => Ok(0),
            Err(e) => Err(TypedStoreError::RocksDBError(e.into_string())),
        }
    }

    fn report_metrics(rocksdb: &Arc<RocksDB>, cf_name: &str, db_metrics: &Arc<DBMetrics>) {
        let cf = rocksdb.cf_handle(cf_name).expect("Failed to get cf");
        db_metrics
            .cf_metrics
            .rocksdb_total_sst_files_size
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::TOTAL_SST_FILES_SIZE)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocksdb_size_all_mem_tables
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::SIZE_ALL_MEM_TABLES)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocksdb_num_snapshots
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::NUM_SNAPSHOTS)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocksdb_oldest_snapshot_time
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::OLDEST_SNAPSHOT_TIME)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocksdb_actual_delayed_write_rate
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::ACTUAL_DELAYED_WRITE_RATE)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocksdb_is_write_stopped
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::IS_WRITE_STOPPED)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocksdb_block_cache_capacity
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::BLOCK_CACHE_CAPACITY)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocksdb_block_cache_usage
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::BLOCK_CACHE_USAGE)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocksdb_block_cache_pinned_usage
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::BLOCK_CACHE_PINNED_USAGE)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocskdb_estimate_table_readers_mem
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::ESTIMATE_TABLE_READERS_MEM)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocksdb_estimated_num_keys
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::ESTIMATE_NUM_KEYS)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocksdb_mem_table_flush_pending
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::MEM_TABLE_FLUSH_PENDING)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocskdb_compaction_pending
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::COMPACTION_PENDING)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocskdb_num_running_compactions
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::NUM_RUNNING_COMPACTIONS)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocksdb_num_running_flushes
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::NUM_RUNNING_FLUSHES)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocksdb_estimate_oldest_key_time
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::ESTIMATE_OLDEST_KEY_TIME)
                    .unwrap_or(METRICS_ERROR),
            );
        db_metrics
            .cf_metrics
            .rocskdb_background_errors
            .with_label_values(&[cf_name])
            .set(
                Self::get_int_property(rocksdb, &cf, properties::BACKGROUND_ERRORS)
                    .unwrap_or(METRICS_ERROR),
            );
        let db_name = rocksdb.db_name();
        if let RocksDB::DBWithThreadMode(ref rocksdb) = **rocksdb {
            let mem_usage_stats =
                rocksdb::perf::get_memory_usage_stats(Some(&[&rocksdb.underlying]), None);
            db_metrics
                .rocksdb_mem_table_usage
                .with_label_values(&[&db_name])
                .set(
                    mem_usage_stats
                        .as_ref()
                        .map(|x| x.mem_table_total as i64)
                        .unwrap_or(METRICS_ERROR),
                );
            db_metrics
                .rocksdb_unflushed_mem_table_usage
                .with_label_values(&[&db_name])
                .set(
                    mem_usage_stats
                        .as_ref()
                        .map(|x| x.mem_table_unflushed as i64)
                        .unwrap_or(METRICS_ERROR),
                );
            db_metrics
                .rocksdb_table_readers_usage
                .with_label_values(&[&db_name])
                .set(
                    mem_usage_stats
                        .as_ref()
                        .map(|x| x.mem_table_readers_total as i64)
                        .unwrap_or(METRICS_ERROR),
                );
        }
    }

    pub fn transaction(&self) -> Result<DBTransaction<'_>, TypedStoreError> {
        DBTransaction::new(&self.rocksdb)
    }

    pub fn transaction_without_snapshot(&self) -> Result<DBTransaction<'_>, TypedStoreError> {
        DBTransaction::new_without_snapshot(&self.rocksdb)
    }

    pub fn table_summary(&self) -> eyre::Result<TableSummary> {
        let mut num_keys = 0;
        let mut key_bytes_total = 0;
        let mut value_bytes_total = 0;
        let mut key_hist = hdrhistogram::Histogram::<u64>::new_with_max(100000, 2).unwrap();
        let mut value_hist = hdrhistogram::Histogram::<u64>::new_with_max(100000, 2).unwrap();
        let iter = self.iterator_cf().map(Result::unwrap);
        for (key, value) in iter {
            num_keys += 1;
            key_bytes_total += key.len();
            value_bytes_total += value.len();
            key_hist.record(key.len() as u64)?;
            value_hist.record(value.len() as u64)?;
        }
        Ok(TableSummary {
            num_keys,
            key_bytes_total,
            value_bytes_total,
            key_hist,
            value_hist,
        })
    }
}

/// Provides a mutable struct to form a collection of database write operations, and execute them.
///
/// Batching write and delete operations is faster than performing them one by one and ensures their atomicity,
///  ie. they are all written or none is.
/// This is also true of operations across column families in the same database.
///
/// Serializations / Deserialization, and naming of column families is performed by passing a DBMap<K,V>
/// with each operation.
///
/// ```
/// use typed_store::rocks::*;
/// use tempfile::tempdir;
/// use typed_store::Map;
/// use typed_store::metrics::DBMetrics;
/// use prometheus::Registry;
/// use core::fmt::Error;
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Error> {
/// let rocks = open_cf(tempfile::tempdir().unwrap(), None, MetricConf::default(), &["First_CF", "Second_CF"]).unwrap();
///
/// let db_cf_1 = DBMap::reopen(&rocks, Some("First_CF"), &ReadWriteOptions::default())
///     .expect("Failed to open storage");
/// let keys_vals_1 = (1..100).map(|i| (i, i.to_string()));
///
/// let db_cf_2 = DBMap::reopen(&rocks, Some("Second_CF"), &ReadWriteOptions::default())
///     .expect("Failed to open storage");
/// let keys_vals_2 = (1000..1100).map(|i| (i, i.to_string()));
///
/// let batch = db_cf_1
///     .batch()
///     .insert_batch(&db_cf_1, keys_vals_1.clone())
///     .expect("Failed to batch insert")
///     .insert_batch(&db_cf_2, keys_vals_2.clone())
///     .expect("Failed to batch insert");
///
/// let _ = batch.write().expect("Failed to execute batch");
/// for (k, v) in keys_vals_1 {
///     let val = db_cf_1.get(&k).expect("Failed to get inserted key");
///     assert_eq!(Some(v), val);
/// }
///
/// for (k, v) in keys_vals_2 {
///     let val = db_cf_2.get(&k).expect("Failed to get inserted key");
///     assert_eq!(Some(v), val);
/// }
/// Ok(())
/// }
/// ```
///
pub struct DBBatch {
    rocksdb: Arc<RocksDB>,
    batch: RocksDBBatch,
    db_metrics: Arc<DBMetrics>,
    write_sample_interval: SamplingInterval,
}

impl DBBatch {
    /// Create a new batch associated with a DB reference.
    ///
    /// Use `open_cf` to get the DB reference or an existing open database.
    pub fn new(
        dbref: &Arc<RocksDB>,
        batch: RocksDBBatch,
        db_metrics: &Arc<DBMetrics>,
        write_sample_interval: &SamplingInterval,
    ) -> Self {
        DBBatch {
            rocksdb: dbref.clone(),
            batch,
            db_metrics: db_metrics.clone(),
            write_sample_interval: write_sample_interval.clone(),
        }
    }

    /// Consume the batch and write its operations to the database
    #[instrument(level = "trace", skip_all, err)]
    pub fn write(self) -> Result<(), TypedStoreError> {
        let report_metrics = if self.write_sample_interval.sample() {
            let db_name = self.rocksdb.db_name();
            let timer = self
                .db_metrics
                .op_metrics
                .rocksdb_batch_commit_latency_seconds
                .with_label_values(&[&db_name])
                .start_timer();
            let size = self.batch.size_in_bytes();
            Some((db_name, size, timer, RocksDBPerfContext::default()))
        } else {
            None
        };
        self.rocksdb.write(self.batch)?;
        if let Some((db_name, batch_size, _timer, _perf_ctx)) = report_metrics {
            self.db_metrics
                .op_metrics
                .rocksdb_batch_commit_bytes
                .with_label_values(&[&db_name])
                .observe(batch_size as f64);
            self.db_metrics
                .write_perf_ctx_metrics
                .report_metrics(&db_name);
        }
        Ok(())
    }

    /// Deletes a set of keys given as an iterator
    pub fn delete_batch_non_consuming<J: Borrow<K>, K: Serialize, V>(
        &mut self,
        db: &DBMap<K, V>,
        purged_vals: impl IntoIterator<Item = J>,
    ) -> Result<(), TypedStoreError> {
        if !Arc::ptr_eq(&db.rocksdb, &self.rocksdb) {
            return Err(TypedStoreError::CrossDBBatch);
        }

        purged_vals
            .into_iter()
            .try_for_each::<_, Result<_, TypedStoreError>>(|k| {
                let k_buf = be_fix_int_ser(k.borrow())?;
                self.batch.delete_cf(&db.cf(), k_buf);

                Ok(())
            })?;
        Ok(())
    }
    /// Deletes a range of keys between `from` (inclusive) and `to` (non-inclusive)
    pub fn delete_range_non_consuming<K: Serialize, V>(
        &mut self,
        db: &DBMap<K, V>,
        from: &K,
        to: &K,
    ) -> Result<(), TypedStoreError> {
        if !Arc::ptr_eq(&db.rocksdb, &self.rocksdb) {
            return Err(TypedStoreError::CrossDBBatch);
        }

        let from_buf = be_fix_int_ser(from)?;
        let to_buf = be_fix_int_ser(to)?;

        self.batch.delete_range_cf(&db.cf(), from_buf, to_buf)
    }

    /// inserts a range of (key, value) pairs given as an iterator
    pub fn insert_batch_non_consuming<J: Borrow<K>, K: Serialize, U: Borrow<V>, V: Serialize>(
        &mut self,
        db: &DBMap<K, V>,
        new_vals: impl IntoIterator<Item = (J, U)>,
    ) -> Result<(), TypedStoreError> {
        if !Arc::ptr_eq(&db.rocksdb, &self.rocksdb) {
            return Err(TypedStoreError::CrossDBBatch);
        }

        new_vals
            .into_iter()
            .try_for_each::<_, Result<_, TypedStoreError>>(|(k, v)| {
                let k_buf = be_fix_int_ser(k.borrow())?;
                let v_buf = bincode::serialize(v.borrow())?;
                self.batch.put_cf(&db.cf(), k_buf, v_buf);
                Ok(())
            })?;
        Ok(())
    }
}

// TODO: Remove this entire implementation once we switch to sally
impl DBBatch {
    pub fn delete_batch<J: Borrow<K>, K: Serialize, V>(
        mut self,
        db: &DBMap<K, V>,
        purged_vals: impl IntoIterator<Item = J>,
    ) -> Result<Self, TypedStoreError> {
        if !Arc::ptr_eq(&db.rocksdb, &self.rocksdb) {
            return Err(TypedStoreError::CrossDBBatch);
        }

        purged_vals
            .into_iter()
            .try_for_each::<_, Result<_, TypedStoreError>>(|k| {
                let k_buf = be_fix_int_ser(k.borrow())?;
                self.batch.delete_cf(&db.cf(), k_buf);

                Ok(())
            })?;
        Ok(self)
    }

    /// Deletes a range of keys between `from` (inclusive) and `to` (non-inclusive)
    pub fn delete_range<K: Serialize, V>(
        mut self,
        db: &DBMap<K, V>,
        from: &K,
        to: &K,
    ) -> Result<Self, TypedStoreError> {
        if !Arc::ptr_eq(&db.rocksdb, &self.rocksdb) {
            return Err(TypedStoreError::CrossDBBatch);
        }

        let from_buf = be_fix_int_ser(from)?;
        let to_buf = be_fix_int_ser(to)?;

        self.batch.delete_range_cf(&db.cf(), from_buf, to_buf)?;
        Ok(self)
    }

    /// inserts a range of (key, value) pairs given as an iterator
    pub fn insert_batch<J: Borrow<K>, K: Serialize, U: Borrow<V>, V: Serialize>(
        mut self,
        db: &DBMap<K, V>,
        new_vals: impl IntoIterator<Item = (J, U)>,
    ) -> Result<Self, TypedStoreError> {
        if !Arc::ptr_eq(&db.rocksdb, &self.rocksdb) {
            return Err(TypedStoreError::CrossDBBatch);
        }

        new_vals
            .into_iter()
            .try_for_each::<_, Result<_, TypedStoreError>>(|(k, v)| {
                let k_buf = be_fix_int_ser(k.borrow())?;
                let v_buf = bincode::serialize(v.borrow())?;
                self.batch.put_cf(&db.cf(), k_buf, v_buf);
                Ok(())
            })?;
        Ok(self)
    }
}

pub struct DBTransaction<'a> {
    rocksdb: Arc<RocksDB>,
    transaction: Transaction<'a, rocksdb::OptimisticTransactionDB>,
}

impl<'a> DBTransaction<'a> {
    pub fn new(db: &'a Arc<RocksDB>) -> Result<Self, TypedStoreError> {
        Ok(Self {
            rocksdb: db.clone(),
            transaction: db.transaction()?,
        })
    }

    pub fn new_without_snapshot(db: &'a Arc<RocksDB>) -> Result<Self, TypedStoreError> {
        Ok(Self {
            rocksdb: db.clone(),
            transaction: db.transaction_without_snapshot()?,
        })
    }

    pub fn insert_batch<J: Borrow<K>, K: Serialize, U: Borrow<V>, V: Serialize>(
        self,
        db: &DBMap<K, V>,
        new_vals: impl IntoIterator<Item = (J, U)>,
    ) -> Result<Self, TypedStoreError> {
        if !Arc::ptr_eq(&db.rocksdb, &self.rocksdb) {
            return Err(TypedStoreError::CrossDBBatch);
        }

        new_vals
            .into_iter()
            .try_for_each::<_, Result<_, TypedStoreError>>(|(k, v)| {
                let k_buf = be_fix_int_ser(k.borrow())?;
                let v_buf = bincode::serialize(v.borrow())?;
                self.transaction.put_cf(&db.cf(), k_buf, v_buf)?;
                Ok(())
            })?;
        Ok(self)
    }

    /// Deletes a set of keys given as an iterator
    pub fn delete_batch<J: Borrow<K>, K: Serialize, V>(
        self,
        db: &DBMap<K, V>,
        purged_vals: impl IntoIterator<Item = J>,
    ) -> Result<Self, TypedStoreError> {
        if !Arc::ptr_eq(&db.rocksdb, &self.rocksdb) {
            return Err(TypedStoreError::CrossDBBatch);
        }
        purged_vals
            .into_iter()
            .try_for_each::<_, Result<_, TypedStoreError>>(|k| {
                let k_buf = be_fix_int_ser(k.borrow())?;
                self.transaction.delete_cf(&db.cf(), k_buf)?;
                Ok(())
            })?;
        Ok(self)
    }

    pub fn snapshot(
        &self,
    ) -> rocksdb::SnapshotWithThreadMode<'_, Transaction<'a, rocksdb::OptimisticTransactionDB>>
    {
        self.transaction.snapshot()
    }

    pub fn get_for_update<K: Serialize, V: DeserializeOwned>(
        &self,
        db: &DBMap<K, V>,
        key: &K,
    ) -> Result<Option<V>, TypedStoreError> {
        if !Arc::ptr_eq(&db.rocksdb, &self.rocksdb) {
            return Err(TypedStoreError::CrossDBBatch);
        }
        let k_buf = be_fix_int_ser(key.borrow())?;
        match self
            .transaction
            .get_for_update_cf_opt(&db.cf(), k_buf, true, &db.opts.readopts())?
        {
            Some(data) => Ok(Some(bincode::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    pub fn get<K: Serialize + DeserializeOwned, V: Serialize + DeserializeOwned>(
        &self,
        db: &DBMap<K, V>,
        key: &K,
    ) -> Result<Option<V>, TypedStoreError> {
        let key_buf = be_fix_int_ser(key)?;
        self.transaction
            .get_cf_opt(&db.cf(), key_buf, &db.opts.readopts())
            .map_err(|e| TypedStoreError::RocksDBError(e.to_string()))
            .map(|res| res.and_then(|bytes| bincode::deserialize::<V>(&bytes).ok()))
    }

    pub fn multi_get<J: Borrow<K>, K: Serialize + DeserializeOwned, V: DeserializeOwned>(
        &self,
        db: &DBMap<K, V>,
        keys: impl IntoIterator<Item = J>,
    ) -> Result<Vec<Option<V>>, TypedStoreError> {
        let cf = db.cf();
        let keys_bytes: Result<Vec<_>, TypedStoreError> = keys
            .into_iter()
            .map(|k| Ok((&cf, be_fix_int_ser(k.borrow())?)))
            .collect();

        let results = self
            .transaction
            .multi_get_cf_opt(keys_bytes?, &db.opts.readopts());

        let values_parsed: Result<Vec<_>, TypedStoreError> = results
            .into_iter()
            .map(|value_byte| match value_byte? {
                Some(data) => Ok(Some(bincode::deserialize(&data)?)),
                None => Ok(None),
            })
            .collect();

        values_parsed
    }

    pub fn iter<K: DeserializeOwned, V: DeserializeOwned>(
        &'a self,
        db: &DBMap<K, V>,
    ) -> Iter<'a, K, V> {
        let mut db_iter = self
            .transaction
            .raw_iterator_cf_opt(&db.cf(), db.opts.readopts());
        db_iter.seek_to_first();

        Iter::new(
            RocksDBRawIter::OptimisticTransaction(db_iter),
            db.cf.clone(),
            &db.db_metrics,
            &db.iter_latency_sample_interval,
        )
    }

    pub fn keys<K: DeserializeOwned, V: DeserializeOwned>(
        &'a self,
        db: &DBMap<K, V>,
    ) -> Keys<'a, K> {
        let mut db_iter = RocksDBRawIter::OptimisticTransaction(
            self.transaction
                .raw_iterator_cf_opt(&db.cf(), db.opts.readopts()),
        );
        db_iter.seek_to_first();

        Keys::new(db_iter)
    }

    pub fn values<K: DeserializeOwned, V: DeserializeOwned>(
        &'a self,
        db: &DBMap<K, V>,
    ) -> Values<'a, V> {
        let mut db_iter = RocksDBRawIter::OptimisticTransaction(
            self.transaction
                .raw_iterator_cf_opt(&db.cf(), db.opts.readopts()),
        );
        db_iter.seek_to_first();

        Values::new(db_iter)
    }

    pub fn commit(self) -> Result<(), TypedStoreError> {
        fail_point!("transaction-commit");
        self.transaction.commit().map_err(|e| match e.kind() {
            // empirically, this is what you get when there is a write conflict. it is not
            // documented whether this is the only time you can get this error.
            ErrorKind::Busy | ErrorKind::TryAgain => TypedStoreError::RetryableTransactionError,
            _ => e.into(),
        })?;
        Ok(())
    }
}

macro_rules! delegate_iter_call {
    ($self:ident.$method:ident($($args:ident),*)) => {
        match $self {
            Self::DB(db) => db.$method($($args),*),
            Self::OptimisticTransactionDB(db) => db.$method($($args),*),
            Self::OptimisticTransaction(db) => db.$method($($args),*),
        }
    }
}

pub enum RocksDBRawIter<'a> {
    DB(rocksdb::DBRawIteratorWithThreadMode<'a, DBWithThreadMode<MultiThreaded>>),
    OptimisticTransactionDB(
        rocksdb::DBRawIteratorWithThreadMode<'a, rocksdb::OptimisticTransactionDB<MultiThreaded>>,
    ),
    OptimisticTransaction(
        rocksdb::DBRawIteratorWithThreadMode<
            'a,
            Transaction<'a, rocksdb::OptimisticTransactionDB<MultiThreaded>>,
        >,
    ),
}

impl<'a> RocksDBRawIter<'a> {
    pub fn valid(&self) -> bool {
        delegate_iter_call!(self.valid())
    }
    pub fn key(&self) -> Option<&[u8]> {
        delegate_iter_call!(self.key())
    }
    pub fn value(&self) -> Option<&[u8]> {
        delegate_iter_call!(self.value())
    }
    pub fn next(&mut self) {
        delegate_iter_call!(self.next())
    }
    pub fn prev(&mut self) {
        delegate_iter_call!(self.prev())
    }
    pub fn seek<K: AsRef<[u8]>>(&mut self, key: K) {
        delegate_iter_call!(self.seek(key))
    }
    pub fn seek_to_last(&mut self) {
        delegate_iter_call!(self.seek_to_last())
    }
    pub fn seek_to_first(&mut self) {
        delegate_iter_call!(self.seek_to_first())
    }
    pub fn seek_for_prev<K: AsRef<[u8]>>(&mut self, key: K) {
        delegate_iter_call!(self.seek_for_prev(key))
    }
}

pub enum RocksDBIter<'a> {
    DB(rocksdb::DBIteratorWithThreadMode<'a, DBWithThreadMode<MultiThreaded>>),
    OptimisticTransactionDB(
        rocksdb::DBIteratorWithThreadMode<'a, rocksdb::OptimisticTransactionDB<MultiThreaded>>,
    ),
}

impl<'a> Iterator for RocksDBIter<'a> {
    type Item = Result<(Box<[u8]>, Box<[u8]>), Error>;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::DB(db) => db.next(),
            Self::OptimisticTransactionDB(db) => db.next(),
        }
    }
}

impl<'a, K, V> Map<'a, K, V> for DBMap<K, V>
where
    K: Serialize + DeserializeOwned,
    V: Serialize + DeserializeOwned,
{
    type Error = TypedStoreError;
    type Iterator = Iter<'a, K, V>;
    type Keys = Keys<'a, K>;
    type Values = Values<'a, V>;

    #[instrument(level = "trace", skip_all, err)]
    fn contains_key(&self, key: &K) -> Result<bool, TypedStoreError> {
        let key_buf = be_fix_int_ser(key)?;
        // [`rocksdb::DBWithThreadMode::key_may_exist_cf`] can have false positives,
        // but no false negatives. We use it to short-circuit the absent case
        let readopts = self.opts.readopts();
        Ok(self
            .rocksdb
            .key_may_exist_cf(&self.cf(), &key_buf, &readopts)
            && self
                .rocksdb
                .get_pinned_cf(&self.cf(), &key_buf, &readopts)?
                .is_some())
    }

    #[instrument(level = "trace", skip_all, err)]
    fn get(&self, key: &K) -> Result<Option<V>, TypedStoreError> {
        let report_metrics = if self.read_sample_interval.sample() {
            let timer = self
                .db_metrics
                .op_metrics
                .rocksdb_get_latency_seconds
                .with_label_values(&[&self.cf])
                .start_timer();
            Some((timer, RocksDBPerfContext::default()))
        } else {
            None
        };
        let key_buf = be_fix_int_ser(key)?;
        let res = self
            .rocksdb
            .get_pinned_cf(&self.cf(), &key_buf, &self.opts.readopts())?;
        if report_metrics.is_some() {
            self.db_metrics
                .op_metrics
                .rocksdb_get_bytes
                .with_label_values(&[&self.cf])
                .observe(res.as_ref().map_or(0.0, |v| v.len() as f64));
            self.db_metrics
                .read_perf_ctx_metrics
                .report_metrics(&self.cf);
        }
        match res {
            Some(data) => Ok(Some(bincode::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    #[instrument(level = "trace", skip_all, err)]
    fn get_raw_bytes(&self, key: &K) -> Result<Option<Vec<u8>>, TypedStoreError> {
        let report_metrics = if self.read_sample_interval.sample() {
            let timer = self
                .db_metrics
                .op_metrics
                .rocksdb_get_latency_seconds
                .with_label_values(&[&self.cf])
                .start_timer();
            Some((timer, RocksDBPerfContext::default()))
        } else {
            None
        };
        let key_buf = be_fix_int_ser(key)?;
        let res = self
            .rocksdb
            .get_pinned_cf(&self.cf(), &key_buf, &self.opts.readopts())?;
        if report_metrics.is_some() {
            self.db_metrics
                .op_metrics
                .rocksdb_get_bytes
                .with_label_values(&[&self.cf])
                .observe(res.as_ref().map_or(0.0, |v| v.len() as f64));
            self.db_metrics
                .read_perf_ctx_metrics
                .report_metrics(&self.cf);
        }
        match res {
            Some(data) => Ok(Some(data.to_vec())),
            None => Ok(None),
        }
    }

    #[instrument(level = "trace", skip_all, err)]
    fn insert(&self, key: &K, value: &V) -> Result<(), TypedStoreError> {
        let report_metrics = if self.write_sample_interval.sample() {
            let timer = self
                .db_metrics
                .op_metrics
                .rocksdb_put_latency_seconds
                .with_label_values(&[&self.cf])
                .start_timer();
            Some((timer, RocksDBPerfContext::default()))
        } else {
            None
        };
        let key_buf = be_fix_int_ser(key)?;
        let value_buf = bincode::serialize(value)?;
        if report_metrics.is_some() {
            self.db_metrics
                .op_metrics
                .rocksdb_put_bytes
                .with_label_values(&[&self.cf])
                .observe((key_buf.len() + value_buf.len()) as f64);
            self.db_metrics
                .write_perf_ctx_metrics
                .report_metrics(&self.cf);
        }
        self.rocksdb
            .put_cf(&self.cf(), &key_buf, &value_buf, &self.opts.writeopts())?;
        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    fn remove(&self, key: &K) -> Result<(), TypedStoreError> {
        let report_metrics = if self.write_sample_interval.sample() {
            let timer = self
                .db_metrics
                .op_metrics
                .rocksdb_delete_latency_seconds
                .with_label_values(&[&self.cf])
                .start_timer();
            Some((timer, RocksDBPerfContext::default()))
        } else {
            None
        };
        let key_buf = be_fix_int_ser(key)?;
        self.rocksdb
            .delete_cf(&self.cf(), key_buf, &self.opts.writeopts())?;
        if report_metrics.is_some() {
            self.db_metrics
                .op_metrics
                .rocksdb_deletes
                .with_label_values(&[&self.cf])
                .inc();
            self.db_metrics
                .write_perf_ctx_metrics
                .report_metrics(&self.cf);
        }
        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    fn clear(&self) -> Result<(), TypedStoreError> {
        let _ = self.rocksdb.drop_cf(&self.cf);
        self.rocksdb
            .create_cf(self.cf.clone(), &default_db_options().options)?;
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    fn iter(&'a self) -> Self::Iterator {
        let report_metrics = if self.iter_latency_sample_interval.sample() {
            let timer = self
                .db_metrics
                .op_metrics
                .rocksdb_iter_latency_seconds
                .with_label_values(&[&self.cf])
                .start_timer();
            Some((timer, RocksDBPerfContext::default()))
        } else {
            None
        };
        let mut db_iter = self
            .rocksdb
            .raw_iterator_cf(&self.cf(), self.opts.readopts());
        db_iter.seek_to_first();
        if let Some((timer, _perf_ctx)) = report_metrics {
            timer.stop_and_record();
            self.db_metrics
                .read_perf_ctx_metrics
                .report_metrics(&self.cf);
        }
        Iter::new(
            db_iter,
            self.cf.clone(),
            &self.db_metrics,
            &self.iter_bytes_sample_interval,
        )
    }

    fn keys(&'a self) -> Self::Keys {
        let mut db_iter = self
            .rocksdb
            .raw_iterator_cf(&self.cf(), self.opts.readopts());
        db_iter.seek_to_first();

        Keys::new(db_iter)
    }

    fn values(&'a self) -> Self::Values {
        let mut db_iter = self
            .rocksdb
            .raw_iterator_cf(&self.cf(), self.opts.readopts());
        db_iter.seek_to_first();

        Values::new(db_iter)
    }

    /// Returns a vector of values corresponding to the keys provided.
    #[instrument(level = "trace", skip_all, err)]
    fn multi_get<J>(
        &self,
        keys: impl IntoIterator<Item = J>,
    ) -> Result<Vec<Option<V>>, TypedStoreError>
    where
        J: Borrow<K>,
    {
        let report_metrics = if self.read_sample_interval.sample() {
            let timer = self
                .db_metrics
                .op_metrics
                .rocksdb_multiget_latency_seconds
                .with_label_values(&[&self.cf])
                .start_timer();
            Some((timer, RocksDBPerfContext::default()))
        } else {
            None
        };
        let cf = self.cf();

        let keys_bytes: Result<Vec<_>, TypedStoreError> = keys
            .into_iter()
            .map(|k| Ok((&cf, be_fix_int_ser(k.borrow())?)))
            .collect();

        let results = self
            .rocksdb
            .multi_get_cf(keys_bytes?, &self.opts.readopts());
        let entry_size = |entry: &Result<Option<Vec<u8>>, rocksdb::Error>| -> f64 {
            entry
                .as_ref()
                .map_or(0.0, |e| e.as_ref().map_or(0.0, |v| v.len() as f64))
        };
        if report_metrics.is_some() {
            self.db_metrics
                .op_metrics
                .rocksdb_multiget_bytes
                .with_label_values(&[&self.cf])
                .observe(results.iter().map(entry_size).sum());
            self.db_metrics
                .read_perf_ctx_metrics
                .report_metrics(&self.cf);
        }
        let values_parsed: Result<Vec<_>, TypedStoreError> = results
            .into_iter()
            .map(|value_byte| match value_byte? {
                Some(data) => Ok(Some(bincode::deserialize(&data)?)),
                None => Ok(None),
            })
            .collect();

        values_parsed
    }

    /// Convenience method for batch insertion
    #[instrument(level = "trace", skip_all, err)]
    fn multi_insert<J, U>(
        &self,
        key_val_pairs: impl IntoIterator<Item = (J, U)>,
    ) -> Result<(), Self::Error>
    where
        J: Borrow<K>,
        U: Borrow<V>,
    {
        self.batch().insert_batch(self, key_val_pairs)?.write()
    }

    /// Convenience method for batch removal
    #[instrument(level = "trace", skip_all, err)]
    fn multi_remove<J>(&self, keys: impl IntoIterator<Item = J>) -> Result<(), Self::Error>
    where
        J: Borrow<K>,
    {
        self.batch().delete_batch(self, keys)?.write()
    }

    /// Try to catch up with primary when running as secondary
    #[instrument(level = "trace", skip_all, err)]
    fn try_catch_up_with_primary(&self) -> Result<(), Self::Error> {
        Ok(self.rocksdb.try_catch_up_with_primary()?)
    }
}

impl<J, K, U, V> TryExtend<(J, U)> for DBMap<K, V>
where
    J: Borrow<K>,
    U: Borrow<V>,
    K: Serialize,
    V: Serialize,
{
    type Error = TypedStoreError;

    fn try_extend<T>(&mut self, iter: &mut T) -> Result<(), Self::Error>
    where
        T: Iterator<Item = (J, U)>,
    {
        let batch = self.batch().insert_batch(self, iter)?;
        batch.write()
    }

    fn try_extend_from_slice(&mut self, slice: &[(J, U)]) -> Result<(), Self::Error> {
        let slice_of_refs = slice.iter().map(|(k, v)| (k.borrow(), v.borrow()));
        let batch = self.batch().insert_batch(self, slice_of_refs)?;
        batch.write()
    }
}

fn read_size_from_env(var_name: &str) -> Option<usize> {
    env::var(var_name)
        .tap_err(|e| debug!("Env var {} is not set: {}", var_name, e))
        .ok()?
        .parse::<usize>()
        .tap_err(|e| {
            info!(
                "Env var {} does not contain valid usize integer: {}",
                var_name, e
            )
        })
        .ok()
}

#[derive(Default, Clone, Debug)]
pub struct ReadWriteOptions {
    pub ignore_range_deletions: bool,
}

impl ReadWriteOptions {
    pub fn readopts(&self) -> ReadOptions {
        let mut readopts = ReadOptions::default();
        readopts.set_ignore_range_deletions(self.ignore_range_deletions);
        readopts
    }
    pub fn writeopts(&self) -> WriteOptions {
        WriteOptions::default()
    }
}

#[derive(Default, Clone)]
pub struct DBOptions {
    pub options: rocksdb::Options,
    pub rw_options: ReadWriteOptions,
}

/// Creates a default RocksDB option, to be used when RocksDB option is not specified..
pub fn default_db_options() -> DBOptions {
    let mut opt = rocksdb::Options::default();
    // Sui uses multiple RocksDB in a node, so total sizes of write buffers and WAL can be higher
    // than the limits below.
    //
    // RocksDB also exposes the option to configure total write buffer size across multiple instances
    // via `write_buffer_manager`. But the write buffer flush policy (flushing the buffer receiving
    // the next write) may not work well. So sticking to per-db write buffer size limit for now.
    //
    // The environment variables are only meant to be emergency overrides. They may go away in future.
    // If you need to modify an option, either update the default value, or override the option in
    // Sui / Narwhal.
    opt.set_db_write_buffer_size(
        read_size_from_env(ENV_VAR_DB_WRITE_BUFFER_SIZE).unwrap_or(DEFAULT_DB_WRITE_BUFFER_SIZE)
            * 1024
            * 1024,
    );
    opt.set_max_total_wal_size(
        read_size_from_env(ENV_VAR_DB_WAL_SIZE).unwrap_or(DEFAULT_DB_WAL_SIZE) as u64 * 1024 * 1024,
    );
    // According to docs, we almost certainly want to set this to number of cores to not be bottlenecked
    // by rocksdb
    opt.increase_parallelism((num_cpus::get() as i32) / 8);
    DBOptions {
        options: opt,
        rw_options: ReadWriteOptions::default(),
    }
}

/// Opens a database with options, and a number of column families that are created if they do not exist.
#[instrument(level="debug", skip_all, fields(path = ?path.as_ref(), cf = ?opt_cfs), err)]
pub fn open_cf<P: AsRef<Path>>(
    path: P,
    db_options: Option<rocksdb::Options>,
    metric_conf: MetricConf,
    opt_cfs: &[&str],
) -> Result<Arc<RocksDB>, TypedStoreError> {
    let options = db_options.unwrap_or_else(|| default_db_options().options);
    let column_descriptors: Vec<_> = opt_cfs.iter().map(|name| (*name, &options)).collect();
    open_cf_opts(
        path,
        Some(options.clone()),
        metric_conf,
        &column_descriptors[..],
    )
}

fn prepare_db_options<P: AsRef<Path>>(
    path: &P,
    db_options: Option<rocksdb::Options>,
    opt_cfs: &[(&str, &rocksdb::Options)],
) -> rocksdb::Options {
    // Customize database options
    let mut options = db_options.unwrap_or_else(|| default_db_options().options);
    let mut opt_cfs: std::collections::HashMap<_, _> = opt_cfs.iter().cloned().collect();
    let cfs = rocksdb::DBWithThreadMode::<MultiThreaded>::list_cf(&options, path)
        .ok()
        .unwrap_or_default();

    let default_db_options = default_db_options();
    // Add CFs not explicitly listed
    for cf_key in cfs.iter() {
        if !opt_cfs.contains_key(&cf_key[..]) {
            opt_cfs.insert(cf_key, &default_db_options.options);
        }
    }

    options.create_if_missing(true);
    options.create_missing_column_families(true);
    options
}

/// Opens a database with options, and a number of column families with individual options that are created if they do not exist.
#[instrument(level="debug", skip_all, fields(path = ?path.as_ref()), err)]
pub fn open_cf_opts<P: AsRef<Path>>(
    path: P,
    db_options: Option<rocksdb::Options>,
    metric_conf: MetricConf,
    opt_cfs: &[(&str, &rocksdb::Options)],
) -> Result<Arc<RocksDB>, TypedStoreError> {
    let path = path.as_ref();
    // In the simulator, we intercept the wall clock in the test thread only. This causes problems
    // because rocksdb uses the simulated clock when creating its background threads, but then
    // those threads see the real wall clock (because they are not the test thread), which causes
    // rocksdb to panic. The `nondeterministic` macro evaluates expressions in new threads, which
    // resolves the issue.
    //
    // This is a no-op in non-simulator builds.
    nondeterministic!({
        let options = prepare_db_options(&path, db_options, opt_cfs);
        let rocksdb = {
            rocksdb::DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(
                &options,
                path,
                opt_cfs
                    .iter()
                    .map(|(name, opts)| ColumnFamilyDescriptor::new(*name, (*opts).clone())),
            )?
        };
        Ok(Arc::new(RocksDB::DBWithThreadMode(
            DBWithThreadModeWrapper {
                underlying: rocksdb,
                metric_conf,
            },
        )))
    })
}

/// Opens a database with options, and a number of column families with individual options that are created if they do not exist.
#[instrument(level="debug", skip_all, fields(path = ?path.as_ref()), err)]
pub fn open_cf_opts_transactional<P: AsRef<Path>>(
    path: P,
    db_options: Option<rocksdb::Options>,
    metric_conf: MetricConf,
    opt_cfs: &[(&str, &rocksdb::Options)],
) -> Result<Arc<RocksDB>, TypedStoreError> {
    let path = path.as_ref();
    // See comment above for explanation of why nondeterministic is necessary here.
    nondeterministic!({
        let options = prepare_db_options(&path, db_options, opt_cfs);
        let rocksdb = rocksdb::OptimisticTransactionDB::<MultiThreaded>::open_cf_descriptors(
            &options,
            path,
            opt_cfs
                .iter()
                .map(|(name, opts)| ColumnFamilyDescriptor::new(*name, (*opts).clone())),
        )?;
        Ok(Arc::new(RocksDB::OptimisticTransactionDB(
            OptimisticTransactionDBWrapper {
                underlying: rocksdb,
                metric_conf,
            },
        )))
    })
}

/// Opens a database with options, and a number of column families with individual options that are created if they do not exist.
pub fn open_cf_opts_secondary<P: AsRef<Path>>(
    primary_path: P,
    secondary_path: Option<P>,
    db_options: Option<rocksdb::Options>,
    metric_conf: MetricConf,
    opt_cfs: &[(&str, &rocksdb::Options)],
) -> Result<Arc<RocksDB>, TypedStoreError> {
    let primary_path = primary_path.as_ref();
    let secondary_path = secondary_path.as_ref().map(|p| p.as_ref());
    // See comment above for explanation of why nondeterministic is necessary here.
    nondeterministic!({
        // Customize database options
        let mut options = db_options.unwrap_or_else(|| default_db_options().options);

        fdlimit::raise_fd_limit();
        // This is a requirement by RocksDB when opening as secondary
        options.set_max_open_files(-1);

        let mut opt_cfs: std::collections::HashMap<_, _> = opt_cfs.iter().cloned().collect();
        let cfs = rocksdb::DBWithThreadMode::<MultiThreaded>::list_cf(&options, primary_path)
            .ok()
            .unwrap_or_default();

        let default_db_options = default_db_options();
        // Add CFs not explicitly listed
        for cf_key in cfs.iter() {
            if !opt_cfs.contains_key(&cf_key[..]) {
                opt_cfs.insert(cf_key, &default_db_options.options);
            }
        }

        let primary_path = primary_path.to_path_buf();
        let secondary_path = secondary_path.map(|q| q.to_path_buf()).unwrap_or_else(|| {
            let mut s = primary_path.clone();
            s.pop();
            s.push("SECONDARY");
            s.as_path().to_path_buf()
        });

        let rocksdb = {
            options.create_if_missing(true);
            options.create_missing_column_families(true);
            rocksdb::DBWithThreadMode::<MultiThreaded>::open_cf_descriptors_as_secondary(
                &options,
                &primary_path,
                &secondary_path,
                opt_cfs
                    .iter()
                    .map(|(name, opts)| ColumnFamilyDescriptor::new(*name, (*opts).clone())),
            )?
        };
        Ok(Arc::new(RocksDB::DBWithThreadMode(
            DBWithThreadModeWrapper {
                underlying: rocksdb,
                metric_conf,
            },
        )))
    })
}

pub fn list_tables(path: std::path::PathBuf) -> eyre::Result<Vec<String>> {
    const DB_DEFAULT_CF_NAME: &str = "default";

    let opts = rocksdb::Options::default();
    rocksdb::DBWithThreadMode::<rocksdb::MultiThreaded>::list_cf(&opts, path)
        .map_err(|e| e.into())
        .map(|q| {
            q.iter()
                .filter_map(|s| {
                    // The `default` table is not used
                    if s != DB_DEFAULT_CF_NAME {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect()
        })
}

/// TODO: Good description of why we're doing this : RocksDB stores keys in BE and has a seek operator on iterators, see `https://github.com/facebook/rocksdb/wiki/Iterator#introduction`
#[inline]
pub fn be_fix_int_ser<S>(t: &S) -> Result<Vec<u8>, TypedStoreError>
where
    S: ?Sized + serde::Serialize,
{
    bincode::DefaultOptions::new()
        .with_big_endian()
        .with_fixint_encoding()
        .serialize(t)
        .map_err(|e| e.into())
}

#[derive(Clone)]
pub struct DBMapTableConfigMap(BTreeMap<String, DBOptions>);
impl DBMapTableConfigMap {
    pub fn new(map: BTreeMap<String, DBOptions>) -> Self {
        Self(map)
    }

    pub fn to_map(&self) -> BTreeMap<String, DBOptions> {
        self.0.clone()
    }
}

pub enum RocksDBAccessType {
    Primary,
    Secondary(Option<PathBuf>),
}

pub fn safe_drop_db(path: PathBuf) -> Result<(), rocksdb::Error> {
    rocksdb::DB::destroy(&rocksdb::Options::default(), path)
}
