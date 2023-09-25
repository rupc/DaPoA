// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{reopen, retry_transaction, retry_transaction_forever};
use rstest::rstest;

fn temp_dir() -> std::path::PathBuf {
    tempfile::tempdir()
        .expect("Failed to open temporary directory")
        .into_path()
}

#[rstest]
#[tokio::test]
async fn test_open(#[values(true, false)] is_transactional: bool) {
    let _db = open_map::<_, u32, String>(temp_dir(), None, is_transactional);
}

#[rstest]
#[tokio::test]
async fn test_reopen(#[values(true, false)] is_transactional: bool) {
    let arc = {
        let db = open_map::<_, u32, String>(temp_dir(), None, is_transactional);
        db.insert(&123456789, &"123456789".to_string())
            .expect("Failed to insert");
        db
    };
    let db = DBMap::<u32, String>::reopen(&arc.rocksdb, None, &ReadWriteOptions::default())
        .expect("Failed to re-open storage");
    assert!(db
        .contains_key(&123456789)
        .expect("Failed to retrieve item in storage"));
}

#[tokio::test]
async fn test_reopen_macro() {
    const FIRST_CF: &str = "First_CF";
    const SECOND_CF: &str = "Second_CF";

    let rocks = open_cf(
        temp_dir(),
        None,
        MetricConf::default(),
        &[FIRST_CF, SECOND_CF],
    )
    .unwrap();

    let (db_map_1, db_map_2) = reopen!(&rocks, FIRST_CF;<i32, String>, SECOND_CF;<i32, String>);

    let keys_vals_cf1 = (1..100).map(|i| (i, i.to_string()));
    let keys_vals_cf2 = (1..100).map(|i| (i, i.to_string()));

    assert_eq!(db_map_1.cf, FIRST_CF);
    assert_eq!(db_map_2.cf, SECOND_CF);

    assert!(db_map_1.multi_insert(keys_vals_cf1).is_ok());
    assert!(db_map_2.multi_insert(keys_vals_cf2).is_ok());
}

#[rstest]
#[tokio::test]
async fn test_wrong_reopen(#[values(true, false)] is_transactional: bool) {
    let rocks = open_rocksdb(temp_dir(), &["foo", "bar", "baz"], is_transactional);
    let db = DBMap::<u8, u8>::reopen(&rocks, Some("quux"), &ReadWriteOptions::default());
    assert!(db.is_err());
}

#[rstest]
#[tokio::test]
async fn test_contains_key(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);

    db.insert(&123456789, &"123456789".to_string())
        .expect("Failed to insert");
    assert!(db
        .contains_key(&123456789)
        .expect("Failed to call contains key"));
    assert!(!db
        .contains_key(&000000000)
        .expect("Failed to call contains key"));
}

#[rstest]
#[tokio::test]
async fn test_get(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);

    db.insert(&123456789, &"123456789".to_string())
        .expect("Failed to insert");
    assert_eq!(
        Some("123456789".to_string()),
        db.get(&123456789).expect("Failed to get")
    );
    assert_eq!(None, db.get(&000000000).expect("Failed to get"));
}

#[rstest]
#[tokio::test]
async fn test_get_raw(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);

    db.insert(&123456789, &"123456789".to_string())
        .expect("Failed to insert");

    let val_bytes = db
        .get_raw_bytes(&123456789)
        .expect("Failed to get_raw_bytes")
        .unwrap();

    assert_eq!(
        bincode::serialize(&"123456789".to_string()).unwrap(),
        val_bytes
    );
    assert_eq!(
        None,
        db.get_raw_bytes(&000000000)
            .expect("Failed to get_raw_bytes")
    );
}

#[rstest]
#[tokio::test]
async fn test_multi_get(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);

    db.insert(&123, &"123".to_string())
        .expect("Failed to insert");
    db.insert(&456, &"456".to_string())
        .expect("Failed to insert");

    let result = db.multi_get([123, 456, 789]).expect("Failed to multi get");

    assert_eq!(result.len(), 3);
    assert_eq!(result[0], Some("123".to_string()));
    assert_eq!(result[1], Some("456".to_string()));
    assert_eq!(result[2], None);
}

#[rstest]
#[tokio::test]
async fn test_skip(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);

    db.insert(&123, &"123".to_string())
        .expect("Failed to insert");
    db.insert(&456, &"456".to_string())
        .expect("Failed to insert");
    db.insert(&789, &"789".to_string())
        .expect("Failed to insert");

    // Skip all smaller
    let key_vals: Vec<_> = db.iter().skip_to(&456).expect("Seek failed").collect();
    assert_eq!(key_vals.len(), 2);
    assert_eq!(key_vals[0], (456, "456".to_string()));
    assert_eq!(key_vals[1], (789, "789".to_string()));

    // Skip all smaller: same for the keys iterator
    let keys: Vec<_> = db.keys().skip_to(&456).expect("Seek failed").collect();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], (456));
    assert_eq!(keys[1], (789));

    // Skip to the end
    assert_eq!(db.iter().skip_to(&999).expect("Seek failed").count(), 0);
    // same for the keys
    assert_eq!(db.keys().skip_to(&999).expect("Seek failed").count(), 0);

    // Skip to last
    assert_eq!(
        db.iter().skip_to_last().next(),
        Some((789, "789".to_string()))
    );
    // same for the keys
    assert_eq!(db.keys().skip_to_last().next(), Some(789));

    // Skip to successor of first value
    assert_eq!(db.iter().skip_to(&000).expect("Skip failed").count(), 3);
    assert_eq!(db.keys().skip_to(&000).expect("Skip failed").count(), 3);
}

#[rstest]
#[tokio::test]
async fn test_skip_to_previous_simple(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);

    db.insert(&123, &"123".to_string())
        .expect("Failed to insert");
    db.insert(&456, &"456".to_string())
        .expect("Failed to insert");
    db.insert(&789, &"789".to_string())
        .expect("Failed to insert");

    // Skip to the one before the end
    let key_vals: Vec<_> = db
        .iter()
        .skip_prior_to(&999)
        .expect("Seek failed")
        .collect();
    assert_eq!(key_vals.len(), 1);
    assert_eq!(key_vals[0], (789, "789".to_string()));
    // Same for the keys iterator
    let keys: Vec<_> = db
        .keys()
        .skip_prior_to(&999)
        .expect("Seek failed")
        .collect();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], (789));

    // Skip to prior of first value
    // Note: returns an empty iterator!
    assert_eq!(
        db.iter().skip_prior_to(&000).expect("Seek failed").count(),
        0
    );
    // Same for the keys iterator
    assert_eq!(
        db.keys().skip_prior_to(&000).expect("Seek failed").count(),
        0
    );
}

#[rstest]
#[tokio::test]
async fn test_iter_skip_to_previous_gap(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);

    for i in 1..100 {
        if i != 50 {
            db.insert(&i, &i.to_string()).unwrap();
        }
    }

    // Skip prior to will return an iterator starting with an "unexpected" key if the sought one is not in the table
    let db_iter = db.iter().skip_prior_to(&50).unwrap();

    assert_eq!(
        (49..50)
            .chain(51..100)
            .map(|i| (i, i.to_string()))
            .collect::<Vec<_>>(),
        db_iter.collect::<Vec<_>>()
    );
    // Same logic in the keys iterator
    let db_iter = db.keys().skip_prior_to(&50).unwrap();

    assert_eq!(
        (49..50).chain(51..100).collect::<Vec<_>>(),
        db_iter.collect::<Vec<_>>()
    );
}

#[rstest]
#[tokio::test]
async fn test_remove(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);

    db.insert(&123456789, &"123456789".to_string())
        .expect("Failed to insert");
    assert!(db.get(&123456789).expect("Failed to get").is_some());

    db.remove(&123456789).expect("Failed to remove");
    assert!(db.get(&123456789).expect("Failed to get").is_none());
}

#[rstest]
#[tokio::test]
async fn test_iter(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);
    db.insert(&123456789, &"123456789".to_string())
        .expect("Failed to insert");

    let mut iter = db.iter();
    assert_eq!(Some((123456789, "123456789".to_string())), iter.next());
    assert_eq!(None, iter.next());
}

#[rstest]
#[tokio::test]
async fn test_iter_reverse(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);

    db.insert(&1, &"1".to_string()).expect("Failed to insert");
    db.insert(&2, &"2".to_string()).expect("Failed to insert");
    db.insert(&3, &"3".to_string()).expect("Failed to insert");

    let mut iter = db.iter().skip_to_last().reverse();
    assert_eq!(Some((3, "3".to_string())), iter.next());
    assert_eq!(Some((2, "2".to_string())), iter.next());
    assert_eq!(Some((1, "1".to_string())), iter.next());
    assert_eq!(None, iter.next());

    let mut iter = db.iter().skip_to(&2).unwrap().reverse();
    assert_eq!(Some((2, "2".to_string())), iter.next());
    assert_eq!(Some((1, "1".to_string())), iter.next());
    assert_eq!(None, iter.next());
}

#[rstest]
#[tokio::test]
async fn test_keys(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);

    db.insert(&123456789, &"123456789".to_string())
        .expect("Failed to insert");

    let mut keys = db.keys();
    assert_eq!(Some(123456789), keys.next());
    assert_eq!(None, keys.next());
}

#[rstest]
#[tokio::test]
async fn test_values(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);

    db.insert(&123456789, &"123456789".to_string())
        .expect("Failed to insert");

    let mut values = db.values();
    assert_eq!(Some("123456789".to_string()), values.next());
    assert_eq!(None, values.next());
}

#[rstest]
#[tokio::test]
async fn test_try_extend(#[values(true, false)] is_transactional: bool) {
    let mut db = open_map(temp_dir(), None, is_transactional);
    let mut keys_vals = (1..100).map(|i| (i, i.to_string()));

    db.try_extend(&mut keys_vals)
        .expect("Failed to extend the DB with (k, v) pairs");
    for (k, v) in keys_vals {
        let val = db.get(&k).expect("Failed to get inserted key");
        assert_eq!(Some(v), val);
    }
}

#[rstest]
#[tokio::test]
async fn test_try_extend_from_slice(#[values(true, false)] is_transactional: bool) {
    let mut db = open_map(temp_dir(), None, is_transactional);
    let keys_vals = (1..100).map(|i| (i, i.to_string()));

    db.try_extend_from_slice(&keys_vals.clone().collect::<Vec<_>>()[..])
        .expect("Failed to extend the DB with (k, v) pairs");
    for (k, v) in keys_vals {
        let val = db.get(&k).expect("Failed to get inserted key");
        assert_eq!(Some(v), val);
    }
}

#[rstest]
#[tokio::test]
async fn test_insert_batch(#[values(true, false)] is_transactional: bool) {
    let db = open_map(temp_dir(), None, is_transactional);
    let keys_vals = (1..100).map(|i| (i, i.to_string()));
    let insert_batch = db
        .batch()
        .insert_batch(&db, keys_vals.clone())
        .expect("Failed to batch insert");
    insert_batch.write().expect("Failed to execute batch");
    for (k, v) in keys_vals {
        let val = db.get(&k).expect("Failed to get inserted key");
        assert_eq!(Some(v), val);
    }
}

#[rstest]
#[tokio::test]
async fn test_insert_batch_across_cf(#[values(true, false)] is_transactional: bool) {
    let rocks = open_rocksdb(temp_dir(), &["First_CF", "Second_CF"], is_transactional);

    let db_cf_1 = DBMap::reopen(&rocks, Some("First_CF"), &ReadWriteOptions::default())
        .expect("Failed to open storage");
    let keys_vals_1 = (1..100).map(|i| (i, i.to_string()));

    let db_cf_2 = DBMap::reopen(&rocks, Some("Second_CF"), &ReadWriteOptions::default())
        .expect("Failed to open storage");
    let keys_vals_2 = (1000..1100).map(|i| (i, i.to_string()));

    let batch = db_cf_1
        .batch()
        .insert_batch(&db_cf_1, keys_vals_1.clone())
        .expect("Failed to batch insert")
        .insert_batch(&db_cf_2, keys_vals_2.clone())
        .expect("Failed to batch insert");

    batch.write().expect("Failed to execute batch");
    for (k, v) in keys_vals_1 {
        let val = db_cf_1.get(&k).expect("Failed to get inserted key");
        assert_eq!(Some(v), val);
    }

    for (k, v) in keys_vals_2 {
        let val = db_cf_2.get(&k).expect("Failed to get inserted key");
        assert_eq!(Some(v), val);
    }
}

#[rstest]
#[tokio::test]
async fn test_insert_batch_across_different_db(#[values(true, false)] is_transactional: bool) {
    let rocks = open_rocksdb(temp_dir(), &["First_CF", "Second_CF"], is_transactional);
    let rocks2 = open_rocksdb(temp_dir(), &["First_CF", "Second_CF"], is_transactional);

    let db_cf_1: DBMap<i32, String> =
        DBMap::reopen(&rocks, Some("First_CF"), &ReadWriteOptions::default())
            .expect("Failed to open storage");
    let keys_vals_1 = (1..100).map(|i| (i, i.to_string()));

    let db_cf_2: DBMap<i32, String> =
        DBMap::reopen(&rocks2, Some("Second_CF"), &ReadWriteOptions::default())
            .expect("Failed to open storage");
    let keys_vals_2 = (1000..1100).map(|i| (i, i.to_string()));

    assert!(db_cf_1
        .batch()
        .insert_batch(&db_cf_1, keys_vals_1)
        .expect("Failed to batch insert")
        .insert_batch(&db_cf_2, keys_vals_2)
        .is_err());
}

#[tokio::test]
async fn test_delete_batch() {
    let db = DBMap::<i32, String>::open(
        temp_dir(),
        MetricConf::default(),
        None,
        None,
        &ReadWriteOptions::default(),
    )
    .expect("Failed to open storage");

    let keys_vals = (1..100).map(|i| (i, i.to_string()));
    let insert_batch = db
        .batch()
        .insert_batch(&db, keys_vals)
        .expect("Failed to batch insert");

    // delete the odd-index keys
    let deletion_keys = (1..100).step_by(2);
    let delete_batch = insert_batch
        .delete_batch(&db, deletion_keys)
        .expect("Failed to batch delete");

    delete_batch.write().expect("Failed to execute batch");

    for k in db.keys() {
        assert_eq!(k % 2, 0);
    }
}

#[tokio::test]
async fn test_delete_range() {
    let db: DBMap<i32, String> = DBMap::open(
        temp_dir(),
        MetricConf::default(),
        None,
        None,
        &ReadWriteOptions::default(),
    )
    .expect("Failed to open storage");

    // Note that the last element is (100, "100".to_owned()) here
    let keys_vals = (0..101).map(|i| (i, i.to_string()));
    let insert_batch = db
        .batch()
        .insert_batch(&db, keys_vals)
        .expect("Failed to batch insert");

    let delete_range_batch = insert_batch
        .delete_range(&db, &50, &100)
        .expect("Failed to delete range");

    delete_range_batch.write().expect("Failed to execute batch");

    for k in 0..50 {
        assert!(db.contains_key(&k).expect("Failed to query legal key"),);
    }
    for k in 50..100 {
        assert!(!db.contains_key(&k).expect("Failed to query legal key"));
    }

    // range operator is not inclusive of to
    assert!(db.contains_key(&100).expect("Failed to query legal key"));
}

#[tokio::test]
async fn test_clear() {
    let db = DBMap::<i32, String>::open(
        temp_dir(),
        MetricConf::default(),
        None,
        Some("table"),
        &ReadWriteOptions::default(),
    )
    .expect("Failed to open storage");
    // Test clear of empty map
    let _ = db.clear();

    let keys_vals = (0..101).map(|i| (i, i.to_string()));
    let insert_batch = db
        .batch()
        .insert_batch(&db, keys_vals)
        .expect("Failed to batch insert");

    insert_batch.write().expect("Failed to execute batch");

    // Check we have multiple entries
    assert!(db.iter().count() > 1);
    let _ = db.clear();
    assert_eq!(db.iter().count(), 0);
    // Clear again to ensure safety when clearing empty map
    let _ = db.clear();
    assert_eq!(db.iter().count(), 0);
    // Clear with one item
    let _ = db.insert(&1, &"e".to_string());
    assert_eq!(db.iter().count(), 1);
    let _ = db.clear();
    assert_eq!(db.iter().count(), 0);
}

#[tokio::test]
async fn test_is_empty() {
    let db = DBMap::<i32, String>::open(
        temp_dir(),
        MetricConf::default(),
        None,
        Some("table"),
        &ReadWriteOptions::default(),
    )
    .expect("Failed to open storage");

    // Test empty map is truly empty
    assert!(db.is_empty());
    let _ = db.clear();
    assert!(db.is_empty());

    let keys_vals = (0..101).map(|i| (i, i.to_string()));
    let insert_batch = db
        .batch()
        .insert_batch(&db, keys_vals)
        .expect("Failed to batch insert");

    insert_batch.write().expect("Failed to execute batch");

    // Check we have multiple entries and not empty
    assert!(db.iter().count() > 1);
    assert!(!db.is_empty());

    // Clear again to ensure empty works after clearing
    let _ = db.clear();
    assert_eq!(db.iter().count(), 0);
    assert!(db.is_empty());
}

#[rstest]
#[tokio::test]
async fn test_multi_insert(#[values(true, false)] is_transactional: bool) {
    // Init a DB
    let db: DBMap<i32, String> = open_map(temp_dir(), Some("table"), is_transactional);
    // Create kv pairs
    let keys_vals = (0..101).map(|i| (i, i.to_string()));

    db.multi_insert(keys_vals.clone())
        .expect("Failed to multi-insert");

    for (k, v) in keys_vals {
        let val = db.get(&k).expect("Failed to get inserted key");
        assert_eq!(Some(v), val);
    }
}

#[rstest]
#[tokio::test]
async fn test_checkpoint(#[values(true, false)] is_transactional: bool) {
    let path_prefix = temp_dir();
    let db_path = path_prefix.join("db");
    let db: DBMap<i32, String> = open_map(db_path, Some("table"), is_transactional);
    // Create kv pairs
    let keys_vals = (0..101).map(|i| (i, i.to_string()));

    db.multi_insert(keys_vals.clone())
        .expect("Failed to multi-insert");
    let checkpointed_path = path_prefix.join("checkpointed_db");
    db.rocksdb
        .checkpoint(&checkpointed_path)
        .expect("Failed to create db checkpoint");
    // Create more kv pairs
    let new_keys_vals = (101..201).map(|i| (i, i.to_string()));
    db.multi_insert(new_keys_vals.clone())
        .expect("Failed to multi-insert");
    // Verify checkpoint
    let checkpointed_db: DBMap<i32, String> =
        open_map(checkpointed_path, Some("table"), is_transactional);
    // Ensure keys inserted before checkpoint are present in original and checkpointed db
    for (k, v) in keys_vals {
        let val = db.get(&k).expect("Failed to get inserted key");
        assert_eq!(Some(v.clone()), val);
        let val = checkpointed_db.get(&k).expect("Failed to get inserted key");
        assert_eq!(Some(v), val);
    }
    // Ensure keys inserted after checkpoint are only present in original db but not in checkpointed db
    for (k, v) in new_keys_vals {
        let val = db.get(&k).expect("Failed to get inserted key");
        assert_eq!(Some(v.clone()), val);
        let val = checkpointed_db.get(&k).expect("Failed to get inserted key");
        assert_eq!(None, val);
    }
}

#[rstest]
#[tokio::test]
async fn test_multi_remove(#[values(true, false)] is_transactional: bool) {
    // Init a DB
    let db: DBMap<i32, String> = open_map(temp_dir(), Some("table"), is_transactional);

    // Create kv pairs
    let keys_vals = (0..101).map(|i| (i, i.to_string()));

    db.multi_insert(keys_vals.clone())
        .expect("Failed to multi-insert");

    // Check insertion
    for (k, v) in keys_vals.clone() {
        let val = db.get(&k).expect("Failed to get inserted key");
        assert_eq!(Some(v), val);
    }

    // Remove 50 items
    db.multi_remove(keys_vals.clone().map(|kv| kv.0).take(50))
        .expect("Failed to multi-remove");
    assert_eq!(db.iter().count(), 101 - 50);

    // Check that the remaining are present
    for (k, v) in keys_vals.skip(50) {
        let val = db.get(&k).expect("Failed to get inserted key");
        assert_eq!(Some(v), val);
    }
}

#[tokio::test]
async fn test_transactional() {
    let key = "key";
    let path = temp_dir();
    let opt = rocksdb::Options::default();
    let rocksdb =
        open_cf_opts_transactional(path, None, MetricConf::default(), &[("cf", &opt)]).unwrap();
    let db = DBMap::<String, String>::reopen(&rocksdb, None, &ReadWriteOptions::default())
        .expect("Failed to re-open storage");

    // transaction is used instead
    let mut tx1 = db.transaction().expect("failed to initiate transaction");
    let mut tx2 = db.transaction().expect("failed to initiate transaction");

    tx1 = tx1
        .insert_batch(&db, vec![(key.to_string(), "1".to_string())])
        .unwrap();
    tx2 = tx2
        .insert_batch(&db, vec![(key.to_string(), "2".to_string())])
        .unwrap();

    tx1.commit().expect("failed to commit first transaction");
    assert!(tx2.commit().is_err());
    assert_eq!(db.get(&key.to_string()).unwrap(), Some("1".to_string()));
}

#[tokio::test]
async fn test_transaction_snapshot() {
    let key = "key".to_string();
    let path = temp_dir();
    let opt = rocksdb::Options::default();
    let rocksdb =
        open_cf_opts_transactional(path, None, MetricConf::default(), &[("cf", &opt)]).unwrap();
    let db = DBMap::<String, String>::reopen(&rocksdb, None, &ReadWriteOptions::default())
        .expect("Failed to re-open storage");

    // transaction without set_snapshot succeeds when extraneous write occurs before transaction
    // write.
    let mut tx1 = db
        .transaction_without_snapshot()
        .expect("failed to initiate transaction");
    // write occurs after transaction is created but before first write
    db.insert(&key, &"1".to_string()).unwrap();
    tx1 = tx1
        .insert_batch(&db, vec![(key.to_string(), "2".to_string())])
        .unwrap();
    tx1.commit().expect("failed to commit first transaction");
    assert_eq!(db.get(&key).unwrap().unwrap(), "2".to_string());

    // transaction without set_snapshot fails when extraneous write occurs after transaction
    // write.
    let mut tx1 = db
        .transaction_without_snapshot()
        .expect("failed to initiate transaction");
    tx1 = tx1
        .insert_batch(&db, vec![(key.to_string(), "2".to_string())])
        .unwrap();
    db.insert(&key, &"1".to_string()).unwrap();
    assert!(matches!(
        tx1.commit(),
        Err(TypedStoreError::RetryableTransactionError)
    ));
    assert_eq!(db.get(&key).unwrap().unwrap(), "1".to_string());

    // failed transaction with set_snapshot
    let mut tx1 = db.transaction().expect("failed to initiate transaction");
    // write occurs after transaction is created, so the conflict is detected
    db.insert(&key, &"1".to_string()).unwrap();
    tx1 = tx1
        .insert_batch(&db, vec![(key.to_string(), "2".to_string())])
        .unwrap();
    assert!(matches!(
        tx1.commit(),
        Err(TypedStoreError::RetryableTransactionError)
    ));

    let mut tx1 = db.transaction().expect("failed to initiate transaction");
    tx1 = tx1
        .insert_batch(&db, vec![(key.to_string(), "2".to_string())])
        .unwrap();
    // no conflicting writes, should succeed this time.
    tx1.commit().unwrap();

    // when to transactions race, one will fail provided that neither commits before the other
    // writes.
    let mut tx1 = db
        .transaction_without_snapshot()
        .expect("failed to initiate transaction");
    let mut tx2 = db
        .transaction_without_snapshot()
        .expect("failed to initiate transaction");
    tx1 = tx1
        .insert_batch(&db, vec![(key.to_string(), "1".to_string())])
        .unwrap();
    tx2 = tx2
        .insert_batch(&db, vec![(key.to_string(), "2".to_string())])
        .unwrap();
    // which ever tx is committed first will succeed.
    tx1.commit().expect("failed to commit");
    assert!(matches!(
        tx2.commit(),
        Err(TypedStoreError::RetryableTransactionError)
    ));

    // IMPORTANT: a race is still possible if one tx commits before the other writes.
    let mut tx1 = db
        .transaction_without_snapshot()
        .expect("failed to initiate transaction");
    let mut tx2 = db
        .transaction_without_snapshot()
        .expect("failed to initiate transaction");
    tx1 = tx1
        .insert_batch(&db, vec![(key.to_string(), "1".to_string())])
        .unwrap();
    tx1.commit().expect("failed to commit");

    tx2 = tx2.insert_batch(&db, vec![(key, "2".to_string())]).unwrap();
    tx2.commit().expect("failed to commit");
}

#[tokio::test]
async fn test_retry_transaction() {
    let key = "key".to_string();
    let path = temp_dir();
    let opt = rocksdb::Options::default();
    let rocksdb =
        open_cf_opts_transactional(path, None, MetricConf::default(), &[("cf", &opt)]).unwrap();
    let db = DBMap::<String, String>::reopen(&rocksdb, None, &ReadWriteOptions::default())
        .expect("Failed to re-open storage");

    let mut conflicts = 0;
    retry_transaction!({
        let mut tx1 = db
            .transaction_without_snapshot()
            .expect("failed to initiate transaction");
        tx1 = tx1
            .insert_batch(&db, vec![(key.to_string(), "2".to_string())])
            .unwrap();
        if conflicts < 3 {
            db.insert(&key, &"1".to_string()).unwrap();
        }
        conflicts += 1;
        tx1.commit()
    })
    // succeeds after we stop causing conflicts
    .unwrap();

    retry_transaction!({
        let mut tx1 = db
            .transaction_without_snapshot()
            .expect("failed to initiate transaction");
        tx1 = tx1
            .insert_batch(&db, vec![(key.to_string(), "2".to_string())])
            .unwrap();
        db.insert(&key, &"1".to_string()).unwrap();
        tx1.commit()
    })
    // fails after hitting maximum number of retries
    .unwrap_err();

    // obviously we cannot verify that this never times out, this is more just a test to make sure
    // the macro compiles as expected.
    tokio::time::timeout(Duration::from_secs(1), async move {
        retry_transaction_forever!({
            let mut tx1 = db
                .transaction_without_snapshot()
                .expect("failed to initiate transaction");
            tx1 = tx1
                .insert_batch(&db, vec![(key.to_string(), "2".to_string())])
                .unwrap();
            db.insert(&key, &"1".to_string()).unwrap();
            tx1.commit()
        })
        // fails after hitting maximum number of retries
        .unwrap_err();
        panic!("should never finish");
    })
    .await
    // must timeout
    .unwrap_err();
}

#[tokio::test]
async fn test_transaction_read_your_write() {
    let key1 = "key1";
    let key2 = "key2";
    let path = temp_dir();
    let opt = rocksdb::Options::default();
    let rocksdb =
        open_cf_opts_transactional(path, None, MetricConf::default(), &[("cf", &opt)]).unwrap();
    let db = DBMap::<String, String>::reopen(&rocksdb, None, &ReadWriteOptions::default())
        .expect("Failed to re-open storage");
    db.insert(&key1.to_string(), &"1".to_string()).unwrap();
    let mut tx = db.transaction().expect("failed to initiate transaction");
    tx = tx
        .insert_batch(
            &db,
            vec![
                (key1.to_string(), "11".to_string()),
                (key2.to_string(), "2".to_string()),
            ],
        )
        .unwrap();
    assert_eq!(db.get(&key1.to_string()).unwrap(), Some("1".to_string()));
    assert_eq!(db.get(&key2.to_string()).unwrap(), None);

    assert_eq!(
        tx.get(&db, &key1.to_string()).unwrap(),
        Some("11".to_string())
    );
    assert_eq!(
        tx.get(&db, &key2.to_string()).unwrap(),
        Some("2".to_string())
    );

    tx = tx.delete_batch(&db, vec![(key2.to_string())]).unwrap();

    assert_eq!(
        tx.multi_get(&db, vec![key1.to_string(), key2.to_string()])
            .unwrap(),
        vec![Some("11".to_string()), None]
    );
    let keys: Vec<String> = tx.keys(&db).into_iter().collect();
    assert_eq!(keys, vec![key1.to_string()]);
    let values: Vec<_> = tx.values(&db).into_iter().collect();
    assert_eq!(values, vec!["11".to_string()]);
    assert!(tx.commit().is_ok());
}

#[tokio::test]
async fn open_as_secondary_test() {
    let primary_path = temp_dir();

    // Init a DB
    let primary_db = DBMap::<i32, String>::open(
        primary_path.clone(),
        MetricConf::default(),
        None,
        Some("table"),
        &ReadWriteOptions::default(),
    )
    .expect("Failed to open storage");
    // Create kv pairs
    let keys_vals = (0..101).map(|i| (i, i.to_string()));

    primary_db
        .multi_insert(keys_vals.clone())
        .expect("Failed to multi-insert");

    let opt = rocksdb::Options::default();
    let secondary_store = open_cf_opts_secondary(
        primary_path,
        None,
        None,
        MetricConf::default(),
        &[("table", &opt)],
    )
    .unwrap();
    let secondary_db = DBMap::<i32, String>::reopen(
        &secondary_store,
        Some("table"),
        &ReadWriteOptions::default(),
    )
    .unwrap();

    secondary_db.try_catch_up_with_primary().unwrap();
    // Check secondary
    for (k, v) in keys_vals {
        assert_eq!(secondary_db.get(&k).unwrap(), Some(v));
    }

    // Update the value from 0 to 10
    primary_db.insert(&0, &"10".to_string()).unwrap();

    // This should still be stale since secondary is behind
    assert_eq!(secondary_db.get(&0).unwrap(), Some("0".to_string()));

    // Try force catchup
    secondary_db.try_catch_up_with_primary().unwrap();

    // New value should be present
    assert_eq!(secondary_db.get(&0).unwrap(), Some("10".to_string()));
}

fn open_map<P: AsRef<Path>, K, V>(
    path: P,
    opt_cf: Option<&str>,
    is_transactional: bool,
) -> DBMap<K, V> {
    if is_transactional {
        let cf = opt_cf.unwrap_or(rocksdb::DEFAULT_COLUMN_FAMILY_NAME);
        open_cf_opts_transactional(
            path,
            None,
            MetricConf::default(),
            &[(cf, &default_db_options().options)],
        )
        .map(|db| DBMap::new(db, &ReadWriteOptions::default(), cf))
        .expect("failed to open rocksdb")
    } else {
        DBMap::<K, V>::open(
            path,
            MetricConf::default(),
            None,
            opt_cf,
            &ReadWriteOptions::default(),
        )
        .expect("failed to open rocksdb")
    }
}

fn open_rocksdb<P: AsRef<Path>>(path: P, opt_cfs: &[&str], is_transactional: bool) -> Arc<RocksDB> {
    if is_transactional {
        let options = default_db_options().options;
        let cfs: Vec<_> = opt_cfs.iter().map(|name| (*name, &options)).collect();
        open_cf_opts_transactional(path, None, MetricConf::default(), &cfs)
            .expect("failed to open rocksdb")
    } else {
        open_cf(path, None, MetricConf::default(), opt_cfs).expect("failed to open rocksdb")
    }
}
