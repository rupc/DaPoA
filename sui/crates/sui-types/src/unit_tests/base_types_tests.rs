// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::disallowed_names)]

use std::str::FromStr;

use fastcrypto::encoding::Base58;
use fastcrypto::traits::EncodeDecodeBase64;
use move_binary_format::file_format;

use crate::crypto::bcs_signable_test::{Bar, Foo};
use crate::crypto::{
    get_key_pair, get_key_pair_from_bytes, AccountKeyPair, AuthorityKeyPair, AuthoritySignature,
    Signature, SuiAuthoritySignature, SuiSignature,
};
use crate::intent::{Intent, IntentMessage};
use crate::{gas_coin::GasCoin, object::Object, SUI_FRAMEWORK_ADDRESS};
use sui_protocol_config::ProtocolConfig;

use super::*;

#[test]
fn test_signatures() {
    let (addr1, sec1): (_, AccountKeyPair) = get_key_pair();
    let (addr2, _sec2): (_, AccountKeyPair) = get_key_pair();

    let foo = Foo("hello".into());
    let foox = Foo("hellox".into());
    let bar = Bar("hello".into());

    let s = Signature::new(&foo, &sec1);
    assert!(s.verify(&foo, addr1).is_ok());
    assert!(s.verify(&foo, addr2).is_err());
    assert!(s.verify(&foox, addr1).is_err());
    assert!(s.verify(&bar, addr1).is_err());
}

#[test]
fn test_signatures_serde() {
    let (_, sec1): (_, AccountKeyPair) = get_key_pair();
    let foo = Foo("hello".into());
    let s = Signature::new(&foo, &sec1);

    let serialized = bincode::serialize(&s).unwrap();
    println!("{:?}", serialized);
    let deserialized: Signature = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.as_ref(), s.as_ref());
}

#[test]
fn test_max_sequence_number() {
    let max = SequenceNumber::MAX;
    assert_eq!(max.0 * 2 + 1, u64::MAX);
}

#[test]
fn test_gas_coin_ser_deser_roundtrip() {
    let id = ObjectID::random();
    let coin = GasCoin::new(id, 10);
    let coin_bytes = coin.to_bcs_bytes();

    let deserialized_coin: GasCoin = bcs::from_bytes(&coin_bytes).unwrap();
    assert_eq!(deserialized_coin.id(), coin.id());
    assert_eq!(deserialized_coin.value(), coin.value());
}

#[test]
fn test_update_contents() {
    let id = ObjectID::random();
    let version = SequenceNumber::from(257);
    let value = 10;
    let coin = GasCoin::new(id, value);
    assert_eq!(coin.id(), &id);
    assert_eq!(coin.value(), value);

    let mut coin_obj = coin.to_object(version);
    assert_eq!(&coin_obj.id(), coin.id());

    // update contents should not touch the version number or ID.
    let old_contents = coin_obj.contents().to_vec();
    let old_type_specific_contents = coin_obj.type_specific_contents().to_vec();
    coin_obj.update_coin_contents(old_contents);
    assert_eq!(&coin_obj.id(), coin.id());
    assert_eq!(
        coin_obj.type_specific_contents(),
        old_type_specific_contents
    );
    assert_eq!(GasCoin::try_from(&coin_obj).unwrap().value(), coin.value());
}

#[test]
fn test_lamport_increment_version() {
    let versions = [
        SequenceNumber::from(1),
        SequenceNumber::from(3),
        SequenceNumber::from(257),
        SequenceNumber::from(42),
    ];

    let incremented = SequenceNumber::lamport_increment(versions);

    for version in versions {
        assert!(version < incremented, "Expected: {version} < {incremented}");
    }
}

#[test]
fn test_object_id_conversions() {}

#[test]
fn test_object_id_display() {
    let hex = SAMPLE_ADDRESS;
    let upper_hex = SAMPLE_ADDRESS.to_uppercase();

    let id = ObjectID::from_str(hex).unwrap();
    assert_eq!(format!("{:?}", id), format!("0x{hex}"));
    assert_eq!(format!("{:X}", id), upper_hex);
    assert_eq!(format!("{:x}", id), hex);
    assert_eq!(format!("{:#x}", id), format!("0x{hex}"));
    assert_eq!(format!("{:#X}", id), format!("0x{upper_hex}"));
}

#[test]
fn test_object_id_str_lossless() {
    let id = ObjectID::from_str("0000000000000000000000000000000000c0f1f95c5b1c5f0eda533eff269000")
        .unwrap();
    let id_empty =
        ObjectID::from_str("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    let id_one =
        ObjectID::from_str("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();

    assert_eq!(id.short_str_lossless(), "c0f1f95c5b1c5f0eda533eff269000",);
    assert_eq!(id_empty.short_str_lossless(), "0",);
    assert_eq!(id_one.short_str_lossless(), "1",);
}

#[test]
fn test_object_id_from_hex_literal() {
    let hex_literal = "0x1";
    let hex = "0000000000000000000000000000000000000000000000000000000000000001";

    let obj_id_from_literal = ObjectID::from_hex_literal(hex_literal).unwrap();
    let obj_id = ObjectID::from_str(hex).unwrap();

    assert_eq!(obj_id_from_literal, obj_id);
    assert_eq!(hex_literal, obj_id.to_hex_literal());

    // Missing '0x'
    ObjectID::from_hex_literal(hex).unwrap_err();
    // Too long
    ObjectID::from_hex_literal(
        "0x10000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap_err();
}

#[test]
fn test_object_id_ref() {
    let obj_id = ObjectID::new([1u8; ObjectID::LENGTH]);
    let _: &[u8] = obj_id.as_ref();
}

#[test]
fn test_object_id_from_proto_invalid_length() {
    let bytes = vec![1; 123];
    ObjectID::from_bytes(bytes).unwrap_err();
}

#[test]
fn test_object_id_deserialize_from_json_value() {
    let obj_id = ObjectID::random();
    let json_value = serde_json::to_value(obj_id).expect("serde_json::to_value fail.");
    let obj_id2: ObjectID =
        serde_json::from_value(json_value).expect("serde_json::from_value fail.");
    assert_eq!(obj_id, obj_id2)
}

#[test]
fn test_object_id_serde_json() {
    let hex = format!("0x{}", SAMPLE_ADDRESS);
    let json_hex = format!("\"0x{}\"", SAMPLE_ADDRESS);

    let obj_id = ObjectID::from_hex_literal(&hex).unwrap();

    let json = serde_json::to_string(&obj_id).unwrap();
    let json_obj_id: ObjectID = serde_json::from_str(&json_hex).unwrap();

    assert_eq!(json, json_hex);
    assert_eq!(obj_id, json_obj_id);
}

#[test]
fn test_object_id_serde_not_human_readable() {
    let obj_id = ObjectID::random();
    let serialized = bincode::serialize(&obj_id).unwrap();
    assert_eq!(obj_id.0.to_vec(), serialized);
    let deserialized: ObjectID = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized, obj_id);
}

#[test]
fn test_object_id_serde_with_expected_value() {
    let object_id_vec = SAMPLE_ADDRESS_VEC.to_vec();
    let object_id = ObjectID::try_from(object_id_vec.clone()).unwrap();
    let json_serialized = serde_json::to_string(&object_id).unwrap();
    let bcs_serialized = bcs::to_bytes(&object_id).unwrap();

    let expected_json_address = format!("\"0x{}\"", SAMPLE_ADDRESS);
    assert_eq!(expected_json_address, json_serialized);
    assert_eq!(object_id_vec, bcs_serialized);
}

#[test]
fn test_object_id_zero_padding() {
    let hex = "0x2";
    let long_hex = "0x0000000000000000000000000000000000000000000000000000000000000002";
    let long_hex_alt = "0000000000000000000000000000000000000000000000000000000000000002";
    let obj_id_1 = ObjectID::from_str(hex).unwrap();
    let obj_id_2 = ObjectID::from_str(long_hex).unwrap();
    let obj_id_3 = ObjectID::from_str(long_hex_alt).unwrap();
    let obj_id_4: ObjectID = serde_json::from_str(&format!("\"{}\"", hex)).unwrap();
    let obj_id_5: ObjectID = serde_json::from_str(&format!("\"{}\"", long_hex)).unwrap();
    let obj_id_6: ObjectID = serde_json::from_str(&format!("\"{}\"", long_hex_alt)).unwrap();
    assert_eq!(SUI_FRAMEWORK_ADDRESS, obj_id_1.0);
    assert_eq!(SUI_FRAMEWORK_ADDRESS, obj_id_2.0);
    assert_eq!(SUI_FRAMEWORK_ADDRESS, obj_id_3.0);
    assert_eq!(SUI_FRAMEWORK_ADDRESS, obj_id_4.0);
    assert_eq!(SUI_FRAMEWORK_ADDRESS, obj_id_5.0);
    assert_eq!(SUI_FRAMEWORK_ADDRESS, obj_id_6.0);
}

#[test]
fn test_address_display() {
    let hex = SAMPLE_ADDRESS;
    let upper_hex = SAMPLE_ADDRESS.to_uppercase();

    let id = SuiAddress::from_str(hex).unwrap();
    assert_eq!(format!("{:?}", id), format!("0x{hex}"));
    assert_eq!(format!("{:X}", id), upper_hex);
    assert_eq!(format!("{:x}", id), hex);
    assert_eq!(format!("{:#x}", id), format!("0x{hex}"));
    assert_eq!(format!("{:#X}", id), format!("0x{upper_hex}"));
}

#[test]
fn test_address_serde_not_human_readable() {
    let address = SuiAddress::random_for_testing_only();
    let serialized = bincode::serialize(&address).unwrap();
    let bcs_serialized = bcs::to_bytes(&address).unwrap();
    // bincode use 8 bytes for BYTES len and bcs use 1 byte
    assert_eq!(serialized, bcs_serialized);
    assert_eq!(address.0, serialized[..]);
    let deserialized: SuiAddress = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized, address);
}

#[test]
fn test_address_serde_human_readable() {
    let address = SuiAddress::random_for_testing_only();
    let serialized = serde_json::to_string(&address).unwrap();
    assert_eq!(format!("\"0x{}\"", Hex::encode(address)), serialized);
    let deserialized: SuiAddress = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, address);
}

#[test]
fn test_address_serde_with_expected_value() {
    let address = SuiAddress::try_from(SAMPLE_ADDRESS_VEC.to_vec()).unwrap();
    let json_serialized = serde_json::to_string(&address).unwrap();
    let bcs_serialized = bcs::to_bytes(&address).unwrap();

    let expected_json_address = format!("\"0x{}\"", SAMPLE_ADDRESS);
    assert_eq!(expected_json_address, json_serialized);
    assert_eq!(SAMPLE_ADDRESS_VEC.to_vec(), bcs_serialized);
}

#[test]
fn test_transaction_digest_serde_not_human_readable() {
    let digest = TransactionDigest::random();
    let serialized = bincode::serialize(&digest).unwrap();
    let bcs_serialized = bcs::to_bytes(&digest).unwrap();
    // bincode use 8 bytes for BYTES len and bcs use 1 byte
    assert_eq!(serialized[8..], bcs_serialized[1..]);
    assert_eq!(digest.inner(), &serialized[8..]);
    let deserialized: TransactionDigest = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized, digest);
}

#[test]
fn test_transaction_digest_serde_human_readable() {
    let digest = TransactionDigest::random();
    let serialized = serde_json::to_string(&digest).unwrap();
    assert_eq!(
        format!("\"{}\"", Base58::encode(digest.inner())),
        serialized
    );
    let deserialized: TransactionDigest = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, digest);
}

#[test]
fn test_authority_signature_serde_not_human_readable() {
    let (_, key): (_, AuthorityKeyPair) = get_key_pair();
    let sig = AuthoritySignature::new_secure(
        &IntentMessage::new(Intent::default(), Foo("some data".to_string())),
        &0,
        &key,
    );
    let serialized = bincode::serialize(&sig).unwrap();
    let bcs_serialized = bcs::to_bytes(&sig).unwrap();

    assert_eq!(serialized, bcs_serialized);
    let deserialized: AuthoritySignature = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.as_ref(), sig.as_ref());
}

#[test]
fn test_authority_signature_serde_human_readable() {
    let (_, key): (_, AuthorityKeyPair) = get_key_pair();
    let sig = AuthoritySignature::new_secure(
        &IntentMessage::new(Intent::default(), Foo("some data".to_string())),
        &0,
        &key,
    );
    let serialized = serde_json::to_string(&sig).unwrap();
    assert_eq!(format!("\"{}\"", sig.encode_base64()), serialized);
    let deserialized: AuthoritySignature = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.as_ref(), sig.as_ref());
}

#[test]
fn test_object_id_from_empty_string() {
    assert!(ObjectID::try_from("".to_string()).is_err());
    assert!(ObjectID::from_str("").is_err());
}

#[test]
fn test_move_object_size_for_gas_metering() {
    let object = Object::with_id_owner_for_testing(
        ObjectID::random(),
        SuiAddress::random_for_testing_only(),
    );
    let size = object.object_size_for_gas_metering();
    let serialized = bcs::to_bytes(&object).unwrap();
    // If the following assertion breaks, it's likely you have changed MoveObject's fields.
    // Make sure to adjust `object_size_for_gas_metering()` to include those changes.
    assert_eq!(size - 4, serialized.len());
}

#[test]
fn test_move_package_size_for_gas_metering() {
    let module = file_format::empty_module();
    let package = Object::new_package(
        vec![module],
        TransactionDigest::genesis(),
        ProtocolConfig::get_for_max_version().max_move_package_size(),
    )
    .unwrap();
    let size = package.object_size_for_gas_metering();
    let serialized = bcs::to_bytes(&package).unwrap();
    // If the following assertion breaks, it's likely you have changed MovePackage's fields.
    // Make sure to adjust `object_size_for_gas_metering()` to include those changes.
    assert_eq!(size - 2, serialized.len());
}

// A sample address in hex generated by the current address derivation algorithm.
#[cfg(test)]
const SAMPLE_ADDRESS: &str = "32866f0109fa1ba911392dcd2d4260f1d824313316f5467abf64187b3eefa555";
const SAMPLE_ADDRESS_VEC: [u8; 32] = [
    50, 134, 111, 1, 9, 250, 27, 169, 17, 57, 45, 205, 45, 66, 96, 241, 216, 36, 49, 51, 22, 245,
    70, 122, 191, 100, 24, 123, 62, 239, 165, 85,
];

// Derive a sample address and public key tuple from KeyPair bytes.
fn derive_sample_address() -> (SuiAddress, AccountKeyPair) {
    let (address, pub_key) = get_key_pair_from_bytes(&[
        10, 112, 5, 142, 174, 127, 187, 146, 251, 68, 22, 191, 128, 68, 84, 13, 102, 71, 77, 57,
        92, 154, 128, 240, 158, 45, 13, 123, 57, 21, 194, 214, 189, 215, 127, 86, 129, 189, 1, 4,
        90, 106, 17, 10, 123, 200, 40, 18, 34, 173, 240, 91, 213, 72, 183, 249, 213, 210, 39, 181,
        105, 254, 59, 163,
    ])
    .unwrap();
    (address, pub_key)
}

// Required to capture address derivation algorithm updates that break some tests and deployments.
#[test]
fn test_address_backwards_compatibility() {
    let (address, _) = derive_sample_address();
    assert_eq!(
        address.to_vec(),
        Hex::decode(SAMPLE_ADDRESS).expect("Decoding failed"),
        "If this test broke, then the algorithm for deriving addresses from public keys has \
               changed. If this was intentional, please compute a new sample address in hex format \
               from `derive_sample_address` and update the SAMPLE_ADDRESS const above with the new \
               derived address hex value. Note that existing deployments (i.e. devnet) might \
               also require updates if they use fixed values generated by the old algorithm."
    );
}
