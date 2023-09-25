// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::traits::KeyPair as KeypairTraits;

use crate::crypto::Signer;
use crate::{
    base_types::{dbg_addr, ExecutionDigests, ObjectID},
    committee::{Committee, ProtocolVersion},
    crypto::{
        get_key_pair, get_key_pair_from_rng, AccountKeyPair, AuthorityKeyPair,
        AuthorityPublicKeyBytes, Signature,
    },
    gas::GasCostSummary,
    intent::Intent,
    messages::{Transaction, TransactionData, VerifiedTransaction},
    messages_checkpoint::{
        CertifiedCheckpointSummary, CheckpointContents, SignedCheckpointSummary,
    },
    object::Object,
};
use std::collections::BTreeMap;

pub fn make_committee_key<R>(rand: &mut R) -> (Vec<AuthorityKeyPair>, Committee)
where
    R: rand::CryptoRng + rand::RngCore,
{
    make_committee_key_num(4, rand)
}

pub fn make_committee_key_num<R>(num: usize, rand: &mut R) -> (Vec<AuthorityKeyPair>, Committee)
where
    R: rand::CryptoRng + rand::RngCore,
{
    let mut authorities: BTreeMap<AuthorityPublicKeyBytes, u64> = BTreeMap::new();
    let mut keys = Vec::new();

    for _ in 0..num {
        let (_, inner_authority_key): (_, AuthorityKeyPair) = get_key_pair_from_rng(rand);
        authorities.insert(
            /* address */ AuthorityPublicKeyBytes::from(inner_authority_key.public()),
            /* voting right */ 1,
        );
        keys.push(inner_authority_key);
    }

    let committee = Committee::new(0, ProtocolVersion::MIN, authorities).unwrap();
    (keys, committee)
}

// Creates a fake sender-signed transaction for testing. This transaction will
// not actually work.
pub fn create_fake_transaction() -> VerifiedTransaction {
    let (sender, sender_key): (_, AccountKeyPair) = get_key_pair();
    let recipient = dbg_addr(2);
    let object_id = ObjectID::random();
    let object = Object::immutable_with_id_for_testing(object_id);
    let data = TransactionData::new_transfer_sui_with_dummy_gas_price(
        recipient,
        sender,
        None,
        object.compute_object_reference(),
        10000,
    );
    to_sender_signed_transaction(data, &sender_key)
}

// This is used to sign transaction with signer using default Intent.
pub fn to_sender_signed_transaction(
    data: TransactionData,
    signer: &dyn Signer<Signature>,
) -> VerifiedTransaction {
    to_sender_signed_transaction_with_multi_signers(data, vec![signer])
}

pub fn to_sender_signed_transaction_with_multi_signers(
    data: TransactionData,
    signers: Vec<&dyn Signer<Signature>>,
) -> VerifiedTransaction {
    VerifiedTransaction::new_unchecked(Transaction::from_data_and_signer(
        data,
        Intent::default(),
        signers,
    ))
}

pub fn mock_certified_checkpoint<'a>(
    keys: impl Iterator<Item = &'a AuthorityKeyPair>,
    committee: Committee,
    seq_num: u64,
) -> CertifiedCheckpointSummary {
    let contents = CheckpointContents::new_with_causally_ordered_transactions(
        [ExecutionDigests::random()].into_iter(),
    );

    let signed_checkpoints: Vec<_> = keys
        .map(|k| {
            let name = k.public().into();

            SignedCheckpointSummary::new(
                committee.epoch,
                seq_num,
                0,
                name,
                k,
                &contents,
                None,
                GasCostSummary::default(),
                None,
                0,
            )
        })
        .collect();

    CertifiedCheckpointSummary::aggregate(signed_checkpoints, &committee).expect("Cert is OK")
}
