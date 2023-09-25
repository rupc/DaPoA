// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::{CertificateDigest, HeaderDigest, Round, TimestampMs, VoteDigest};
use config::Epoch;
use fastcrypto::hash::Digest;
use std::sync::{Arc, Mutex};
use store::StoreError;
use thiserror::Error;
use tokio::sync::broadcast;

#[cfg(test)]
#[path = "./tests/error_test.rs"]
mod error_test;

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($e);
    };
}

#[macro_export(local_inner_macros)]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            bail!($e);
        }
    };
}

pub type DagResult<T> = Result<T, DagError>;

// Notification for certificate accepted.
// TODO: use a lighter weight alternative to broadcast::channel.
pub type AcceptNotification = Arc<Mutex<Option<broadcast::Receiver<()>>>>;

#[derive(Clone, Debug, Error)]
pub enum DagError {
    #[error("Channel {0} has closed unexpectedly")]
    ClosedChannel(String),

    #[error("Invalid Authorities Bitmap: {0}")]
    InvalidBitmap(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Storage failure: {0}")]
    StoreError(#[from] StoreError),

    #[error("Invalid header digest")]
    InvalidHeaderDigest,

    #[error("Header {0} has bad worker IDs")]
    HeaderHasBadWorkerIds(HeaderDigest),

    #[error("Header {0} has parents with invalid round numbers")]
    HeaderHasInvalidParentRoundNumbers(HeaderDigest),

    #[error("Header {0} has more than one parent certificate with the same authority")]
    HeaderHasDuplicateParentAuthorities(HeaderDigest),

    #[error("Received message from unknown authority {0}")]
    UnknownAuthority(String),

    #[error("Authority {0} appears in quorum more than once")]
    AuthorityReuse(String),

    #[error("Received unexpected vote for header {0}")]
    UnexpectedVote(HeaderDigest),

    #[error("Already sent a vote with digest {0} for round {1}")]
    AlreadyVoted(VoteDigest, Round),

    #[error("Could not form a certificate for header {0}")]
    CouldNotFormCertificate(HeaderDigest),

    #[error("Received certificate without a quorum")]
    CertificateRequiresQuorum,

    #[error("Cannot load certificates from our own proposed header")]
    ProposedHeaderMissingCertificates,

    #[error("Parents of header {0} are not a quorum")]
    HeaderRequiresQuorum(HeaderDigest),

    #[error("Message {0} (round {1}) too old for GC round {2}")]
    TooOld(Digest<{ crypto::DIGEST_LENGTH }>, Round, Round),

    #[error("Message {0} (round {1}) is too new for this primary at round {2}")]
    TooNew(Digest<{ crypto::DIGEST_LENGTH }>, Round, Round),

    #[error("Vote {0} (round {1}) too old for round {2}")]
    VoteTooOld(Digest<{ crypto::DIGEST_LENGTH }>, Round, Round),

    #[error("Invalid epoch (expected {expected}, received {received})")]
    InvalidEpoch { expected: Epoch, received: Epoch },

    #[error("Invalid round (expected {expected}, received {received})")]
    InvalidRound { expected: Round, received: Round },

    #[error("Invalid timestamp (created at {created_time}, received at {local_time})")]
    InvalidTimestamp {
        created_time: TimestampMs,
        local_time: TimestampMs,
    },

    #[error("Invalid parent {0} (not found in genesis)")]
    InvalidGenesisParent(CertificateDigest),

    #[error("No peer can be reached for fetching certificates! Check if network is healthy.")]
    NoCertificateFetched,

    #[error("Too many certificates in the FetchCertificatesResponse {0} > {1}")]
    TooManyFetchedCertificatesReturned(usize, usize),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Processing was suspended to retrieve parent certificates")]
    Suspended(AcceptNotification),

    #[error("System shutting down")]
    ShuttingDown,

    #[error("Channel full")]
    ChannelFull,

    #[error("Operation was canceled")]
    Canceled,
}

impl<T> From<tokio::sync::mpsc::error::TrySendError<T>> for DagError {
    fn from(err: tokio::sync::mpsc::error::TrySendError<T>) -> Self {
        match err {
            tokio::sync::mpsc::error::TrySendError::Full(_) => DagError::ChannelFull,
            tokio::sync::mpsc::error::TrySendError::Closed(_) => DagError::ShuttingDown,
        }
    }
}

pub fn new_accept_notification(receiver: broadcast::Receiver<()>) -> AcceptNotification {
    Arc::new(std::sync::Mutex::new(Some(receiver)))
}
