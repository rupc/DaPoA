// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::hash::Digest;
use std::fmt::{Debug, Display, Formatter};
use std::slice::Iter;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::base_types::ExecutionDigests;
use crate::committee::{EpochId, ProtocolVersion, StakeUnit};
use crate::crypto::{AuthoritySignInfo, AuthoritySignInfoTrait, AuthorityStrongQuorumSignInfo};
use crate::error::SuiResult;
use crate::gas::GasCostSummary;
use crate::intent::{Intent, IntentScope};
use crate::signature::GenericSignature;
use crate::{
    base_types::AuthorityName,
    committee::Committee,
    crypto::{sha3_hash, AuthoritySignature, VerificationObligation},
    error::SuiError,
};
use fastcrypto::traits::Signer;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use crate::digests::CheckpointContentsDigest;
pub use crate::digests::CheckpointDigest;

pub type CheckpointSequenceNumber = u64;
pub type CheckpointTimestamp = u64;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointRequest {
    /// if a sequence number is specified, return the checkpoint with that sequence number;
    /// otherwise if None returns the latest authenticated checkpoint stored.
    pub sequence_number: Option<CheckpointSequenceNumber>,
    // A flag, if true also return the contents of the
    // checkpoint besides the meta-data.
    pub request_content: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointResponse {
    pub checkpoint: Option<CertifiedCheckpointSummary>,
    pub contents: Option<CheckpointContents>,
}

// The constituent parts of checkpoints, signed and certified

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub struct EndOfEpochData {
    /// next_epoch_committee is `Some` if and only if the current checkpoint is
    /// the last checkpoint of an epoch.
    /// Therefore next_epoch_committee can be used to pick the last checkpoint of an epoch,
    /// which is often useful to get epoch level summary stats like total gas cost of an epoch,
    /// or the total number of transactions from genesis to the end of an epoch.
    /// The committee is stored as a vector of validator pub key and stake pairs. The vector
    /// should be sorted based on the Committee data structure.
    pub next_epoch_committee: Vec<(AuthorityName, StakeUnit)>,

    /// The protocol version that is in effect during the epoch that starts immediately after this
    /// checkpoint.
    pub next_epoch_protocol_version: ProtocolVersion,

    /// The digest of the union of all checkpoint accumulators,
    /// representing the state of the system at the end of the epoch.
    #[schemars(with = "[u8; 32]")]
    pub root_state_digest: Digest<32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub struct CheckpointSummary {
    pub epoch: EpochId,
    pub sequence_number: CheckpointSequenceNumber,
    /// Total number of transactions committed since genesis, including those in this
    /// checkpoint.
    pub network_total_transactions: u64,
    pub content_digest: CheckpointContentsDigest,
    pub previous_digest: Option<CheckpointDigest>,
    /// The running total gas costs of all transactions included in the current epoch so far
    /// until this checkpoint.
    pub epoch_rolling_gas_cost_summary: GasCostSummary,

    /// Timestamp of the checkpoint - number of milliseconds from the Unix epoch
    /// Checkpoint timestamps are monotonic, but not strongly monotonic - subsequent
    /// checkpoints can have same timestamp if they originate from the same underlining consensus commit
    pub timestamp_ms: CheckpointTimestamp,

    /// Present only on the final checkpoint of the epoch.
    pub end_of_epoch_data: Option<EndOfEpochData>,

    /// CheckpointSummary is not an evolvable structure - it must be readable by any version of the
    /// code. Therefore, in order to allow extensions to be added to CheckpointSummary, we allow
    /// opaque data to be added to checkpoints which can be deserialized based on the current
    /// protocol version.
    pub version_specific_data: Vec<u8>,
}

impl CheckpointSummary {
    pub fn new(
        epoch: EpochId,
        sequence_number: CheckpointSequenceNumber,
        network_total_transactions: u64,
        transactions: &CheckpointContents,
        previous_digest: Option<CheckpointDigest>,
        epoch_rolling_gas_cost_summary: GasCostSummary,
        end_of_epoch_data: Option<EndOfEpochData>,
        timestamp_ms: CheckpointTimestamp,
    ) -> CheckpointSummary {
        let content_digest = transactions.digest();

        Self {
            epoch,
            sequence_number,
            network_total_transactions,
            content_digest,
            previous_digest,
            epoch_rolling_gas_cost_summary,
            end_of_epoch_data,
            timestamp_ms,
            version_specific_data: Vec::new(),
        }
    }

    pub fn sequence_number(&self) -> &CheckpointSequenceNumber {
        &self.sequence_number
    }

    pub fn digest(&self) -> CheckpointDigest {
        CheckpointDigest::new(sha3_hash(self))
    }

    pub fn timestamp(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.timestamp_ms)
    }
}

impl Display for CheckpointSummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CheckpointSummary {{ epoch: {:?}, seq: {:?}, content_digest: {},
            epoch_rolling_gas_cost_summary: {:?}}}",
            self.epoch,
            self.sequence_number,
            self.content_digest,
            self.epoch_rolling_gas_cost_summary,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointSummaryEnvelope<S> {
    pub summary: CheckpointSummary,
    pub auth_signature: S,
}

impl<S> CheckpointSummaryEnvelope<S> {
    pub fn summary(&self) -> &CheckpointSummary {
        &self.summary
    }

    pub fn digest(&self) -> CheckpointDigest {
        self.summary.digest()
    }

    pub fn epoch(&self) -> EpochId {
        self.summary.epoch
    }

    pub fn sequence_number(&self) -> CheckpointSequenceNumber {
        self.summary.sequence_number
    }

    pub fn content_digest(&self) -> CheckpointContentsDigest {
        self.summary.content_digest
    }

    pub fn previous_digest(&self) -> Option<CheckpointDigest> {
        self.summary.previous_digest
    }

    pub fn next_epoch_committee(&self) -> Option<&[(AuthorityName, StakeUnit)]> {
        self.summary
            .end_of_epoch_data
            .as_ref()
            .map(|e| e.next_epoch_committee.as_slice())
    }
}

impl<S: Debug> Display for CheckpointSummaryEnvelope<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.summary)?;
        writeln!(f, "Signature: {:?}", self.auth_signature)?;
        Ok(())
    }
}

pub type SignedCheckpointSummary = CheckpointSummaryEnvelope<AuthoritySignInfo>;

impl SignedCheckpointSummary {
    /// Create a new signed checkpoint proposal for this authority
    pub fn new(
        epoch: EpochId,
        sequence_number: CheckpointSequenceNumber,
        network_total_transactions: u64,
        authority: AuthorityName,
        signer: &dyn Signer<AuthoritySignature>,
        transactions: &CheckpointContents,
        previous_digest: Option<CheckpointDigest>,
        epoch_rolling_gas_cost_summary: GasCostSummary,
        end_of_epoch_data: Option<EndOfEpochData>,
        timestamp_ms: CheckpointTimestamp,
    ) -> SignedCheckpointSummary {
        let checkpoint = CheckpointSummary::new(
            epoch,
            sequence_number,
            network_total_transactions,
            transactions,
            previous_digest,
            epoch_rolling_gas_cost_summary,
            end_of_epoch_data,
            timestamp_ms,
        );
        SignedCheckpointSummary::new_from_summary(checkpoint, authority, signer)
    }

    pub fn new_from_summary(
        checkpoint: CheckpointSummary,
        authority: AuthorityName,
        signer: &dyn Signer<AuthoritySignature>,
    ) -> SignedCheckpointSummary {
        let epoch = checkpoint.epoch;
        let auth_signature = AuthoritySignInfo::new(
            epoch,
            &checkpoint,
            Intent::default().with_scope(IntentScope::CheckpointSummary),
            authority,
            signer,
        );
        SignedCheckpointSummary {
            summary: checkpoint,
            auth_signature,
        }
    }

    pub fn authority(&self) -> &AuthorityName {
        &self.auth_signature.authority
    }

    /// Checks that the signature on the digest is correct, and verify the contents as well if
    /// provided.
    pub fn verify(
        &self,
        committee: &Committee,
        contents: Option<&CheckpointContents>,
    ) -> Result<(), SuiError> {
        fp_ensure!(
            self.summary.epoch == committee.epoch,
            SuiError::from("Epoch in the summary doesn't match with the signature")
        );
        self.auth_signature.verify_secure(
            &self.summary,
            Intent::default().with_scope(IntentScope::CheckpointSummary),
            committee,
        )?;

        if let Some(contents) = contents {
            let content_digest = contents.digest();
            fp_ensure!(
                content_digest == self.summary.content_digest,
                SuiError::GenericAuthorityError{error:format!("Checkpoint contents digest mismatch: summary={:?}, received content digest {:?}, received {} transactions", self.summary, content_digest, contents.size())}
            );
        }

        Ok(())
    }
}

// Checkpoints are signed by an authority and 2f+1 form a
// certificate that others can use to catch up. The actual
// content of the digest must at the very least commit to
// the set of transactions contained in the certificate but
// we might extend this to contain roots of merkle trees,
// or other authenticated data structures to support light
// clients and more efficient sync protocols.

pub type CertifiedCheckpointSummary = CheckpointSummaryEnvelope<AuthorityStrongQuorumSignInfo>;

impl CertifiedCheckpointSummary {
    /// Aggregate many checkpoint signatures to form a checkpoint certificate.
    pub fn aggregate(
        signed_checkpoints: Vec<SignedCheckpointSummary>,
        committee: &Committee,
    ) -> Result<CertifiedCheckpointSummary, SuiError> {
        fp_ensure!(
            !signed_checkpoints.is_empty(),
            SuiError::from("Need at least one signed checkpoint to aggregate")
        );
        fp_ensure!(
            signed_checkpoints
                .iter()
                .all(|c| c.summary.epoch == committee.epoch),
            SuiError::from("SignedCheckpoint is from different epoch as committee")
        );

        let certified_checkpoint = CertifiedCheckpointSummary {
            summary: signed_checkpoints[0].summary.clone(),
            auth_signature: AuthorityStrongQuorumSignInfo::new_from_auth_sign_infos(
                signed_checkpoints
                    .into_iter()
                    .map(|v| v.auth_signature)
                    .collect(),
                committee,
            )?,
        };

        certified_checkpoint.verify(committee, None)?;
        Ok(certified_checkpoint)
    }

    pub fn signatory_authorities<'a>(
        &'a self,
        committee: &'a Committee,
    ) -> impl Iterator<Item = SuiResult<&AuthorityName>> {
        self.auth_signature.authorities(committee)
    }

    /// Check that a certificate is valid, and signed by a quorum of authorities
    pub fn verify(
        &self,
        committee: &Committee,
        contents: Option<&CheckpointContents>,
    ) -> Result<(), SuiError> {
        fp_ensure!(
            self.summary.epoch == committee.epoch,
            SuiError::from("Epoch in the summary doesn't match with the committee")
        );
        let mut obligation = VerificationObligation::default();
        let idx = obligation.add_message(
            &self.summary,
            self.auth_signature.epoch,
            Intent::default().with_scope(IntentScope::CheckpointSummary),
        );
        self.auth_signature
            .add_to_verification_obligation(committee, &mut obligation, idx)?;

        obligation.verify_all()?;

        if let Some(contents) = contents {
            let content_digest = contents.digest();
            fp_ensure!(
                content_digest == self.summary.content_digest,
                SuiError::GenericAuthorityError{error:format!("Checkpoint contents digest mismatch: summary={:?}, content digest = {:?}, transactions {}", self.summary, content_digest, contents.size())}
            );
        }

        Ok(())
    }
}

/// A type-safe way to ensure that a checkpoint has been verified
#[derive(Clone, Debug)]
pub struct VerifiedCheckpoint(CertifiedCheckpointSummary);

// The only acceptable way to construct this type is via explicitly verifying it
static_assertions::assert_not_impl_any!(VerifiedCheckpoint: Serialize, DeserializeOwned);

impl VerifiedCheckpoint {
    pub fn new(
        checkpoint: CertifiedCheckpointSummary,
        committee: &Committee,
    ) -> Result<Self, (CertifiedCheckpointSummary, SuiError)> {
        match checkpoint.verify(committee, None) {
            Ok(()) => Ok(Self(checkpoint)),
            Err(err) => Err((checkpoint, err)),
        }
    }

    pub fn new_unchecked(checkpoint: CertifiedCheckpointSummary) -> Self {
        Self(checkpoint)
    }

    pub fn inner(&self) -> &CertifiedCheckpointSummary {
        &self.0
    }

    pub fn into_inner(self) -> CertifiedCheckpointSummary {
        self.0
    }

    pub fn into_summary_and_sequence(self) -> (CheckpointSequenceNumber, CheckpointSummary) {
        (self.summary.sequence_number, self.0.summary)
    }
}

impl std::ops::Deref for VerifiedCheckpoint {
    type Target = CertifiedCheckpointSummary;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// This is a message validators publish to consensus in order to sign checkpoint
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointSignatureMessage {
    pub summary: SignedCheckpointSummary,
}

/// CheckpointContents are the transactions included in an upcoming checkpoint.
/// They must have already been causally ordered. Since the causal order algorithm
/// is the same among validators, we expect all honest validators to come up with
/// the same order for each checkpoint content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CheckpointContents {
    transactions: Vec<ExecutionDigests>,
    /// This field 'pins' user signatures for the checkpoint
    /// The length of this vector is same as length of transactions vector
    /// System transactions has empty signatures
    user_signatures: Vec<Vec<GenericSignature>>,
}

impl CheckpointSignatureMessage {
    pub fn verify(&self, committee: &Committee) -> SuiResult {
        self.summary.verify(committee, None)
    }
}

impl CheckpointContents {
    pub fn new_with_causally_ordered_transactions<T>(contents: T) -> Self
    where
        T: IntoIterator<Item = ExecutionDigests>,
    {
        let transactions: Vec<_> = contents.into_iter().collect();
        let user_signatures = transactions.iter().map(|_| vec![]).collect();
        Self {
            transactions,
            user_signatures,
        }
    }

    pub fn new_with_causally_ordered_transactions_and_signatures<T>(
        contents: T,
        user_signatures: Vec<Vec<GenericSignature>>,
    ) -> Self
    where
        T: IntoIterator<Item = ExecutionDigests>,
    {
        let transactions: Vec<_> = contents.into_iter().collect();
        assert_eq!(transactions.len(), user_signatures.len());
        Self {
            transactions,
            user_signatures,
        }
    }

    pub fn iter(&self) -> Iter<'_, ExecutionDigests> {
        self.transactions.iter()
    }

    /// Return an iterator that enumerates the transactions in the contents.
    /// The iterator item is a tuple of (sequence_number, &ExecutionDigests),
    /// where the sequence_number indicates the index of the transaction in the
    /// global ordering of executed transactions since genesis.
    pub fn enumerate_transactions(
        &self,
        ckpt: &CheckpointSummary,
    ) -> impl Iterator<Item = (u64, &ExecutionDigests)> {
        let start = ckpt.network_total_transactions - self.size() as u64;

        (0u64..)
            .zip(self.iter())
            .map(move |(i, digests)| (i + start, digests))
    }

    pub fn into_inner(self) -> Vec<ExecutionDigests> {
        self.transactions
    }

    pub fn size(&self) -> usize {
        self.transactions.len()
    }

    pub fn digest(&self) -> CheckpointContentsDigest {
        CheckpointContentsDigest::new(sha3_hash(self))
    }
}

#[cfg(test)]
mod tests {
    use fastcrypto::traits::KeyPair;
    use rand::prelude::StdRng;
    use rand::SeedableRng;

    use super::*;
    use crate::utils::make_committee_key;

    // TODO use the file name as a seed
    const RNG_SEED: [u8; 32] = [
        21, 23, 199, 200, 234, 250, 252, 178, 94, 15, 202, 178, 62, 186, 88, 137, 233, 192, 130,
        157, 179, 179, 65, 9, 31, 249, 221, 123, 225, 112, 199, 247,
    ];

    #[test]
    fn test_signed_checkpoint() {
        let mut rng = StdRng::from_seed(RNG_SEED);
        let (keys, committee) = make_committee_key(&mut rng);
        let (_, committee2) = make_committee_key(&mut rng);

        let set = CheckpointContents::new_with_causally_ordered_transactions(
            [ExecutionDigests::random()].into_iter(),
        );

        // TODO: duplicated in a test below.
        let signed_checkpoints: Vec<_> = keys
            .iter()
            .map(|k| {
                let name = k.public().into();

                SignedCheckpointSummary::new(
                    committee.epoch,
                    1,
                    0,
                    name,
                    k,
                    &set,
                    None,
                    GasCostSummary::default(),
                    None,
                    0,
                )
            })
            .collect();

        signed_checkpoints
            .iter()
            .for_each(|c| c.verify(&committee, None).expect("signature ok"));

        // fails when not signed by member of committee
        signed_checkpoints
            .iter()
            .for_each(|c| assert!(c.verify(&committee2, None).is_err()));
    }

    #[test]
    fn test_certified_checkpoint() {
        let mut rng = StdRng::from_seed(RNG_SEED);
        let (keys, committee) = make_committee_key(&mut rng);

        let set = CheckpointContents::new_with_causally_ordered_transactions(
            [ExecutionDigests::random()].into_iter(),
        );

        let signed_checkpoints: Vec<_> = keys
            .iter()
            .map(|k| {
                let name = k.public().into();

                SignedCheckpointSummary::new(
                    committee.epoch,
                    1,
                    0,
                    name,
                    k,
                    &set,
                    None,
                    GasCostSummary::default(),
                    None,
                    0,
                )
            })
            .collect();

        let checkpoint_cert = CertifiedCheckpointSummary::aggregate(signed_checkpoints, &committee)
            .expect("Cert is OK");

        // Signature is correct on proposal, and with same transactions
        assert!(checkpoint_cert.verify(&committee, Some(&set)).is_ok());

        // Make a bad proposal
        let signed_checkpoints: Vec<_> = keys
            .iter()
            .map(|k| {
                let name = k.public().into();
                let set = CheckpointContents::new_with_causally_ordered_transactions(
                    [ExecutionDigests::random()].into_iter(),
                );

                SignedCheckpointSummary::new(
                    committee.epoch,
                    1,
                    0,
                    name,
                    k,
                    &set,
                    None,
                    GasCostSummary::default(),
                    None,
                    0,
                )
            })
            .collect();

        assert!(CertifiedCheckpointSummary::aggregate(signed_checkpoints, &committee).is_err());
    }
}
