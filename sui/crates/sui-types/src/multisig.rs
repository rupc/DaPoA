// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    crypto::{CompressedSignature, SignatureScheme},
    signature::AuthenticatorTrait,
    sui_serde::SuiBitmap,
};
pub use enum_dispatch::enum_dispatch;
use fastcrypto::{
    ed25519::Ed25519PublicKey,
    encoding::Base64,
    error::FastCryptoError,
    secp256k1::Secp256k1PublicKey,
    secp256r1::Secp256r1PublicKey,
    traits::{ToFromBytes, VerifyingKey},
};
use once_cell::sync::OnceCell;
use roaring::RoaringBitmap;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::hash::{Hash, Hasher};

use crate::{
    base_types::SuiAddress,
    crypto::{PublicKey, Signature},
    error::SuiError,
    intent::IntentMessage,
};

#[cfg(test)]
#[path = "unit_tests/multisig_tests.rs"]
mod multisig_tests;

pub type WeightUnit = u8;
pub type ThresholdUnit = u16;
pub const MAX_SIGNER_IN_MULTISIG: usize = 10;

/// This initialize the underlying bytes representation of MultiSig. It encodes
/// [struct MultiSig] as the MultiSig flag (0x03) concat with the bcs bytes
/// of [struct MultiSig] i.e. `flag || bcs_bytes(MultiSig)`.
impl AsRef<[u8]> for MultiSig {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| {
                let mut bytes = Vec::new();
                bytes.push(SignatureScheme::MultiSig.flag());
                bytes.extend_from_slice(
                    bcs::to_bytes(self)
                        .expect("BCS serialization should not fail")
                        .as_slice(),
                );
                Ok(bytes)
            })
            .expect("OnceCell invariant violated")
    }
}

/// The struct that contains signatures and public keys necessary for authenticating a MultiSig.
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, JsonSchema)]
pub struct MultiSig {
    /// The plain signature encoded with signature scheme.
    sigs: Vec<CompressedSignature>,
    /// A bitmap that indicates the position of which public key the signature should be authenticated with.
    #[schemars(with = "Base64")]
    #[serde_as(as = "SuiBitmap")]
    bitmap: RoaringBitmap,
    /// The public key encoded with each public key with its signature scheme used along with the corresponding weight.
    pub multisig_pk: MultiSigPublicKey,
    /// A bytes representation of [struct MultiSig]. This helps with implementing [trait AsRef<[u8]>].
    #[serde(skip)]
    bytes: OnceCell<Vec<u8>>,
}

/// Necessary trait for [struct SenderSignedData].
impl PartialEq for MultiSig {
    fn eq(&self, other: &Self) -> bool {
        self.sigs == other.sigs
            && self.bitmap == other.bitmap
            && self.multisig_pk == other.multisig_pk
    }
}

/// Necessary trait for [struct SenderSignedData].
impl Eq for MultiSig {}

/// Necessary trait for [struct SenderSignedData].
impl Hash for MultiSig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl AuthenticatorTrait for MultiSig {
    fn verify_secure_generic<T>(
        &self,
        value: &IntentMessage<T>,
        author: SuiAddress,
    ) -> Result<(), SuiError>
    where
        T: Serialize,
    {
        if self.multisig_pk.pk_map.len() > MAX_SIGNER_IN_MULTISIG {
            return Err(SuiError::InvalidSignature {
                error: "Invalid number of public keys".to_string(),
            });
        }

        if <SuiAddress as From<MultiSigPublicKey>>::from(self.multisig_pk.clone()) != author {
            return Err(SuiError::InvalidSignature {
                error: "Invalid address".to_string(),
            });
        }
        let mut weight_sum: u16 = 0;
        let message = bcs::to_bytes(&value).expect("Message serialization should not fail");

        // Verify each signature against its corresponding signature scheme and public key.
        // TODO: further optimization can be done because multiple Ed25519 signatures can be batch verified.
        for (sig, i) in self.sigs.iter().zip(&self.bitmap) {
            let pk_map =
                self.multisig_pk
                    .pk_map
                    .get(i as usize)
                    .ok_or(SuiError::InvalidSignature {
                        error: "Invalid public keys index".to_string(),
                    })?;
            let res = match sig {
                CompressedSignature::Ed25519(s) => {
                    let pk = Ed25519PublicKey::from_bytes(pk_map.0.as_ref()).map_err(|_| {
                        SuiError::InvalidSignature {
                            error: "Invalid public key".to_string(),
                        }
                    })?;
                    pk.verify(&message, &s.try_into()?)
                }
                CompressedSignature::Secp256k1(s) => {
                    let pk = Secp256k1PublicKey::from_bytes(pk_map.0.as_ref()).map_err(|_| {
                        SuiError::InvalidSignature {
                            error: "Invalid public key".to_string(),
                        }
                    })?;
                    pk.verify(&message, &s.try_into()?)
                }
                CompressedSignature::Secp256r1(s) => {
                    let pk = Secp256r1PublicKey::from_bytes(pk_map.0.as_ref()).map_err(|_| {
                        SuiError::InvalidSignature {
                            error: "Invalid public key".to_string(),
                        }
                    })?;
                    pk.verify(&message, &s.try_into()?)
                }
            };
            if res.is_ok() {
                weight_sum += pk_map.1 as u16;
            } else {
                return Err(SuiError::InvalidSignature {
                    error: format!("Invalid signature for pk={:?}", pk_map.0),
                });
            }
        }

        if weight_sum >= self.multisig_pk.threshold {
            Ok(())
        } else {
            Err(SuiError::InvalidSignature {
                error: format!("Insufficient weight {:?}", weight_sum),
            })
        }
    }
}

impl MultiSig {
    /// This combines a list of [enum Signature] `flag || signature || pk` to a MultiSig.
    pub fn combine(
        full_sigs: Vec<Signature>,
        multisig_pk: MultiSigPublicKey,
    ) -> Result<Self, SuiError> {
        if full_sigs.len() > multisig_pk.pk_map.len()
            || multisig_pk.pk_map.len() > MAX_SIGNER_IN_MULTISIG
            || full_sigs.is_empty()
            || multisig_pk.pk_map.is_empty()
        {
            return Err(SuiError::InvalidSignature {
                error: "Invalid number of signatures".to_string(),
            });
        }
        let mut bitmap = RoaringBitmap::new();
        let mut sigs = Vec::new();
        for s in full_sigs {
            bitmap.insert(multisig_pk.get_index(s.to_public_key()?).ok_or(
                SuiError::IncorrectSigner {
                    error: "pk does not exist".to_string(),
                },
            )?);
            sigs.push(s.to_compressed()?);
        }
        Ok(MultiSig {
            sigs,
            bitmap,
            multisig_pk,
            bytes: OnceCell::new(),
        })
    }

    pub fn validate(&self) -> Result<(), FastCryptoError> {
        if self.sigs.len() > self.multisig_pk.pk_map.len() || self.sigs.is_empty() {
            return Err(FastCryptoError::InvalidInput);
        }
        self.multisig_pk.validate()?;
        Ok(())
    }
}

/// The struct that contains the public key used for authenticating a MultiSig.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MultiSigPublicKey {
    /// A list of public key and its corresponding weight.
    pk_map: Vec<(PublicKey, WeightUnit)>,
    /// If the total weight of the public keys corresponding to verified signatures is larger than threshold, the MultiSig is verified.
    threshold: ThresholdUnit,
}

impl MultiSigPublicKey {
    pub fn new(
        pks: Vec<PublicKey>,
        weights: Vec<WeightUnit>,
        threshold: ThresholdUnit,
    ) -> Result<Self, SuiError> {
        if pks.is_empty()
            || weights.is_empty()
            || threshold == 0
            || pks.len() != weights.len()
            || pks.len() > MAX_SIGNER_IN_MULTISIG
            || weights.iter().any(|w| w == &0)
        {
            return Err(SuiError::InvalidSignature {
                error: "Invalid number of public keys".to_string(),
            });
        }
        Ok(MultiSigPublicKey {
            pk_map: pks.into_iter().zip(weights.into_iter()).collect(),
            threshold,
        })
    }

    pub fn get_index(&self, pk: PublicKey) -> Option<u32> {
        self.pk_map.iter().position(|x| x.0 == pk).map(|x| x as u32)
    }

    pub fn threshold(&self) -> &ThresholdUnit {
        &self.threshold
    }

    pub fn pubkeys(&self) -> &Vec<(PublicKey, WeightUnit)> {
        &self.pk_map
    }

    pub fn validate(&self) -> Result<(), FastCryptoError> {
        if self.threshold == 0
            || self.pubkeys().is_empty()
            || self.pubkeys().len() > MAX_SIGNER_IN_MULTISIG
            || self.pubkeys().iter().any(|pk_weight| pk_weight.1 == 0)
        {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(())
    }
}
