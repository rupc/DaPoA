// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// This file contain response types used by RPC, most of the types mirrors it's internal type counterparts.
/// These mirrored types allow us to optimise the JSON serde without impacting the internal types, which are optimise for storage.
///
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fmt::Write;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use colored::Colorize;
use fastcrypto::encoding::{Base64, Encoding, Hex};
use itertools::Itertools;
use move_binary_format::file_format::{Ability, AbilitySet, StructTypeParameter, Visibility};
use move_binary_format::normalized::{
    Field as NormalizedField, Function as SuiNormalizedFunction, Module as NormalizedModule,
    Struct as NormalizedStruct, Type as NormalizedType,
};
use move_bytecode_utils::module_cache::GetModule;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::{StructTag, TypeTag};
use move_core_types::value::{MoveStruct, MoveStructLayout, MoveValue};
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use serde_json::{json, Value};
use serde_with::serde_as;
use sui_json::SuiJsonValue;
use sui_protocol_config::ProtocolConfig;
use sui_types::base_types::{
    ObjectDigest, ObjectID, ObjectInfo, ObjectRef, SequenceNumber, SuiAddress, TransactionDigest,
    TransactionEffectsDigest,
};
use sui_types::coin::CoinMetadata;
use sui_types::committee::EpochId;
use sui_types::crypto::SuiAuthorityStrongQuorumSignInfo;
use sui_types::digests::TransactionEventsDigest;
use sui_types::dynamic_field::DynamicFieldInfo;
use sui_types::error::{ExecutionError, SuiError, UserInputError, UserInputResult};
use sui_types::event::{BalanceChangeType, Event, EventID};
use sui_types::event::{EventEnvelope, EventType};
use sui_types::filter::EventFilter;
use sui_types::gas::GasCostSummary;
use sui_types::gas_coin::GasCoin;
use sui_types::messages::{
    CallArg, EffectsFinalityInfo, ExecutionStatus, GenesisObject, InputObjectKind,
    MoveModulePublish, ObjectArg, Pay, PayAllSui, PaySui, SenderSignedData, SingleTransactionKind,
    TransactionData, TransactionEffects, TransactionEvents, TransactionKind,
};
use sui_types::messages_checkpoint::{
    CheckpointContents, CheckpointDigest, CheckpointSequenceNumber, CheckpointSummary,
    CheckpointTimestamp, EndOfEpochData,
};
use sui_types::move_package::{disassemble_modules, MovePackage};
use sui_types::object::{
    Data, MoveObject, Object, ObjectFormatOptions, ObjectRead, Owner, PastObjectRead,
};
use sui_types::signature::GenericSignature;
use sui_types::{parse_sui_struct_tag, parse_sui_type_tag};
use tracing::warn;

#[cfg(test)]
#[path = "unit_tests/rpc_types_tests.rs"]
mod rpc_types_tests;

pub type SuiMoveTypeParameterIndex = u16;
pub type TransactionsPage = Page<TransactionDigest, TransactionDigest>;
pub type EventPage = Page<SuiEventEnvelope, EventID>;
pub type CoinPage = Page<Coin, ObjectID>;
pub type DynamicFieldPage = Page<DynamicFieldInfo, ObjectID>;

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Balance {
    pub coin_type: String,
    pub coin_object_count: usize,
    pub total_balance: u128,
    pub locked_balance: HashMap<EpochId, u128>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Coin {
    pub coin_type: String,
    pub coin_object_id: ObjectID,
    pub version: SequenceNumber,
    pub digest: ObjectDigest,
    pub balance: u64,
    pub locked_until_epoch: Option<EpochId>,
    pub previous_transaction: TransactionDigest,
}

impl Coin {
    pub fn object_ref(&self) -> ObjectRef {
        (self.coin_object_id, self.version, self.digest)
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub enum SuiMoveAbility {
    Copy,
    Drop,
    Store,
    Key,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct SuiMoveAbilitySet {
    pub abilities: Vec<SuiMoveAbility>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub enum SuiMoveVisibility {
    Private,
    Public,
    Friend,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct SuiMoveStructTypeParameter {
    pub constraints: SuiMoveAbilitySet,
    pub is_phantom: bool,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct SuiMoveNormalizedField {
    pub name: String,
    pub type_: SuiMoveNormalizedType,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct SuiMoveNormalizedStruct {
    pub abilities: SuiMoveAbilitySet,
    pub type_parameters: Vec<SuiMoveStructTypeParameter>,
    pub fields: Vec<SuiMoveNormalizedField>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub enum SuiMoveNormalizedType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    Address,
    Signer,
    Struct {
        address: String,
        module: String,
        name: String,
        type_arguments: Vec<SuiMoveNormalizedType>,
    },
    Vector(Box<SuiMoveNormalizedType>),
    TypeParameter(SuiMoveTypeParameterIndex),
    Reference(Box<SuiMoveNormalizedType>),
    MutableReference(Box<SuiMoveNormalizedType>),
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct SuiMoveNormalizedFunction {
    pub visibility: SuiMoveVisibility,
    pub is_entry: bool,
    pub type_parameters: Vec<SuiMoveAbilitySet>,
    pub parameters: Vec<SuiMoveNormalizedType>,
    pub return_: Vec<SuiMoveNormalizedType>,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct SuiMoveModuleId {
    address: String,
    name: String,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct SuiMoveNormalizedModule {
    pub file_format_version: u32,
    pub address: String,
    pub name: String,
    pub friends: Vec<SuiMoveModuleId>,
    pub structs: BTreeMap<String, SuiMoveNormalizedStruct>,
    pub exposed_functions: BTreeMap<String, SuiMoveNormalizedFunction>,
}

impl From<NormalizedModule> for SuiMoveNormalizedModule {
    fn from(module: NormalizedModule) -> Self {
        Self {
            file_format_version: module.file_format_version,
            address: module.address.to_hex_literal(),
            name: module.name.to_string(),
            friends: module
                .friends
                .into_iter()
                .map(|module_id| SuiMoveModuleId {
                    address: module_id.address().to_hex_literal(),
                    name: module_id.name().to_string(),
                })
                .collect::<Vec<SuiMoveModuleId>>(),
            structs: module
                .structs
                .into_iter()
                .map(|(name, struct_)| (name.to_string(), SuiMoveNormalizedStruct::from(struct_)))
                .collect::<BTreeMap<String, SuiMoveNormalizedStruct>>(),
            exposed_functions: module
                .exposed_functions
                .into_iter()
                .map(|(name, function)| {
                    (name.to_string(), SuiMoveNormalizedFunction::from(function))
                })
                .collect::<BTreeMap<String, SuiMoveNormalizedFunction>>(),
        }
    }
}

impl From<SuiNormalizedFunction> for SuiMoveNormalizedFunction {
    fn from(function: SuiNormalizedFunction) -> Self {
        Self {
            visibility: match function.visibility {
                Visibility::Private => SuiMoveVisibility::Private,
                Visibility::Public => SuiMoveVisibility::Public,
                Visibility::Friend => SuiMoveVisibility::Friend,
            },
            is_entry: function.is_entry,
            type_parameters: function
                .type_parameters
                .into_iter()
                .map(|a| a.into())
                .collect::<Vec<SuiMoveAbilitySet>>(),
            parameters: function
                .parameters
                .into_iter()
                .map(SuiMoveNormalizedType::from)
                .collect::<Vec<SuiMoveNormalizedType>>(),
            return_: function
                .return_
                .into_iter()
                .map(SuiMoveNormalizedType::from)
                .collect::<Vec<SuiMoveNormalizedType>>(),
        }
    }
}

impl From<NormalizedStruct> for SuiMoveNormalizedStruct {
    fn from(struct_: NormalizedStruct) -> Self {
        Self {
            abilities: struct_.abilities.into(),
            type_parameters: struct_
                .type_parameters
                .into_iter()
                .map(SuiMoveStructTypeParameter::from)
                .collect::<Vec<SuiMoveStructTypeParameter>>(),
            fields: struct_
                .fields
                .into_iter()
                .map(SuiMoveNormalizedField::from)
                .collect::<Vec<SuiMoveNormalizedField>>(),
        }
    }
}

impl From<StructTypeParameter> for SuiMoveStructTypeParameter {
    fn from(type_parameter: StructTypeParameter) -> Self {
        Self {
            constraints: type_parameter.constraints.into(),
            is_phantom: type_parameter.is_phantom,
        }
    }
}

impl From<NormalizedField> for SuiMoveNormalizedField {
    fn from(normalized_field: NormalizedField) -> Self {
        Self {
            name: normalized_field.name.to_string(),
            type_: SuiMoveNormalizedType::from(normalized_field.type_),
        }
    }
}

impl From<NormalizedType> for SuiMoveNormalizedType {
    fn from(type_: NormalizedType) -> Self {
        match type_ {
            NormalizedType::Bool => SuiMoveNormalizedType::Bool,
            NormalizedType::U8 => SuiMoveNormalizedType::U8,
            NormalizedType::U16 => SuiMoveNormalizedType::U16,
            NormalizedType::U32 => SuiMoveNormalizedType::U32,
            NormalizedType::U64 => SuiMoveNormalizedType::U64,
            NormalizedType::U128 => SuiMoveNormalizedType::U128,
            NormalizedType::U256 => SuiMoveNormalizedType::U256,
            NormalizedType::Address => SuiMoveNormalizedType::Address,
            NormalizedType::Signer => SuiMoveNormalizedType::Signer,
            NormalizedType::Struct {
                address,
                module,
                name,
                type_arguments,
            } => SuiMoveNormalizedType::Struct {
                address: address.to_hex_literal(),
                module: module.to_string(),
                name: name.to_string(),
                type_arguments: type_arguments
                    .into_iter()
                    .map(SuiMoveNormalizedType::from)
                    .collect::<Vec<SuiMoveNormalizedType>>(),
            },
            NormalizedType::Vector(v) => {
                SuiMoveNormalizedType::Vector(Box::new(SuiMoveNormalizedType::from(*v)))
            }
            NormalizedType::TypeParameter(t) => SuiMoveNormalizedType::TypeParameter(t),
            NormalizedType::Reference(r) => {
                SuiMoveNormalizedType::Reference(Box::new(SuiMoveNormalizedType::from(*r)))
            }
            NormalizedType::MutableReference(mr) => {
                SuiMoveNormalizedType::MutableReference(Box::new(SuiMoveNormalizedType::from(*mr)))
            }
        }
    }
}

impl From<AbilitySet> for SuiMoveAbilitySet {
    fn from(set: AbilitySet) -> SuiMoveAbilitySet {
        Self {
            abilities: set
                .into_iter()
                .map(|a| match a {
                    Ability::Copy => SuiMoveAbility::Copy,
                    Ability::Drop => SuiMoveAbility::Drop,
                    Ability::Key => SuiMoveAbility::Key,
                    Ability::Store => SuiMoveAbility::Store,
                })
                .collect::<Vec<SuiMoveAbility>>(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub enum ObjectValueKind {
    ByImmutableReference,
    ByMutableReference,
    ByValue,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub enum MoveFunctionArgType {
    Pure,
    Object(ObjectValueKind),
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SuiTransactionResponse {
    pub transaction: SuiTransaction,
    pub effects: SuiTransactionEffects,
    pub events: SuiTransactionEvents,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_local_execution: Option<bool>,
    /// The checkpoint number when this transaction was included and hence finalized.
    /// This is only returned in the read api, not in the transaction execution api.
    pub checkpoint: Option<CheckpointSequenceNumber>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub enum SuiTBlsSignObjectCommitmentType {
    /// Check that the object is committed by the consensus.
    ConsensusCommitted,
    /// Check that the object is committed using the effects certificate.
    FastPathCommitted(SuiFinalizedEffects),
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
pub struct SuiTBlsSignRandomnessObjectResponse {
    pub signature: fastcrypto_tbls::types::RawSignature,
}

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SuiCoinMetadata {
    /// Number of decimal places the coin uses.
    pub decimals: u8,
    /// Name for the token
    pub name: String,
    /// Symbol for the token
    pub symbol: String,
    /// Description of the token
    pub description: String,
    /// URL for the token logo
    pub icon_url: Option<String>,
    /// Object id for the CoinMetadata object
    pub id: Option<ObjectID>,
}

impl TryFrom<Object> for SuiCoinMetadata {
    type Error = SuiError;
    fn try_from(object: Object) -> Result<Self, Self::Error> {
        let metadata: CoinMetadata = object.try_into()?;
        let CoinMetadata {
            decimals,
            name,
            symbol,
            description,
            icon_url,
            id,
        } = metadata;
        Ok(Self {
            id: Some(*id.object_id()),
            decimals,
            name,
            symbol,
            description,
            icon_url,
        })
    }
}

pub type SuiRawObject = SuiObject<SuiRawData>;
pub type SuiParsedObject = SuiObject<SuiParsedData>;

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Eq, PartialEq)]
#[serde(rename_all = "camelCase", rename = "Object")]
pub struct SuiObject<T: SuiData> {
    /// The meat of the object
    pub data: T,
    /// The owner that unlocks this object
    pub owner: Owner,
    /// The digest of the transaction that created or last mutated this object
    pub previous_transaction: TransactionDigest,
    /// The amount of SUI we would rebate if this object gets deleted.
    /// This number is re-calculated each time the object is mutated based on
    /// the present storage gas price.
    pub storage_rebate: u64,
    pub reference: SuiObjectRef,
}

impl TryInto<Object> for SuiObject<SuiRawData> {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Object, Self::Error> {
        let protocol_config = ProtocolConfig::get_for_min_version();
        let data = match self.data {
            SuiRawData::MoveObject(o) => {
                let struct_tag = parse_sui_struct_tag(o.type_())?;
                Data::Move(unsafe {
                    MoveObject::new_from_execution(
                        struct_tag,
                        o.has_public_transfer,
                        o.version,
                        o.bcs_bytes,
                        &protocol_config,
                    )?
                })
            }
            SuiRawData::Package(p) => Data::Package(MovePackage::new(
                p.id,
                self.reference.version,
                &p.module_map,
                protocol_config.max_move_package_size(),
            )?),
        };
        Ok(Object {
            data,
            owner: self.owner,
            previous_transaction: self.previous_transaction,
            storage_rebate: self.storage_rebate,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase", rename = "ObjectRef")]
pub struct SuiObjectRef {
    /// Hex code as string representing the object id
    pub object_id: ObjectID,
    /// Object version.
    pub version: SequenceNumber,
    /// Base64 string representing the object digest
    pub digest: ObjectDigest,
}

impl SuiObjectRef {
    pub fn to_object_ref(&self) -> ObjectRef {
        (self.object_id, self.version, self.digest)
    }
}

impl Display for SuiObjectRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Object ID: {}, version: {}, digest: {}",
            self.object_id, self.version, self.digest
        )
    }
}

impl From<ObjectRef> for SuiObjectRef {
    fn from(oref: ObjectRef) -> Self {
        Self {
            object_id: oref.0,
            version: oref.1,
            digest: oref.2,
        }
    }
}

impl Display for SuiParsedObject {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let type_ = if self.data.type_().is_some() {
            "Move Object"
        } else {
            "Move Package"
        };
        let mut writer = String::new();
        writeln!(
            writer,
            "{}",
            format!(
                "----- {type_} ({}[{}]) -----",
                self.id(),
                self.version().value()
            )
            .bold()
        )?;
        writeln!(writer, "{}: {}", "Owner".bold().bright_black(), self.owner)?;
        writeln!(
            writer,
            "{}: {}",
            "Version".bold().bright_black(),
            self.version().value()
        )?;
        writeln!(
            writer,
            "{}: {}",
            "Storage Rebate".bold().bright_black(),
            self.storage_rebate
        )?;
        writeln!(
            writer,
            "{}: {:?}",
            "Previous Transaction".bold().bright_black(),
            self.previous_transaction
        )?;
        writeln!(writer, "{}", "----- Data -----".bold())?;
        write!(writer, "{}", &self.data)?;
        write!(f, "{}", writer)
    }
}

impl<T: SuiData> SuiObject<T> {
    pub fn id(&self) -> ObjectID {
        self.reference.object_id
    }
    pub fn version(&self) -> SequenceNumber {
        self.reference.version
    }

    pub fn try_from(o: Object, layout: Option<MoveStructLayout>) -> Result<Self, anyhow::Error> {
        let oref = o.compute_object_reference();
        let data = match o.data {
            Data::Move(m) => {
                let layout = layout.ok_or(SuiError::ObjectSerializationError {
                    error: "Layout is required to convert Move object to json".to_owned(),
                })?;
                T::try_from_object(m, layout)?
            }
            Data::Package(p) => T::try_from_package(p)?,
        };
        Ok(Self {
            data,
            owner: o.owner,
            previous_transaction: o.previous_transaction,
            storage_rebate: o.storage_rebate,
            reference: oref.into(),
        })
    }
}

pub trait SuiData: Sized {
    type ObjectType;
    type PackageType;
    fn try_from_object(object: MoveObject, layout: MoveStructLayout)
        -> Result<Self, anyhow::Error>;
    fn try_from_package(package: MovePackage) -> Result<Self, anyhow::Error>;
    fn try_as_move(&self) -> Option<&Self::ObjectType>;
    fn try_as_package(&self) -> Option<&Self::PackageType>;
    fn type_(&self) -> Option<&str>;
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq)]
#[serde(tag = "dataType", rename_all = "camelCase", rename = "RawData")]
pub enum SuiRawData {
    // Manually handle generic schema generation
    MoveObject(SuiRawMoveObject),
    Package(SuiRawMovePackage),
}

impl SuiData for SuiRawData {
    type ObjectType = SuiRawMoveObject;
    type PackageType = SuiRawMovePackage;

    fn try_from_object(object: MoveObject, _: MoveStructLayout) -> Result<Self, anyhow::Error> {
        Ok(Self::MoveObject(object.into()))
    }

    fn try_from_package(package: MovePackage) -> Result<Self, anyhow::Error> {
        Ok(Self::Package(package.into()))
    }

    fn try_as_move(&self) -> Option<&Self::ObjectType> {
        match self {
            Self::MoveObject(o) => Some(o),
            Self::Package(_) => None,
        }
    }

    fn try_as_package(&self) -> Option<&Self::PackageType> {
        match self {
            Self::MoveObject(_) => None,
            Self::Package(p) => Some(p),
        }
    }

    fn type_(&self) -> Option<&str> {
        match self {
            Self::MoveObject(o) => Some(o.type_.as_ref()),
            Self::Package(_) => None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq)]
#[serde(tag = "dataType", rename_all = "camelCase", rename = "Data")]
pub enum SuiParsedData {
    // Manually handle generic schema generation
    MoveObject(SuiParsedMoveObject),
    Package(SuiMovePackage),
}

impl SuiData for SuiParsedData {
    type ObjectType = SuiParsedMoveObject;
    type PackageType = SuiMovePackage;

    fn try_from_object(
        object: MoveObject,
        layout: MoveStructLayout,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self::MoveObject(SuiParsedMoveObject::try_from_layout(
            object, layout,
        )?))
    }

    fn try_from_package(package: MovePackage) -> Result<Self, anyhow::Error> {
        Ok(Self::Package(SuiMovePackage {
            disassembled: package.disassemble()?,
        }))
    }

    fn try_as_move(&self) -> Option<&Self::ObjectType> {
        match self {
            Self::MoveObject(o) => Some(o),
            Self::Package(_) => None,
        }
    }

    fn try_as_package(&self) -> Option<&Self::PackageType> {
        match self {
            Self::MoveObject(_) => None,
            Self::Package(p) => Some(p),
        }
    }

    fn type_(&self) -> Option<&str> {
        match self {
            Self::MoveObject(o) => Some(&o.type_),
            Self::Package(_) => None,
        }
    }
}

impl Display for SuiParsedData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = String::new();
        match self {
            SuiParsedData::MoveObject(o) => {
                writeln!(writer, "{}: {}", "type".bold().bright_black(), o.type_)?;
                write!(writer, "{}", &o.fields)?;
            }
            SuiParsedData::Package(p) => {
                write!(
                    writer,
                    "{}: {:?}",
                    "Modules".bold().bright_black(),
                    p.disassembled.keys()
                )?;
            }
        }
        write!(f, "{}", writer)
    }
}

fn indent<T: Display>(d: &T, indent: usize) -> String {
    d.to_string()
        .lines()
        .map(|line| format!("{:indent$}{}", "", line))
        .join("\n")
}

pub trait SuiMoveObject: Sized {
    fn try_from_layout(object: MoveObject, layout: MoveStructLayout)
        -> Result<Self, anyhow::Error>;

    fn try_from(o: MoveObject, resolver: &impl GetModule) -> Result<Self, anyhow::Error> {
        let layout = o.get_layout(ObjectFormatOptions::default(), resolver)?;
        Self::try_from_layout(o, layout)
    }

    fn type_(&self) -> &str;
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq)]
#[serde(rename = "MoveObject")]
pub struct SuiParsedMoveObject {
    #[serde(rename = "type")]
    pub type_: String,
    pub has_public_transfer: bool,
    pub fields: SuiMoveStruct,
}

impl SuiMoveObject for SuiParsedMoveObject {
    fn try_from_layout(
        object: MoveObject,
        layout: MoveStructLayout,
    ) -> Result<Self, anyhow::Error> {
        let move_struct = object.to_move_struct(&layout)?.into();

        Ok(
            if let SuiMoveStruct::WithTypes { type_, fields } = move_struct {
                SuiParsedMoveObject {
                    type_,
                    has_public_transfer: object.has_public_transfer(),
                    fields: SuiMoveStruct::WithFields(fields),
                }
            } else {
                SuiParsedMoveObject {
                    type_: object.type_.to_string(),
                    has_public_transfer: object.has_public_transfer(),
                    fields: move_struct,
                }
            },
        )
    }

    fn type_(&self) -> &str {
        &self.type_
    }
}

pub fn type_and_fields_from_move_struct(
    type_: &StructTag,
    move_struct: MoveStruct,
) -> (String, SuiMoveStruct) {
    match move_struct.into() {
        SuiMoveStruct::WithTypes { type_, fields } => (type_, SuiMoveStruct::WithFields(fields)),
        fields => (type_.to_string(), fields),
    }
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq)]
#[serde(rename = "RawMoveObject")]
pub struct SuiRawMoveObject {
    #[serde(rename = "type")]
    pub type_: String,
    pub has_public_transfer: bool,
    pub version: SequenceNumber,
    #[serde_as(as = "Base64")]
    #[schemars(with = "Base64")]
    pub bcs_bytes: Vec<u8>,
}

impl From<MoveObject> for SuiRawMoveObject {
    fn from(o: MoveObject) -> Self {
        Self {
            type_: o.type_.to_string(),
            has_public_transfer: o.has_public_transfer(),
            version: o.version(),
            bcs_bytes: o.into_contents(),
        }
    }
}

impl SuiMoveObject for SuiRawMoveObject {
    fn try_from_layout(
        object: MoveObject,
        _layout: MoveStructLayout,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            type_: object.type_.to_string(),
            has_public_transfer: object.has_public_transfer(),
            version: object.version(),
            bcs_bytes: object.into_contents(),
        })
    }

    fn type_(&self) -> &str {
        &self.type_
    }
}

impl SuiRawMoveObject {
    pub fn deserialize<'a, T: Deserialize<'a>>(&'a self) -> Result<T, anyhow::Error> {
        Ok(bcs::from_bytes(self.bcs_bytes.as_slice())?)
    }
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq)]
#[serde(rename = "RawMovePackage")]
pub struct SuiRawMovePackage {
    pub id: ObjectID,
    #[schemars(with = "BTreeMap<String, Base64>")]
    #[serde_as(as = "BTreeMap<_, Base64>")]
    pub module_map: BTreeMap<String, Vec<u8>>,
}

impl From<MovePackage> for SuiRawMovePackage {
    fn from(p: MovePackage) -> Self {
        Self {
            id: p.id(),
            module_map: p.serialized_module_map().clone(),
        }
    }
}

impl TryFrom<&SuiParsedObject> for GasCoin {
    type Error = SuiError;
    fn try_from(object: &SuiParsedObject) -> Result<Self, Self::Error> {
        match &object.data {
            SuiParsedData::MoveObject(o) => {
                if GasCoin::type_().to_string() == o.type_ {
                    return GasCoin::try_from(&o.fields);
                }
            }
            SuiParsedData::Package(_) => {}
        }

        Err(SuiError::TypeError {
            error: format!(
                "Gas object type is not a gas coin: {:?}",
                object.data.type_()
            ),
        })
    }
}

impl TryFrom<&SuiMoveStruct> for GasCoin {
    type Error = SuiError;
    fn try_from(move_struct: &SuiMoveStruct) -> Result<Self, Self::Error> {
        match move_struct {
            SuiMoveStruct::WithFields(fields) | SuiMoveStruct::WithTypes { type_: _, fields } => {
                if let Some(SuiMoveValue::String(balance)) = fields.get("balance") {
                    if let Ok(balance) = balance.parse::<u64>() {
                        if let Some(SuiMoveValue::UID { id }) = fields.get("id") {
                            return Ok(GasCoin::new(*id, balance));
                        }
                    }
                }
            }
            _ => {}
        }
        Err(SuiError::TypeError {
            error: format!("Struct is not a gas coin: {move_struct:?}"),
        })
    }
}

pub type GetObjectDataResponse = SuiObjectRead<SuiParsedData>;
pub type GetRawObjectDataResponse = SuiObjectRead<SuiRawData>;

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(tag = "status", content = "details", rename = "ObjectRead")]
pub enum SuiObjectRead<T: SuiData> {
    Exists(SuiObject<T>),
    NotExists(ObjectID),
    Deleted(SuiObjectRef),
}

impl<T: SuiData> SuiObjectRead<T> {
    /// Returns a reference to the object if there is any, otherwise an Err if
    /// the object does not exist or is deleted.
    pub fn object(&self) -> UserInputResult<&SuiObject<T>> {
        match &self {
            Self::Deleted(oref) => Err(UserInputError::ObjectDeleted {
                object_ref: oref.to_object_ref(),
            }),
            Self::NotExists(id) => Err(UserInputError::ObjectNotFound {
                object_id: *id,
                version: None,
            }),
            Self::Exists(o) => Ok(o),
        }
    }

    /// Returns the object value if there is any, otherwise an Err if
    /// the object does not exist or is deleted.
    pub fn into_object(self) -> UserInputResult<SuiObject<T>> {
        match self {
            Self::Deleted(oref) => Err(UserInputError::ObjectDeleted {
                object_ref: oref.to_object_ref(),
            }),
            Self::NotExists(id) => Err(UserInputError::ObjectNotFound {
                object_id: id,
                version: None,
            }),
            Self::Exists(o) => Ok(o),
        }
    }
}

impl<T: SuiData> TryFrom<ObjectRead> for SuiObjectRead<T> {
    type Error = anyhow::Error;

    fn try_from(value: ObjectRead) -> Result<Self, Self::Error> {
        match value {
            ObjectRead::NotExists(id) => Ok(SuiObjectRead::NotExists(id)),
            ObjectRead::Exists(_, o, layout) => {
                Ok(SuiObjectRead::Exists(SuiObject::try_from(o, layout)?))
            }
            ObjectRead::Deleted(oref) => Ok(SuiObjectRead::Deleted(oref.into())),
        }
    }
}

pub type GetPastObjectDataResponse = SuiPastObjectRead<SuiParsedData>;

#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(tag = "status", content = "details", rename = "ObjectRead")]
pub enum SuiPastObjectRead<T: SuiData> {
    /// The object exists and is found with this version
    VersionFound(SuiObject<T>),
    /// The object does not exist
    ObjectNotExists(ObjectID),
    /// The object is found to be deleted with this version
    ObjectDeleted(SuiObjectRef),
    /// The object exists but not found with this version
    VersionNotFound(ObjectID, SequenceNumber),
    /// The asked object version is higher than the latest
    VersionTooHigh {
        object_id: ObjectID,
        asked_version: SequenceNumber,
        latest_version: SequenceNumber,
    },
}

impl<T: SuiData> SuiPastObjectRead<T> {
    /// Returns a reference to the object if there is any, otherwise an Err
    pub fn object(&self) -> UserInputResult<&SuiObject<T>> {
        match &self {
            Self::ObjectDeleted(oref) => Err(UserInputError::ObjectDeleted {
                object_ref: oref.to_object_ref(),
            }),
            Self::ObjectNotExists(id) => Err(UserInputError::ObjectNotFound {
                object_id: *id,
                version: None,
            }),
            Self::VersionFound(o) => Ok(o),
            Self::VersionNotFound(id, seq_num) => Err(UserInputError::ObjectNotFound {
                object_id: *id,
                version: Some(*seq_num),
            }),
            Self::VersionTooHigh {
                object_id,
                asked_version,
                latest_version,
            } => Err(UserInputError::ObjectSequenceNumberTooHigh {
                object_id: *object_id,
                asked_version: *asked_version,
                latest_version: *latest_version,
            }),
        }
    }

    /// Returns the object value if there is any, otherwise an Err
    pub fn into_object(self) -> UserInputResult<SuiObject<T>> {
        match self {
            Self::ObjectDeleted(oref) => Err(UserInputError::ObjectDeleted {
                object_ref: oref.to_object_ref(),
            }),
            Self::ObjectNotExists(id) => Err(UserInputError::ObjectNotFound {
                object_id: id,
                version: None,
            }),
            Self::VersionFound(o) => Ok(o),
            Self::VersionNotFound(object_id, version) => Err(UserInputError::ObjectNotFound {
                object_id,
                version: Some(version),
            }),
            Self::VersionTooHigh {
                object_id,
                asked_version,
                latest_version,
            } => Err(UserInputError::ObjectSequenceNumberTooHigh {
                object_id,
                asked_version,
                latest_version,
            }),
        }
    }
}

impl<T: SuiData> TryFrom<PastObjectRead> for SuiPastObjectRead<T> {
    type Error = anyhow::Error;

    fn try_from(value: PastObjectRead) -> Result<Self, Self::Error> {
        match value {
            PastObjectRead::ObjectNotExists(id) => Ok(SuiPastObjectRead::ObjectNotExists(id)),
            PastObjectRead::VersionFound(_, o, layout) => Ok(SuiPastObjectRead::VersionFound(
                SuiObject::try_from(o, layout)?,
            )),
            PastObjectRead::ObjectDeleted(oref) => {
                Ok(SuiPastObjectRead::ObjectDeleted(oref.into()))
            }
            PastObjectRead::VersionNotFound(id, seq_num) => {
                Ok(SuiPastObjectRead::VersionNotFound(id, seq_num))
            }
            PastObjectRead::VersionTooHigh {
                object_id,
                asked_version,
                latest_version,
            } => Ok(SuiPastObjectRead::VersionTooHigh {
                object_id,
                asked_version,
                latest_version,
            }),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq)]
#[serde(untagged, rename = "MoveValue")]
pub enum SuiMoveValue {
    Number(u64),
    Bool(bool),
    Address(SuiAddress),
    Vector(Vec<SuiMoveValue>),
    String(String),
    UID { id: ObjectID },
    Struct(SuiMoveStruct),
    Option(Box<Option<SuiMoveValue>>),
}

impl SuiMoveValue {
    /// Extract values from MoveValue without type information in json format
    pub fn to_json_value(self) -> Value {
        match self {
            SuiMoveValue::Struct(move_struct) => move_struct.to_json_value(),
            SuiMoveValue::Vector(values) => SuiMoveStruct::Runtime(values).to_json_value(),
            SuiMoveValue::Number(v) => json!(v),
            SuiMoveValue::Bool(v) => json!(v),
            SuiMoveValue::Address(v) => json!(v),
            SuiMoveValue::String(v) => json!(v),
            SuiMoveValue::UID { id } => json!({ "id": id }),
            SuiMoveValue::Option(v) => json!(v),
        }
    }
}

impl Display for SuiMoveValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = String::new();
        match self {
            SuiMoveValue::Number(value) => write!(writer, "{}", value)?,
            SuiMoveValue::Bool(value) => write!(writer, "{}", value)?,
            SuiMoveValue::Address(value) => write!(writer, "{}", value)?,
            SuiMoveValue::String(value) => write!(writer, "{}", value)?,
            SuiMoveValue::UID { id } => write!(writer, "{id}")?,
            SuiMoveValue::Struct(value) => write!(writer, "{}", value)?,
            SuiMoveValue::Option(value) => write!(writer, "{:?}", value)?,
            SuiMoveValue::Vector(vec) => {
                write!(
                    writer,
                    "{}",
                    vec.iter().map(|value| format!("{value}")).join(",\n")
                )?;
            }
        }
        write!(f, "{}", writer.trim_end_matches('\n'))
    }
}

impl From<MoveValue> for SuiMoveValue {
    fn from(value: MoveValue) -> Self {
        match value {
            MoveValue::U8(value) => SuiMoveValue::Number(value.into()),
            MoveValue::U16(value) => SuiMoveValue::Number(value.into()),
            MoveValue::U32(value) => SuiMoveValue::Number(value.into()),
            MoveValue::U64(value) => SuiMoveValue::String(format!("{value}")),
            MoveValue::U128(value) => SuiMoveValue::String(format!("{value}")),
            MoveValue::U256(value) => SuiMoveValue::String(format!("{value}")),
            MoveValue::Bool(value) => SuiMoveValue::Bool(value),
            MoveValue::Vector(values) => {
                SuiMoveValue::Vector(values.into_iter().map(|value| value.into()).collect())
            }
            MoveValue::Struct(value) => {
                // Best effort Sui core type conversion
                if let MoveStruct::WithTypes { type_, fields } = &value {
                    if let Some(value) = try_convert_type(type_, fields) {
                        return value;
                    }
                };
                SuiMoveValue::Struct(value.into())
            }
            MoveValue::Signer(value) | MoveValue::Address(value) => {
                SuiMoveValue::Address(SuiAddress::from(ObjectID::from(value)))
            }
        }
    }
}

fn to_bytearray(value: &[MoveValue]) -> Option<Vec<u8>> {
    if value.iter().all(|value| matches!(value, MoveValue::U8(_))) {
        let bytearray = value
            .iter()
            .flat_map(|value| {
                if let MoveValue::U8(u8) = value {
                    Some(*u8)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Some(bytearray)
    } else {
        None
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq)]
#[serde(untagged, rename = "MoveStruct")]
pub enum SuiMoveStruct {
    Runtime(Vec<SuiMoveValue>),
    WithTypes {
        #[serde(rename = "type")]
        type_: String,
        fields: BTreeMap<String, SuiMoveValue>,
    },
    WithFields(BTreeMap<String, SuiMoveValue>),
}

impl SuiMoveStruct {
    /// Extract values from MoveStruct without type information in json format
    pub fn to_json_value(self) -> Value {
        // Unwrap MoveStructs
        match self {
            SuiMoveStruct::Runtime(values) => {
                let values = values
                    .into_iter()
                    .map(|value| value.to_json_value())
                    .collect::<Vec<_>>();
                json!(values)
            }
            // We only care about values here, assuming struct type information is known at the client side.
            SuiMoveStruct::WithTypes { type_: _, fields } | SuiMoveStruct::WithFields(fields) => {
                let fields = fields
                    .into_iter()
                    .map(|(key, value)| (key, value.to_json_value()))
                    .collect::<BTreeMap<_, _>>();
                json!(fields)
            }
        }
    }
}

impl Display for SuiMoveStruct {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = String::new();
        match self {
            SuiMoveStruct::Runtime(_) => {}
            SuiMoveStruct::WithFields(fields) => {
                for (name, value) in fields {
                    writeln!(writer, "{}: {value}", name.bold().bright_black())?;
                }
            }
            SuiMoveStruct::WithTypes { type_, fields } => {
                writeln!(writer)?;
                writeln!(writer, "  {}: {type_}", "type".bold().bright_black())?;
                for (name, value) in fields {
                    let value = format!("{}", value);
                    let value = if value.starts_with('\n') {
                        indent(&value, 2)
                    } else {
                        value
                    };
                    writeln!(writer, "  {}: {value}", name.bold().bright_black())?;
                }
            }
        }
        write!(f, "{}", writer.trim_end_matches('\n'))
    }
}

fn try_convert_type(type_: &StructTag, fields: &[(Identifier, MoveValue)]) -> Option<SuiMoveValue> {
    let struct_name = format!(
        "0x{}::{}::{}",
        type_.address.short_str_lossless(),
        type_.module,
        type_.name
    );
    let mut values = fields
        .iter()
        .map(|(id, value)| (id.to_string(), value))
        .collect::<BTreeMap<_, _>>();
    match struct_name.as_str() {
        "0x1::string::String" | "0x1::ascii::String" => {
            if let Some(MoveValue::Vector(bytes)) = values.remove("bytes") {
                return to_bytearray(bytes)
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .map(SuiMoveValue::String);
            }
        }
        "0x2::url::Url" => {
            return values.remove("url").cloned().map(SuiMoveValue::from);
        }
        "0x2::object::ID" => {
            return values.remove("bytes").cloned().map(SuiMoveValue::from);
        }
        "0x2::object::UID" => {
            let id = values.remove("id").cloned().map(SuiMoveValue::from);
            if let Some(SuiMoveValue::Address(address)) = id {
                return Some(SuiMoveValue::UID {
                    id: ObjectID::from(address),
                });
            }
        }
        "0x2::balance::Balance" => {
            return values.remove("value").cloned().map(SuiMoveValue::from);
        }
        "0x1::option::Option" => {
            if let Some(MoveValue::Vector(values)) = values.remove("vec") {
                return Some(SuiMoveValue::Option(Box::new(
                    // in Move option is modeled as vec of 1 element
                    values.first().cloned().map(SuiMoveValue::from),
                )));
            }
        }
        _ => return None,
    }
    warn!(
        fields =? fields,
        "Failed to convert {struct_name} to SuiMoveValue"
    );
    None
}

impl From<MoveStruct> for SuiMoveStruct {
    fn from(move_struct: MoveStruct) -> Self {
        match move_struct {
            MoveStruct::Runtime(value) => {
                SuiMoveStruct::Runtime(value.into_iter().map(|value| value.into()).collect())
            }
            MoveStruct::WithFields(value) => SuiMoveStruct::WithFields(
                value
                    .into_iter()
                    .map(|(id, value)| (id.into_string(), value.into()))
                    .collect(),
            ),
            MoveStruct::WithTypes { type_, fields } => SuiMoveStruct::WithTypes {
                type_: type_.to_string(),
                fields: fields
                    .into_iter()
                    .map(|(id, value)| (id.into_string(), value.into()))
                    .collect(),
            },
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq)]
#[serde(rename = "MovePackage")]
pub struct SuiMovePackage {
    pub disassembled: BTreeMap<String, Value>,
}

impl From<MoveModulePublish> for SuiMovePackage {
    fn from(m: MoveModulePublish) -> Self {
        Self {
            // In case of failed publish transaction, disassemble can fail, we can only return empty module map in that case.
            disassembled: disassemble_modules(m.modules.iter()).unwrap_or_default(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq)]
#[serde(rename = "Pay")]
pub struct SuiPay {
    /// The coins to be used for payment
    pub coins: Vec<SuiObjectRef>,
    /// The addresses that will receive payment
    pub recipients: Vec<SuiAddress>,
    /// The amounts each recipient will receive.
    /// Must be the same length as amounts
    pub amounts: Vec<u64>,
}

impl From<Pay> for SuiPay {
    fn from(p: Pay) -> Self {
        let coins = p.coins.into_iter().map(|c| c.into()).collect();
        SuiPay {
            coins,
            recipients: p.recipients,
            amounts: p.amounts,
        }
    }
}

/// Send SUI coins to a list of addresses, following a list of amounts.
/// only for SUI coin and does not require a separate gas coin object.
/// Specifically, what pay_sui does are:
/// 1. debit each input_coin to create new coin following the order of
/// amounts and assign it to the corresponding recipient.
/// 2. accumulate all residual SUI from input coins left and deposit all SUI to the first
/// input coin, then use the first input coin as the gas coin object.
/// 3. the balance of the first input coin after tx is sum(input_coins) - sum(amounts) - actual_gas_cost
/// 4. all other input coints other than the first one are deleted.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq)]
#[serde(rename = "PaySui")]
pub struct SuiPaySui {
    /// The coins to be used for payment
    pub coins: Vec<SuiObjectRef>,
    /// The addresses that will receive payment
    pub recipients: Vec<SuiAddress>,
    /// The amounts each recipient will receive.
    /// Must be the same length as amounts
    pub amounts: Vec<u64>,
}

impl From<PaySui> for SuiPaySui {
    fn from(p: PaySui) -> Self {
        let coins = p.coins.into_iter().map(|c| c.into()).collect();
        SuiPaySui {
            coins,
            recipients: p.recipients,
            amounts: p.amounts,
        }
    }
}

/// Send all SUI coins to one recipient.
/// only for SUI coin and does not require a separate gas coin object either.
/// Specifically, what pay_all_sui does are:
/// 1. accumulate all SUI from input coins and deposit all SUI to the first input coin
/// 2. transfer the updated first coin to the recipient and also use this first coin as
/// gas coin object.
/// 3. the balance of the first input coin after tx is sum(input_coins) - actual_gas_cost.
/// 4. all other input coins other than the first are deleted.
#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone, Eq, PartialEq)]
#[serde(rename = "PayAllSui")]
pub struct SuiPayAllSui {
    /// The coins to be used for payment
    pub coins: Vec<SuiObjectRef>,
    /// The addresses that will receive payment
    pub recipient: SuiAddress,
}

impl From<PayAllSui> for SuiPayAllSui {
    fn from(p: PayAllSui) -> Self {
        let coins = p.coins.into_iter().map(|c| c.into()).collect();
        SuiPayAllSui {
            coins,
            recipient: p.recipient,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[serde(rename = "GasData", rename_all = "camelCase")]
pub struct SuiGasData {
    pub payment: SuiObjectRef,
    pub owner: SuiAddress,
    pub price: u64,
    pub budget: u64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[serde(rename = "TransactionData", rename_all = "camelCase")]
pub struct SuiTransactionData {
    pub transactions: Vec<SuiTransactionKind>,
    pub sender: SuiAddress,
    pub gas_data: SuiGasData,
}

impl Display for SuiTransactionData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = String::new();
        if self.transactions.len() == 1 {
            writeln!(writer, "{}", self.transactions.first().unwrap())?;
        } else {
            writeln!(writer, "Transaction Kind : Batch")?;
            writeln!(writer, "List of transactions in the batch:")?;
            for kind in &self.transactions {
                writeln!(writer, "{}", kind)?;
            }
        }
        writeln!(writer, "Sender: {}", self.sender)?;
        writeln!(writer, "Gas Payment: {}", self.gas_data.payment)?;
        writeln!(writer, "Gas Owner: {}", self.gas_data.owner)?;
        writeln!(writer, "Gas Price: {}", self.gas_data.price)?;
        writeln!(writer, "Gas Budget: {}", self.gas_data.budget)?;
        write!(f, "{}", writer)
    }
}

impl TryFrom<TransactionData> for SuiTransactionData {
    type Error = anyhow::Error;

    fn try_from(data: TransactionData) -> Result<Self, Self::Error> {
        let transactions = match data.kind.clone() {
            TransactionKind::Single(tx) => {
                vec![tx.try_into()?]
            }
            TransactionKind::Batch(txs) => txs
                .into_iter()
                .map(SuiTransactionKind::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        };
        Ok(Self {
            transactions,
            sender: data.sender(),
            gas_data: SuiGasData {
                payment: data.gas().into(),
                owner: data.gas_owner(),
                price: data.gas_price(),
                budget: data.gas_budget(),
            },
        })
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema, Clone)]
#[serde(rename = "Transaction", rename_all = "camelCase")]
pub struct SuiTransaction {
    pub data: SuiTransactionData,
    pub tx_signatures: Vec<GenericSignature>,
}

impl TryFrom<SenderSignedData> for SuiTransaction {
    type Error = anyhow::Error;

    fn try_from(data: SenderSignedData) -> Result<Self, Self::Error> {
        Ok(Self {
            data: data.intent_message.value.try_into()?,
            tx_signatures: data.tx_signatures,
        })
    }
}

impl Display for SuiTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = String::new();
        writeln!(writer, "Transaction Signature: {:?}", self.tx_signatures)?;
        write!(writer, "{}", &self.data)?;
        write!(f, "{}", writer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SuiGenesisTransaction {
    pub objects: Vec<ObjectID>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SuiConsensusCommitPrologue {
    pub epoch: u64,
    pub round: u64,
    pub commit_timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "TransactionKind")]
pub enum SuiTransactionKind {
    /// Initiate an object transfer between addresses
    TransferObject(SuiTransferObject),
    /// Pay one or more recipients from a set of input coins
    Pay(SuiPay),
    /// Pay one or more recipients from a set of Sui coins, the input coins
    /// are also used to for gas payments.
    PaySui(SuiPaySui),
    /// Pay one or more recipients from a set of Sui coins, the input coins
    /// are also used to for gas payments.
    PayAllSui(SuiPayAllSui),
    /// Publish a new Move module
    Publish(SuiMovePackage),
    /// Call a function in a published Move module
    Call(SuiMoveCall),
    /// Initiate a SUI coin transfer between addresses
    TransferSui(SuiTransferSui),
    /// A system transaction that will update epoch information on-chain.
    ChangeEpoch(SuiChangeEpoch),
    /// A system transaction used for initializing the initial state of the chain.
    Genesis(SuiGenesisTransaction),
    /// A system transaction marking the start of a series of transactions scheduled as part of a
    /// checkpoint
    ConsensusCommitPrologue(SuiConsensusCommitPrologue),
    // .. more transaction types go here
}

impl Display for SuiTransactionKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = String::new();
        match &self {
            Self::TransferObject(t) => {
                writeln!(writer, "Transaction Kind : Transfer Object")?;
                writeln!(writer, "Recipient : {}", t.recipient)?;
                writeln!(writer, "Object ID : {}", t.object_ref.object_id)?;
                writeln!(writer, "Version : {:?}", t.object_ref.version)?;
                write!(
                    writer,
                    "Object Digest : {}",
                    Base64::encode(t.object_ref.digest)
                )?;
            }
            Self::TransferSui(t) => {
                writeln!(writer, "Transaction Kind : Transfer SUI")?;
                writeln!(writer, "Recipient : {}", t.recipient)?;
                if let Some(amount) = t.amount {
                    writeln!(writer, "Amount: {}", amount)?;
                } else {
                    writeln!(writer, "Amount: Full Balance")?;
                }
            }
            Self::Pay(p) => {
                writeln!(writer, "Transaction Kind : Pay")?;
                writeln!(writer, "Coins:")?;
                for obj_ref in &p.coins {
                    writeln!(writer, "Object ID : {}", obj_ref.object_id)?;
                }
                writeln!(writer, "Recipients:")?;
                for recipient in &p.recipients {
                    writeln!(writer, "{}", recipient)?;
                }
                writeln!(writer, "Amounts:")?;
                for amount in &p.amounts {
                    writeln!(writer, "{}", amount)?
                }
            }
            Self::PaySui(p) => {
                writeln!(writer, "Transaction Kind : Pay SUI")?;
                writeln!(writer, "Coins:")?;
                for obj_ref in &p.coins {
                    writeln!(writer, "Object ID : {}", obj_ref.object_id)?;
                }
                writeln!(writer, "Recipients:")?;
                for recipient in &p.recipients {
                    writeln!(writer, "{}", recipient)?;
                }
                writeln!(writer, "Amounts:")?;
                for amount in &p.amounts {
                    writeln!(writer, "{}", amount)?
                }
            }
            Self::PayAllSui(p) => {
                writeln!(writer, "Transaction Kind : Pay SUI")?;
                writeln!(writer, "Coins:")?;
                for obj_ref in &p.coins {
                    writeln!(writer, "Object ID : {}", obj_ref.object_id)?;
                }
                writeln!(writer, "Recipient:")?;
                writeln!(writer, "{}", &p.recipient)?;
            }
            Self::Publish(_p) => {
                write!(writer, "Transaction Kind : Publish")?;
            }
            Self::Call(c) => {
                writeln!(writer, "Transaction Kind : Call")?;
                writeln!(writer, "Package ID : {}", c.package.to_hex_literal())?;
                writeln!(writer, "Module : {}", c.module)?;
                writeln!(writer, "Function : {}", c.function)?;
                writeln!(writer, "Arguments : {:?}", c.arguments)?;
                write!(writer, "Type Arguments : {:?}", c.type_arguments)?;
            }
            Self::ChangeEpoch(e) => {
                writeln!(writer, "Transaction Kind : Epoch Change")?;
                writeln!(writer, "New epoch ID : {}", e.epoch)?;
                writeln!(writer, "Storage gas reward : {}", e.storage_charge)?;
                writeln!(writer, "Computation gas reward : {}", e.computation_charge)?;
                writeln!(writer, "Storage rebate : {}", e.storage_rebate)?;
                writeln!(writer, "Timestamp : {}", e.epoch_start_timestamp_ms)?;
            }
            Self::Genesis(_) => {
                writeln!(writer, "Transaction Kind : Genesis Transaction")?;
            }
            Self::ConsensusCommitPrologue(p) => {
                writeln!(writer, "Transaction Kind : Consensus Commit Prologue")?;
                writeln!(
                    writer,
                    "Epoch: {}, Round: {}, Timestamp : {}",
                    p.epoch, p.round, p.commit_timestamp_ms
                )?;
            }
        }
        write!(f, "{}", writer)
    }
}

impl TryFrom<SingleTransactionKind> for SuiTransactionKind {
    type Error = anyhow::Error;

    fn try_from(tx: SingleTransactionKind) -> Result<Self, Self::Error> {
        Ok(match tx {
            SingleTransactionKind::TransferObject(t) => Self::TransferObject(SuiTransferObject {
                recipient: t.recipient,
                object_ref: t.object_ref.into(),
            }),
            SingleTransactionKind::TransferSui(t) => Self::TransferSui(SuiTransferSui {
                recipient: t.recipient,
                amount: t.amount,
            }),
            SingleTransactionKind::Pay(p) => Self::Pay(p.into()),
            SingleTransactionKind::PaySui(p) => Self::PaySui(p.into()),
            SingleTransactionKind::PayAllSui(p) => Self::PayAllSui(p.into()),
            SingleTransactionKind::Publish(p) => Self::Publish(p.into()),
            SingleTransactionKind::Call(c) => Self::Call(SuiMoveCall {
                package: c.package,
                module: c.module.to_string(),
                function: c.function.to_string(),
                type_arguments: c.type_arguments.iter().map(|ty| ty.to_string()).collect(),
                arguments: c
                    .arguments
                    .into_iter()
                    .map(|arg| match arg {
                        CallArg::Pure(p) => SuiJsonValue::from_bcs_bytes(&p),
                        CallArg::Object(ObjectArg::ImmOrOwnedObject((id, _, _)))
                        | CallArg::Object(ObjectArg::SharedObject { id, .. }) => {
                            SuiJsonValue::new(Value::String(Hex::encode(id)))
                        }
                        CallArg::ObjVec(vec) => SuiJsonValue::new(Value::Array(
                            vec.iter()
                                .map(|obj_arg| match obj_arg {
                                    ObjectArg::ImmOrOwnedObject((id, _, _))
                                    | ObjectArg::SharedObject { id, .. } => {
                                        Value::String(Hex::encode(id))
                                    }
                                })
                                .collect(),
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            }),
            SingleTransactionKind::ChangeEpoch(e) => Self::ChangeEpoch(SuiChangeEpoch {
                epoch: e.epoch,
                storage_charge: e.storage_charge,
                computation_charge: e.computation_charge,
                storage_rebate: e.storage_rebate,
                epoch_start_timestamp_ms: e.epoch_start_timestamp_ms,
            }),
            SingleTransactionKind::Genesis(g) => Self::Genesis(SuiGenesisTransaction {
                objects: g.objects.iter().map(GenesisObject::id).collect(),
            }),
            SingleTransactionKind::ConsensusCommitPrologue(p) => {
                Self::ConsensusCommitPrologue(SuiConsensusCommitPrologue {
                    epoch: p.epoch,
                    round: p.round,
                    commit_timestamp_ms: p.commit_timestamp_ms,
                })
            }
            SingleTransactionKind::ProgrammableTransaction(_) => {
                anyhow::bail!("programmable transactions are not yet supported")
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "MoveCall", rename_all = "camelCase")]
pub struct SuiMoveCall {
    pub package: ObjectID,
    pub module: String,
    pub function: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub type_arguments: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<SuiJsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SuiChangeEpoch {
    pub epoch: EpochId,
    pub storage_charge: u64,
    pub computation_charge: u64,
    pub storage_rebate: u64,
    pub epoch_start_timestamp_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "EffectsFinalityInfo", rename_all = "camelCase")]
pub enum SuiEffectsFinalityInfo {
    Certified(SuiAuthorityStrongQuorumSignInfo),
    Checkpointed(EpochId, CheckpointSequenceNumber),
}

impl From<EffectsFinalityInfo> for SuiEffectsFinalityInfo {
    fn from(info: EffectsFinalityInfo) -> Self {
        match info {
            EffectsFinalityInfo::Certified(cert) => {
                Self::Certified(SuiAuthorityStrongQuorumSignInfo::from(&cert))
            }
            EffectsFinalityInfo::Checkpointed(epoch, checkpoint) => {
                Self::Checkpointed(epoch, checkpoint)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "FinalizedEffects", rename_all = "camelCase")]
pub struct SuiFinalizedEffects {
    pub transaction_effects_digest: TransactionEffectsDigest,
    pub effects: SuiTransactionEffects,
    pub finality_info: SuiEffectsFinalityInfo,
}

impl Display for SuiFinalizedEffects {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = String::new();
        writeln!(
            writer,
            "Transaction Effects Digest: {:?}",
            self.transaction_effects_digest
        )?;
        writeln!(writer, "Transaction Effects: {:?}", self.effects)?;
        match &self.finality_info {
            SuiEffectsFinalityInfo::Certified(cert) => {
                writeln!(writer, "Signed Authorities Bitmap: {:?}", cert.signers_map)?;
            }
            SuiEffectsFinalityInfo::Checkpointed(epoch, checkpoint) => {
                writeln!(
                    writer,
                    "Finalized at epoch {:?}, checkpoint {:?}",
                    epoch, checkpoint
                )?;
            }
        }

        write!(f, "{}", writer)
    }
}

/// The response from processing a transaction or a certified transaction
#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "TransactionEffects", rename_all = "camelCase")]
pub struct SuiTransactionEffects {
    /// The status of the execution
    pub status: SuiExecutionStatus,
    /// The epoch when this transaction was executed.
    pub executed_epoch: EpochId,
    pub gas_used: SuiGasCostSummary,
    /// The object references of the shared objects used in this transaction. Empty if no shared objects were used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_objects: Vec<SuiObjectRef>,
    /// The transaction digest
    pub transaction_digest: TransactionDigest,
    /// ObjectRef and owner of new objects created.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub created: Vec<OwnedObjectRef>,
    /// ObjectRef and owner of mutated objects, including gas object.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mutated: Vec<OwnedObjectRef>,
    /// ObjectRef and owner of objects that are unwrapped in this transaction.
    /// Unwrapped objects are objects that were wrapped into other objects in the past,
    /// and just got extracted out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unwrapped: Vec<OwnedObjectRef>,
    /// Object Refs of objects now deleted (the old refs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deleted: Vec<SuiObjectRef>,
    /// Object refs of objects previously wrapped in other objects but now deleted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unwrapped_then_deleted: Vec<SuiObjectRef>,
    /// Object refs of objects now wrapped in other objects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wrapped: Vec<SuiObjectRef>,
    /// The updated gas object reference. Have a dedicated field for convenient access.
    /// It's also included in mutated.
    pub gas_object: OwnedObjectRef,
    /// The digest of the events emitted during execution,
    /// can be None if the transaction does not emmit any event.
    pub events_digest: Option<TransactionEventsDigest>,
    /// The set of transaction digests this transaction depends on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<TransactionDigest>,
}

impl SuiTransactionEffects {
    /// Return an iterator of mutated objects, but excluding the gas object.
    pub fn mutated_excluding_gas(&self) -> impl Iterator<Item = &OwnedObjectRef> {
        self.mutated.iter().filter(|o| *o != &self.gas_object)
    }
}

impl From<TransactionEffects> for SuiTransactionEffects {
    fn from(effect: TransactionEffects) -> Self {
        Self {
            status: effect.status.into(),
            executed_epoch: effect.executed_epoch,
            gas_used: effect.gas_used.into(),
            shared_objects: to_sui_object_ref(effect.shared_objects),
            transaction_digest: effect.transaction_digest,
            created: to_owned_ref(effect.created),
            mutated: to_owned_ref(effect.mutated),
            unwrapped: to_owned_ref(effect.unwrapped),
            deleted: to_sui_object_ref(effect.deleted),
            unwrapped_then_deleted: to_sui_object_ref(effect.unwrapped_then_deleted),
            wrapped: to_sui_object_ref(effect.wrapped),
            gas_object: OwnedObjectRef {
                owner: effect.gas_object.1,
                reference: effect.gas_object.0.into(),
            },
            events_digest: effect.events_digest,
            dependencies: effect.dependencies,
        }
    }
}

impl Display for SuiTransactionEffects {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut writer = String::new();
        writeln!(writer, "Status : {:?}", self.status)?;
        if !self.created.is_empty() {
            writeln!(writer, "Created Objects:")?;
            for oref in &self.created {
                writeln!(
                    writer,
                    "  - ID: {} , Owner: {}",
                    oref.reference.object_id, oref.owner
                )?;
            }
        }
        if !self.mutated.is_empty() {
            writeln!(writer, "Mutated Objects:")?;
            for oref in &self.mutated {
                writeln!(
                    writer,
                    "  - ID: {} , Owner: {}",
                    oref.reference.object_id, oref.owner
                )?;
            }
        }
        if !self.deleted.is_empty() {
            writeln!(writer, "Deleted Objects:")?;
            for oref in &self.deleted {
                writeln!(writer, "  - ID: {}", oref.object_id)?;
            }
        }
        if !self.wrapped.is_empty() {
            writeln!(writer, "Wrapped Objects:")?;
            for oref in &self.wrapped {
                writeln!(writer, "  - ID: {}", oref.object_id)?;
            }
        }
        if !self.unwrapped.is_empty() {
            writeln!(writer, "Unwrapped Objects:")?;
            for oref in &self.unwrapped {
                writeln!(
                    writer,
                    "  - ID: {} , Owner: {}",
                    oref.reference.object_id, oref.owner
                )?;
            }
        }
        write!(f, "{}", writer)
    }
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DryRunTransactionResponse {
    pub effects: SuiTransactionEffects,
    pub events: SuiTransactionEvents,
}

#[derive(Eq, PartialEq, Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "TransactionEffects", transparent)]
pub struct SuiTransactionEvents {
    pub data: Vec<SuiEvent>,
}

impl SuiTransactionEvents {
    pub fn try_from(
        events: TransactionEvents,
        resolver: &impl GetModule,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            data: events
                .data
                .into_iter()
                .map(|event| SuiEvent::try_from(event, resolver))
                .collect::<Result<_, _>>()?,
        })
    }
}

/// The response from processing a dev inspect transaction
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "DevInspectResults", rename_all = "camelCase")]
pub struct DevInspectResults {
    /// Summary of effects that likely would be generated if the transaction is actually run.
    /// Note however, that not all dev-inspect transactions are actually usable as transactions so
    /// it might not be possible actually generate these effects from a normal transaction.
    pub effects: SuiTransactionEffects,
    /// Events that likely would be generated if the transaction is actually run.
    pub events: SuiTransactionEvents,
    /// Execution results (including return values) from executing the transactions
    /// Currently contains only return values from Move calls
    pub results: Result<Vec<(usize, SuiExecutionResult)>, String>,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "SuiExecutionResult", rename_all = "camelCase")]
pub struct SuiExecutionResult {
    /// The value of any arguments that were mutably borrowed.
    /// Non-mut borrowed values are not included
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mutable_reference_outputs: Vec<(/* local index */ u8, Vec<u8>, SuiTypeTag)>,
    /// The return values from the function
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub return_values: Vec<(Vec<u8>, SuiTypeTag)>,
}

type ExecutionResult = (
    /*  mutable_reference_outputs */ Vec<(u8, Vec<u8>, TypeTag)>,
    /*  return_values */ Vec<(Vec<u8>, TypeTag)>,
);

impl DevInspectResults {
    pub fn new(
        effects: TransactionEffects,
        events: TransactionEvents,
        return_values: Result<Vec<(usize, ExecutionResult)>, ExecutionError>,
        resolver: &impl GetModule,
    ) -> Result<Self, anyhow::Error> {
        let results = match return_values {
            Err(e) => Err(format!("{}", e)),
            Ok(srvs) => Ok(srvs
                .into_iter()
                .map(|(idx, srv)| {
                    let (mutable_reference_outputs, return_values) = srv;
                    let mutable_reference_outputs = mutable_reference_outputs
                        .into_iter()
                        .map(|(i, bytes, tag)| (i, bytes, SuiTypeTag::from(tag)))
                        .collect();
                    let return_values = return_values
                        .into_iter()
                        .map(|(bytes, tag)| (bytes, SuiTypeTag::from(tag)))
                        .collect();
                    let res = SuiExecutionResult {
                        mutable_reference_outputs,
                        return_values,
                    };
                    (idx, res)
                })
                .collect()),
        };
        Ok(Self {
            effects: effects.into(),
            events: SuiTransactionEvents::try_from(events, resolver)?,
            results,
        })
    }
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub enum SuiTransactionBuilderMode {
    /// Regular Sui Transactions that are committed on chain
    Commit,
    /// Simulated transaction that allows calling any Move function with
    /// arbitrary values.
    DevInspect,
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "ExecutionStatus", rename_all = "camelCase", tag = "status")]
pub enum SuiExecutionStatus {
    // Gas used in the success case.
    Success,
    // Gas used in the failed case, and the error.
    Failure { error: String },
}

impl SuiExecutionStatus {
    pub fn is_ok(&self) -> bool {
        matches!(self, SuiExecutionStatus::Success { .. })
    }
    pub fn is_err(&self) -> bool {
        matches!(self, SuiExecutionStatus::Failure { .. })
    }
}

impl From<ExecutionStatus> for SuiExecutionStatus {
    fn from(status: ExecutionStatus) -> Self {
        match status {
            ExecutionStatus::Success => Self::Success,
            ExecutionStatus::Failure {
                error,
                command: None,
            } => Self::Failure {
                error: format!("{error:?}"),
            },
            ExecutionStatus::Failure {
                error,
                command: Some(idx),
            } => Self::Failure {
                error: format!("{error:?} in command {idx}"),
            },
        }
    }
}

fn to_sui_object_ref(refs: Vec<ObjectRef>) -> Vec<SuiObjectRef> {
    refs.into_iter().map(SuiObjectRef::from).collect()
}

fn to_owned_ref(owned_refs: Vec<(ObjectRef, Owner)>) -> Vec<OwnedObjectRef> {
    owned_refs
        .into_iter()
        .map(|(oref, owner)| OwnedObjectRef {
            owner,
            reference: oref.into(),
        })
        .collect()
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "GasCostSummary", rename_all = "camelCase")]
pub struct SuiGasCostSummary {
    pub computation_cost: u64,
    pub storage_cost: u64,
    pub storage_rebate: u64,
}

impl From<GasCostSummary> for SuiGasCostSummary {
    fn from(s: GasCostSummary) -> Self {
        Self {
            computation_cost: s.computation_cost,
            storage_cost: s.storage_cost,
            storage_rebate: s.storage_rebate,
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "OwnedObjectRef")]
pub struct OwnedObjectRef {
    pub owner: Owner,
    pub reference: SuiObjectRef,
}

#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "EventEnvelope", rename_all = "camelCase")]
pub struct SuiEventEnvelope {
    /// UTC timestamp in milliseconds since epoch (1/1/1970)
    pub timestamp: u64,
    /// Transaction digest of associated transaction
    pub tx_digest: TransactionDigest,
    /// Sequential event ID, ie (transaction seq number, event seq number).
    /// 1) Serves as a unique event ID for each fullnode
    /// 2) Also serves to sequence events for the purposes of pagination and querying.
    ///    A higher id is an event seen later by that fullnode.
    /// This ID is the "cursor" for event querying.
    pub id: EventID,
    /// Specific event type
    pub event: SuiEvent,
}

#[serde_as]
#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "Event", rename_all = "camelCase")]
pub enum SuiEvent {
    /// Move-specific event
    #[serde(rename_all = "camelCase")]
    MoveEvent {
        // TODO: What's the best way to serialize this using `AccountAddress::short_str_lossless` ??
        package_id: ObjectID,
        transaction_module: String,
        sender: SuiAddress,
        type_: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        fields: Option<SuiMoveStruct>,
        #[serde_as(as = "Base64")]
        #[schemars(with = "Base64")]
        bcs: Vec<u8>,
    },
    /// Module published
    #[serde(rename_all = "camelCase")]
    Publish {
        sender: SuiAddress,
        package_id: ObjectID,
        version: SequenceNumber,
        digest: ObjectDigest,
    },
    /// Coin balance changing event
    #[serde(rename_all = "camelCase")]
    CoinBalanceChange {
        package_id: ObjectID,
        transaction_module: String,
        sender: SuiAddress,
        change_type: BalanceChangeType,
        owner: Owner,
        coin_type: String,
        coin_object_id: ObjectID,
        version: SequenceNumber,
        amount: i128,
    },
    /// Epoch change
    EpochChange(EpochId),
    /// New checkpoint
    Checkpoint(CheckpointSequenceNumber),
    /// Transfer objects to new address / wrap in another object / coin
    #[serde(rename_all = "camelCase")]
    TransferObject {
        package_id: ObjectID,
        transaction_module: String,
        sender: SuiAddress,
        recipient: Owner,
        object_type: String,
        object_id: ObjectID,
        version: SequenceNumber,
    },
    /// Object mutated.
    #[serde(rename_all = "camelCase")]
    MutateObject {
        package_id: ObjectID,
        transaction_module: String,
        sender: SuiAddress,
        object_type: String,
        object_id: ObjectID,
        version: SequenceNumber,
    },
    /// Delete object
    #[serde(rename_all = "camelCase")]
    DeleteObject {
        package_id: ObjectID,
        transaction_module: String,
        sender: SuiAddress,
        object_id: ObjectID,
        version: SequenceNumber,
    },
    /// New object creation
    #[serde(rename_all = "camelCase")]
    NewObject {
        package_id: ObjectID,
        transaction_module: String,
        sender: SuiAddress,
        recipient: Owner,
        object_type: String,
        object_id: ObjectID,
        version: SequenceNumber,
    },
}

impl TryFrom<SuiEvent> for Event {
    type Error = anyhow::Error;
    fn try_from(event: SuiEvent) -> Result<Self, Self::Error> {
        Ok(match event {
            SuiEvent::MoveEvent {
                package_id,
                transaction_module,
                sender,
                type_,
                fields: _,
                bcs,
            } => Event::MoveEvent {
                package_id,
                transaction_module: Identifier::from_str(&transaction_module)?,
                sender,
                type_: parse_sui_struct_tag(&type_)?,
                contents: bcs,
            },
            SuiEvent::Publish {
                sender,
                package_id,
                version,
                digest,
            } => Event::Publish {
                sender,
                package_id,
                version,
                digest,
            },
            SuiEvent::TransferObject {
                package_id,
                transaction_module,
                sender,
                recipient,
                object_type,
                object_id,
                version,
            } => Event::TransferObject {
                package_id,
                transaction_module: Identifier::from_str(&transaction_module)?,
                sender,
                recipient,
                object_type,
                object_id,
                version,
            },
            SuiEvent::DeleteObject {
                package_id,
                transaction_module,
                sender,
                object_id,
                version,
            } => Event::DeleteObject {
                package_id,
                transaction_module: Identifier::from_str(&transaction_module)?,
                sender,
                object_id,
                version,
            },
            SuiEvent::NewObject {
                package_id,
                transaction_module,
                sender,
                recipient,
                object_type,
                object_id,
                version,
            } => Event::NewObject {
                package_id,
                transaction_module: Identifier::from_str(&transaction_module)?,
                sender,
                recipient,
                object_type,
                object_id,
                version,
            },
            SuiEvent::EpochChange(id) => Event::EpochChange(id),
            SuiEvent::Checkpoint(seq) => Event::Checkpoint(seq),
            SuiEvent::CoinBalanceChange {
                package_id,
                transaction_module,
                sender,
                change_type,
                owner,
                coin_object_id: coin_id,
                version,
                coin_type,
                amount,
            } => Event::CoinBalanceChange {
                package_id,
                transaction_module: Identifier::from_str(&transaction_module)?,
                sender,
                change_type,
                owner,
                coin_type,
                coin_object_id: coin_id,
                version,
                amount,
            },
            SuiEvent::MutateObject {
                package_id,
                transaction_module,
                sender,
                object_type,
                object_id,
                version,
            } => Event::MutateObject {
                package_id,
                transaction_module: Identifier::from_str(&transaction_module)?,
                sender,
                object_type,
                object_id,
                version,
            },
        })
    }
}

impl SuiEvent {
    pub fn try_from(event: Event, resolver: &impl GetModule) -> Result<Self, anyhow::Error> {
        Ok(match event {
            Event::MoveEvent {
                package_id,
                transaction_module,
                sender,
                type_,
                contents,
            } => {
                let bcs = contents.to_vec();

                let (type_, fields) = if let Ok(move_struct) =
                    Event::move_event_to_move_struct(&type_, &contents, resolver)
                {
                    let (type_, field) = type_and_fields_from_move_struct(&type_, move_struct);
                    (type_, Some(field))
                } else {
                    (type_.to_string(), None)
                };

                SuiEvent::MoveEvent {
                    package_id,
                    transaction_module: transaction_module.to_string(),
                    sender,
                    type_,
                    fields,
                    bcs,
                }
            }
            Event::Publish {
                sender,
                package_id,
                version,
                digest,
            } => SuiEvent::Publish {
                sender,
                package_id,
                version,
                digest,
            },
            Event::TransferObject {
                package_id,
                transaction_module,
                sender,
                recipient,
                object_type,
                object_id,
                version,
            } => SuiEvent::TransferObject {
                package_id,
                transaction_module: transaction_module.to_string(),
                sender,
                recipient,
                object_type,
                object_id,
                version,
            },
            Event::DeleteObject {
                package_id,
                transaction_module,
                sender,
                object_id,
                version,
            } => SuiEvent::DeleteObject {
                package_id,
                transaction_module: transaction_module.to_string(),
                sender,
                object_id,
                version,
            },
            Event::NewObject {
                package_id,
                transaction_module,
                sender,
                recipient,
                object_type,
                object_id,
                version,
            } => SuiEvent::NewObject {
                package_id,
                transaction_module: transaction_module.to_string(),
                sender,
                recipient,
                object_type,
                object_id,
                version,
            },
            Event::EpochChange(id) => SuiEvent::EpochChange(id),
            Event::Checkpoint(seq) => SuiEvent::Checkpoint(seq),
            Event::CoinBalanceChange {
                package_id,
                transaction_module,
                sender,
                change_type,
                owner,
                coin_object_id: coin_id,
                version,
                coin_type,
                amount,
            } => SuiEvent::CoinBalanceChange {
                package_id,
                transaction_module: transaction_module.to_string(),
                sender,
                change_type,
                owner,
                coin_object_id: coin_id,
                version,
                coin_type,
                amount,
            },
            Event::MutateObject {
                package_id,
                transaction_module,
                sender,
                object_type,
                object_id,
                version,
            } => SuiEvent::MutateObject {
                package_id,
                transaction_module: transaction_module.to_string(),
                sender,
                object_type,
                object_id,
                version,
            },
        })
    }

    pub fn get_event_type(&self) -> String {
        match self {
            SuiEvent::MoveEvent { .. } => "MoveEvent".to_string(),
            SuiEvent::Publish { .. } => "Publish".to_string(),
            SuiEvent::TransferObject { .. } => "TransferObject".to_string(),
            SuiEvent::DeleteObject { .. } => "DeleteObject".to_string(),
            SuiEvent::NewObject { .. } => "NewObject".to_string(),
            SuiEvent::EpochChange(..) => "EpochChange".to_string(),
            SuiEvent::Checkpoint(..) => "CheckPoint".to_string(),
            SuiEvent::CoinBalanceChange { .. } => "CoinBalanceChange".to_string(),
            SuiEvent::MutateObject { .. } => "MutateObject".to_string(),
        }
    }
}

impl PartialEq<SuiEventEnvelope> for EventEnvelope {
    fn eq(&self, other: &SuiEventEnvelope) -> bool {
        self.timestamp == other.timestamp
            && self.tx_digest == other.tx_digest
            && self.event == other.event
    }
}

impl PartialEq<SuiEvent> for Event {
    fn eq(&self, other: &SuiEvent) -> bool {
        match self {
            Event::MoveEvent {
                package_id: self_package_id,
                transaction_module: self_transaction_module,
                sender: self_sender,
                type_: self_type,
                contents: self_contents,
            } => {
                if let SuiEvent::MoveEvent {
                    package_id,
                    transaction_module,
                    sender,
                    type_,
                    fields: _fields,
                    bcs,
                } = other
                {
                    package_id == self_package_id
                        && &self_transaction_module.to_string() == transaction_module
                        && self_sender == sender
                        && &self_type.to_string() == type_
                        && self_contents == bcs
                } else {
                    false
                }
            }
            Event::Publish {
                sender: self_sender,
                package_id: self_package_id,
                version: self_version,
                digest: self_digest,
            } => {
                if let SuiEvent::Publish {
                    package_id,
                    sender,
                    version,
                    digest,
                } = other
                {
                    package_id == self_package_id
                        && self_sender == sender
                        && self_version == version
                        && self_digest == digest
                } else {
                    false
                }
            }
            Event::TransferObject {
                package_id: self_package_id,
                transaction_module: self_transaction_module,
                sender: self_sender,
                recipient: self_recipient,
                object_type: self_object_type,
                object_id: self_object_id,
                version: self_version,
            } => {
                if let SuiEvent::TransferObject {
                    package_id,
                    transaction_module,
                    sender,
                    recipient,
                    object_type,
                    object_id,
                    version,
                } = other
                {
                    package_id == self_package_id
                        && &self_transaction_module.to_string() == transaction_module
                        && self_sender == sender
                        && self_recipient == recipient
                        && self_object_id == object_id
                        && self_version == version
                        && self_object_type == object_type
                } else {
                    false
                }
            }
            Event::DeleteObject {
                package_id: self_package_id,
                transaction_module: self_transaction_module,
                sender: self_sender,
                object_id: self_object_id,
                version: self_version,
            } => {
                if let SuiEvent::DeleteObject {
                    package_id,
                    transaction_module,
                    sender,
                    object_id,
                    version,
                } = other
                {
                    package_id == self_package_id
                        && &self_transaction_module.to_string() == transaction_module
                        && self_sender == sender
                        && self_object_id == object_id
                        && self_version == version
                } else {
                    false
                }
            }
            Event::NewObject {
                package_id: self_package_id,
                transaction_module: self_transaction_module,
                sender: self_sender,
                recipient: self_recipient,
                object_type: self_object_type,
                object_id: self_object_id,
                version: self_version,
            } => {
                if let SuiEvent::NewObject {
                    package_id,
                    transaction_module,
                    sender,
                    recipient,
                    object_type,
                    object_id,
                    version,
                } = other
                {
                    package_id == self_package_id
                        && &self_transaction_module.to_string() == transaction_module
                        && self_sender == sender
                        && self_recipient == recipient
                        && self_object_id == object_id
                        && self_object_type == object_type
                        && self_version == version
                } else {
                    false
                }
            }
            Event::EpochChange(self_id) => {
                if let SuiEvent::EpochChange(id) = other {
                    self_id == id
                } else {
                    false
                }
            }
            Event::Checkpoint(self_id) => {
                if let SuiEvent::Checkpoint(id) = other {
                    self_id == id
                } else {
                    false
                }
            }
            Event::CoinBalanceChange {
                package_id: self_package_id,
                transaction_module: self_transaction_module,
                sender: self_sender,
                change_type: self_change_type,
                owner: self_owner,
                coin_object_id: self_coin_id,
                version: self_version,
                coin_type: self_coin_type,
                amount: self_amount,
            } => {
                if let SuiEvent::CoinBalanceChange {
                    package_id,
                    transaction_module,
                    sender,
                    change_type,
                    owner,
                    coin_object_id,
                    version,
                    coin_type,
                    amount,
                } = other
                {
                    package_id == self_package_id
                        && &self_transaction_module.to_string() == transaction_module
                        && self_owner == owner
                        && self_coin_id == coin_object_id
                        && self_version == version
                        && &self_coin_type.to_string() == coin_type
                        && self_amount == amount
                        && self_sender == sender
                        && self_change_type == change_type
                } else {
                    false
                }
            }
            Event::MutateObject {
                package_id: self_package_id,
                transaction_module: self_transaction_module,
                sender: self_sender,
                object_type: self_object_type,
                object_id: self_object_id,
                version: self_version,
            } => {
                if let SuiEvent::MutateObject {
                    package_id,
                    transaction_module,
                    sender,
                    object_type,
                    object_id,
                    version,
                } = other
                {
                    package_id == self_package_id
                        && &self_transaction_module.to_string() == transaction_module
                        && self_sender == sender
                        && self_object_type == object_type
                        && self_object_id == object_id
                        && self_version == version
                } else {
                    false
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "TransferObject", rename_all = "camelCase")]
pub struct SuiTransferObject {
    pub recipient: SuiAddress,
    pub object_ref: SuiObjectRef,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "TransferSui", rename_all = "camelCase")]
pub struct SuiTransferSui {
    pub recipient: SuiAddress,
    pub amount: Option<u64>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "InputObjectKind")]
pub enum SuiInputObjectKind {
    // A Move package, must be immutable.
    MovePackage(ObjectID),
    // A Move object, either immutable, or owned mutable.
    ImmOrOwnedMoveObject(SuiObjectRef),
    // A Move object that's shared and mutable.
    SharedMoveObject {
        id: ObjectID,
        initial_shared_version: SequenceNumber,
        #[serde(default = "default_shared_object_mutability")]
        mutable: bool,
    },
}

const fn default_shared_object_mutability() -> bool {
    true
}

impl From<InputObjectKind> for SuiInputObjectKind {
    fn from(input: InputObjectKind) -> Self {
        match input {
            InputObjectKind::MovePackage(id) => Self::MovePackage(id),
            InputObjectKind::ImmOrOwnedMoveObject(oref) => Self::ImmOrOwnedMoveObject(oref.into()),
            InputObjectKind::SharedMoveObject {
                id,
                initial_shared_version,
                mutable,
            } => Self::SharedMoveObject {
                id,
                initial_shared_version,
                mutable,
            },
        }
    }
}

#[derive(Clone, Serialize, Deserialize, JsonSchema, Ord, PartialOrd, Eq, PartialEq, Debug)]
#[serde(rename = "ObjectInfo", rename_all = "camelCase")]
pub struct SuiObjectInfo {
    pub object_id: ObjectID,
    pub version: SequenceNumber,
    pub digest: ObjectDigest,
    #[serde(rename = "type")]
    pub type_: String,
    pub owner: Owner,
    pub previous_transaction: TransactionDigest,
}

impl SuiObjectInfo {
    pub fn to_object_ref(&self) -> ObjectRef {
        (self.object_id, self.version, self.digest)
    }
}

impl From<ObjectInfo> for SuiObjectInfo {
    fn from(info: ObjectInfo) -> Self {
        Self {
            object_id: info.object_id,
            version: info.version,
            digest: info.digest,
            type_: format!("{}", info.type_),
            owner: info.owner,
            previous_transaction: info.previous_transaction,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObjectExistsResponse {
    object_ref: SuiObjectRef,
    owner: Owner,
    previous_transaction: TransactionDigest,
    data: SuiParsedData,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObjectNotExistsResponse {
    object_id: String,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone)]
#[serde(rename = "TypeTag", rename_all = "camelCase")]
pub struct SuiTypeTag(String);

impl TryInto<TypeTag> for SuiTypeTag {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<TypeTag, Self::Error> {
        parse_sui_type_tag(&self.0)
    }
}

impl From<TypeTag> for SuiTypeTag {
    fn from(tag: TypeTag) -> Self {
        Self(format!("{}", tag))
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum RPCTransactionRequestParams {
    TransferObjectRequestParams(TransferObjectParams),
    MoveCallRequestParams(MoveCallParams),
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TransferObjectParams {
    pub recipient: SuiAddress,
    pub object_id: ObjectID,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MoveCallParams {
    pub package_object_id: ObjectID,
    pub module: String,
    pub function: String,
    #[serde(default)]
    pub type_arguments: Vec<SuiTypeTag>,
    pub arguments: Vec<SuiJsonValue>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename = "EventFilter")]
pub enum SuiEventFilter {
    Package(ObjectID),
    Module(String),
    /// Move StructTag string value of the event type e.g. `0x2::devnet_nft::MintNFTEvent`
    MoveEventType(String),
    MoveEventField {
        path: String,
        value: Value,
    },
    SenderAddress(SuiAddress),
    EventType(EventType),
    ObjectId(ObjectID),
    All(Vec<SuiEventFilter>),
    Any(Vec<SuiEventFilter>),
    And(Box<SuiEventFilter>, Box<SuiEventFilter>),
    Or(Box<SuiEventFilter>, Box<SuiEventFilter>),
}

impl TryInto<EventFilter> for SuiEventFilter {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<EventFilter, anyhow::Error> {
        use SuiEventFilter::*;
        Ok(match self {
            Package(id) => EventFilter::Package(id),
            Module(module) => EventFilter::Module(Identifier::new(module)?),
            MoveEventType(event_type) => {
                // parse_sui_struct_tag converts StructTag string e.g. `0x2::devnet_nft::MintNFTEvent` to StructTag object
                EventFilter::MoveEventType(parse_sui_struct_tag(&event_type)?)
            }
            MoveEventField { path, value } => EventFilter::MoveEventField { path, value },
            SenderAddress(address) => EventFilter::SenderAddress(address),
            ObjectId(id) => EventFilter::ObjectId(id),
            All(filters) => EventFilter::MatchAll(
                filters
                    .into_iter()
                    .map(SuiEventFilter::try_into)
                    .collect::<Result<_, _>>()?,
            ),
            Any(filters) => EventFilter::MatchAny(
                filters
                    .into_iter()
                    .map(SuiEventFilter::try_into)
                    .collect::<Result<_, _>>()?,
            ),
            And(filter_a, filter_b) => All(vec![*filter_a, *filter_b]).try_into()?,
            Or(filter_a, filter_b) => Any(vec![*filter_a, *filter_b]).try_into()?,
            EventType(type_) => EventFilter::EventType(type_),
        })
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TransactionBytes {
    /// BCS serialized transaction data bytes without its type tag, as base-64 encoded string.
    pub tx_bytes: Base64,
    /// the gas object to be used
    pub gas: SuiObjectRef,
    /// objects to be used in this transaction
    pub input_objects: Vec<SuiInputObjectKind>,
}

impl TransactionBytes {
    pub fn from_data(data: TransactionData) -> Result<Self, anyhow::Error> {
        Ok(Self {
            tx_bytes: Base64::from_bytes(bcs::to_bytes(&data)?.as_slice()),
            gas: data.gas().into(),
            input_objects: data
                .input_objects()?
                .into_iter()
                .map(SuiInputObjectKind::from)
                .collect(),
        })
    }

    pub fn to_data(self) -> Result<TransactionData, anyhow::Error> {
        bcs::from_bytes::<TransactionData>(&self.tx_bytes.to_vec().map_err(|e| anyhow::anyhow!(e))?)
            .map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Page<T, C> {
    pub data: Vec<T>,
    pub next_cursor: Option<C>,
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    /// Checkpoint's epoch ID
    pub epoch: EpochId,
    /// Checkpoint sequence number
    pub sequence_number: CheckpointSequenceNumber,
    /// Checkpoint digest
    pub digest: CheckpointDigest,
    /// Total number of transactions committed since genesis, including those in this
    /// checkpoint.
    pub network_total_transactions: u64,
    /// Digest of the previous checkpoint
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
    /// Transaction digests
    pub transactions: Vec<TransactionDigest>,
}

impl From<(CheckpointSummary, CheckpointContents)> for Checkpoint {
    fn from((summary, contents): (CheckpointSummary, CheckpointContents)) -> Self {
        let digest = summary.digest();
        let CheckpointSummary {
            epoch,
            sequence_number,
            network_total_transactions,
            previous_digest,
            epoch_rolling_gas_cost_summary,
            timestamp_ms,
            end_of_epoch_data,
            ..
        } = summary;

        Checkpoint {
            epoch,
            sequence_number,
            digest,
            network_total_transactions,
            previous_digest,
            epoch_rolling_gas_cost_summary,
            timestamp_ms,
            end_of_epoch_data,
            transactions: contents.iter().map(|digest| digest.transaction).collect(),
        }
    }
}

#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CheckpointId {
    SequenceNumber(CheckpointSequenceNumber),
    Digest(CheckpointDigest),
}

impl From<CheckpointSequenceNumber> for CheckpointId {
    fn from(seq: CheckpointSequenceNumber) -> Self {
        Self::SequenceNumber(seq)
    }
}

impl From<CheckpointDigest> for CheckpointId {
    fn from(digest: CheckpointDigest) -> Self {
        Self::Digest(digest)
    }
}
