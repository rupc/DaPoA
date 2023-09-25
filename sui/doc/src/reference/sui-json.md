---
title: SuiJSON
---

*SuiJSON* is a JSON-based format with restrictions that allow Sui to align JSON inputs more closely with Move call arguments.

This table shows the restrictions placed on JSON types to make them SuiJSON compatible:

| JSON    | SuiJSON Restrictions                         | Move Type Mapping                                                                               |
|---------|----------------------------------------------|-------------------------------------------------------------------------------------------------|
| Number  | Must be unsigned integer                     | U8<br>U16<br>U32<br>(U64 is encoded as String)<br>(U128 is encoded as String)<br>(U256 is encoded as String)                                                        |
| String  | No restrictions                              | Vector&lt;U8><br>Address<br>ObjectID<br>TypeTag<br>Identifier<br>Unsigned Integer (256 bit max) |
| Boolean | No restrictions                              | Bool                                                                                            |
| Array   | Must be homogeneous JSON and of SuiJSON type | Vector                                                                                          |
| Null    | Not allowed                                  |
| Object  | Not allowed                                  |

## Type coercion reasoning

Due to the loosely typed nature of JSON/SuiJSON and the strongly typed nature of Move types, we sometimes need to overload SuiJSON types to represent multiple Move types.

For example `SuiJSON::Number` can represent both *U8* and *U32*. This means we have to coerce and sometimes convert types.

Which type we coerce depends on the expected Move type. For example, if the Move function expects a U8, we must have received a `SuiJSON::Number` with a value less than 256. More importantly, we have no way to easily express Move addresses in JSON, so we encode them as hex strings prefixed by `0x`.

Additionally, Move supports U128 and U256 but JSON doesn't. As a result we allow encoding numbers as strings.

## Type coercion rules

| Move Type | SuiJSON Representations | Valid Examples | Invalid Examples |
| --- | --- | --- | --- |
| Bool | Bool | `true`, `false` |  | 
| U8 | Supports 3 formats:<ul><li>Unsigned number &lt; 256.</li><li>Decimal string with value &lt; 256.</li><li>One byte hex string prefixed with `0x`.</li></ul> | `7`<br>`"70"`<br>`"0x43"` | `-5`: negative not allowed<br>`3.9`: float not allowed<br>`NaN`: not allowed<br>`300`: U8 must be less than 256<br>`" 9"`: Spaces not allowed in string<br>`"9A"`: Hex num must be prefixed with `0x`<br>`"0x09CD"`: Too large for U8 |
| U16                   | Three formats are supported<ul><li>Unsigned number &lt; 65536. </li><li>Decimal string with value &lt; 65536.</li><li>Two byte hex string prefixed with `0x`.</li></ul>                                                                                                                                                               | `712`<br>`"570"`<br>`"0x423"`                                                                | `-5`: negative not allowed<br>`3.9`: float not allowed<br>`NaN`: not allowed<br>`98342300`: U16 must be less than 65536<br>`" 19"`: Spaces not allowed in string<br>`"9EA"`: Hex num must be prefixed with `0x`<br>`"0x049C1D"`: Too large for U16                 
| U32                   | Three formats are supported<ul><li>Unsigned number &lt; 4294967296. </li><li>Decimal string with value &lt; 4294967296.</li><li>One byte hex string prefixed with `0x`.</li></ul>                                                                                                                                                               | `9823247`<br>`"987120"`<br>`"0x4BADE93"`                                                                | `-5`: negative not allowed<br>`3.9`: float not allowed<br>`NaN`: not allowed<br>`123456789123456`: U32 must be less than 4294967296<br>`" 9"`: Spaces not allowed in string<br>`"9A"`: Hex num must be prefixed with `0x`<br>`"0x3FF1FF9FFDEFF"`: Too large for U32                 
| U64 | Supports two formats<ul><li>Decimal string with value &lt; U64::MAX.</li><li>Up to 8 byte hex string prefixed with `0x`.</li></ul> |`"747944370"`<br>`"0x2B1A39A15E"` | `123434`: Although this is a valid U64 number, it must be encoded as a string |
| U128                 | Two formats are supported<ul><li>Decimal string with value &lt; U128::MAX.</li><li>Up to 16 byte hex string prefixed with `0x`.</li></ul>                                                                                                                                                                                         | `"74794734937420002470"`<br>`"0x2B1A39A1514E1D8A7CE"`                                    | `34`: Although this is a valid U128 number, it must be encoded as a string                                                                                                                                                                            |
| U256                 | Two formats are supported<ul><li>Decimal string with value &lt; U256::MAX.</li><li>Up to 32 byte hex string prefixed with `0x`.</li></ul>                                                                                                                                                                                         | `"747947349374200024707479473493742000247"`<br>`"0x2B1762FECADA39753FCAB2A1514E1D8A7CE"`                                    | `123434`: Although this is a valid U256 number, it must be encoded as a string                                                                                                                                                                            | 
| Address | 20 byte hex string prefixed with `0x` | `"0x2B1A39A1514E1D8A7CE45919CFEB4FEE70B4E011"` | `0x2B1A39`: string too short<br>`2B1A39A1514E1D8A7CE45919CFEB4FEE70B4E011`: missing `0x` prefix<br>`0xG2B1A39A1514E1D8A7CE45919CFEB4FEE70B4E01`: invalid hex char `G` |
| ObjectID | 20 byte hex string prefixed with `0x` | `"0x2B1A39A1514E1D8A7CE45919CFEB4FEE70B4E011"` | Similar to above |
| Identifier | Typically used for module and function names. Encoded as one of the following:<ol><li>A String whose first character is a letter and the remaining characters are letters, digits or underscore.</li><li>A String whose first character is an underscore, and there is at least one further letter, digit or underscore</li></ol> | `"function"`,<br>`"_function"`,<br>`"some_name"`,<br>`"\___\_some_name"`,<br>`"Another"` | `"_"`: missing trailing underscore, digit or letter,<br>`"8name"`: cannot start with digit,<br>`".function"`: cannot start with period,<br>`" "`: cannot be empty space,<br>`"func name"`: cannot have spaces |
| Vector&lt;Move Type> | Homogeneous vector of aforementioned types including nested vectors of primitive types (only "flat" vectors of ObjectIDs are allowed) | `[1,2,3,4]`: simple U8 vector<br>`[[3,600],[],[0,7,4]]`: nested U32 vector `["0x2B1A39A1514E1D8A7CE45919CFEB4FEE", "0x2B1A39A1514E1D8A7CE45919CFEB4FEF"]`: ObjectID vector | `[1,2,3,false]`: not homogeneous JSON<br>`[1,2,null,4]`: invalid elements<br>`[1,2,"7"]`: although we allow encoding numbers as strings meaning this array can evaluate to `[1,2,7]`, the array is still ambiguous so it fails the homogeneity check. |
| Vector&lt;U8> | <em>For convenience, we allow:</em><br>U8 vectors represented as UTF-8 (and ASCII) strings. | `"√®ˆbo72 √∂†∆˚–œ∑π2ie"`: UTF-8<br>`"abcdE738-2 _=?"`: ASCII | |

