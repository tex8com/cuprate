//! Output distributions for [`crate::json::GetOutputDistributionResponse`].

//---------------------------------------------------------------------------------------------------- Use
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "epee")]
use cuprate_epee_encoding::{
    container_as_blob::ContainerAsBlob,
    epee_object, error,
    macros::bytes::{Buf, BufMut},
    read_epee_value, write_field, EpeeObject, EpeeObjectBuilder,
};

//---------------------------------------------------------------------------------------------------- Free
/// TODO: <https://github.com/Cuprate/cuprate/pull/229#discussion_r1690531904>.
///
/// Used for [`Distribution::CompressedBinary::distribution`].
#[doc = crate::macros::monero_definition_link!(
    "cc73fe71162d564ffda8e549b79a350bca53c454",
    "rpc/core_rpc_server_commands_defs.h",
    45..=55
)]
#[cfg(any(feature = "epee", feature = "serde"))]
fn compress_integer_array(values: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 8);

    for value in values {
        write_monero_varint(*value, &mut bytes);
    }

    bytes
}

/// TODO: <https://github.com/Cuprate/cuprate/pull/229#discussion_r1690531904>.
///
/// Used for [`Distribution::CompressedBinary::distribution`].
#[doc = crate::macros::monero_definition_link!(
    "cc73fe71162d564ffda8e549b79a350bca53c454",
    "rpc/core_rpc_server_commands_defs.h",
    57..=72
)]
#[cfg(any(feature = "epee", feature = "serde"))]
fn decompress_integer_array(bytes: &[u8]) -> Vec<u64> {
    let mut values = Vec::with_capacity(bytes.len());
    let mut cursor = bytes;

    while !cursor.is_empty() {
        let Some(value) = read_monero_varint(&mut cursor) else {
            break;
        };

        values.push(value);
    }

    values
}

#[cfg(any(feature = "epee", feature = "serde"))]
fn write_monero_varint(value: u64, bytes: &mut Vec<u8>) {
    let mut value = value;

    while value >= 0x80 {
        bytes.push(((value as u8) & 0x7f) | 0x80);
        value >>= 7;
    }

    bytes.push(value as u8);
}

#[cfg(any(feature = "epee", feature = "serde"))]
fn read_monero_varint(bytes: &mut &[u8]) -> Option<u64> {
    let mut value = 0_u64;
    let mut shift = 0_u32;

    loop {
        let byte = *bytes.first()?;
        *bytes = &bytes[1..];

        if shift + 7 >= u64::BITS {
            let limit = 1_u8 << (u64::BITS - shift);
            if byte >= limit {
                return None;
            }
        }

        if byte == 0 && shift != 0 {
            return None;
        }

        value |= u64::from(byte & 0x7f) << shift;

        if byte & 0x80 == 0 {
            return Some(value);
        }

        shift += 7;
    }
}

//---------------------------------------------------------------------------------------------------- Distribution
#[doc = crate::macros::monero_definition_link!(
    "cc73fe71162d564ffda8e549b79a350bca53c454",
    "rpc/core_rpc_server_commands_defs.h",
    2468..=2508
)]
/// Used in [`crate::json::GetOutputDistributionResponse`].
///
/// # Internals
/// This type's (de)serialization depends on `monerod`'s (de)serialization.
///
/// During serialization:
/// [`Self::Uncompressed`] will emit:
/// - `compress: false`
///
/// [`Self::CompressedBinary`] will emit:
/// - `binary: true`
/// - `compress: true`
///
/// Upon deserialization, the presence of a `compressed_data`
/// field signifies that the [`Self::CompressedBinary`] should
/// be selected.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum Distribution {
    /// Distribution data will be (de)serialized as either JSON or binary (uncompressed).
    Uncompressed(DistributionUncompressed),
    /// Distribution data will be (de)serialized as compressed binary.
    CompressedBinary(DistributionCompressedBinary),
}

impl Default for Distribution {
    fn default() -> Self {
        Self::Uncompressed(DistributionUncompressed::default())
    }
}

/// Data within [`Distribution::Uncompressed`].
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DistributionUncompressed {
    pub start_height: u64,
    pub base: u64,
    /// TODO: this is a binary JSON string if `binary == true`.
    pub distribution: Vec<u64>,
    pub amount: u64,
    pub binary: bool,
}

#[cfg(feature = "epee")]
epee_object! {
    DistributionUncompressed,
    start_height: u64,
    base: u64,
    distribution: Vec<u64>,
    amount: u64,
    binary: bool,
}

/// Data within [`Distribution::CompressedBinary`].
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DistributionCompressedBinary {
    pub start_height: u64,
    pub base: u64,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serialize_distribution_as_compressed_data")
    )]
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "deserialize_compressed_data_as_distribution")
    )]
    #[cfg_attr(feature = "serde", serde(rename = "compressed_data"))]
    pub distribution: Vec<u64>,
    pub amount: u64,
}

#[cfg(feature = "epee")]
epee_object! {
    DistributionCompressedBinary,
    start_height: u64,
    base: u64,
    distribution: Vec<u64>,
    amount: u64,
}

/// Serializer function for [`DistributionCompressedBinary::distribution`].
///
/// 1. Compresses the distribution array
/// 2. Serializes the compressed data
#[cfg(feature = "serde")]
#[expect(clippy::ptr_arg)]
fn serialize_distribution_as_compressed_data<S>(v: &Vec<u64>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    compress_integer_array(v).serialize(s)
}

/// Deserializer function for [`DistributionCompressedBinary::distribution`].
///
/// 1. Deserializes as `compressed_data` field.
/// 2. Decompresses and returns the data
#[cfg(feature = "serde")]
fn deserialize_compressed_data_as_distribution<'de, D>(d: D) -> Result<Vec<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<u8>::deserialize(d).map(|v| decompress_integer_array(&v))
}

//---------------------------------------------------------------------------------------------------- Epee
#[cfg(feature = "epee")]
/// [`EpeeObjectBuilder`] for [`Distribution`].
///
/// Not for public usage.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct __DistributionEpeeBuilder {
    pub start_height: Option<u64>,
    pub base: Option<u64>,
    pub distribution: Option<Vec<u64>>,
    pub amount: Option<u64>,
    pub compressed_data: Option<Vec<u8>>,
    pub binary: Option<bool>,
    pub compress: Option<bool>,
}

#[cfg(feature = "epee")]
impl EpeeObjectBuilder<Distribution> for __DistributionEpeeBuilder {
    fn add_field<B: Buf>(&mut self, name: &str, r: &mut B) -> error::Result<bool> {
        macro_rules! read_epee_field {
            ($($field:ident),*) => {
                match name {
                    $(
                        stringify!($field) => { self.$field = Some(read_epee_value(r)?); },
                    )*
                    _ => return Ok(false),
                }
            };
        }

        read_epee_field! {
            start_height,
            base,
            amount,
            binary,
            compress,
            compressed_data,
            distribution
        }

        Ok(true)
    }

    fn finish(self) -> error::Result<Distribution> {
        const ELSE: error::Error = error::Error::Format("Required field was not found!");

        let start_height = self.start_height.ok_or(ELSE)?;
        let base = self.base.ok_or(ELSE)?;
        let amount = self.amount.ok_or(ELSE)?;

        let distribution = if let Some(compressed_data) = self.compressed_data {
            let distribution = decompress_integer_array(&compressed_data);
            Distribution::CompressedBinary(DistributionCompressedBinary {
                start_height,
                base,
                distribution,
                amount,
            })
        } else if let Some(distribution) = self.distribution {
            Distribution::Uncompressed(DistributionUncompressed {
                binary: self.binary.ok_or(ELSE)?,
                distribution,
                start_height,
                base,
                amount,
            })
        } else {
            return Err(ELSE);
        };

        Ok(distribution)
    }
}

#[cfg(feature = "epee")]
impl EpeeObject for Distribution {
    type Builder = __DistributionEpeeBuilder;

    fn number_of_fields(&self) -> u64 {
        match self {
            // Inner struct fields + `compress`.
            Self::Uncompressed(s) => s.number_of_fields() + 1,
            // Inner struct fields + `compress` + `binary`.
            Self::CompressedBinary(s) => s.number_of_fields() + 2,
        }
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> error::Result<()> {
        match self {
            Self::Uncompressed(DistributionUncompressed {
                start_height,
                base,
                distribution,
                amount,
                binary,
            }) => {
                write_field(amount, "amount", w)?;
                write_field(start_height, "start_height", w)?;
                write_field(binary, "binary", w)?;
                write_field(false, "compress", w)?;
                if binary {
                    write_field(ContainerAsBlob::from(distribution), "distribution", w)?;
                } else {
                    write_field(distribution, "distribution", w)?;
                }
                write_field(base, "base", w)?;
            }

            Self::CompressedBinary(DistributionCompressedBinary {
                start_height,
                base,
                distribution,
                amount,
            }) => {
                let compressed_data = compress_integer_array(&distribution);

                write_field(amount, "amount", w)?;
                write_field(start_height, "start_height", w)?;
                write_field(true, "binary", w)?;
                write_field(true, "compress", w)?;
                write_field(compressed_data, "compressed_data", w)?;
                write_field(base, "base", w)?;
            }
        }

        Ok(())
    }
}

//---------------------------------------------------------------------------------------------------- Tests
#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    /// Tests that [`compress_integer_array`] outputs as expected.
    #[test]
    fn compress() {
        let varints = &[16_384, 16_383, 16_382, 16_381];
        let bytes = compress_integer_array(varints);

        let expected = vec![128, 128, 1, 255, 127, 254, 127, 253, 127];
        assert_eq!(expected, bytes);
    }

    /// Tests that [`decompress_integer_array`] outputs as expected.
    #[test]
    fn decompress() {
        let bytes = &[128, 128, 1, 255, 127, 254, 127, 253, 127];
        let varints = decompress_integer_array(bytes);

        let expected = vec![16_384, 16_383, 16_382, 16_381];
        assert_eq!(expected, varints);
    }

    #[cfg(feature = "epee")]
    #[test]
    fn compressed_binary_epee_roundtrip() {
        use crate::{base::AccessResponseBase, json::GetOutputDistributionResponse};

        let response = GetOutputDistributionResponse {
            base: AccessResponseBase::OK,
            distributions: vec![Distribution::CompressedBinary(
                DistributionCompressedBinary {
                    start_height: 1,
                    base: 2,
                    distribution: vec![16_384, 16_383, 16_382, 16_381],
                    amount: 0,
                },
            )],
        };

        let bytes = cuprate_epee_encoding::to_bytes(response.clone()).unwrap();
        assert!(bytes
            .as_ref()
            .windows("compressed_data".len())
            .any(|window| window == b"compressed_data"));

        let field_position = |field: &[u8]| {
            bytes
                .as_ref()
                .windows(field.len())
                .position(|window| window == field)
                .unwrap()
        };

        assert!(
            field_position(b"amount") < field_position(b"start_height")
                && field_position(b"start_height") < field_position(b"binary")
                && field_position(b"binary") < field_position(b"compress")
                && field_position(b"compress") < field_position(b"compressed_data")
                && field_position(b"compressed_data") < field_position(b"base")
        );

        let mut bytes = bytes.freeze();
        let decoded = cuprate_epee_encoding::from_bytes(&mut bytes).unwrap();
        assert_eq!(response, decoded);
    }
}
