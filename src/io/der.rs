// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Building blocks for parsing DER-encoded ASN.1 structures.
//!
//! This module contains the foundational parts of an ASN.1 DER parser.

use super::Positive;
use crate::errors::{Error, ErrorKind, Result};
use untrusted;

pub const CONSTRUCTED: u8 = 1 << 5;
pub const CONTEXT_SPECIFIC: u8 = 2 << 6;

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Tag {
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    OID = 0x06,
    Sequence = CONSTRUCTED | 0x10, // 0x30
    UTCTime = 0x17,
    GeneralizedTime = 0x18,

    ContextSpecificConstructed0 = CONTEXT_SPECIFIC | CONSTRUCTED | 0,
    ContextSpecificConstructed1 = CONTEXT_SPECIFIC | CONSTRUCTED | 1,
    ContextSpecificConstructed3 = CONTEXT_SPECIFIC | CONSTRUCTED | 3,
}

impl From<Tag> for usize {
    fn from(tag: Tag) -> Self {
        tag as Self
    }
}

impl From<Tag> for u8 {
    fn from(tag: Tag) -> Self {
        tag as Self
    } // XXX: narrowing conversion.
}

pub fn expect_tag_and_get_value<'a>(
    input: &mut untrusted::Reader<'a>,
    tag: Tag,
) -> Result<untrusted::Input<'a>> {
    let (actual_tag, inner) = read_tag_and_get_value(input).unwrap();
    if usize::from(tag) != usize::from(actual_tag) {
        return Err(Error::from(ErrorKind::CryptoError));
    }
    Ok(inner)
}

pub fn read_tag_and_get_value<'a>(
    input: &mut untrusted::Reader<'a>,
) -> Result<(u8, untrusted::Input<'a>)> {
    let tag = input.read_byte().unwrap();
    if (tag & 0x1F) == 0x1F {
        return Err(Error::from(ErrorKind::CryptoError)); // High tag number form is not allowed.
    }
    // If the high order bit of the first byte is set to zero then the length
    // is encoded in the seven remaining bits of that byte. Otherwise, those
    // seven bits represent the number of bytes used to encode the length.
    let length = match input.read_byte().unwrap() {
        n if (n & 0x80) == 0 => usize::from(n),
        0x81 => {
            let second_byte = input.read_byte().unwrap();
            if second_byte < 128 {
                return Err(Error::from(ErrorKind::CryptoError)); // Not the canonical encoding.
            }
            usize::from(second_byte)
        }
        0x82 => {
            let second_byte = usize::from(input.read_byte().unwrap());
            let third_byte = usize::from(input.read_byte().unwrap());
            let combined = (second_byte << 8) | third_byte;
            if combined < 256 {
                return Err(Error::from(ErrorKind::CryptoError)); // Not the canonical encoding.
            }
            combined
        }
        _ => {
            return Err(Error::from(ErrorKind::CryptoError)); // We don't support longer lengths.
        }
    };

    let inner = input.read_bytes(length).unwrap();
    Ok((tag, inner))
}

pub fn bit_string_with_no_unused_bits<'a>(
    input: &mut untrusted::Reader<'a>,
) -> Result<untrusted::Input<'a>> {
    match nested(
        input,
        Tag::BitString,
        Error::from(ErrorKind::CryptoError),
        |value| {
            let unused_bits_at_end = value.read_byte().unwrap();
            if unused_bits_at_end != 0 {
                return Err(Error::from(ErrorKind::CryptoError));
            }
            Ok(value.read_bytes_to_end())
        },
    ) {
        Ok(x) => Ok(x),
        Err(_) => Err(Error::from(ErrorKind::CryptoError)),
    }
}

// TODO: investigate taking decoder as a reference to reduce generated code
// size.
pub fn nested<'a, F, R, E>(
    input: &mut untrusted::Reader<'a>,
    tag: Tag,
    error: E,
    decoder: F,
) -> std::result::Result<R, E>
where
    F: FnOnce(&mut untrusted::Reader<'a>) -> std::result::Result<R, E>,
{
    let inner = expect_tag_and_get_value(input, tag).unwrap();
    inner.read_all(error, decoder)
}

fn nonnegative_integer<'a>(
    input: &mut untrusted::Reader<'a>,
    min_value: u8,
) -> Result<untrusted::Input<'a>> {
    // Verify that |input|, which has had any leading zero stripped off, is the
    // encoding of a value of at least |min_value|.
    fn check_minimum(input: untrusted::Input, min_value: u8) -> Result<()> {
        input.read_all(Error::from(ErrorKind::CryptoError), |input| {
            let first_byte = input.read_byte().unwrap();
            if input.at_end() && first_byte < min_value {
                return Err(Error::from(ErrorKind::CryptoError));
            }
            let _ = input.read_bytes_to_end();
            Ok(())
        })
    }

    let value = expect_tag_and_get_value(input, Tag::Integer).unwrap();

    value.read_all(Error::from(ErrorKind::CryptoError), |input| {
        // Empty encodings are not allowed.
        let first_byte = input.read_byte().unwrap();

        if first_byte == 0 {
            if input.at_end() {
                // |value| is the legal encoding of zero.
                if min_value > 0 {
                    return Err(Error::from(ErrorKind::CryptoError));
                }
                return Ok(value);
            }

            let r = input.read_bytes_to_end();
            r.read_all(Error::from(ErrorKind::CryptoError), |input| {
                let second_byte = input.read_byte().unwrap();
                if (second_byte & 0x80) == 0 {
                    // A leading zero is only allowed when the value's high bit
                    // is set.
                    return Err(Error::from(ErrorKind::CryptoError));
                }
                let _ = input.read_bytes_to_end();
                Ok(())
            })
            .unwrap();
            check_minimum(r, min_value).unwrap();
            return Ok(r);
        }

        // Negative values are not allowed.
        if (first_byte & 0x80) != 0 {
            return Err(Error::from(ErrorKind::CryptoError));
        }

        let _ = input.read_bytes_to_end();
        check_minimum(value, min_value).unwrap();
        Ok(value)
    })
}

/// Parse as integer with a value in the in the range [0, 255], returning its
/// numeric value. This is typically used for parsing version numbers.
#[inline]
pub fn small_nonnegative_integer(input: &mut untrusted::Reader) -> Result<u8> {
    let value = nonnegative_integer(input, 0).unwrap();
    value.read_all(Error::from(ErrorKind::CryptoError), |input| {
        let r = input.read_byte().unwrap();
        Ok(r)
    })
}

/// Parses a positive DER integer, returning the big-endian-encoded value,
/// sans any leading zero byte.
pub fn positive_integer<'a>(input: &mut untrusted::Reader<'a>) -> Result<Positive<'a>> {
    Ok(Positive::new_non_empty_without_leading_zeros(
        nonnegative_integer(input, 1).unwrap(),
    ))
}
