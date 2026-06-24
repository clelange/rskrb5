use super::{Error, ObjectIdentifier, oid};

pub(super) const TAG_SEQUENCE: u8 = 0x30;
pub(super) const TAG_OBJECT_IDENTIFIER: u8 = 0x06;
pub(super) const TAG_OCTET_STRING: u8 = 0x04;
pub(super) const TAG_BIT_STRING: u8 = 0x03;
pub(super) const TAG_ENUMERATED: u8 = 0x0a;
pub(super) const TAG_APPLICATION_0: u8 = 0x60;
pub(super) const TAG_CONTEXT_0: u8 = 0xa0;
pub(super) const TAG_CONTEXT_1: u8 = 0xa1;
pub(super) const TAG_CONTEXT_2: u8 = 0xa2;
pub(super) const TAG_CONTEXT_3: u8 = 0xa3;

#[derive(Clone, Copy)]
pub(super) struct Tlv<'a> {
    pub(super) tag: u8,
    pub(super) value: &'a [u8],
}

pub(super) struct DerReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn read_tlv(&mut self) -> Result<Tlv<'a>, Error> {
        if self.offset >= self.bytes.len() {
            return Err(Error::TruncatedDer);
        }

        let tag = self.bytes[self.offset];
        self.offset += 1;
        if tag & 0x1f == 0x1f {
            return Err(Error::HighTagNumber);
        }
        let length = self.read_len()?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(Error::LengthExceedsInput)?;
        if end > self.bytes.len() {
            return Err(Error::LengthExceedsInput);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(Tlv { tag, value })
    }

    pub(super) fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(len).ok_or(Error::TruncatedDer)?;
        if end > self.bytes.len() {
            return Err(Error::TruncatedDer);
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    pub(super) fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    pub(super) fn finish(&self) -> Result<(), Error> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::TrailingData)
        }
    }

    fn read_len(&mut self) -> Result<usize, Error> {
        if self.offset >= self.bytes.len() {
            return Err(Error::TruncatedDer);
        }
        let first = self.bytes[self.offset];
        self.offset += 1;
        if first & 0x80 == 0 {
            return Ok(first.into());
        }

        let count = (first & 0x7f) as usize;
        if count == 0 {
            return Err(Error::IndefiniteLength);
        }
        if count > std::mem::size_of::<usize>() || self.offset + count > self.bytes.len() {
            return Err(Error::LengthExceedsInput);
        }

        let mut length = 0usize;
        for byte in &self.bytes[self.offset..self.offset + count] {
            length = (length << 8) | usize::from(*byte);
        }
        self.offset += count;
        Ok(length)
    }
}

pub(super) fn read_single_tlv(bytes: &[u8], expected_tag: u8) -> Result<Tlv<'_>, Error> {
    let mut reader = DerReader::new(bytes);
    let tlv = reader.read_tlv()?;
    reader.finish()?;
    if tlv.tag != expected_tag {
        return Err(Error::UnexpectedTag {
            expected: expected_tag,
            actual: tlv.tag,
        });
    }
    Ok(tlv)
}

pub(super) fn decode_oid_tlv(tlv: Tlv<'_>) -> Result<ObjectIdentifier, Error> {
    if tlv.tag != TAG_OBJECT_IDENTIFIER {
        return Err(Error::UnexpectedTag {
            expected: TAG_OBJECT_IDENTIFIER,
            actual: tlv.tag,
        });
    }
    decode_oid_value(tlv.value)
}

fn decode_oid_value(value: &[u8]) -> Result<ObjectIdentifier, Error> {
    if value.is_empty() {
        return Err(Error::InvalidOidEncoding);
    }

    let first = value[0];
    let first_arc = u32::from(first / 40);
    let second_arc = u32::from(first % 40);
    let mut arcs = vec![first_arc, second_arc];
    let mut idx = 1;
    while idx < value.len() {
        let mut arc = 0u32;
        loop {
            if idx >= value.len() {
                return Err(Error::InvalidOidEncoding);
            }
            let byte = value[idx];
            idx += 1;
            arc = arc.checked_shl(7).ok_or(Error::InvalidOidEncoding)? | u32::from(byte & 0x7f);
            if byte & 0x80 == 0 {
                break;
            }
        }
        arcs.push(arc);
    }

    ObjectIdentifier::from_arcs(arcs)
}

pub(super) fn encode_oid(oid: &ObjectIdentifier) -> Result<Vec<u8>, Error> {
    oid::validate_arcs(oid.arcs())?;
    let mut value = Vec::new();
    let first = oid.arcs()[0]
        .checked_mul(40)
        .and_then(|base| base.checked_add(oid.arcs()[1]))
        .ok_or(Error::InvalidOid)?;
    encode_base128(first, &mut value);
    for arc in &oid.arcs()[2..] {
        encode_base128(*arc, &mut value);
    }
    Ok(encode_tlv(TAG_OBJECT_IDENTIFIER, &value))
}

fn encode_base128(mut value: u32, out: &mut Vec<u8>) {
    let mut stack = [0u8; 5];
    let mut len = 1;
    stack[4] = (value & 0x7f) as u8;
    value >>= 7;
    while value > 0 {
        len += 1;
        stack[5 - len] = ((value & 0x7f) as u8) | 0x80;
        value >>= 7;
    }
    out.extend_from_slice(&stack[5 - len..]);
}

pub(super) fn decode_u32(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.is_empty() || bytes.len() > 5 {
        return Err(Error::InvalidInteger);
    }
    if bytes[0] & 0x80 != 0 {
        return Err(Error::InvalidInteger);
    }
    let mut value = 0u32;
    for byte in bytes {
        value = value.checked_shl(8).ok_or(Error::InvalidInteger)? | u32::from(*byte);
    }
    Ok(value)
}

pub(super) fn encode_u32(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let mut encoded = bytes[first_nonzero..].to_vec();
    if encoded[0] & 0x80 != 0 {
        encoded.insert(0, 0);
    }
    encoded
}

pub(super) fn encode_explicit(tag: u8, inner_der: &[u8]) -> Vec<u8> {
    encode_tlv(tag, inner_der)
}

pub(super) fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + value.len());
    out.push(tag);
    encode_len(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

fn encode_len(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
        return;
    }

    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .expect("non-short length is nonzero");
    let length_bytes = &bytes[first..];
    out.push(0x80 | length_bytes.len() as u8);
    out.extend_from_slice(length_bytes);
}
