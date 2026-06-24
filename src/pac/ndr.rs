use super::reader::Reader;
use super::{
    CLAIM_TYPE_ID_BOOLEAN, CLAIM_TYPE_ID_INT64, CLAIM_TYPE_ID_STRING, CLAIM_TYPE_ID_UINT64,
    ClaimEntry, ClaimValues, ClaimsArray, DomainGroupMembership, Error, GroupMembership,
    RpcUnicodeString, SecpkgSupplementalCredential, Sid, SidAndAttributes,
};

const MAX_REASONABLE_NDR_COUNT: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RpcUnicodeStringDescriptor {
    length: u16,
    maximum_length: u16,
    referent_id: u32,
}

impl RpcUnicodeStringDescriptor {
    pub(super) fn read(reader: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            length: reader.read_u16()?,
            maximum_length: reader.read_u16()?,
            referent_id: reader.read_u32()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClaimsArrayDescriptor {
    claims_source_type: u16,
    claims_count: u32,
    claim_entries_ref: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClaimEntryDescriptor {
    id_ref: u32,
    claim_type: u16,
    value_count: u32,
    values_ref: u32,
}

pub(super) fn read_ndr_wrapper(reader: &mut Reader<'_>, target: &'static str) -> Result<(), Error> {
    let minimum = 20;
    if reader.len() < minimum {
        return Err(Error::TooShort {
            target,
            minimum,
            actual: reader.len(),
        });
    }

    let integer_endian = reader.read_u8()?;
    let character_set = reader.read_u8()?;
    let floating_point = reader.read_u8()?;
    let reserved = reader.read_u8()?;
    if integer_endian != 1 || character_set != 0x10 || floating_point != 0x08 || reserved != 0 {
        return Err(Error::InvalidNdrHeader);
    }

    let _fill = reader.read_u32()?;
    let object_len = reader.read_u32()?;
    let _reserved = reader.read_u32()?;
    let object_len = usize::try_from(object_len).map_err(|_| Error::LengthOverflow)?;
    if object_len > reader.len().saturating_sub(16) {
        return Err(Error::InvalidNdrObjectLength {
            object_len,
            remaining: reader.len().saturating_sub(16),
        });
    }

    let top_level_referent = reader.read_u32()?;
    if top_level_referent == 0 {
        return Err(Error::MissingNdrPointer(target));
    }
    Ok(())
}

pub(super) fn read_ndr_u16(reader: &mut Reader<'_>) -> Result<u16, Error> {
    reader.align(2)?;
    reader.read_u16()
}

pub(super) fn read_ndr_u32(reader: &mut Reader<'_>) -> Result<u32, Error> {
    reader.align(4)?;
    reader.read_u32()
}

fn read_ndr_u64(reader: &mut Reader<'_>) -> Result<u64, Error> {
    reader.align(8)?;
    reader.read_u64()
}

fn read_ndr_reasonable_count(reader: &mut Reader<'_>, target: &'static str) -> Result<u32, Error> {
    let count = read_ndr_u32(reader)?;
    if count > MAX_REASONABLE_NDR_COUNT {
        return Err(Error::UnreasonableNdrCount { target, count });
    }
    Ok(count)
}

pub(super) fn read_deferred_u8_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<u8>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let len = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let bytes = reader.read_bytes(len)?.to_vec();
    reader.align(4)?;
    Ok(bytes)
}

pub(super) fn read_counted_supplemental_credentials(
    reader: &mut Reader<'_>,
    count: u32,
) -> Result<Vec<SecpkgSupplementalCredential>, Error> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        descriptors.push((
            RpcUnicodeStringDescriptor::read(reader)?,
            read_ndr_u32(reader)?,
            read_ndr_u32(reader)?,
        ));
    }

    let mut supplemental_credentials = Vec::with_capacity(count);
    for (package_name, credential_size, credentials_ref) in descriptors {
        let package_name = read_deferred_unicode_string(
            reader,
            package_name,
            "SECPKGSupplementalCred.PackageName",
        )?;
        let credential_bytes = read_deferred_u8_array(
            reader,
            credentials_ref,
            credential_size,
            "SECPKGSupplementalCred.Credentials",
        )?;
        supplemental_credentials.push(SecpkgSupplementalCredential {
            package_name,
            credential_size,
            credentials: credential_bytes,
        });
    }
    Ok(supplemental_credentials)
}

pub(super) fn read_deferred_rpc_unicode_strings(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<RpcUnicodeString>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        descriptors.push(RpcUnicodeStringDescriptor::read(reader)?);
    }

    let mut strings = Vec::with_capacity(count);
    for descriptor in descriptors {
        strings.push(read_deferred_unicode_string(reader, descriptor, target)?);
    }
    Ok(strings)
}

pub(super) fn read_deferred_claims_arrays(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<ClaimsArray>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        descriptors.push(ClaimsArrayDescriptor {
            claims_source_type: read_ndr_u16(reader)?,
            claims_count: read_ndr_u32(reader)?,
            claim_entries_ref: read_ndr_u32(reader)?,
        });
    }

    let mut arrays = Vec::with_capacity(count);
    for descriptor in descriptors {
        let claim_entries = read_deferred_claim_entries(
            reader,
            descriptor.claim_entries_ref,
            descriptor.claims_count,
            "ClaimsArray.ClaimEntries",
        )?;
        arrays.push(ClaimsArray {
            claims_source_type: descriptor.claims_source_type,
            claims_count: descriptor.claims_count,
            claim_entries,
        });
    }
    Ok(arrays)
}

fn read_deferred_claim_entries(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<ClaimEntry>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        descriptors.push(read_claim_entry_descriptor(reader)?);
    }

    let mut entries = Vec::with_capacity(count);
    for descriptor in descriptors {
        let id = read_deferred_claim_string(reader, descriptor.id_ref, "ClaimEntry.ID")?;
        let values = match descriptor.claim_type {
            CLAIM_TYPE_ID_INT64 => ClaimValues::Int64(read_deferred_i64_array(
                reader,
                descriptor.values_ref,
                descriptor.value_count,
                "ClaimEntry.Int64Values",
            )?),
            CLAIM_TYPE_ID_UINT64 => ClaimValues::UInt64(read_deferred_u64_array(
                reader,
                descriptor.values_ref,
                descriptor.value_count,
                "ClaimEntry.UInt64Values",
            )?),
            CLAIM_TYPE_ID_STRING => ClaimValues::String(read_deferred_lpwstr_array(
                reader,
                descriptor.values_ref,
                descriptor.value_count,
                "ClaimEntry.StringValues",
            )?),
            CLAIM_TYPE_ID_BOOLEAN => ClaimValues::Boolean(read_deferred_bool_array(
                reader,
                descriptor.values_ref,
                descriptor.value_count,
                "ClaimEntry.BooleanValues",
            )?),
            claim_type => return Err(Error::UnsupportedClaimType(claim_type)),
        };
        entries.push(ClaimEntry {
            id,
            claim_type: descriptor.claim_type,
            values,
        });
    }
    Ok(entries)
}

fn read_claim_entry_descriptor(reader: &mut Reader<'_>) -> Result<ClaimEntryDescriptor, Error> {
    let id_ref = read_ndr_u32(reader)?;
    let claim_type = read_ndr_u16(reader)?;
    let union_tag = read_ndr_u16(reader)?;
    if union_tag != claim_type {
        return Err(Error::InvalidClaimUnionTag {
            claim_type,
            union_tag,
        });
    }
    Ok(ClaimEntryDescriptor {
        id_ref,
        claim_type,
        value_count: read_ndr_u32(reader)?,
        values_ref: read_ndr_u32(reader)?,
    })
}

fn read_deferred_i64_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<i64>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(read_ndr_u64(reader)? as i64);
    }
    Ok(values)
}

fn read_deferred_u64_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<u64>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(read_ndr_u64(reader)?);
    }
    Ok(values)
}

fn read_deferred_bool_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<bool>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(reader.read_u8()? != 0);
    }
    reader.align(4)?;
    Ok(values)
}

fn read_deferred_lpwstr_array(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<String>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut string_refs = Vec::with_capacity(count);
    for _ in 0..count {
        string_refs.push(read_ndr_u32(reader)?);
    }

    let mut values = Vec::with_capacity(count);
    for string_ref in string_refs {
        values.push(read_deferred_claim_string(reader, string_ref, target)?);
    }
    Ok(values)
}

fn read_deferred_claim_string(
    reader: &mut Reader<'_>,
    referent_id: u32,
    target: &'static str,
) -> Result<String, Error> {
    if referent_id == 0 {
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_ndr_reasonable_count(reader, target)?;
    let offset = read_ndr_u32(reader)?;
    let actual_count = read_ndr_reasonable_count(reader, target)?;
    if offset > max_count || actual_count > max_count.saturating_sub(offset) {
        return Err(Error::InvalidNdrArrayBounds {
            target,
            max_count,
            offset,
            actual_count,
        });
    }

    let actual_count = usize::try_from(actual_count).map_err(|_| Error::LengthOverflow)?;
    let mut units = Vec::with_capacity(actual_count);
    for _ in 0..actual_count {
        units.push(reader.read_u16()?);
    }
    reader.align(4)?;

    if units.last().copied() == Some(0) {
        units.pop();
    }
    String::from_utf16(&units).map_err(|error| Error::InvalidUtf16 {
        target,
        message: error.to_string(),
    })
}

pub(super) fn ensure_zero_trailing(
    reader: &mut Reader<'_>,
    target: &'static str,
) -> Result<(), Error> {
    reader.align(4)?;
    if reader.remaining_bytes().iter().any(|byte| *byte != 0) {
        return Err(Error::TrailingNdrBytesAfter {
            target,
            remaining: reader.remaining(),
        });
    }
    Ok(())
}

pub(super) fn read_deferred_unicode_string(
    reader: &mut Reader<'_>,
    descriptor: RpcUnicodeStringDescriptor,
    target: &'static str,
) -> Result<RpcUnicodeString, Error> {
    if descriptor.maximum_length < descriptor.length {
        return Err(Error::InvalidRpcUnicodeString {
            target,
            length: descriptor.length,
            maximum_length: descriptor.maximum_length,
        });
    }
    if !descriptor.length.is_multiple_of(2) {
        return Err(Error::InvalidUtf16Length {
            target,
            bytes: descriptor.length.into(),
        });
    }
    if descriptor.referent_id == 0 {
        return Ok(RpcUnicodeString {
            length: descriptor.length,
            maximum_length: descriptor.maximum_length,
            value: String::new(),
        });
    }

    let max_count = read_reasonable_count(reader, target)?;
    let offset = reader.read_u32()?;
    let actual_count = read_reasonable_count(reader, target)?;
    if offset > max_count || actual_count > max_count.saturating_sub(offset) {
        return Err(Error::InvalidNdrArrayBounds {
            target,
            max_count,
            offset,
            actual_count,
        });
    }

    let actual_count = usize::try_from(actual_count).map_err(|_| Error::LengthOverflow)?;
    let mut units = Vec::with_capacity(actual_count);
    for _ in 0..actual_count {
        units.push(reader.read_u16()?);
    }
    reader.align(4)?;

    let logical_len = usize::from(descriptor.length / 2);
    if logical_len > units.len() {
        return Err(Error::InvalidRpcUnicodeStringData {
            target,
            expected_units: logical_len,
            actual_units: units.len(),
        });
    }

    let value = String::from_utf16(&units[..logical_len]).map_err(|error| Error::InvalidUtf16 {
        target,
        message: error.to_string(),
    })?;
    Ok(RpcUnicodeString {
        length: descriptor.length,
        maximum_length: descriptor.maximum_length,
        value,
    })
}

pub(super) fn read_deferred_group_memberships(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<GroupMembership>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut groups = Vec::with_capacity(count);
    for _ in 0..count {
        groups.push(GroupMembership {
            relative_id: reader.read_u32()?,
            attributes: reader.read_u32()?,
        });
    }
    Ok(groups)
}

pub(super) fn read_deferred_sid(
    reader: &mut Reader<'_>,
    referent_id: u32,
    target: &'static str,
) -> Result<Option<Sid>, Error> {
    if referent_id == 0 {
        return Ok(None);
    }

    let max_sub_authority_count = read_reasonable_count(reader, target)?;
    let revision = reader.read_u8()?;
    let sub_authority_count = reader.read_u8()?;
    if revision != 1 {
        return Err(Error::InvalidSidRevision(revision));
    }
    if u32::from(sub_authority_count) > max_sub_authority_count || sub_authority_count > 15 {
        return Err(Error::InvalidSidSubAuthorityCount {
            target,
            max_count: max_sub_authority_count,
            actual_count: sub_authority_count,
        });
    }

    let identifier_authority: [u8; 6] = reader
        .read_bytes(6)?
        .try_into()
        .expect("6-byte slice converts to array");
    let mut sub_authorities = Vec::with_capacity(sub_authority_count.into());
    for _ in 0..sub_authority_count {
        sub_authorities.push(reader.read_u32()?);
    }
    reader.align(4)?;

    Ok(Some(Sid {
        revision,
        identifier_authority,
        sub_authorities,
    }))
}

pub(super) fn read_deferred_sid_and_attributes(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<SidAndAttributes>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut refs_and_attributes = Vec::with_capacity(count);
    for _ in 0..count {
        refs_and_attributes.push((reader.read_u32()?, reader.read_u32()?));
    }

    let mut out = Vec::with_capacity(count);
    for (sid_ref, attributes) in refs_and_attributes {
        let sid =
            read_deferred_sid(reader, sid_ref, target)?.ok_or(Error::MissingNdrPointer(target))?;
        out.push(SidAndAttributes { sid, attributes });
    }
    Ok(out)
}

pub(super) fn read_deferred_domain_group_memberships(
    reader: &mut Reader<'_>,
    referent_id: u32,
    count: u32,
    target: &'static str,
) -> Result<Vec<DomainGroupMembership>, Error> {
    if referent_id == 0 {
        if count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::MissingNdrPointer(target));
    }

    let max_count = read_reasonable_count(reader, target)?;
    if max_count != count {
        return Err(Error::CountMismatch {
            target,
            expected: count,
            actual: max_count,
        });
    }

    let count = usize::try_from(count).map_err(|_| Error::LengthOverflow)?;
    let mut descriptors = Vec::with_capacity(count);
    for _ in 0..count {
        descriptors.push((reader.read_u32()?, reader.read_u32()?, reader.read_u32()?));
    }

    let mut groups = Vec::with_capacity(count);
    for (domain_id_ref, group_count, group_ids_ref) in descriptors {
        let domain_id = read_deferred_sid(reader, domain_id_ref, target)?
            .ok_or(Error::MissingNdrPointer(target))?;
        let group_ids =
            read_deferred_group_memberships(reader, group_ids_ref, group_count, target)?;
        groups.push(DomainGroupMembership {
            domain_id,
            group_count,
            group_ids,
        });
    }
    Ok(groups)
}

fn read_reasonable_count(reader: &mut Reader<'_>, target: &'static str) -> Result<u32, Error> {
    let count = reader.read_u32()?;
    if count > MAX_REASONABLE_NDR_COUNT {
        return Err(Error::UnreasonableNdrCount { target, count });
    }
    Ok(count)
}
