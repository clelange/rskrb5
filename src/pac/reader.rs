use super::{Error, FileTime};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(super) fn remaining_bytes(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    pub(super) fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.read_bytes(1)?[0])
    }

    pub(super) fn read_u16(&mut self) -> Result<u16, Error> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(super) fn read_u32(&mut self) -> Result<u32, Error> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(super) fn read_u64(&mut self) -> Result<u64, Error> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(super) fn read_filetime(&mut self) -> Result<FileTime, Error> {
        Ok(FileTime::from_ticks(self.read_u64()?))
    }

    pub(super) fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(len).ok_or(Error::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(Error::Truncated {
                offset: self.offset,
                needed: len,
                remaining: self.remaining(),
            });
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    pub(super) fn align(&mut self, alignment: usize) -> Result<(), Error> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(Error::InvalidAlignment(alignment));
        }
        let aligned = (self.offset + alignment - 1) & !(alignment - 1);
        if aligned > self.bytes.len() {
            return Err(Error::Truncated {
                offset: self.offset,
                needed: aligned - self.offset,
                remaining: self.remaining(),
            });
        }
        self.offset = aligned;
        Ok(())
    }
}
