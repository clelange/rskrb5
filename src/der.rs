pub(crate) fn trim_zero_padded_der(bytes: &[u8]) -> &[u8] {
    let Some(end) = top_level_der_end(bytes) else {
        return bytes;
    };
    if bytes[end..].iter().all(|byte| *byte == 0) {
        &bytes[..end]
    } else {
        bytes
    }
}

fn top_level_der_end(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }

    let mut offset = 1;
    if bytes[0] & 0x1f == 0x1f {
        loop {
            let byte = *bytes.get(offset)?;
            offset += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }

    let first_len = *bytes.get(offset)?;
    offset += 1;
    let len = if first_len & 0x80 == 0 {
        usize::from(first_len)
    } else {
        let count = usize::from(first_len & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return None;
        }
        let len_bytes = bytes.get(offset..offset.checked_add(count)?)?;
        offset += count;
        let mut len = 0usize;
        for byte in len_bytes {
            len = (len << 8) | usize::from(*byte);
        }
        len
    };

    let end = offset.checked_add(len)?;
    (end <= bytes.len()).then_some(end)
}

#[cfg(test)]
mod tests {
    use super::trim_zero_padded_der;

    #[test]
    fn leaves_exact_der_unchanged() {
        let bytes = [0x30, 0x03, 0x04, 0x01, 0x00];
        assert_eq!(trim_zero_padded_der(&bytes), bytes);
    }

    #[test]
    fn trims_only_zero_bytes_after_top_level_der_value() {
        let bytes = [0x30, 0x03, 0x04, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(trim_zero_padded_der(&bytes), [0x30, 0x03, 0x04, 0x01, 0x00]);
    }

    #[test]
    fn leaves_nonzero_trailing_bytes_for_strict_decoder_errors() {
        let bytes = [0x30, 0x03, 0x04, 0x01, 0x00, 0x01];
        assert_eq!(trim_zero_padded_der(&bytes), bytes);
    }

    #[test]
    fn leaves_malformed_der_unchanged() {
        let bytes = [0x30, 0x81];
        assert_eq!(trim_zero_padded_der(&bytes), bytes);
    }
}
