use crate::{Error, Result};

/// A stack-only canonical DNS hostname. Unicode must be converted to IDNA by
/// the import/UI layer; wire names outside hostname syntax are not policy keys.
pub(crate) struct Domain {
    bytes: [u8; 253],
    len: usize,
}
impl Domain {
    pub(crate) fn parse(input: &str) -> Result<Self> {
        let input = input.strip_suffix('.').unwrap_or(input);
        if input.is_empty() || input.len() > 253 {
            return Err(Error::new(
                "hostname must contain 1–253 ASCII bytes; use IDNA A-labels for Unicode",
            ));
        }
        let mut result = Self {
            bytes: [0; 253],
            len: input.len(),
        };
        let mut label_len = 0;
        let mut last_was_hyphen = false;
        let mut numeric = true;
        // Validate labels and normalize case in one pass. A colon or non-ASCII
        // byte fails here, so only numeric/dotted names need an IPv4 parse.
        for (out, byte) in result.bytes.iter_mut().zip(input.bytes()) {
            if byte == b'.' {
                if label_len == 0 || last_was_hyphen {
                    return Err(Error::new("invalid hostname label"));
                }
                label_len = 0;
            } else {
                if !(byte.is_ascii_alphanumeric() || (byte == b'-' && label_len != 0)) {
                    return Err(Error::new("invalid hostname label"));
                }
                label_len += 1;
                if label_len > 63 {
                    return Err(Error::new("invalid hostname label"));
                }
                numeric &= byte.is_ascii_digit();
            }
            last_was_hyphen = byte == b'-';
            *out = byte.to_ascii_lowercase();
        }
        if label_len == 0 || last_was_hyphen {
            return Err(Error::new("invalid hostname label"));
        }
        if numeric && input.parse::<std::net::Ipv4Addr>().is_ok() {
            return Err(Error::new("IP addresses are not domain rules"));
        }
        Ok(result)
    }
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    pub(crate) fn as_str(&self) -> &str {
        // Construction proves ASCII. No unchecked conversions in production.
        std::str::from_utf8(&self.bytes[..self.len]).expect("validated ASCII hostname")
    }
}
