const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    OddLength,
    BadDigit,
    WrongLength { expected: usize, got: usize },
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OddLength => write!(f, "hex 문자열 길이가 홀수"),
            Self::BadDigit => write!(f, "hex가 아닌 문자 포함"),
            Self::WrongLength { expected, got } => {
                write!(f, "hex 길이 불일치: {expected}바이트 기대, {got}바이트")
            }
        }
    }
}

impl std::error::Error for HexError {}

fn digit(c: u8) -> Result<u8, HexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(HexError::BadDigit),
    }
}

pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    let raw = s.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let hi = digit(pair[0])?;
        let lo = digit(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

pub fn decode_fixed<const N: usize>(s: &str) -> Result<[u8; N], HexError> {
    // 길이부터 봅니다. 먼저 decode 하면 신뢰할 수 없는 입력이 아무리 길어도 통째로
    // 할당하고 해독한 뒤에야 거부하게 됩니다
    if s.len() != N.saturating_mul(2) {
        return Err(HexError::WrongLength {
            expected: N,
            got: s.len() / 2,
        });
    }
    let v = decode(s)?;
    if v.len() != N {
        return Err(HexError::WrongLength {
            expected: N,
            got: v.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let bytes = [0x00u8, 0x0f, 0xff, 0xa5, 0x10];
        assert_eq!(encode(&bytes), "000fffa510");
        assert_eq!(decode("000fffa510").unwrap(), bytes);
    }

    #[test]
    fn rejects_uppercase() {
        assert_eq!(decode("00FF"), Err(HexError::BadDigit));
    }

    #[test]
    fn rejects_odd_length() {
        assert_eq!(decode("abc"), Err(HexError::OddLength));
    }

    #[test]
    fn rejects_non_hex() {
        assert_eq!(decode("zz"), Err(HexError::BadDigit));
    }

    #[test]
    fn fixed_length_enforced() {
        assert!(decode_fixed::<2>("abcd").is_ok());
        assert!(matches!(
            decode_fixed::<32>("abcd"),
            Err(HexError::WrongLength {
                expected: 32,
                got: 2
            })
        ));
    }
}
