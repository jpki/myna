//! 軽量 BER TLV パーサ
//!
//! JPKI カードデータの読み取りに必要な最小限の BER デコード機能を提供する。

use std::fmt;

/// BER TLV のパース結果
#[allow(clippy::upper_case_acronyms)]
pub struct TLV<'a> {
    /// タグバイト列（short form: 1バイト、long form: 2バイト以上）
    pub tag: u32,
    /// TLV の value 部分
    pub data: &'a [u8],
}

/// BER パースエラー
#[derive(Debug)]
pub enum BerError {
    /// データ不足（追加で必要なバイト数）
    Incomplete(usize),
    /// 不正なエンコーディング
    Invalid(&'static str),
}

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BerError::Incomplete(n) => write!(f, "データが{}バイト不足しています", n),
            BerError::Invalid(msg) => write!(f, "不正な BER エンコーディング: {}", msg),
        }
    }
}

/// タグを読み取り (タグ値, 消費バイト数) を返す
fn read_tag(input: &[u8]) -> Result<(u32, usize), BerError> {
    if input.is_empty() {
        return Err(BerError::Incomplete(1));
    }
    let first = input[0];
    if first & 0x1f != 0x1f {
        // Short form: タグ番号が 1 バイトに収まる
        return Ok((first as u32, 1));
    }
    // Long form: 後続バイトの bit7 が 0 になるまで読む
    let mut tag = first as u32;
    let mut i = 1;
    loop {
        if i >= input.len() {
            return Err(BerError::Incomplete(1));
        }
        tag = (tag << 8) | input[i] as u32;
        i += 1;
        if input[i - 1] & 0x80 == 0 {
            break;
        }
    }
    Ok((tag, i))
}

/// 長さを読み取り (値の長さ, 消費バイト数) を返す
fn read_length(input: &[u8]) -> Result<(usize, usize), BerError> {
    if input.is_empty() {
        return Err(BerError::Incomplete(1));
    }
    let first = input[0];
    if first < 0x80 {
        // Short form: 長さが 1 バイトに収まる (0–127)
        return Ok((first as usize, 1));
    }
    if first == 0x80 {
        return Err(BerError::Invalid("indefinite length not supported"));
    }
    let num_bytes = (first & 0x7f) as usize;
    if 1 + num_bytes > input.len() {
        return Err(BerError::Incomplete(1 + num_bytes - input.len()));
    }
    let mut len: usize = 0;
    for b in &input[1..1 + num_bytes] {
        len = (len << 8) | *b as usize;
    }
    Ok((len, 1 + num_bytes))
}

/// BER TLV を 1 つパースし `(残りバイト列, TLV)` を返す
///
/// データが不足している場合は `Err(BerError::Incomplete(n))` で
/// 追加で必要なバイト数 `n` を返す。
pub fn parse(input: &[u8]) -> Result<(&[u8], TLV<'_>), BerError> {
    let (tag, tag_len) = read_tag(input)?;
    let (value_len, len_len) = read_length(&input[tag_len..])?;
    let header_len = tag_len + len_len;
    let total_len = header_len + value_len;
    if input.len() < total_len {
        return Err(BerError::Incomplete(total_len - input.len()));
    }
    let data = &input[header_len..total_len];
    let remaining = &input[total_len..];
    Ok((remaining, TLV { tag, data }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_tag_short_length() {
        // tag=0x30 (SEQUENCE), length=3, value=[0x01, 0x02, 0x03]
        let input = [0x30, 0x03, 0x01, 0x02, 0x03];
        let (rem, tlv) = parse(&input).unwrap();
        assert_eq!(tlv.tag, 0x30);
        assert_eq!(tlv.data, &[0x01, 0x02, 0x03]);
        assert!(rem.is_empty());
    }

    #[test]
    fn short_tag_with_remaining() {
        let input = [0x04, 0x02, 0xAA, 0xBB, 0x05, 0x00];
        let (rem, tlv) = parse(&input).unwrap();
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.data, &[0xAA, 0xBB]);
        assert_eq!(rem, &[0x05, 0x00]);
    }

    #[test]
    fn long_tag_long_length() {
        // tag=0xff40 (private, 2-byte), length=0x82 0x00 0x9f (159)
        let bytes = [0xff, 0x40, 0x82, 0x00, 0x9f];
        match parse(&bytes) {
            Err(BerError::Incomplete(n)) => assert_eq!(n, 159),
            other => panic!("expected Incomplete(159), got {:?}", other.err()),
        }
    }

    #[test]
    fn long_length_one_byte() {
        // tag=0x30, length=0x81 0x80 (128)
        let mut input = vec![0x30, 0x81, 0x80];
        input.extend(vec![0x00; 128]);
        let (rem, tlv) = parse(&input).unwrap();
        assert_eq!(tlv.tag, 0x30);
        assert_eq!(tlv.data.len(), 128);
        assert!(rem.is_empty());
    }

    #[test]
    fn empty_input() {
        assert!(matches!(parse(&[]), Err(BerError::Incomplete(1))));
    }
}
