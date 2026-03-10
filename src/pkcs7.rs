/// PKCS#7 SignedData構造のASN.1 DERビルダー
///
/// カード上の秘密鍵を使ったCMS署名のために、PKCS#7 SignedData構造を
/// 手動でDER構築する。openssl crateのPkcs7::signは秘密鍵オブジェクトが
/// 必要なため、外部署名デバイス(スマートカード)との統合には使えない。

use openssl::hash::{hash, MessageDigest};
use openssl::x509::X509;

// --- DERエンコーディングヘルパー ---

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_length(content.len()));
    out.extend(content);
    out
}

fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    der_wrap(0x30, &content)
}

fn der_set(items: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    der_wrap(0x31, &content)
}

fn der_integer(value: u8) -> Vec<u8> {
    vec![0x02, 0x01, value]
}

fn der_integer_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    if bytes.is_empty() || bytes[0] & 0x80 != 0 {
        content.push(0x00);
    }
    content.extend(bytes);
    der_wrap(0x02, &content)
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    der_wrap(0x04, data)
}

// --- UTCTime ---

fn civil_from_epoch(epoch_secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let day_secs = epoch_secs.rem_euclid(86400) as u32;
    let days = epoch_secs.div_euclid(86400);
    let hour = day_secs / 3600;
    let min = (day_secs % 3600) / 60;
    let sec = day_secs % 60;

    // Howard Hinnant's civil_from_days algorithm
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    (year, m, d, hour, min, sec)
}

fn der_utc_time_now() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (year, month, day, hour, min, sec) = civil_from_epoch(secs);
    let time_str = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year % 100,
        month,
        day,
        hour,
        min,
        sec
    );
    der_wrap(0x17, time_str.as_bytes())
}

// --- OID定数 (DERエンコード済み: tag + length + value) ---

const OID_SIGNED_DATA: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
];
const OID_DATA: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
];
const OID_RSA_ENCRYPTION: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];
const OID_CONTENT_TYPE: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03,
];
const OID_SIGNING_TIME: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05,
];
const OID_MESSAGE_DIGEST: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
];
const OID_SHA1: [u8; 7] = [0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_SHA256: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];
const OID_SHA384: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
];
const OID_SHA512: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
];
const ASN1_NULL: [u8; 2] = [0x05, 0x00];

fn digest_algorithm_id(md: MessageDigest) -> Vec<u8> {
    let oid: &[u8] = if md == MessageDigest::sha1() {
        &OID_SHA1
    } else if md == MessageDigest::sha256() {
        &OID_SHA256
    } else if md == MessageDigest::sha384() {
        &OID_SHA384
    } else if md == MessageDigest::sha512() {
        &OID_SHA512
    } else {
        panic!("Unsupported digest algorithm");
    };
    der_sequence(&[oid, &ASN1_NULL])
}

/// 認証属性(authenticated attributes)をSET OFとしてDERエンコード
fn build_auth_attrs(content_digest: &[u8], signing_time_der: &[u8]) -> Vec<u8> {
    let content_type_attr = der_sequence(&[&OID_CONTENT_TYPE, &der_set(&[&OID_DATA])]);

    let signing_time_attr = der_sequence(&[&OID_SIGNING_TIME, &der_set(&[signing_time_der])]);

    let message_digest_attr = der_sequence(&[
        &OID_MESSAGE_DIGEST,
        &der_set(&[&der_octet_string(content_digest)]),
    ]);

    der_set(&[
        &content_type_attr,
        &signing_time_attr,
        &message_digest_attr,
    ])
}

/// 署名に必要なデータを準備する
///
/// Returns: (attrs_set_der, attrs_digest)
/// - attrs_set_der: SET OFタグ(0x31)でエンコードされた認証属性(署名検証用/PKCS#7埋め込み用)
/// - attrs_digest: 認証属性のハッシュ値(DigestInfoに包んでカードに送る)
pub fn prepare_signing(content: &[u8], md: MessageDigest) -> (Vec<u8>, Vec<u8>) {
    let content_digest = hash(md, content).unwrap();
    let signing_time = der_utc_time_now();
    let attrs_set = build_auth_attrs(&content_digest, &signing_time);
    let attrs_digest = hash(md, &attrs_set).unwrap().to_vec();
    (attrs_set, attrs_digest)
}

/// PKCS#7 SignedData構造の完全なDERを構築する
///
/// - content: 署名対象データ
/// - cert: 署名者の証明書
/// - signature: カードで計算された署名値
/// - md: ダイジェストアルゴリズム
/// - attrs_set: prepare_signingで作成された認証属性(SET OFタグ付き)
/// - detached: trueならコンテンツを含めない(デタッチ署名)
pub fn build_signed_data(
    content: &[u8],
    cert: &X509,
    signature: &[u8],
    md: MessageDigest,
    attrs_set: &[u8],
    detached: bool,
) -> Vec<u8> {
    let digest_alg_id = digest_algorithm_id(md);
    let cert_der = cert.to_der().unwrap();

    // IssuerAndSerialNumber
    let issuer_der = cert.issuer_name().to_der().unwrap();
    let serial_bytes = cert.serial_number().to_bn().unwrap().to_vec();
    let serial_der = der_integer_bytes(&serial_bytes);
    let issuer_and_serial = der_sequence(&[&issuer_der, &serial_der]);

    // signedAttrs: SET(0x31)タグを[0] IMPLICIT(0xa0)に変更
    let mut signed_attrs_implicit = attrs_set.to_vec();
    if !signed_attrs_implicit.is_empty() {
        signed_attrs_implicit[0] = 0xa0;
    }

    // SignatureAlgorithm
    let sig_alg_id = der_sequence(&[&OID_RSA_ENCRYPTION, &ASN1_NULL]);

    // SignerInfo
    let signer_info = der_sequence(&[
        &der_integer(1),
        &issuer_and_serial,
        &digest_alg_id,
        &signed_attrs_implicit,
        &sig_alg_id,
        &der_octet_string(signature),
    ]);

    // EncapsulatedContentInfo
    let content_info = if detached {
        der_sequence(&[&OID_DATA])
    } else {
        let explicit_content = der_wrap(0xa0, &der_octet_string(content));
        der_sequence(&[&OID_DATA, &explicit_content])
    };

    // Certificates [0] IMPLICIT SET OF Certificate
    let certs_implicit = der_wrap(0xa0, &cert_der);

    // SignedData
    let signed_data = der_sequence(&[
        &der_integer(1),
        &der_set(&[&digest_alg_id]),
        &content_info,
        &certs_implicit,
        &der_set(&[&signer_info]),
    ]);

    // 最外側のContentInfo
    let explicit_signed_data = der_wrap(0xa0, &signed_data);
    der_sequence(&[&OID_SIGNED_DATA, &explicit_signed_data])
}

/// 事前計算されたハッシュを使って署名準備する（PDF署名用）
///
/// prepare_signing と同じだが、content の代わりに既にハッシュ済みの値を受け取る。
pub fn prepare_signing_with_hash(content_hash: &[u8], md: MessageDigest) -> (Vec<u8>, Vec<u8>) {
    let signing_time = der_utc_time_now();
    let attrs_set = build_auth_attrs(content_hash, &signing_time);
    let attrs_digest = hash(md, &attrs_set).unwrap().to_vec();
    (attrs_set, attrs_digest)
}

/// detached モード専用の SignedData 構築（コンテンツなし、PDF署名用）
pub fn build_signed_data_detached(
    cert: &X509,
    signature: &[u8],
    md: MessageDigest,
    attrs_set: &[u8],
) -> Vec<u8> {
    build_signed_data(&[], cert, signature, md, attrs_set, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_length() {
        assert_eq!(der_length(0), vec![0x00]);
        assert_eq!(der_length(127), vec![0x7f]);
        assert_eq!(der_length(128), vec![0x81, 0x80]);
        assert_eq!(der_length(255), vec![0x81, 0xff]);
        assert_eq!(der_length(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_der_integer() {
        assert_eq!(der_integer(1), vec![0x02, 0x01, 0x01]);
    }

    #[test]
    fn test_der_integer_bytes() {
        // Positive number, no leading zero needed
        assert_eq!(der_integer_bytes(&[0x01]), vec![0x02, 0x01, 0x01]);
        // High bit set, needs leading zero
        assert_eq!(
            der_integer_bytes(&[0x80]),
            vec![0x02, 0x02, 0x00, 0x80]
        );
        // Empty bytes
        assert_eq!(der_integer_bytes(&[]), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_civil_from_epoch() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let (y, m, d, h, min, s) = civil_from_epoch(1704067200);
        assert_eq!((y, m, d, h, min, s), (2024, 1, 1, 0, 0, 0));

        // 1970-01-01 00:00:00 UTC = 0
        let (y, m, d, h, min, s) = civil_from_epoch(0);
        assert_eq!((y, m, d, h, min, s), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn test_digest_algorithm_id() {
        let sha256 = digest_algorithm_id(MessageDigest::sha256());
        // SEQUENCE { OID sha256, NULL }
        assert_eq!(sha256[0], 0x30); // SEQUENCE tag
        assert!(sha256.len() > 4);
    }
}
