/// PKCS#7 SignedData構造のDERビルダー (RustCrypto cms/der クレート使用)
///
/// カード上の秘密鍵を使ったCMS署名のために、PKCS#7 SignedData構造を構築する。
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{Any, Null, ObjectIdentifier, OctetString, SetOfVec, UtcTime};
use der::oid::AssociatedOid;
use der::oid::db::{rfc5911, rfc5912};
use der::{DateTime, Decode, Encode, EncodeValue, Sequence, Tagged};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_cert::attr::Attribute;

// --- 公開型 ---

/// ハッシュアルゴリズム
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// 認証属性のSET OF (署名検証用/PKCS#7埋め込み用)
pub type AuthAttrs = SetOfVec<Attribute>;

// --- 内部ヘルパー ---

/// RFC 8017 / PKCS#1 DigestInfo (AlgorithmIdentifier + digest OCTET STRING)
#[derive(Sequence)]
struct DigestInfoOwned {
    algorithm: AlgorithmIdentifierOwned,
    digest: OctetString,
}

fn null_any() -> Any {
    Any::encode_from(&Null).expect("NULL encoding cannot fail")
}

fn digest_alg_id(alg: HashAlgorithm) -> AlgorithmIdentifierOwned {
    let oid = match alg {
        HashAlgorithm::Sha1 => Sha1::OID,
        HashAlgorithm::Sha256 => Sha256::OID,
        HashAlgorithm::Sha384 => Sha384::OID,
        HashAlgorithm::Sha512 => Sha512::OID,
    };
    AlgorithmIdentifierOwned {
        oid,
        parameters: Some(null_any()),
    }
}

fn hash_data(alg: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
        HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
    }
}

fn utctime_now() -> UtcTime {
    let now = std::time::SystemTime::now();
    let dt = DateTime::from_system_time(now).expect("system time out of range");
    UtcTime::try_from(dt).expect("UTCTime conversion cannot fail")
}

fn make_attribute(oid: ObjectIdentifier, value: impl Tagged + EncodeValue) -> Attribute {
    let mut values: SetOfVec<Any> = SetOfVec::new();
    values
        .insert(Any::encode_from(&value).expect("attribute value encoding cannot fail"))
        .unwrap();
    Attribute { oid, values }
}

/// 認証属性(authenticated attributes)をSET OFとして構築する
fn build_auth_attrs(content_digest: &[u8], signing_time: UtcTime) -> AuthAttrs {
    let digest_os = OctetString::new(content_digest).expect("content digest must be non-empty");
    let mut attrs: AuthAttrs = SetOfVec::new();
    attrs
        .insert(make_attribute(rfc5911::ID_CONTENT_TYPE, rfc5911::ID_DATA))
        .unwrap();
    attrs
        .insert(make_attribute(rfc5911::ID_SIGNING_TIME, signing_time))
        .unwrap();
    attrs
        .insert(make_attribute(rfc5911::ID_MESSAGE_DIGEST, digest_os))
        .unwrap();
    attrs
}

// --- 公開API ---

/// DigestInfo DER を構築する（スマートカードの署名コマンドに渡す T 値）
///
/// DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }
pub fn build_digest_info(alg: HashAlgorithm, hash: &[u8]) -> Vec<u8> {
    DigestInfoOwned {
        algorithm: digest_alg_id(alg),
        digest: OctetString::new(hash).expect("hash cannot be empty"),
    }
    .to_der()
    .expect("DigestInfo encoding cannot fail")
}

/// 署名に必要なデータを準備する
///
/// Returns: (attrs_set, attrs_digest)
/// - attrs_set: SET OFでエンコードされた認証属性(署名検証用/PKCS#7埋め込み用)
/// - attrs_digest: 認証属性のハッシュ値(DigestInfoに包んでカードに送る)
pub fn prepare_signing(content: &[u8], alg: HashAlgorithm) -> (AuthAttrs, Vec<u8>) {
    let content_digest = hash_data(alg, content);
    let signing_time = utctime_now();
    let attrs = build_auth_attrs(&content_digest, signing_time);
    let attrs_der = attrs.to_der().unwrap();
    let attrs_digest = hash_data(alg, &attrs_der);
    (attrs, attrs_digest)
}

/// 事前計算されたハッシュを使って署名準備する（PDF署名用）
///
/// prepare_signing と同じだが、content の代わりに既にハッシュ済みの値を受け取る。
pub fn prepare_signing_with_hash(content_hash: &[u8], alg: HashAlgorithm) -> (AuthAttrs, Vec<u8>) {
    let signing_time = utctime_now();
    let attrs = build_auth_attrs(content_hash, signing_time);
    let attrs_der = attrs.to_der().unwrap();
    let attrs_digest = hash_data(alg, &attrs_der);
    (attrs, attrs_digest)
}

/// PKCS#7 SignedData構造の完全なDERを構築する
///
/// - content: 署名対象データ
/// - cert_der: 署名者の証明書DER
/// - signature: カードで計算された署名値
/// - alg: ダイジェストアルゴリズム
/// - attrs: prepare_signingで作成された認証属性
/// - detached: trueならコンテンツを含めない(デタッチ署名)
pub fn build_signed_data(
    content: &[u8],
    cert_der: &[u8],
    signature: &[u8],
    alg: HashAlgorithm,
    attrs: &AuthAttrs,
    detached: bool,
) -> Vec<u8> {
    let cert = Certificate::from_der(cert_der).expect("invalid certificate DER");

    // IssuerAndSerialNumber
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: cert.tbs_certificate.issuer.clone(),
        serial_number: cert.tbs_certificate.serial_number.clone(),
    });

    let digest_alg = digest_alg_id(alg);
    let rsa_alg = AlgorithmIdentifierOwned {
        oid: rfc5912::RSA_ENCRYPTION,
        parameters: Some(null_any()),
    };

    // SignerInfo (signed_attrs は [0] IMPLICIT タグで自動エンコードされる)
    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid,
        digest_alg: digest_alg.clone(),
        signed_attrs: Some(attrs.clone()),
        signature_algorithm: rsa_alg,
        signature: OctetString::new(signature).unwrap(),
        unsigned_attrs: None,
    };

    // EncapsulatedContentInfo
    let encap_content_info = if detached {
        EncapsulatedContentInfo {
            econtent_type: rfc5911::ID_DATA,
            econtent: None,
        }
    } else {
        EncapsulatedContentInfo {
            econtent_type: rfc5911::ID_DATA,
            econtent: Some(Any::encode_from(&OctetString::new(content).unwrap()).unwrap()),
        }
    };

    // Certificates [0] IMPLICIT
    let cert_choice = CertificateChoices::Certificate(cert);
    let mut cert_set_inner: SetOfVec<CertificateChoices> = SetOfVec::new();
    cert_set_inner.insert(cert_choice).unwrap();

    // DigestAlgorithmIdentifiers
    let mut digest_algs: SetOfVec<AlgorithmIdentifierOwned> = SetOfVec::new();
    digest_algs.insert(digest_alg).unwrap();

    // SignerInfos
    let mut signer_infos_inner: SetOfVec<SignerInfo> = SetOfVec::new();
    signer_infos_inner.insert(signer_info).unwrap();

    // SignedData
    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: digest_algs,
        encap_content_info,
        certificates: Some(CertificateSet(cert_set_inner)),
        crls: None,
        signer_infos: SignerInfos(signer_infos_inner),
    };

    // 最外側のContentInfo
    let signed_data_der = signed_data.to_der().unwrap();
    let content_info = ContentInfo {
        content_type: rfc5911::ID_SIGNED_DATA,
        content: Any::from_der(&signed_data_der).unwrap(),
    };

    content_info.to_der().unwrap()
}

/// detached モード専用の SignedData 構築（コンテンツなし、PDF署名用）
pub fn build_signed_data_detached(
    cert_der: &[u8],
    signature: &[u8],
    alg: HashAlgorithm,
    attrs: &AuthAttrs,
) -> Vec<u8> {
    build_signed_data(&[], cert_der, signature, alg, attrs, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_data_sha256() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = hash_data(HashAlgorithm::Sha256, b"");
        assert_eq!(hash.len(), 32);
        assert_eq!(hash[0], 0xe3);
        assert_eq!(hash[1], 0xb0);
    }

    #[test]
    fn test_hash_data_sha1() {
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let hash = hash_data(HashAlgorithm::Sha1, b"");
        assert_eq!(hash.len(), 20);
        assert_eq!(hash[0], 0xda);
        assert_eq!(hash[1], 0x39);
    }

    #[test]
    fn test_digest_alg_id_sha256() {
        let alg = digest_alg_id(HashAlgorithm::Sha256);
        assert_eq!(alg.oid, Sha256::OID);
        assert!(alg.parameters.is_some());
    }

    #[test]
    fn test_build_auth_attrs_has_three_attrs() {
        let digest = [0u8; 32];
        let time = utctime_now();
        let attrs = build_auth_attrs(&digest, time);
        assert_eq!(attrs.len(), 3);
    }

    #[test]
    fn test_prepare_signing_returns_valid_attrs() {
        let content = b"Hello, World!";
        let (attrs, digest) = prepare_signing(content, HashAlgorithm::Sha256);
        assert_eq!(attrs.len(), 3);
        assert_eq!(digest.len(), 32); // SHA-256 digest length
    }

    #[test]
    fn test_prepare_signing_with_hash() {
        let content_hash = [0u8; 32];
        let (attrs, digest) = prepare_signing_with_hash(&content_hash, HashAlgorithm::Sha256);
        assert_eq!(attrs.len(), 3);
        assert_eq!(digest.len(), 32);
    }
}
