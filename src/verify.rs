use crate::error::Error;
use crate::ta::{self, EmbeddedTrustAnchor};
use cms::cert::CertificateChoices;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::{ObjectIdentifier, OctetString};
use der::oid::AssociatedOid;
use der::oid::db::{rfc5911, rfc5912};
use der::{Decode, Encode};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams,
    Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey,
};
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature as Pkcs1Sig, VerifyingKey};
use rsa::signature::Verifier;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::DecodePublicKey;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use x509_cert::time::Validity;

pub(crate) fn build_sign_verifier() -> Result<Vec<EmbeddedTrustAnchor>, Error> {
    ta::build_sign_store()
}

pub(crate) fn log_sign_trust_anchors(roots: &[EmbeddedTrustAnchor]) -> Result<(), Error> {
    log::info!(
        "Using {} embedded sign trust anchor(s); card CA certificates are not used for verification",
        roots.len()
    );
    for root in roots {
        log::debug!(
            "Trust anchor {}: {}",
            root.name,
            ta::describe_cert(&root.cert)
        );
        log::trace!(
            "Trust anchor {} SHA-256 fingerprint: {}",
            root.name,
            ta::cert_fingerprint(&root.cert)?
        );
    }
    Ok(())
}

pub(crate) fn log_pkcs7_signers(signed_data: &SignedData) -> Result<(), Error> {
    log::info!(
        "Found {} signer certificate(s) in PKCS#7",
        signed_data.signer_infos.0.len()
    );
    if let Some(certs) = &signed_data.certificates {
        log::debug!("PKCS#7 includes {} certificate(s)", certs.0.len());
    }
    for (i, si) in signed_data.signer_infos.0.iter().enumerate() {
        if let Some(cert) = find_cert_for_signer(signed_data, si)? {
            log::info!("Signer certificate {}: {}", i + 1, ta::describe_cert(cert));
            log::trace!(
                "Signer certificate {} SHA-256 fingerprint: {}",
                i + 1,
                ta::cert_fingerprint(cert)?
            );
        }
    }
    Ok(())
}

pub(crate) fn verify_signer_certificates(
    signed_data: &SignedData,
    roots: &[EmbeddedTrustAnchor],
) -> Result<(), Error> {
    for (i, si) in signed_data.signer_infos.0.iter().enumerate() {
        log::info!(
            "Validating signer certificate {} against embedded trust anchors",
            i + 1
        );
        let cert = find_cert_for_signer(signed_data, si)?
            .ok_or_else(|| Error::new("署名者証明書が SignedData 内に見つかりません"))?;

        match verify_cert_chain(cert, roots)? {
            Some(name) => {
                log::info!("Signer certificate {} verified by {}", i + 1, name);
            }
            None => {
                log::warn!(
                    "Signer certificate {} could not be verified by any trust anchor",
                    i + 1
                );
            }
        }
    }
    Ok(())
}

/// CMS 署名全体を検証する（messageDigest・RSA署名・証明書チェーン）
///
/// - content: detached 署名の場合は署名対象データ。embedded の場合は None
///   （EncapsulatedContentInfo から自動取得）。
pub(crate) fn verify_cms_signature(
    signed_data: &SignedData,
    content: Option<&[u8]>,
    roots: &[EmbeddedTrustAnchor],
) -> Result<(), Error> {
    if signed_data.signer_infos.0.is_empty() {
        return Err(Error::new("SignedData に署名者情報がありません"));
    }

    // embedded の場合は EncapsulatedContentInfo からコンテンツを取り出す
    let embedded_content = match content {
        Some(_) => None,
        None => extract_econtent(signed_data)?,
    };
    let content_data = match content {
        Some(d) => d,
        None => embedded_content
            .as_deref()
            .ok_or_else(|| Error::new("署名対象コンテンツが見つかりません"))?,
    };

    for (i, si) in signed_data.signer_infos.0.iter().enumerate() {
        let cert = find_cert_for_signer(signed_data, si)?
            .ok_or_else(|| Error::new("署名者証明書が SignedData 内に見つかりません"))?;

        // 1. messageDigest 検証
        verify_message_digest(si, content_data)?;
        log::debug!("Signer {}: messageDigest OK", i + 1);

        // 2. RSA 署名検証（signed attrs SET OF DER に対して）
        let signed_attrs = si
            .signed_attrs
            .as_ref()
            .ok_or_else(|| Error::new("SignerInfo に signedAttrs がありません"))?;
        let signed_attrs_der = signed_attrs
            .to_der()
            .map_err(|e| Error::with_source("signedAttrs の DER エンコードに失敗しました", e))?;
        let sig_bytes = si.signature.as_bytes();
        let sig_alg = &si.signature_algorithm.oid;
        if is_ml_dsa(sig_alg) {
            verify_ml_dsa(cert, &signed_attrs_der, sig_bytes)?;
            log::info!("Signer certificate {}: ML-DSA signature OK", i + 1);
        } else {
            verify_rsa_pkcs1v15(cert, &signed_attrs_der, sig_bytes, &si.digest_alg.oid)?;
            log::info!("Signer certificate {}: RSA signature OK", i + 1);
        }

        // 3. 証明書チェーン検証
        let root_name = verify_cert_chain(cert, roots)?
            .ok_or_else(|| Error::new("署名者証明書を信頼アンカーで検証できませんでした"))?;
        log::info!(
            "Signer certificate {}: certificate chain verified by {}",
            i + 1,
            root_name
        );
    }
    Ok(())
}

// --- 内部ヘルパー ---

/// EncapsulatedContentInfo から embedded コンテンツを取り出す
fn extract_econtent(signed_data: &SignedData) -> Result<Option<Vec<u8>>, Error> {
    let econtent = match &signed_data.encap_content_info.econtent {
        Some(any) => any,
        None => return Ok(None),
    };
    let der = econtent
        .to_der()
        .map_err(|e| Error::with_source("econtent の DER エンコードに失敗しました", e))?;
    let os = OctetString::from_der(&der)
        .map_err(|e| Error::with_source("econtent の OCTET STRING デコードに失敗しました", e))?;
    Ok(Some(os.as_bytes().to_vec()))
}

/// SignerInfo.sid に対応する証明書を SignedData.certificates から探す
fn find_cert_for_signer<'a>(
    signed_data: &'a SignedData,
    si: &SignerInfo,
) -> Result<Option<&'a Certificate>, Error> {
    let certs = match &signed_data.certificates {
        Some(c) => c,
        None => return Ok(None),
    };
    match &si.sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            for choice in certs.0.iter() {
                if let CertificateChoices::Certificate(cert) = choice
                    && cert.tbs_certificate.issuer == ias.issuer
                    && cert.tbs_certificate.serial_number == ias.serial_number
                {
                    return Ok(Some(cert));
                }
            }
            Ok(None)
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            let target = ski.0.as_bytes();
            for choice in certs.0.iter() {
                if let CertificateChoices::Certificate(cert) = choice
                    && let Some(cert_ski) = extract_cert_ski(cert)?
                    && cert_ski == target
                {
                    return Ok(Some(cert));
                }
            }
            Ok(None)
        }
    }
}

/// 証明書から SubjectKeyIdentifier を取り出す。
///
/// 1. SubjectKeyIdentifier 拡張 (OID 2.5.29.14) があればその値を返す。
/// 2. 拡張がなければ RFC 5280 §4.2.1.2 method (1) に従い、
///    SubjectPublicKey BIT STRING 内容に対する SHA-1 を返す。
fn extract_cert_ski(cert: &Certificate) -> Result<Option<Vec<u8>>, Error> {
    if let Some(ext) = find_extension(cert, &SubjectKeyIdentifier::OID) {
        let ski = SubjectKeyIdentifier::from_der(ext.extn_value.as_bytes()).map_err(|e| {
            Error::with_source("SubjectKeyIdentifier 拡張のデコードに失敗しました", e)
        })?;
        return Ok(Some(ski.0.as_bytes().to_vec()));
    }
    let spk = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::new("SubjectPublicKey BitString に余剰ビットがあります"))?;
    Ok(Some(Sha1::digest(spk).to_vec()))
}

/// 証明書から指定 OID の拡張を検索する
fn find_extension<'a>(cert: &'a Certificate, oid: &ObjectIdentifier) -> Option<&'a Extension> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| &e.extn_id == oid)
}

/// messageDigest 認証属性とコンテンツのハッシュを照合する
fn verify_message_digest(si: &SignerInfo, content_data: &[u8]) -> Result<(), Error> {
    let signed_attrs = si
        .signed_attrs
        .as_ref()
        .ok_or_else(|| Error::new("signedAttrs がありません"))?;

    // messageDigest 属性の値を取得
    let mut expected: Option<Vec<u8>> = None;
    for attr in signed_attrs.iter() {
        if attr.oid == rfc5911::ID_MESSAGE_DIGEST {
            let any = attr
                .values
                .iter()
                .next()
                .ok_or_else(|| Error::new("messageDigest 属性の値がありません"))?;
            let der = any.to_der().map_err(|e| {
                Error::with_source("messageDigest Any の DER 変換に失敗しました", e)
            })?;
            let os = OctetString::from_der(&der).map_err(|e| {
                Error::with_source("messageDigest の OCTET STRING デコードに失敗しました", e)
            })?;
            expected = Some(os.as_bytes().to_vec());
            break;
        }
    }
    let expected =
        expected.ok_or_else(|| Error::new("messageDigest 属性が signedAttrs に見つかりません"))?;

    let actual = hash_with_oid(&si.digest_alg.oid, content_data)?;
    if actual != expected {
        return Err(Error::new(
            "messageDigest が一致しません（コンテンツ改ざんの可能性）",
        ));
    }
    Ok(())
}

/// OID に対応するアルゴリズムでデータをハッシュする
fn hash_with_oid(oid: &ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>, Error> {
    if *oid == rfc5912::ID_SHA_1 {
        Ok(Sha1::digest(data).to_vec())
    } else if *oid == rfc5912::ID_SHA_256 {
        Ok(Sha256::digest(data).to_vec())
    } else if *oid == rfc5912::ID_SHA_384 {
        Ok(Sha384::digest(data).to_vec())
    } else if *oid == rfc5912::ID_SHA_512 {
        Ok(Sha512::digest(data).to_vec())
    } else {
        Err(Error::new(format!(
            "未対応のダイジェストアルゴリズム OID: {}",
            oid
        )))
    }
}

/// 証明書から RSA 公開鍵を取り出す
pub(crate) fn rsa_pub_key_from_cert(cert: &Certificate) -> Result<RsaPublicKey, Error> {
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::with_source("SPKI の DER エンコードに失敗しました", e))?;
    RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| Error::with_source("RSA 公開鍵のデコードに失敗しました", e))
}

/// RSA PKCS#1 v1.5 署名を検証する（msg はハッシュ前の生データ）
fn verify_rsa_pkcs1v15(
    cert: &Certificate,
    msg: &[u8],
    sig_bytes: &[u8],
    digest_oid: &ObjectIdentifier,
) -> Result<(), Error> {
    let rsa_key = rsa_pub_key_from_cert(cert)?;
    let sig = Pkcs1Sig::try_from(sig_bytes)
        .map_err(|e| Error::with_source("署名値のデコードに失敗しました", e))?;

    let result = if *digest_oid == rfc5912::ID_SHA_1 {
        VerifyingKey::<Sha1>::new(rsa_key).verify(msg, &sig)
    } else if *digest_oid == rfc5912::ID_SHA_256 {
        VerifyingKey::<Sha256>::new(rsa_key).verify(msg, &sig)
    } else if *digest_oid == rfc5912::ID_SHA_384 {
        VerifyingKey::<Sha384>::new(rsa_key).verify(msg, &sig)
    } else if *digest_oid == rfc5912::ID_SHA_512 {
        VerifyingKey::<Sha512>::new(rsa_key).verify(msg, &sig)
    } else {
        return Err(Error::new(format!(
            "未対応のダイジェストアルゴリズム: {}",
            digest_oid
        )));
    };
    result.map_err(|e| Error::with_source("RSA 署名検証に失敗しました", e))
}

/// NIST ML-DSA 署名アルゴリズム OID (FIPS 204)
const ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
const ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
const ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

fn is_ml_dsa(oid: &ObjectIdentifier) -> bool {
    *oid == ML_DSA_44 || *oid == ML_DSA_65 || *oid == ML_DSA_87
}

/// ML-DSA 署名を検証する（純粋 ML-DSA、空コンテキスト、signed attrs SET OF DER が対象）
fn verify_ml_dsa(cert: &Certificate, msg: &[u8], sig_bytes: &[u8]) -> Result<(), Error> {
    let raw_pub = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::new("ML-DSA 公開鍵の BitString に余剰ビットがあります"))?;
    let alg_oid = &cert.tbs_certificate.subject_public_key_info.algorithm.oid;

    if *alg_oid == ML_DSA_44 {
        verify_ml_dsa_param::<MlDsa44>(raw_pub, msg, sig_bytes)
    } else if *alg_oid == ML_DSA_65 {
        verify_ml_dsa_param::<MlDsa65>(raw_pub, msg, sig_bytes)
    } else if *alg_oid == ML_DSA_87 {
        verify_ml_dsa_param::<MlDsa87>(raw_pub, msg, sig_bytes)
    } else {
        Err(Error::new(format!(
            "未対応の公開鍵アルゴリズム: {}",
            alg_oid
        )))
    }
}

fn verify_ml_dsa_param<P>(raw_pub: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<(), Error>
where
    P: MlDsaParams,
{
    let enc_vk = EncodedVerifyingKey::<P>::try_from(raw_pub)
        .map_err(|_| Error::new("ML-DSA 公開鍵長がパラメータセットと一致しません"))?;
    let vk = MlDsaVerifyingKey::<P>::decode(&enc_vk);

    let enc_sig = EncodedSignature::<P>::try_from(sig_bytes)
        .map_err(|_| Error::new("ML-DSA 署名長がパラメータセットと一致しません"))?;
    let sig = MlDsaSignature::<P>::decode(&enc_sig)
        .ok_or_else(|| Error::new("ML-DSA 署名値のデコードに失敗しました"))?;

    if vk.verify_with_context(msg, &[], &sig) {
        Ok(())
    } else {
        Err(Error::new("ML-DSA 署名検証に失敗しました"))
    }
}

/// 証明書が trust anchor のいずれかで署名されているか検証する
///
/// 併せて以下の構造的検査を実施する:
/// - 署名者証明書の `notBefore`/`notAfter` 有効期間 (RFC 5280 §6.1.3 (a)(2))
/// - 署名者証明書の `KeyUsage` 拡張 (`digitalSignature` または `nonRepudiation` を要求、
///   RFC 5280 §4.2.1.3)
/// - 署名検証に成功した trust anchor の `BasicConstraints` 拡張 (`cA = TRUE` を要求、
///   RFC 5280 §4.2.1.9)
///
/// なお、CRL / OCSP による失効状態の確認は本関数では行わない。
/// JPKI 署名用証明書の正式な失効検証は、公的個人認証法 §17 により総務大臣に届け出た
/// プラットフォーム事業者の領分に属するため、myna の "カジュアル検証" の枠組みでは
/// 意図的に範囲外としている。詳細は該当 advisory を参照。
///
/// 返値: 検証に成功した trust anchor の名前。いずれにも一致しなければ None。
fn verify_cert_chain<'a>(
    cert: &Certificate,
    roots: &'a [EmbeddedTrustAnchor],
) -> Result<Option<&'a str>, Error> {
    let now = now_unix_secs()?;
    check_validity(&cert.tbs_certificate.validity, now)?;
    check_signing_key_usage(cert)?;

    let tbs_der = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| Error::with_source("TBSCertificate の DER エンコードに失敗しました", e))?;
    let sig_bytes = cert
        .signature
        .as_bytes()
        .ok_or_else(|| Error::new("証明書署名の BitString に余剰ビットがあります"))?;
    let digest_oid = sig_alg_to_digest_oid(&cert.signature_algorithm.oid)?;

    for root in roots {
        if verify_rsa_pkcs1v15(&root.cert, &tbs_der, sig_bytes, &digest_oid).is_ok() {
            check_root_basic_constraints(&root.cert)?;
            return Ok(Some(root.name));
        }
    }
    Ok(None)
}

/// 現在時刻を UNIX_EPOCH からの秒数で返す
fn now_unix_secs() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::new("システム時刻が UNIX_EPOCH より前です"))
}

/// `Validity` が現在時刻を含むか検査する (RFC 5280 §6.1.3 (a)(2))
fn check_validity(validity: &Validity, now_secs: u64) -> Result<(), Error> {
    let nb = validity.not_before.to_unix_duration().as_secs();
    let na = validity.not_after.to_unix_duration().as_secs();
    if now_secs < nb {
        return Err(Error::new(format!(
            "証明書がまだ有効期間に入っていません (notBefore={}, now={})",
            nb, now_secs
        )));
    }
    if now_secs > na {
        return Err(Error::new(format!(
            "証明書が有効期間を過ぎています (notAfter={}, now={})",
            na, now_secs
        )));
    }
    Ok(())
}

/// 署名者証明書の `KeyUsage` を検査する (RFC 5280 §4.2.1.3)
///
/// `KeyUsage` 拡張が存在する場合は `digitalSignature` または `nonRepudiation` ビットを要求する。
/// 拡張が存在しない場合は許容する (RFC 5280 では拡張は OPTIONAL のため)。
fn check_signing_key_usage(cert: &Certificate) -> Result<(), Error> {
    let ext = match find_extension(cert, &KeyUsage::OID) {
        Some(e) => e,
        None => return Ok(()),
    };
    let ku = KeyUsage::from_der(ext.extn_value.as_bytes())
        .map_err(|e| Error::with_source("KeyUsage 拡張のデコードに失敗しました", e))?;
    validate_key_usage(&ku)
}

fn validate_key_usage(ku: &KeyUsage) -> Result<(), Error> {
    if ku.digital_signature() || ku.non_repudiation() {
        Ok(())
    } else {
        Err(Error::new(
            "KeyUsage 拡張に digitalSignature/nonRepudiation ビットがありません \
             (この証明書は署名検証用ではありません)",
        ))
    }
}

/// trust anchor の `BasicConstraints` を検査する (RFC 5280 §4.2.1.9)
///
/// CA 証明書の `cA` ビットが TRUE であることを要求する。
/// `BasicConstraints` 拡張がない場合は CA としての確認ができないためエラー。
fn check_root_basic_constraints(cert: &Certificate) -> Result<(), Error> {
    let ext = find_extension(cert, &BasicConstraints::OID).ok_or_else(|| {
        Error::new("trust anchor に BasicConstraints 拡張がありません (CA:TRUE 確認不能)")
    })?;
    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
        .map_err(|e| Error::with_source("BasicConstraints 拡張のデコードに失敗しました", e))?;
    validate_basic_constraints(&bc)
}

fn validate_basic_constraints(bc: &BasicConstraints) -> Result<(), Error> {
    if !bc.ca {
        return Err(Error::new(
            "trust anchor の BasicConstraints が cA=FALSE です (CA 証明書ではありません)",
        ));
    }
    Ok(())
}

/// sha*WithRSAEncryption OID からダイジェスト OID を返す
fn sig_alg_to_digest_oid(oid: &ObjectIdentifier) -> Result<ObjectIdentifier, Error> {
    if *oid == rfc5912::SHA_1_WITH_RSA_ENCRYPTION {
        Ok(rfc5912::ID_SHA_1)
    } else if *oid == rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
        Ok(rfc5912::ID_SHA_256)
    } else if *oid == rfc5912::SHA_384_WITH_RSA_ENCRYPTION {
        Ok(rfc5912::ID_SHA_384)
    } else if *oid == rfc5912::SHA_512_WITH_RSA_ENCRYPTION {
        Ok(rfc5912::ID_SHA_512)
    } else {
        Err(Error::new(format!("未対応の署名アルゴリズム OID: {}", oid)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkcs7;
    use cms::content_info::ContentInfo;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;

    /// テスト用の署名値を生成する（PKCS#1 v1.5 パディング付き）
    fn test_sign(priv_key: &RsaPrivateKey, data: &[u8]) -> Vec<u8> {
        use rsa::BigUint;
        use rsa::hazmat::rsa_decrypt_and_check;
        use rsa::traits::PublicKeyParts;
        let key_size = priv_key.size();
        let ps_len = key_size - data.len() - 3;
        let mut em = vec![0x00u8, 0x01];
        em.extend(std::iter::repeat_n(0xffu8, ps_len));
        em.push(0x00);
        em.extend_from_slice(data);
        let m = BigUint::from_bytes_be(&em);
        let c = rsa_decrypt_and_check(priv_key, None::<&mut rsa::rand_core::OsRng>, &m).unwrap();
        let mut sig = c.to_bytes_be();
        while sig.len() < key_size {
            sig.insert(0, 0u8);
        }
        sig
    }

    /// テスト用 embedded SignedData DER を構築する
    fn build_test_signed_data(content: &[u8], detached: bool) -> Vec<u8> {
        let cert_der = include_bytes!("../tests/fixtures/sign_cert.der");
        let sign_key_pem = include_bytes!("../tests/fixtures/sign_key.pem");
        let pem_str = std::str::from_utf8(sign_key_pem).unwrap();
        let priv_key = RsaPrivateKey::from_pkcs8_pem(pem_str).unwrap();

        let alg = pkcs7::HashAlgorithm::Sha256;
        let (attrs, attrs_digest) = pkcs7::prepare_signing(content, alg);
        let digest_info = pkcs7::build_digest_info(alg, &attrs_digest);
        let signature = test_sign(&priv_key, &digest_info);

        pkcs7::build_signed_data(content, cert_der, &signature, alg, &attrs, detached)
    }

    fn parse_signed_data(pkcs7_der: &[u8]) -> SignedData {
        let ci = ContentInfo::from_der(pkcs7_der).unwrap();
        let content_der = ci.content.to_der().unwrap();
        SignedData::from_der(&content_der).unwrap()
    }

    #[test]
    fn test_extract_econtent_embedded() {
        let content = b"Hello, embedded CMS!";
        let pkcs7_der = build_test_signed_data(content, false);
        let signed_data = parse_signed_data(&pkcs7_der);

        let extracted = extract_econtent(&signed_data).unwrap();
        assert_eq!(extracted.as_deref(), Some(content.as_slice()));
    }

    #[test]
    fn test_extract_econtent_detached() {
        let content = b"Hello, detached CMS!";
        let pkcs7_der = build_test_signed_data(content, true);
        let signed_data = parse_signed_data(&pkcs7_der);

        let extracted = extract_econtent(&signed_data).unwrap();
        assert!(extracted.is_none());
    }

    #[test]
    fn test_verify_message_digest_embedded_ok() {
        let content = b"Hello, embedded CMS!";
        let pkcs7_der = build_test_signed_data(content, false);
        let signed_data = parse_signed_data(&pkcs7_der);

        let si = signed_data.signer_infos.0.iter().next().unwrap();
        // embedded コンテンツを取り出して検証
        let econtent = extract_econtent(&signed_data).unwrap().unwrap();
        assert!(verify_message_digest(si, &econtent).is_ok());
    }

    #[test]
    fn test_verify_message_digest_embedded_tampered() {
        let content = b"Hello, embedded CMS!";
        let pkcs7_der = build_test_signed_data(content, false);
        let signed_data = parse_signed_data(&pkcs7_der);

        let si = signed_data.signer_infos.0.iter().next().unwrap();
        // 改ざんされたコンテンツで検証 → 失敗するべき
        let tampered = b"Tampered content!!!!";
        let result = verify_message_digest(si, tampered);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("一致しません"), "msg = {}", msg);
    }

    #[test]
    fn test_verify_message_digest_detached_ok() {
        let content = b"Hello, detached CMS!";
        let pkcs7_der = build_test_signed_data(content, true);
        let signed_data = parse_signed_data(&pkcs7_der);

        let si = signed_data.signer_infos.0.iter().next().unwrap();
        assert!(verify_message_digest(si, content).is_ok());
    }

    #[test]
    fn test_verify_cms_signature_embedded_content_used() {
        // embedded 署名で content=None を渡した場合、
        // EncapsulatedContentInfo から自動取得して messageDigest を検証する。
        // 信頼アンカーがないと証明書チェーン検証で失敗するが、
        // messageDigest/RSA署名検証まで到達することを確認する。
        let content = b"Test embedded content";
        let pkcs7_der = build_test_signed_data(content, false);
        let signed_data = parse_signed_data(&pkcs7_der);

        let result = verify_cms_signature(&signed_data, None, &[]);
        // 信頼アンカーなしなので証明書チェーンで失敗するが、
        // "署名対象コンテンツが見つかりません" エラーにはならない
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            !msg.contains("署名対象コンテンツが見つかりません"),
            "embedded コンテンツが取得できていない: {}",
            msg
        );
        // messageDigest は通過し、RSA署名 or 証明書チェーンで失敗
        assert!(
            msg.contains("信頼アンカー") || msg.contains("RSA"),
            "想定外のエラー: {}",
            msg
        );
    }

    // ---------------------------------------------------------------------
    // GHSA-58hw-cg5m-88rp: 証明書チェーン検証の不変条件
    // ---------------------------------------------------------------------

    use der::asn1::GeneralizedTime;
    use std::time::Duration;
    use x509_cert::time::{Time, Validity};

    fn validity_unix(nb_secs: u64, na_secs: u64) -> Validity {
        Validity {
            not_before: Time::GeneralTime(
                GeneralizedTime::from_unix_duration(Duration::from_secs(nb_secs)).unwrap(),
            ),
            not_after: Time::GeneralTime(
                GeneralizedTime::from_unix_duration(Duration::from_secs(na_secs)).unwrap(),
            ),
        }
    }

    #[test]
    fn test_check_validity_accepts_in_range() {
        let v = validity_unix(1_000_000_000, 4_000_000_000);
        check_validity(&v, 2_000_000_000).expect("有効期間内は受理されるべき");
    }

    #[test]
    fn test_check_validity_rejects_expired() {
        // notAfter = 2010-12-31, now = 2026
        let v = validity_unix(1_262_304_000, 1_293_840_000);
        let err = check_validity(&v, 1_775_500_800).expect_err("期限切れ証明書は拒否されるべき");
        assert!(
            err.to_string().contains("有効期間を過ぎています"),
            "{}",
            err
        );
    }

    #[test]
    fn test_check_validity_rejects_not_yet_valid() {
        // notBefore is in the future
        let v = validity_unix(4_000_000_000, 5_000_000_000);
        let err = check_validity(&v, 2_000_000_000)
            .expect_err("有効期間に入っていない証明書は拒否されるべき");
        assert!(
            err.to_string().contains("有効期間に入っていません"),
            "{}",
            err
        );
    }

    #[test]
    fn test_validate_key_usage_accepts_digital_signature() {
        use der::flagset::FlagSet;
        use x509_cert::ext::pkix::KeyUsages;
        let ku = KeyUsage(FlagSet::from(KeyUsages::DigitalSignature));
        validate_key_usage(&ku).expect("digitalSignature ビットがあれば受理されるべき");
    }

    #[test]
    fn test_validate_key_usage_accepts_non_repudiation() {
        use der::flagset::FlagSet;
        use x509_cert::ext::pkix::KeyUsages;
        let ku = KeyUsage(FlagSet::from(KeyUsages::NonRepudiation));
        validate_key_usage(&ku).expect("nonRepudiation ビットがあれば受理されるべき");
    }

    #[test]
    fn test_validate_key_usage_rejects_no_signing_bits() {
        use der::flagset::FlagSet;
        use x509_cert::ext::pkix::KeyUsages;
        // keyEncipherment のみ (= 鍵交換用、署名検証用ではない)
        let ku = KeyUsage(FlagSet::from(KeyUsages::KeyEncipherment));
        let err = validate_key_usage(&ku)
            .expect_err("digitalSignature/nonRepudiation がない場合は拒否されるべき");
        assert!(err.to_string().contains("digitalSignature"), "{}", err);
    }

    #[test]
    fn test_validate_basic_constraints_accepts_ca_true() {
        let bc = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        validate_basic_constraints(&bc).expect("cA=TRUE は受理されるべき");
    }

    #[test]
    fn test_validate_basic_constraints_rejects_ca_false() {
        let bc = BasicConstraints {
            ca: false,
            path_len_constraint: None,
        };
        let err = validate_basic_constraints(&bc)
            .expect_err("cA=FALSE は trust anchor として拒否されるべき");
        assert!(
            err.to_string().contains("CA 証明書ではありません"),
            "{}",
            err
        );
    }

    #[test]
    fn test_check_root_basic_constraints_accepts_embedded_trust_anchors() {
        // 埋込済 trust anchor (sign_ca_2015 / sign_ca_2023) はすべて cA=TRUE のはず
        let roots = ta::build_sign_store().expect("trust anchor のロードに失敗しました");
        assert!(!roots.is_empty(), "trust anchor が空");
        for root in &roots {
            check_root_basic_constraints(&root.cert)
                .unwrap_or_else(|e| panic!("trust anchor {} が拒否された: {}", root.name, e));
        }
    }

    #[test]
    fn test_extract_cert_ski_uses_extension() {
        // tests/fixtures/sign_cert.der の SubjectKeyIdentifier 拡張は
        // openssl x509 -text で確認した値:
        //   86:69:32:07:99:4D:65:AA:25:A2:6B:F8:A4:AF:BB:FA:8A:68:77:55
        let cert_der = include_bytes!("../tests/fixtures/sign_cert.der");
        let cert = Certificate::from_der(cert_der).unwrap();
        let ski = extract_cert_ski(&cert).unwrap().expect("SKI 取得失敗");
        let expected: [u8; 20] = [
            0x86, 0x69, 0x32, 0x07, 0x99, 0x4D, 0x65, 0xAA, 0x25, 0xA2, 0x6B, 0xF8, 0xA4, 0xAF,
            0xBB, 0xFA, 0x8A, 0x68, 0x77, 0x55,
        ];
        assert_eq!(ski.as_slice(), expected, "SKI 不一致");
    }

    #[test]
    fn test_check_signing_key_usage_absent_extension_allowed() {
        // 既存のテスト fixture には KeyUsage 拡張がないため、Ok になるべき。
        // (RFC 5280 では KeyUsage 拡張は OPTIONAL)
        let cert_der = include_bytes!("../tests/fixtures/sign_cert.der");
        let cert = Certificate::from_der(cert_der).unwrap();
        check_signing_key_usage(&cert).expect("KeyUsage 拡張なしは Ok のはず");
    }

    #[test]
    fn test_verify_cms_signature_rejects_when_now_outside_fixture_validity() {
        // 既存 fixture は notBefore=2026-03-16 / notAfter=2036-03-13 なので、
        // 「現在時刻が validity を外れていれば拒否される」ことを check_validity 単独で
        // 確認する (verify_cms_signature 経由で時計を弄ることはできないため)。
        let cert_der = include_bytes!("../tests/fixtures/sign_cert.der");
        let cert = Certificate::from_der(cert_der).unwrap();
        let validity = &cert.tbs_certificate.validity;
        // notBefore より前
        let before = validity.not_before.to_unix_duration().as_secs() - 1;
        assert!(check_validity(validity, before).is_err());
        // notAfter より後
        let after = validity.not_after.to_unix_duration().as_secs() + 1;
        assert!(check_validity(validity, after).is_err());
    }
}

#[cfg(test)]
mod ml_dsa_tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        if s == "-" {
            return Vec::new();
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
            .collect()
    }

    fn acvp_accepts<P: MlDsaParams>(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        let enc_vk = match EncodedVerifyingKey::<P>::try_from(pk) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let vk = MlDsaVerifyingKey::<P>::decode(&enc_vk);
        let enc_sig = match EncodedSignature::<P>::try_from(sig) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig = match MlDsaSignature::<P>::decode(&enc_sig) {
            Some(s) => s,
            None => return false,
        };
        vk.verify_with_context(msg, ctx, &sig)
    }

    fn run_acvp<P: MlDsaParams>(data: &str) {
        let mut n = 0usize;
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(f.len(), 5, "ACVP line must have 5 fields");
            let expected = f[0] == "1";
            let (pk, msg, ctx, sig) = (unhex(f[1]), unhex(f[2]), unhex(f[3]), unhex(f[4]));
            let got = acvp_accepts::<P>(&pk, &msg, &ctx, &sig);
            assert_eq!(got, expected, "ACVP case {} verdict mismatch", n);
            n += 1;
        }
        assert!(n > 0, "no ACVP cases were read");
    }

    #[test]
    fn ml_dsa_44_matches_nist_acvp() {
        run_acvp::<MlDsa44>(include_str!("../tests/fixtures/ml-dsa-44-acvp-sigver.txt"));
    }

    #[test]
    fn ml_dsa_65_matches_nist_acvp() {
        run_acvp::<MlDsa65>(include_str!("../tests/fixtures/ml-dsa-65-acvp-sigver.txt"));
    }

    #[test]
    fn ml_dsa_87_matches_nist_acvp() {
        run_acvp::<MlDsa87>(include_str!("../tests/fixtures/ml-dsa-87-acvp-sigver.txt"));
    }

    fn empty_ctx_case(data: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let f: Vec<&str> = data.split_whitespace().collect();
        (unhex(f[0]), unhex(f[1]), unhex(f[2]))
    }

    fn roundtrip<P: MlDsaParams>(data: &str) {
        let (msg, sig, pk) = empty_ctx_case(data);
        verify_ml_dsa_param::<P>(&pk, &msg, &sig)
            .expect("valid empty-context signature must verify");
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0x01;
        assert!(verify_ml_dsa_param::<P>(&pk, &msg, &bad_sig).is_err());
        let mut bad_msg = msg.clone();
        bad_msg[0] ^= 0x01;
        assert!(verify_ml_dsa_param::<P>(&pk, &bad_msg, &sig).is_err());
    }

    #[test]
    fn ml_dsa_44_empty_context_roundtrip() {
        roundtrip::<MlDsa44>(include_str!("../tests/fixtures/ml-dsa-44-emptyctx.txt"));
    }

    #[test]
    fn ml_dsa_65_empty_context_roundtrip() {
        roundtrip::<MlDsa65>(include_str!("../tests/fixtures/ml-dsa-65-emptyctx.txt"));
    }

    #[test]
    fn ml_dsa_87_empty_context_roundtrip() {
        roundtrip::<MlDsa87>(include_str!("../tests/fixtures/ml-dsa-87-emptyctx.txt"));
    }
}

#[cfg(test)]
mod ml_dsa_cms_e2e_tests {
    use super::*;
    use crate::pkcs7::{self, AuthAttrs, HashAlgorithm};
    use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
    use cms::content_info::CmsVersion;
    use cms::signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignerInfo, SignerInfos,
    };
    use der::asn1::{Any, BitString, GeneralizedTime, SetOfVec};
    use ml_dsa::{B32, Keypair, MlDsa65, SigningKey};
    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::SigningKey as RsaSigningKey;
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
    use rsa::signature::{SignatureEncoding, Signer};
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::certificate::{TbsCertificate, Version};
    use x509_cert::ext::Extension;
    use x509_cert::ext::pkix::BasicConstraints;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

    const SHA256_WITH_RSA: ObjectIdentifier = rfc5912::SHA_256_WITH_RSA_ENCRYPTION;

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn validity_around_now() -> Validity {
        let now = now_secs();
        Validity {
            not_before: Time::GeneralTime(
                GeneralizedTime::from_unix_duration(Duration::from_secs(now - 3600)).unwrap(),
            ),
            not_after: Time::GeneralTime(
                GeneralizedTime::from_unix_duration(Duration::from_secs(now + 3600)).unwrap(),
            ),
        }
    }

    fn ca_private_key() -> RsaPrivateKey {
        let pem = std::str::from_utf8(include_bytes!("../tests/fixtures/sign_key.pem")).unwrap();
        RsaPrivateKey::from_pkcs8_pem(pem).unwrap()
    }

    fn rsa_sign_tbs(ca: &RsaPrivateKey, tbs_der: &[u8]) -> BitString {
        let sk = RsaSigningKey::<Sha256>::new(ca.clone());
        let sig = sk.sign(tbs_der);
        BitString::from_bytes(&sig.to_bytes()).unwrap()
    }

    fn build_ca_cert(ca: &RsaPrivateKey) -> Certificate {
        let spki_der = RsaPublicKey::from(ca).to_public_key_der().unwrap();
        let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).unwrap();
        let name = Name::from_str("CN=myna PQ test CA").unwrap();
        let alg = AlgorithmIdentifierOwned {
            oid: SHA256_WITH_RSA,
            parameters: None,
        };
        let bc = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        let ext = Extension {
            extn_id: BasicConstraints::OID,
            critical: true,
            extn_value: OctetString::new(bc.to_der().unwrap()).unwrap(),
        };
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[0x01]).unwrap(),
            signature: alg.clone(),
            issuer: name.clone(),
            validity: validity_around_now(),
            subject: name,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![ext]),
        };
        let sig = rsa_sign_tbs(ca, &tbs.to_der().unwrap());
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: alg,
            signature: sig,
        }
    }

    fn build_ml_dsa_signer_cert(ca: &RsaPrivateKey, ca_subject: &Name, vk_bytes: &[u8]) -> Certificate {
        let spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ML_DSA_65,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(vk_bytes).unwrap(),
        };
        let alg = AlgorithmIdentifierOwned {
            oid: SHA256_WITH_RSA,
            parameters: None,
        };
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[0x02]).unwrap(),
            signature: alg.clone(),
            issuer: ca_subject.clone(),
            validity: validity_around_now(),
            subject: Name::from_str("CN=myna PQ signer").unwrap(),
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };
        let sig = rsa_sign_tbs(ca, &tbs.to_der().unwrap());
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: alg,
            signature: sig,
        }
    }

    fn build_cms(
        content: &[u8],
        signer_cert: &Certificate,
        attrs: &AuthAttrs,
        ml_sig: &[u8],
    ) -> SignedData {
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: signer_cert.tbs_certificate.issuer.clone(),
            serial_number: signer_cert.tbs_certificate.serial_number.clone(),
        });
        let digest_alg = AlgorithmIdentifierOwned {
            oid: rfc5912::ID_SHA_256,
            parameters: None,
        };
        let ml_alg = AlgorithmIdentifierOwned {
            oid: ML_DSA_65,
            parameters: None,
        };
        let signer_info = SignerInfo {
            version: CmsVersion::V1,
            sid,
            digest_alg: digest_alg.clone(),
            signed_attrs: Some(attrs.clone()),
            signature_algorithm: ml_alg,
            signature: OctetString::new(ml_sig).unwrap(),
            unsigned_attrs: None,
        };
        let encap = EncapsulatedContentInfo {
            econtent_type: rfc5911::ID_DATA,
            econtent: Some(Any::encode_from(&OctetString::new(content).unwrap()).unwrap()),
        };
        let mut certs: SetOfVec<CertificateChoices> = SetOfVec::new();
        certs
            .insert(CertificateChoices::Certificate(signer_cert.clone()))
            .unwrap();
        let mut digest_algs: SetOfVec<AlgorithmIdentifierOwned> = SetOfVec::new();
        digest_algs.insert(digest_alg).unwrap();
        let mut sinfos: SetOfVec<SignerInfo> = SetOfVec::new();
        sinfos.insert(signer_info).unwrap();
        SignedData {
            version: CmsVersion::V1,
            digest_algorithms: digest_algs,
            encap_content_info: encap,
            certificates: Some(CertificateSet(certs)),
            crls: None,
            signer_infos: SignerInfos(sinfos),
        }
    }

    fn fixture() -> (SignedData, Vec<EmbeddedTrustAnchor>, SigningKey<MlDsa65>, Vec<u8>, AuthAttrs) {
        let ca = ca_private_key();
        let ca_cert = build_ca_cert(&ca);
        let ca_subject = ca_cert.tbs_certificate.subject.clone();

        let seed = B32::default();
        let sk = SigningKey::<MlDsa65>::from_seed(&seed);
        let vk_bytes = sk.verifying_key().encode().to_vec();

        let signer_cert = build_ml_dsa_signer_cert(&ca, &ca_subject, &vk_bytes);

        let content = b"myna end to end ML-DSA CMS".to_vec();
        let (attrs, _d) = pkcs7::prepare_signing(&content, HashAlgorithm::Sha256);
        let signed_attrs_der = attrs.to_der().unwrap();
        let ml_sig = ml_dsa::Signer::sign(&sk, &signed_attrs_der).encode().to_vec();

        let signed_data = build_cms(&content, &signer_cert, &attrs, &ml_sig);
        let roots = vec![EmbeddedTrustAnchor {
            name: "myna PQ test CA",
            cert: ca_cert,
        }];
        (signed_data, roots, sk, ml_sig, attrs)
    }

    #[test]
    fn ml_dsa_cms_end_to_end_verifies() {
        let (signed_data, roots, _sk, _sig, _attrs) = fixture();
        verify_cms_signature(&signed_data, None, &roots)
            .expect("valid ML-DSA signed CMS must verify end to end");
    }

    #[test]
    fn ml_dsa_cms_rejects_tampered_signature() {
        let ca = ca_private_key();
        let ca_cert = build_ca_cert(&ca);
        let ca_subject = ca_cert.tbs_certificate.subject.clone();
        let seed = B32::default();
        let sk = SigningKey::<MlDsa65>::from_seed(&seed);
        let vk_bytes = sk.verifying_key().encode().to_vec();
        let signer_cert = build_ml_dsa_signer_cert(&ca, &ca_subject, &vk_bytes);
        let content = b"myna end to end ML-DSA CMS".to_vec();
        let (attrs, _d) = pkcs7::prepare_signing(&content, HashAlgorithm::Sha256);
        let signed_attrs_der = attrs.to_der().unwrap();
        let mut ml_sig = ml_dsa::Signer::sign(&sk, &signed_attrs_der).encode().to_vec();
        ml_sig[0] ^= 0x01;
        let signed_data = build_cms(&content, &signer_cert, &attrs, &ml_sig);
        let roots = vec![EmbeddedTrustAnchor { name: "ca", cert: ca_cert }];
        assert!(verify_cms_signature(&signed_data, None, &roots).is_err());
    }

    #[test]
    fn ml_dsa_cms_rejects_untrusted_anchor() {
        let (signed_data, _roots, _sk, _sig, _attrs) = fixture();
        assert!(verify_cms_signature(&signed_data, None, &[]).is_err());
    }
}
