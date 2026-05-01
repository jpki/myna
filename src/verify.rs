use crate::error::Error;
use crate::ta::{self, EmbeddedTrustAnchor};
use cms::cert::CertificateChoices;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::{ObjectIdentifier, OctetString};
use der::oid::AssociatedOid;
use der::oid::db::{rfc5911, rfc5912};
use der::{Decode, Encode};
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
        verify_rsa_pkcs1v15(cert, &signed_attrs_der, sig_bytes, &si.digest_alg.oid)?;
        log::info!("Signer certificate {}: RSA signature OK", i + 1);

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
