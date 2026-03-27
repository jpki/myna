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
use x509_cert::Certificate;

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
/// - content: detached 署名の場合は署名対象データ。embedded の場合は None。
pub(crate) fn verify_cms_signature(
    signed_data: &SignedData,
    content: Option<&[u8]>,
    roots: &[EmbeddedTrustAnchor],
) -> Result<(), Error> {
    if signed_data.signer_infos.0.is_empty() {
        return Err(Error::new("SignedData に署名者情報がありません"));
    }

    for (i, si) in signed_data.signer_infos.0.iter().enumerate() {
        let cert = find_cert_for_signer(signed_data, si)?
            .ok_or_else(|| Error::new("署名者証明書が SignedData 内に見つかりません"))?;

        // 1. messageDigest 検証
        verify_message_digest(si, content)?;
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
        SignerIdentifier::SubjectKeyIdentifier(_) => Err(Error::new(
            "SubjectKeyIdentifier 形式の署名者 ID には対応していません",
        )),
    }
}

/// messageDigest 認証属性とコンテンツのハッシュを照合する
fn verify_message_digest(si: &SignerInfo, content: Option<&[u8]>) -> Result<(), Error> {
    let content_data = match content {
        Some(d) => d,
        None => return Ok(()), // embedded の場合はスキップ（EncapsulatedContentInfo 内）
    };
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
    if *oid == Sha1::OID {
        Ok(Sha1::digest(data).to_vec())
    } else if *oid == Sha256::OID {
        Ok(Sha256::digest(data).to_vec())
    } else if *oid == Sha384::OID {
        Ok(Sha384::digest(data).to_vec())
    } else if *oid == Sha512::OID {
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

    let result = if *digest_oid == Sha1::OID {
        VerifyingKey::<Sha1>::new(rsa_key).verify(msg, &sig)
    } else if *digest_oid == Sha256::OID {
        VerifyingKey::<Sha256>::new(rsa_key).verify(msg, &sig)
    } else if *digest_oid == Sha384::OID {
        VerifyingKey::<Sha384>::new(rsa_key).verify(msg, &sig)
    } else if *digest_oid == Sha512::OID {
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
/// 返値: 検証に成功した trust anchor の名前。いずれにも一致しなければ None。
fn verify_cert_chain<'a>(
    cert: &Certificate,
    roots: &'a [EmbeddedTrustAnchor],
) -> Result<Option<&'a str>, Error> {
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
            return Ok(Some(root.name));
        }
    }
    Ok(None)
}

/// sha*WithRSAEncryption OID からダイジェスト OID を返す
fn sig_alg_to_digest_oid(oid: &ObjectIdentifier) -> Result<ObjectIdentifier, Error> {
    if *oid == rfc5912::SHA_1_WITH_RSA_ENCRYPTION {
        Ok(Sha1::OID)
    } else if *oid == rfc5912::SHA_256_WITH_RSA_ENCRYPTION {
        Ok(Sha256::OID)
    } else if *oid == rfc5912::SHA_384_WITH_RSA_ENCRYPTION {
        Ok(Sha384::OID)
    } else if *oid == rfc5912::SHA_512_WITH_RSA_ENCRYPTION {
        Ok(Sha512::OID)
    } else {
        Err(Error::new(format!("未対応の署名アルゴリズム OID: {}", oid)))
    }
}
