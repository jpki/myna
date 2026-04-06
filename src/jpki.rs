use crate::error::Error;
use crate::pkcs7;
use crate::reader::MynaReader;
use crate::utils;
use crate::verify;
use clap::ValueEnum;
use der::Decode;
use x509_cert::Certificate;

// ---------------------------------------------------------------------------
// 公開型定義
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, ValueEnum)]
#[clap(rename_all = "snake_case")]
pub enum CertType {
    /// 署名用証明書
    #[value(alias = "signature", alias = "digital_signature")]
    Sign,
    /// 署名用CA証明書
    SignCa,
    /// 認証用証明書
    Auth,
    /// 認証用CA証明書
    AuthCa,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum KeyType {
    /// 署名用鍵
    Sign,
    /// 認証用鍵
    Auth,
}

// ---------------------------------------------------------------------------
// JPKIAP — JPKI アプリケーション構造体
// ---------------------------------------------------------------------------

const JPKI_AID: &str = "D392f000260100000001";

pub struct JPKIAP<'a> {
    pub reader: &'a mut MynaReader,
    token: String,
}

impl MynaReader {
    pub fn jpki_ap(&mut self) -> Result<JPKIAP<'_>, Error> {
        let aid = utils::hex_decode(JPKI_AID).unwrap();
        self.select_df(&aid)
            .map_err(|e| Error::with_source("JPKI APの選択に失敗しました", e))?;
        self.select_ef("0006")
            .map_err(|e| Error::with_source("トークンEFの選択に失敗しました", e))?;
        let data = self
            .read_binary(0, 0x20)
            .map_err(|e| Error::with_source("READ BINARYに失敗しました", e))?;
        let token = String::from_utf8_lossy(&data)
            .trim_end_matches(|c: char| c == '\0' || c.is_ascii_whitespace())
            .to_string();
        Ok(JPKIAP {
            reader: self,
            token,
        })
    }
}

impl<'a> JPKIAP<'a> {
    pub fn close(self) {}

    pub fn token(&self) -> &str {
        &self.token
    }

    /// 証明書読み取り
    pub fn cert_read(
        &mut self,
        cert_type: &CertType,
        credential: Option<&str>,
    ) -> Result<Certificate, Error> {
        match cert_type {
            CertType::Sign => {
                let cred = credential
                    .ok_or_else(|| Error::from("署名用パスワードが必要です"))?
                    .to_uppercase();
                self.reader
                    .select_ef("001b")
                    .map_err(|e| Error::with_source("署名用PIN EFの選択に失敗しました", e))?;
                self.reader
                    .verify_pin(&cred)
                    .map_err(|e| Error::with_source("パスワード認証に失敗しました", e))?;
                self.reader
                    .select_ef("0001")
                    .map_err(|e| Error::with_source("署名用証明書EFの選択に失敗しました", e))?;
            }
            CertType::SignCa => {
                self.reader
                    .select_ef("0002")
                    .map_err(|e| Error::with_source("署名用CA証明書EFの選択に失敗しました", e))?;
            }
            CertType::Auth => {
                if self.token == "JPKIAPGPSETOKEN" {
                    let cred = credential
                        .ok_or_else(|| Error::from("認証用PINが必要です"))?
                        .to_uppercase();
                    self.reader
                        .select_ef("0018")
                        .map_err(|e| Error::with_source("認証用PIN EFの選択に失敗しました", e))?;
                    self.reader
                        .verify_pin(&cred)
                        .map_err(|e| Error::with_source("PIN認証に失敗しました", e))?;
                }
                self.reader
                    .select_ef("000a")
                    .map_err(|e| Error::with_source("認証用証明書EFの選択に失敗しました", e))?;
            }
            CertType::AuthCa => {
                self.reader
                    .select_ef("000b")
                    .map_err(|e| Error::with_source("認証用CA証明書EFの選択に失敗しました", e))?;
            }
        }
        let cert_der = self
            .reader
            .read_binary_all()
            .map_err(|e| Error::with_source("READ BINARYに失敗しました", e))?;
        Certificate::from_der(&cert_der)
            .map_err(|e| Error::with_source("証明書のパースに失敗しました", e))
    }

    /// 低レベルRSA署名
    pub fn pkey_sign(
        &mut self,
        key_type: &KeyType,
        credential: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let credential = credential.to_uppercase();
        match key_type {
            KeyType::Sign => {
                self.reader
                    .select_ef("001b")
                    .map_err(|e| Error::with_source("署名用PIN EFの選択に失敗しました", e))?;
                self.reader
                    .verify_pin(&credential)
                    .map_err(|e| Error::with_source("パスワード認証に失敗しました", e))?;
            }
            KeyType::Auth => {
                self.reader
                    .select_ef("0018")
                    .map_err(|e| Error::with_source("認証用PIN EFの選択に失敗しました", e))?;
                self.reader
                    .verify_pin(&credential)
                    .map_err(|e| Error::with_source("PIN認証に失敗しました", e))?;
            }
        }
        let key_ef = match key_type {
            KeyType::Sign => "001a",
            KeyType::Auth => "0017",
        };
        self.reader
            .select_ef(key_ef)
            .map_err(|e| Error::with_source("鍵EFの選択に失敗しました", e))?;
        self.reader
            .signature(data)
            .map_err(|e| Error::with_source("署名に失敗しました", e))
    }

    /// 低レベルRSA署名検証: 署名値から DigestInfo を取り出す
    pub fn pkey_verify(&mut self, key_type: &KeyType, sig: &[u8]) -> Result<Vec<u8>, Error> {
        let cert_type = match key_type {
            KeyType::Sign => CertType::Sign,
            KeyType::Auth => CertType::Auth,
        };
        let cert = self.cert_read(&cert_type, None)?;
        rsa_pkcs1_public_unpad(&cert, sig)
    }

    /// CMS署名: PKCS#7 SignedData DER を返す
    pub fn cms_sign(
        &mut self,
        content: &[u8],
        password: &str,
        alg: pkcs7::HashAlgorithm,
        detached: bool,
    ) -> Result<Vec<u8>, Error> {
        self.reader
            .select_ef("001b")
            .map_err(|e| Error::with_source("署名用PIN EFの選択に失敗しました", e))?;
        self.reader
            .verify_pin(password)
            .map_err(|e| Error::with_source("パスワード認証に失敗しました", e))?;
        self.reader
            .select_ef("0001")
            .map_err(|e| Error::with_source("署名用証明書EFの選択に失敗しました", e))?;
        let cert_der = self
            .reader
            .read_binary_all()
            .map_err(|e| Error::with_source("READ BINARYに失敗しました", e))?;

        let (attrs, attrs_digest) = pkcs7::prepare_signing(content, alg);
        let digest_info = pkcs7::build_digest_info(alg, &attrs_digest);

        self.reader
            .select_ef("001a")
            .map_err(|e| Error::with_source("署名鍵EFの選択に失敗しました", e))?;
        let signature = self
            .reader
            .signature(&digest_info)
            .map_err(|e| Error::with_source("署名に失敗しました", e))?;

        Ok(pkcs7::build_signed_data(
            content, &cert_der, &signature, alg, &attrs, detached,
        ))
    }

    /// PDF電子署名: 署名済みPDFバイト列を返す
    pub fn pdf_sign(&mut self, pdf_data: &[u8], password: &str) -> Result<Vec<u8>, Error> {
        self.reader
            .select_ef("001b")
            .map_err(|e| Error::with_source("署名用PIN EFの選択に失敗しました", e))?;
        self.reader
            .verify_pin(password)
            .map_err(|e| Error::with_source("パスワード認証に失敗しました", e))?;
        self.reader
            .select_ef("0001")
            .map_err(|e| Error::with_source("署名用証明書EFの選択に失敗しました", e))?;
        let cert_der = self
            .reader
            .read_binary_all()
            .map_err(|e| Error::with_source("READ BINARYに失敗しました", e))?;

        let mut output = crate::pdf::build_pdf_with_placeholder(pdf_data)?;
        let (contents_range, byte_range_placeholder) =
            crate::pdf::locate_signature_placeholders(&output)?;
        crate::pdf::write_byte_range(&mut output, &contents_range, &byte_range_placeholder)?;
        let content_hash = crate::pdf::hash_signed_ranges(&output, &contents_range)?;

        let alg = pkcs7::HashAlgorithm::Sha256;
        let (attrs, attrs_digest) = pkcs7::prepare_signing_with_hash(&content_hash, alg);
        let digest_info = pkcs7::build_digest_info(pkcs7::HashAlgorithm::Sha256, &attrs_digest);

        self.reader
            .select_ef("001a")
            .map_err(|e| Error::with_source("署名鍵EFの選択に失敗しました", e))?;
        let signature = self
            .reader
            .signature(&digest_info)
            .map_err(|e| Error::with_source("署名に失敗しました", e))?;

        let pkcs7_der = pkcs7::build_signed_data_detached(&cert_der, &signature, alg, &attrs);
        crate::pdf::embed_signature(&mut output, &contents_range, &pkcs7_der)?;

        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// CMS 署名検証
// ---------------------------------------------------------------------------

/// CMS(PKCS#7)署名を検証する
pub fn cms_verify(pkcs7_der: &[u8], content: Option<&[u8]>) -> Result<(), Error> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::Encode;

    let ci = ContentInfo::from_der(pkcs7_der)
        .map_err(|e| Error::with_source("ContentInfo の DER パースに失敗しました", e))?;
    let content_der = ci
        .content
        .to_der()
        .map_err(|e| Error::with_source("content の DER エンコードに失敗しました", e))?;
    let signed_data = SignedData::from_der(&content_der)
        .map_err(|e| Error::with_source("SignedData の DER パースに失敗しました", e))?;
    log::info!("Parsed PKCS#7 SignedData");
    verify::log_pkcs7_signers(&signed_data)?;

    log::info!("Building certificate store for CMS verification");
    let roots = verify::build_sign_verifier()?;
    verify::log_sign_trust_anchors(&roots)?;
    verify::verify_signer_certificates(&signed_data, &roots)?;

    log::info!("Checking CMS content digest, signature, and signer certificate chain");
    verify::verify_cms_signature(&signed_data, content, &roots)
}

// ---------------------------------------------------------------------------
// ヘルパー関数
// ---------------------------------------------------------------------------

/// RSA PKCS#1 type-1 public key operation: sig^e mod n → DigestInfo
fn rsa_pkcs1_public_unpad(cert: &Certificate, sig: &[u8]) -> Result<Vec<u8>, Error> {
    use rsa::BigUint;
    use rsa::hazmat::rsa_encrypt;
    use rsa::traits::PublicKeyParts;

    let rsa_key = verify::rsa_pub_key_from_cert(cert)?;
    let key_size = rsa_key.size();

    let c = BigUint::from_bytes_be(sig);
    let m = rsa_encrypt(&rsa_key, &c)
        .map_err(|e| Error::with_source("RSA 公開鍵演算に失敗しました", e))?;

    let mut em = m.to_bytes_be();
    while em.len() < key_size {
        em.insert(0, 0u8);
    }

    if em.len() < 3 || em[0] != 0x00 || em[1] != 0x01 {
        return Err(Error::new("PKCS#1 パディングが不正です"));
    }
    let ps_end = em[2..]
        .iter()
        .position(|&b| b == 0x00)
        .ok_or_else(|| Error::new("PKCS#1 パディング区切りが見つかりません"))?;
    if ps_end == 0 {
        return Err(Error::new("PKCS#1 パディング長が不足しています"));
    }
    Ok(em[2 + ps_end + 1..].to_vec())
}

#[cfg(all(test, feature = "dummy"))]
mod dummy_tests {
    use super::*;
    #[cfg(feature = "dummy")]
    use crate::reader::dummy::JPKI_AID;
    use der::Encode;
    use rsa::pkcs8::DecodePrivateKey;

    fn first_subject_value(cert: &Certificate) -> String {
        let rdn = cert.tbs_certificate.subject.0.first().unwrap();
        let atv = rdn.0.iter().next().unwrap();
        let bytes = atv.value.to_der().unwrap();
        if let Ok(s) = der::asn1::Utf8StringRef::from_der(&bytes) {
            return s.as_str().to_string();
        }
        if let Ok(s) = der::asn1::PrintableStringRef::from_der(&bytes) {
            return s.as_str().to_string();
        }
        panic!("Subject ATV value is not a string type");
    }

    fn setup_reader() -> MynaReader {
        let sign_cert = include_bytes!("../tests/fixtures/sign_cert.der");
        let sign_ca_cert = include_bytes!("../tests/fixtures/sign_ca_cert.der");
        let auth_cert = include_bytes!("../tests/fixtures/auth_cert.der");
        let auth_ca_cert = include_bytes!("../tests/fixtures/auth_ca_cert.der");
        let sign_key_pem = include_bytes!("../tests/fixtures/sign_key.pem");
        let pem_str = std::str::from_utf8(sign_key_pem).unwrap();
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_pem(pem_str).unwrap();

        MynaReader::new()
            .unwrap()
            .with_file(
                JPKI_AID,
                "0006",
                b"JPKIAPICCTOKEN\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec(),
            )
            .with_file(JPKI_AID, "0001", sign_cert.to_vec())
            .with_file(JPKI_AID, "0002", sign_ca_cert.to_vec())
            .with_file(JPKI_AID, "000a", auth_cert.to_vec())
            .with_file(JPKI_AID, "000b", auth_ca_cert.to_vec())
            .with_file(JPKI_AID, "0017", vec![])
            .with_file(JPKI_AID, "001a", vec![])
            .with_pin(JPKI_AID, "0018", "1234", 3)
            .with_pin(JPKI_AID, "001b", "SIGNATURE", 5)
            .with_sign_fn(move |data| {
                use rsa::BigUint;
                use rsa::hazmat::rsa_decrypt_and_check;
                use rsa::traits::PublicKeyParts;
                let key_size = priv_key.size();
                let ps_len = key_size - data.len() - 3;
                let mut em = vec![0x00u8, 0x01];
                em.extend(std::iter::repeat(0xffu8).take(ps_len));
                em.push(0x00);
                em.extend_from_slice(data);
                let m = BigUint::from_bytes_be(&em);
                let c = rsa_decrypt_and_check(&priv_key, None::<&mut rsa::rand_core::OsRng>, &m)
                    .unwrap();
                let mut sig = c.to_bytes_be();
                while sig.len() < key_size {
                    sig.insert(0, 0u8);
                }
                sig
            })
    }

    fn setup_gpse_reader() -> MynaReader {
        let auth_cert = include_bytes!("../tests/fixtures/auth_cert.der");
        MynaReader::new()
            .unwrap()
            .with_file(
                JPKI_AID,
                "0006",
                b"JPKIAPGPSETOKEN\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec(),
            )
            .with_file(JPKI_AID, "000a", auth_cert.to_vec())
            .with_pin(JPKI_AID, "0018", "1234", 3)
    }

    #[test]
    fn test_jpki_ap_token() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let jpki = reader.jpki_ap().unwrap();
        assert_eq!(jpki.token(), "JPKIAPICCTOKEN");
    }

    #[test]
    fn test_jpki_ap_close() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let jpki = reader.jpki_ap().unwrap();
        jpki.close();
        let jpki2 = reader.jpki_ap().unwrap();
        assert_eq!(jpki2.token(), "JPKIAPICCTOKEN");
    }

    #[test]
    fn test_read_auth_cert() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let cert = jpki.cert_read(&CertType::Auth, None).unwrap();
        assert_eq!(first_subject_value(&cert), "Test auth User");
    }

    #[test]
    fn test_pkey_sign_sign() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let digest_info = pkcs7::build_digest_info(pkcs7::HashAlgorithm::Sha256, &[0u8; 32]);
        let sig = jpki
            .pkey_sign(&KeyType::Sign, "SIGNATURE", &digest_info)
            .unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_cms_sign() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let content = b"Hello, World!";
        let pkcs7_der = jpki
            .cms_sign(content, "SIGNATURE", pkcs7::HashAlgorithm::Sha256, false)
            .unwrap();

        let ci = cms::content_info::ContentInfo::from_der(&pkcs7_der).unwrap();
        assert!(!ci.to_der().unwrap().is_empty());
    }

    #[test]
    fn test_read_sign_cert() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let cert = jpki.cert_read(&CertType::Sign, Some("SIGNATURE")).unwrap();
        assert_eq!(first_subject_value(&cert), "Test sign User");
    }

    #[test]
    fn test_read_sign_ca_cert() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let cert = jpki.cert_read(&CertType::SignCa, None).unwrap();
        assert_eq!(first_subject_value(&cert), "Test sign CA");
    }

    #[test]
    fn test_read_auth_ca_cert() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let cert = jpki.cert_read(&CertType::AuthCa, None).unwrap();
        assert_eq!(first_subject_value(&cert), "Test auth CA");
    }

    #[test]
    fn test_read_auth_cert_gpse_token() {
        let mut reader = setup_gpse_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        assert_eq!(jpki.token(), "JPKIAPGPSETOKEN");
        let cert = jpki.cert_read(&CertType::Auth, Some("1234")).unwrap();
        assert_eq!(first_subject_value(&cert), "Test auth User");
    }

    #[test]
    fn test_pkey_sign_auth() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let digest_info = pkcs7::build_digest_info(pkcs7::HashAlgorithm::Sha256, &[0u8; 32]);
        let sig = jpki
            .pkey_sign(&KeyType::Auth, "1234", &digest_info)
            .unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_cms_sign_detached() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let content = b"Hello, World!";
        let pkcs7_der = jpki
            .cms_sign(content, "SIGNATURE", pkcs7::HashAlgorithm::Sha256, true)
            .unwrap();

        let ci = cms::content_info::ContentInfo::from_der(&pkcs7_der).unwrap();
        assert!(!ci.to_der().unwrap().is_empty());
    }

    #[test]
    fn test_cert_read_sign_without_password_fails() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let result = jpki.cert_read(&CertType::Sign, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkey_sign_wrong_password_fails() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let digest_info = pkcs7::build_digest_info(pkcs7::HashAlgorithm::Sha256, &[0u8; 32]);
        let result = jpki.pkey_sign(&KeyType::Sign, "WRONGPW1", &digest_info);
        assert!(result.is_err());
    }
}
