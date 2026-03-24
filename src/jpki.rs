use crate::error::Error;
use crate::pkcs7;
use crate::reader::MynaReader;
use crate::utils;
use crate::verify;
use clap::{Args, Subcommand, ValueEnum};
use der::{Decode, Encode, EncodePem};
use x509_cert::Certificate;
use std::fs;
use std::io::Write;

// ---------------------------------------------------------------------------
// CLI 引数定義
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

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
pub struct CertArgs {
    /// 証明書の種類 [sign, sign-ca, auth, auth-ca]
    #[arg(short = 't', long = "type", value_enum)]
    cert_type: CertType,
    /// 署名用パスワード(6-16桁) signの場合に必要
    #[arg(short, long)]
    password: Option<String>,
    /// 認証用PIN(4桁数字) スマホJPKIのauth時に必要
    #[arg(long)]
    pin: Option<String>,
    /// フォーマット
    #[arg(short, long, value_enum, default_value = "text")]
    format: EnumFormat,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum KeyType {
    /// 署名用鍵
    Sign,
    /// 認証用鍵
    Auth,
}

#[derive(Debug, Args)]
pub struct PkeySignArgs {
    /// 鍵の種類 [sign, auth]
    #[arg(short = 't', long = "type", value_enum)]
    key_type: KeyType,
    /// 署名用パスワード(6-16桁) / 認証用PIN(4桁)
    #[arg(short, long)]
    password: Option<String>,
    /// 入力ファイル
    #[arg(value_name = "INPUT")]
    input: String,
    /// 出力ファイル
    #[arg(short, long)]
    output: String,
}

#[derive(Debug, Args)]
pub struct PkeyVerifyArgs {
    /// 鍵の種類 [sign, auth]
    #[arg(short = 't', long = "type", value_enum)]
    key_type: KeyType,
    /// 署名ファイル
    #[arg(value_name = "INPUT")]
    input: String,
    /// 出力ファイル (省略時はstdout)
    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Subcommand)]
pub enum PkeySubcommand {
    /// 低レベルRSA署名を行います
    Sign(PkeySignArgs),
    /// 低レベルRSA署名を検証します
    Verify(PkeyVerifyArgs),
}

#[derive(Clone, Debug, ValueEnum)]
enum SignType {
    /// 署名用証明書
    Sign,
}

#[derive(Debug, Args)]
pub struct CmsSignArgs {
    /// 署名の種類
    #[arg(short = 't', long = "type", value_enum, default_value = "sign")]
    sign_type: SignType,
    /// 署名用パスワード(6-16桁)
    #[arg(short, long)]
    password: Option<String>,
    /// 署名対象ファイル
    #[arg(value_name = "INPUT")]
    input: String,
    /// 出力ファイル
    #[arg(short, long)]
    output: String,
    /// ダイジェストアルゴリズム
    #[arg(short, long, value_enum, default_value = "sha256")]
    digest: DigestAlgorithm,
    /// 出力形式
    #[arg(short, long, value_enum, default_value = "der")]
    format: CmsFormat,
    /// デタッチ署名
    #[arg(long)]
    detached: bool,
}

#[derive(Debug, Args)]
pub struct CmsVerifyArgs {
    /// 署名ファイル
    signature: String,
    /// デタッチ署名の検証対象ファイル
    #[arg(short, long)]
    content: Option<String>,
    /// 入力形式
    #[arg(short, long, value_enum, default_value = "der")]
    format: CmsFormat,
    /// デタッチ署名
    #[arg(long)]
    detached: bool,
}

/// format
#[derive(Clone, ValueEnum, Debug)]
enum EnumFormat {
    /// text format
    Text,
    /// pem format
    Pem,
    /// der format
    Der,
}

#[derive(Clone, ValueEnum, Debug)]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, ValueEnum, Debug)]
enum CmsFormat {
    Pem,
    Der,
}

#[derive(Subcommand)]
pub enum CmsSubcommand {
    /// CMS署名を行います
    Sign(CmsSignArgs),
    /// CMS署名を検証します
    Verify(CmsVerifyArgs),
}

#[derive(Debug, Args)]
pub struct PdfSignArgs {
    /// 入力PDFファイル
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// 出力PDFファイル
    #[arg(short, long)]
    pub output: String,
    /// 署名用パスワード(6-16桁)
    #[arg(short, long)]
    pub password: Option<String>,
}

#[derive(Debug, Args)]
pub struct PdfVerifyArgs {
    /// 署名済みPDFファイル
    #[arg(value_name = "INPUT")]
    pub input: String,
}

#[derive(Subcommand)]
pub enum PdfSubcommand {
    /// PDFに電子署名を付与します
    Sign(PdfSignArgs),
    /// PDF電子署名を検証します
    Verify(PdfVerifyArgs),
}

#[derive(Subcommand)]
#[allow(clippy::upper_case_acronyms)]
pub enum JPKI {
    /// 証明書を表示します
    Cert(CertArgs),
    /// 低レベルRSA署名・検証
    #[command(subcommand)]
    Pkey(PkeySubcommand),
    /// CMS署名・検証
    #[command(subcommand)]
    Cms(CmsSubcommand),
    /// PDF電子署名
    #[command(subcommand)]
    Pdf(PdfSubcommand),
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
        password: &Option<String>,
        pin: &Option<String>,
    ) -> Result<Certificate, Error> {
        match cert_type {
            CertType::Sign => {
                let pass = validate_sign_password(password)?;
                self.reader
                    .select_ef("001b")
                    .map_err(|e| Error::with_source("署名用PIN EFの選択に失敗しました", e))?;
                self.reader
                    .verify_pin(&pass)
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
                    let p = validate_auth_pin(pin)?;
                    self.reader
                        .select_ef("0018")
                        .map_err(|e| Error::with_source("認証用PIN EFの選択に失敗しました", e))?;
                    self.reader
                        .verify_pin(&p)
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
        credential: &Option<String>,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match key_type {
            KeyType::Sign => {
                let pass = validate_sign_password(credential)?;
                self.reader
                    .select_ef("001b")
                    .map_err(|e| Error::with_source("署名用PIN EFの選択に失敗しました", e))?;
                self.reader
                    .verify_pin(&pass)
                    .map_err(|e| Error::with_source("パスワード認証に失敗しました", e))?;
            }
            KeyType::Auth => {
                let pin = validate_auth_pin(credential)?;
                self.reader
                    .select_ef("0018")
                    .map_err(|e| Error::with_source("認証用PIN EFの選択に失敗しました", e))?;
                self.reader
                    .verify_pin(&pin)
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
// ヘルパー関数
// ---------------------------------------------------------------------------

fn validate_sign_password(password: &Option<String>) -> Result<String, Error> {
    let pass = password
        .clone()
        .ok_or_else(|| Error::from("署名用パスワードが必要です"))?;
    let pass = pass.to_uppercase();
    utils::validate_jpki_sign_password(&pass)?;
    Ok(pass)
}

fn validate_auth_pin(pin: &Option<String>) -> Result<String, Error> {
    let pin = pin
        .clone()
        .ok_or_else(|| Error::from("認証用PINが必要です"))?;
    utils::validate_4digit_pin(&pin)?;
    Ok(pin)
}

fn prompt_sign_password(password: &Option<String>) -> String {
    validate_sign_password(&Some(utils::prompt_input(
        "署名用パスワード(6-16桁): ",
        password,
    )))
    .expect("署名用パスワードが不正です")
}

fn prompt_auth_pin(pin: &Option<String>) -> String {
    validate_auth_pin(&Some(utils::prompt_input("認証用PIN(4桁): ", pin)))
        .expect("認証用PINが不正です")
}

/// RSA PKCS#1 type-1 public key operation: sig^e mod n → DigestInfo
///
/// OpenSSL の RSA_public_decrypt(PKCS1) に相当。署名値から DigestInfo を取り出す。
fn rsa_pkcs1_public_unpad(cert: &Certificate, sig: &[u8]) -> Result<Vec<u8>, Error> {
    use rsa::hazmat::rsa_encrypt;
    use rsa::traits::PublicKeyParts;
    use rsa::BigUint;

    let rsa_key = crate::verify::rsa_pub_key_from_cert(cert)?;
    let key_size = rsa_key.size();

    // RSA public key operation: m = sig^e mod n
    let c = BigUint::from_bytes_be(sig);
    let m = rsa_encrypt(&rsa_key, &c)
        .map_err(|e| Error::with_source("RSA 公開鍵演算に失敗しました", e))?;

    // left-pad to key size
    let mut em = m.to_bytes_be();
    while em.len() < key_size {
        em.insert(0, 0u8);
    }

    // PKCS#1 type 1 padding: 0x00 0x01 <0xff...> 0x00 <message>
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

fn digest_alg_to_hash_alg(alg: &DigestAlgorithm) -> pkcs7::HashAlgorithm {
    match alg {
        DigestAlgorithm::Sha1 => pkcs7::HashAlgorithm::Sha1,
        DigestAlgorithm::Sha256 => pkcs7::HashAlgorithm::Sha256,
        DigestAlgorithm::Sha384 => pkcs7::HashAlgorithm::Sha384,
        DigestAlgorithm::Sha512 => pkcs7::HashAlgorithm::Sha512,
    }
}

/// 証明書を指定フォーマットで出力する共通関数
fn cert_output(cert: &Certificate, format: &EnumFormat) {
    use der::Encode;
    match format {
        EnumFormat::Text => {
            let tbs = &cert.tbs_certificate;
            println!("Subject: {}", tbs.subject);
            println!("Issuer:  {}", tbs.issuer);
            println!("Serial:  {}", utils::hex_encode(tbs.serial_number.as_bytes()));
            println!(
                "Validity: {} - {}",
                tbs.validity.not_before, tbs.validity.not_after
            );
        }
        EnumFormat::Pem => {
            let pem = cert
                .to_pem(der::pem::LineEnding::LF)
                .expect("証明書のPEM変換に失敗しました");
            print!("{}", pem);
        }
        EnumFormat::Der => {
            std::io::stdout()
                .write_all(&cert.to_der().expect("証明書のDER変換に失敗しました"))
                .expect("標準出力への書き込みに失敗しました");
        }
    }
}

// ---------------------------------------------------------------------------
// CLI メインディスパッチ
// ---------------------------------------------------------------------------

pub fn main(subcommand: &JPKI) -> Result<(), Error> {
    match subcommand {
        JPKI::Cert(args) => run_cert(args),
        JPKI::Pkey(cmd) => match cmd {
            PkeySubcommand::Sign(args) => run_pkey_sign(args),
            PkeySubcommand::Verify(args) => run_pkey_verify(args),
        },
        JPKI::Cms(cmd) => match cmd {
            CmsSubcommand::Sign(args) => run_cms_sign(args),
            CmsSubcommand::Verify(args) => run_cms_verify(args),
        },
        JPKI::Pdf(cmd) => match cmd {
            PdfSubcommand::Sign(args) => run_pdf_sign(args),
            PdfSubcommand::Verify(args) => crate::pdf::pdf_verify(args),
        },
    }
}

// ---------------------------------------------------------------------------
// CLI 実行関数
// ---------------------------------------------------------------------------

fn run_cert(args: &CertArgs) -> Result<(), Error> {
    let password = match args.cert_type {
        CertType::Sign => Some(prompt_sign_password(&args.password)),
        _ => args.password.clone(),
    };
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let mut jpki = reader.jpki_ap()?;

    let pin = match args.cert_type {
        CertType::Auth if args.pin.is_none() && jpki.token() == "JPKIAPGPSETOKEN" => {
            Some(prompt_auth_pin(&args.pin))
        }
        _ => args.pin.clone(),
    };

    let cert = jpki.cert_read(&args.cert_type, &password, &pin)?;
    cert_output(&cert, &args.format);
    Ok(())
}

fn run_pkey_sign(args: &PkeySignArgs) -> Result<(), Error> {
    let content = fs::read(&args.input)?;
    let credential = match args.key_type {
        KeyType::Sign => Some(prompt_sign_password(&args.password)),
        KeyType::Auth => Some(prompt_auth_pin(&args.password)),
    };
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let mut jpki = reader.jpki_ap()?;
    let signature = jpki.pkey_sign(&args.key_type, &credential, &content)?;
    fs::write(&args.output, &signature)?;
    println!("署名を保存しました: {}", args.output);
    Ok(())
}

fn run_pkey_verify(args: &PkeyVerifyArgs) -> Result<(), Error> {
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let mut jpki = reader.jpki_ap()?;

    let cert_type = match args.key_type {
        KeyType::Sign => CertType::Sign,
        KeyType::Auth => CertType::Auth,
    };
    let cert = jpki.cert_read(&cert_type, &None, &None)?;
    let sig = fs::read(&args.input)?;
    let result = rsa_pkcs1_public_unpad(&cert, &sig)?;
    if let Some(ref path) = args.output {
        fs::write(path, &result)?;
    } else {
        std::io::stdout().write_all(&result)?;
    }
    Ok(())
}

fn run_cms_sign(args: &CmsSignArgs) -> Result<(), Error> {
    let password = {
        let pass = utils::prompt_input("署名用パスワード(6-16桁): ", &args.password);
        let pass = pass.to_uppercase();
        utils::validate_jpki_sign_password(&pass)?;
        pass
    };
    let content = fs::read(&args.input)?;
    let alg = digest_alg_to_hash_alg(&args.digest);

    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let mut jpki = reader.jpki_ap()?;
    let pkcs7_der = jpki.cms_sign(&content, &password, alg, args.detached)?;

    let output_data = match args.format {
        CmsFormat::Der => pkcs7_der,
        CmsFormat::Pem => {
            let b64 = utils::base64_encode(&pkcs7_der);
            format!(
                "-----BEGIN PKCS7-----\n{}\n-----END PKCS7-----\n",
                b64.trim_end()
            )
            .into_bytes()
        }
    };

    fs::write(&args.output, &output_data)?;
    println!("署名を保存しました: {}", args.output);
    Ok(())
}

fn run_cms_verify(args: &CmsVerifyArgs) -> Result<(), Error> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::Decode;

    log::info!("Loading CMS signature from {}", args.signature);
    let sig_data = fs::read(&args.signature)?;

    // PEM の場合は DER に変換（PEM ラベルを剥いで base64 デコード）
    let pkcs7_der: Vec<u8> = match args.format {
        CmsFormat::Der => sig_data,
        CmsFormat::Pem => {
            log::info!("Decoding PEM-encoded CMS signature");
            let pem_str = std::str::from_utf8(&sig_data)
                .map_err(|e| Error::with_source("PEM の UTF-8 デコードに失敗しました", e))?;
            let (_, der) = der::pem::decode_vec(pem_str.as_bytes())
                .map_err(|e| Error::with_source("PEM のデコードに失敗しました", e))?;
            der
        }
    };

    let ci = ContentInfo::from_der(&pkcs7_der)
        .map_err(|e| Error::with_source("ContentInfo の DER パースに失敗しました", e))?;
    let content_der = ci.content.to_der()
        .map_err(|e| Error::with_source("content の DER エンコードに失敗しました", e))?;
    let signed_data = SignedData::from_der(&content_der)
        .map_err(|e| Error::with_source("SignedData の DER パースに失敗しました", e))?;
    log::info!("Parsed PKCS#7 SignedData");
    verify::log_pkcs7_signers(&signed_data)?;

    log::info!("Building certificate store for CMS verification");
    let roots = verify::build_sign_verifier()?;
    verify::log_sign_trust_anchors(&roots)?;
    verify::verify_signer_certificates(&signed_data, &roots)?;

    let content = if args.detached {
        log::info!("Detached CMS signature: loading external content");
        let content_file = args
            .content
            .as_ref()
            .ok_or_else(|| Error::from("デタッチ署名には-cオプションが必要です"))?;
        Some(fs::read(content_file)?)
    } else {
        None
    };

    log::info!("Checking CMS content digest, signature, and signer certificate chain");
    match verify::verify_cms_signature(&signed_data, content.as_deref(), &roots) {
        Ok(()) => println!("Verification successful"),
        Err(e) => eprintln!("Verification failed: {}", e),
    }
    Ok(())
}

fn run_pdf_sign(args: &PdfSignArgs) -> Result<(), Error> {
    let password = {
        let pass = utils::prompt_input("署名用パスワード(6-16桁): ", &args.password);
        let pass = pass.to_uppercase();
        utils::validate_jpki_sign_password(&pass)?;
        pass
    };
    let pdf_data = fs::read(&args.input)?;

    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let mut jpki = reader.jpki_ap()?;
    let signed_pdf = jpki.pdf_sign(&pdf_data, &password)?;

    fs::write(&args.output, &signed_pdf)?;
    println!("PDF署名を保存しました: {}", args.output);
    Ok(())
}

#[cfg(all(test, feature = "dummy"))]
mod dummy_tests {
    use super::*;
    use der::Encode;
    use rsa::pkcs8::DecodePrivateKey;
    #[cfg(feature = "dummy")]
    use crate::reader::dummy::JPKI_AID;

    /// 証明書の Subject の最初の ATV 値を文字列で返す
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
            .with_file(JPKI_AID, "0017", vec![]) // 認証用鍵EF (placeholder)
            .with_file(JPKI_AID, "001a", vec![]) // 署名用鍵EF (placeholder)
            .with_pin(JPKI_AID, "0018", "1234", 3)
            .with_pin(JPKI_AID, "001b", "SIGNATURE", 5)
            .with_sign_fn(move |data| {
                // raw PKCS#1 type-1 sign: pad data then d^priv mod n
                use rsa::hazmat::rsa_decrypt_and_check;
                use rsa::traits::PublicKeyParts;
                use rsa::BigUint;
                let key_size = priv_key.size();
                // PKCS#1 type 1 pad: 0x00 0x01 <0xff..> 0x00 <data>
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
        // close 後に reader を再利用できること
        let jpki2 = reader.jpki_ap().unwrap();
        assert_eq!(jpki2.token(), "JPKIAPICCTOKEN");
    }

    #[test]
    fn test_read_auth_cert() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let cert = jpki.cert_read(&CertType::Auth, &None, &None).unwrap();
        assert_eq!(first_subject_value(&cert), "Test auth User");
    }

    #[test]
    fn test_pkey_sign_sign() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let digest_info = pkcs7::build_digest_info(pkcs7::HashAlgorithm::Sha256, &[0u8; 32]);
        let sig = jpki
            .pkey_sign(&KeyType::Sign, &Some("SIGNATURE".into()), &digest_info)
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
        let cert = jpki
            .cert_read(&CertType::Sign, &Some("SIGNATURE".into()), &None)
            .unwrap();
        assert_eq!(first_subject_value(&cert), "Test sign User");
    }

    #[test]
    fn test_read_sign_ca_cert() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let cert = jpki
            .cert_read(&CertType::SignCa, &None, &None)
            .unwrap();
        assert_eq!(first_subject_value(&cert), "Test sign CA");
    }

    #[test]
    fn test_read_auth_ca_cert() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let cert = jpki
            .cert_read(&CertType::AuthCa, &None, &None)
            .unwrap();
        assert_eq!(first_subject_value(&cert), "Test auth CA");
    }

    #[test]
    fn test_read_auth_cert_gpse_token() {
        let mut reader = setup_gpse_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        assert_eq!(jpki.token(), "JPKIAPGPSETOKEN");
        let cert = jpki
            .cert_read(&CertType::Auth, &None, &Some("1234".into()))
            .unwrap();
        assert_eq!(first_subject_value(&cert), "Test auth User");
    }

    #[test]
    fn test_pkey_sign_auth() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let digest_info = pkcs7::build_digest_info(pkcs7::HashAlgorithm::Sha256, &[0u8; 32]);
        let sig = jpki
            .pkey_sign(&KeyType::Auth, &Some("1234".into()), &digest_info)
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
        let result = jpki.cert_read(&CertType::Sign, &None, &None);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkey_sign_wrong_password_fails() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let digest_info = pkcs7::build_digest_info(pkcs7::HashAlgorithm::Sha256, &[0u8; 32]);
        let result = jpki.pkey_sign(&KeyType::Sign, &Some("WRONGPW1".into()), &digest_info);
        assert!(result.is_err());
    }
}
