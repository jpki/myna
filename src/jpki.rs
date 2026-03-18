use crate::error::Error;
use crate::pkcs7;
use crate::reader::MynaReader;
use crate::utils;
use crate::verify;
use clap::{Args, Subcommand, ValueEnum};
use openssl::hash::MessageDigest;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::X509;
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
    ) -> Result<X509, Error> {
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
        X509::from_der(&cert_der)
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
        md: MessageDigest,
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
        let cert = X509::from_der(&cert_der)
            .map_err(|e| Error::with_source("証明書のパースに失敗しました", e))?;

        let (attrs_set, attrs_digest) = pkcs7::prepare_signing(content, md);
        let digest_info = make_digest_info_from_md(md, &attrs_digest);

        self.reader
            .select_ef("001a")
            .map_err(|e| Error::with_source("署名鍵EFの選択に失敗しました", e))?;
        let signature = self
            .reader
            .signature(&digest_info)
            .map_err(|e| Error::with_source("署名に失敗しました", e))?;

        Ok(pkcs7::build_signed_data(
            content, &cert, &signature, md, &attrs_set, detached,
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
        let cert = X509::from_der(&cert_der)
            .map_err(|e| Error::with_source("証明書のパースに失敗しました", e))?;

        let mut output = crate::pdf::build_pdf_with_placeholder(pdf_data)?;
        let (contents_range, byte_range_placeholder) =
            crate::pdf::locate_signature_placeholders(&output)?;
        crate::pdf::write_byte_range(&mut output, &contents_range, &byte_range_placeholder)?;
        let content_hash = crate::pdf::hash_signed_ranges(&output, &contents_range)?;

        let md = MessageDigest::sha256();
        let (attrs_set, attrs_digest) = pkcs7::prepare_signing_with_hash(&content_hash, md);
        let digest_info = make_digest_info_from_md(md, &attrs_digest);

        self.reader
            .select_ef("001a")
            .map_err(|e| Error::with_source("署名鍵EFの選択に失敗しました", e))?;
        let signature = self
            .reader
            .signature(&digest_info)
            .map_err(|e| Error::with_source("署名に失敗しました", e))?;

        let pkcs7_der = pkcs7::build_signed_data_detached(&cert, &signature, md, &attrs_set);
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

pub fn to_message_digest(alg: &DigestAlgorithm) -> MessageDigest {
    match alg {
        DigestAlgorithm::Sha1 => MessageDigest::sha1(),
        DigestAlgorithm::Sha256 => MessageDigest::sha256(),
        DigestAlgorithm::Sha384 => MessageDigest::sha384(),
        DigestAlgorithm::Sha512 => MessageDigest::sha512(),
    }
}

pub fn make_digest_info(alg: &DigestAlgorithm, hash: &[u8]) -> Vec<u8> {
    let prefix = match alg {
        DigestAlgorithm::Sha1 => vec![
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ],
        DigestAlgorithm::Sha256 => vec![
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        DigestAlgorithm::Sha384 => vec![
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        DigestAlgorithm::Sha512 => vec![
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
    };
    [prefix, hash.to_vec()].concat()
}

fn make_digest_info_from_md(md: MessageDigest, hash: &[u8]) -> Vec<u8> {
    let alg = if md == MessageDigest::sha256() {
        DigestAlgorithm::Sha256
    } else if md == MessageDigest::sha384() {
        DigestAlgorithm::Sha384
    } else if md == MessageDigest::sha512() {
        DigestAlgorithm::Sha512
    } else {
        DigestAlgorithm::Sha1
    };
    make_digest_info(&alg, hash)
}

/// 証明書を指定フォーマットで出力する共通関数
fn output_cert(cert: &X509, format: &EnumFormat) {
    match format {
        EnumFormat::Text => {
            let text = cert.to_text().expect("証明書のテキスト変換に失敗しました");
            let text = String::from_utf8(text).expect("証明書テキストのUTF-8変換に失敗しました");
            print!("{}", text);
        }
        EnumFormat::Pem => {
            let pem = cert.to_pem().expect("証明書のPEM変換に失敗しました");
            let pem = String::from_utf8(pem).expect("証明書PEMのUTF-8変換に失敗しました");
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
    output_cert(&cert, &args.format);
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
    let pubkey = cert.public_key()?;

    let sig = fs::read(&args.input)?;

    let rsa = pubkey.rsa()?;
    let mut buf = vec![0u8; rsa.size() as usize];
    let len = rsa.public_decrypt(&sig, &mut buf, openssl::rsa::Padding::PKCS1)?;
    let result = &buf[..len];
    if let Some(ref path) = args.output {
        fs::write(path, result)?;
    } else {
        std::io::stdout().write_all(result)?;
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
    let md = to_message_digest(&args.digest);

    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let mut jpki = reader.jpki_ap()?;
    let pkcs7_der = jpki.cms_sign(&content, &password, md, args.detached)?;

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
    log::info!("Loading CMS signature from {}", args.signature);
    let sig_data = fs::read(&args.signature)?;

    let pkcs7_der = match args.format {
        CmsFormat::Der => sig_data,
        CmsFormat::Pem => {
            log::info!("Decoding PEM-encoded CMS signature");
            let pkcs7 = Pkcs7::from_pem(&sig_data)?;
            pkcs7.to_der()?
        }
    };

    let pkcs7 = Pkcs7::from_der(&pkcs7_der)?;
    log::info!("Parsed PKCS#7 SignedData");
    verify::log_pkcs7_signers(&pkcs7)?;

    log::info!("Building certificate store for CMS verification");
    let (store, roots) = verify::build_sign_verifier()?;
    verify::log_sign_trust_anchors(&roots)?;
    verify::verify_signer_certificates(&pkcs7, &store, &roots)?;

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

    let mut flags = Pkcs7Flags::empty();
    if args.detached {
        flags |= Pkcs7Flags::DETACHED;
    }

    let certs = Stack::new()?;
    log::info!("Checking CMS content digest, signature, and signer certificate chain");
    let result = if let Some(ref data) = content {
        pkcs7.verify(&certs, &store, Some(data), None, flags)
    } else {
        pkcs7.verify(&certs, &store, None, None, flags)
    };

    match result {
        Ok(_) => println!("Verification successful"),
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
    #[cfg(feature = "dummy")]
    use crate::reader::dummy::JPKI_AID;

    fn setup_reader() -> MynaReader {
        let sign_cert = include_bytes!("../tests/fixtures/sign_cert.der");
        let sign_ca_cert = include_bytes!("../tests/fixtures/sign_ca_cert.der");
        let auth_cert = include_bytes!("../tests/fixtures/auth_cert.der");
        let auth_ca_cert = include_bytes!("../tests/fixtures/auth_ca_cert.der");
        let sign_key_pem = include_bytes!("../tests/fixtures/sign_key.pem");
        let rsa = openssl::rsa::Rsa::private_key_from_pem(sign_key_pem).unwrap();

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
                let mut buf = vec![0u8; rsa.size() as usize];
                let len = rsa
                    .private_encrypt(data, &mut buf, openssl::rsa::Padding::PKCS1)
                    .unwrap();
                buf[..len].to_vec()
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
        let subject = cert
            .subject_name()
            .entries()
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap();
        assert_eq!(subject.to_string(), "Test auth User");
    }

    #[test]
    fn test_pkey_sign_sign() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let digest_info = make_digest_info(&DigestAlgorithm::Sha256, &[0u8; 32]);
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
        let md = MessageDigest::sha256();
        let pkcs7_der = jpki.cms_sign(content, "SIGNATURE", md, false).unwrap();

        let pkcs7 = openssl::pkcs7::Pkcs7::from_der(&pkcs7_der).unwrap();
        assert!(!pkcs7.to_der().unwrap().is_empty());
    }

    #[test]
    fn test_read_sign_cert() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let cert = jpki
            .cert_read(&CertType::Sign, &Some("SIGNATURE".into()), &None)
            .unwrap();
        let subject = cert
            .subject_name()
            .entries()
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap();
        assert_eq!(subject.to_string(), "Test sign User");
    }

    #[test]
    fn test_read_sign_ca_cert() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let cert = jpki
            .cert_read(&CertType::SignCa, &None, &None)
            .unwrap();
        let subject = cert
            .subject_name()
            .entries()
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap();
        assert_eq!(subject.to_string(), "Test sign CA");
    }

    #[test]
    fn test_read_auth_ca_cert() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let cert = jpki
            .cert_read(&CertType::AuthCa, &None, &None)
            .unwrap();
        let subject = cert
            .subject_name()
            .entries()
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap();
        assert_eq!(subject.to_string(), "Test auth CA");
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
        let subject = cert
            .subject_name()
            .entries()
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap();
        assert_eq!(subject.to_string(), "Test auth User");
    }

    #[test]
    fn test_pkey_sign_auth() {
        let mut reader = setup_reader();
        reader.connect().unwrap();
        let mut jpki = reader.jpki_ap().unwrap();
        let digest_info = make_digest_info(&DigestAlgorithm::Sha256, &[0u8; 32]);
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
        let md = MessageDigest::sha256();
        let pkcs7_der = jpki.cms_sign(content, "SIGNATURE", md, true).unwrap();

        let pkcs7 = openssl::pkcs7::Pkcs7::from_der(&pkcs7_der).unwrap();
        assert!(!pkcs7.to_der().unwrap().is_empty());
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
        let digest_info = make_digest_info(&DigestAlgorithm::Sha256, &[0u8; 32]);
        let result = jpki.pkey_sign(&KeyType::Sign, &Some("WRONGPW1".into()), &digest_info);
        assert!(result.is_err());
    }
}
