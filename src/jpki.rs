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
pub enum RsaKeyType {
    /// 署名用鍵
    Sign,
    /// 認証用鍵
    Auth,
}

#[derive(Debug, Args)]
pub struct PkeySignArgs {
    /// 鍵の種類 [sign, auth]
    #[arg(short = 't', long = "type", value_enum)]
    key_type: RsaKeyType,
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
    key_type: RsaKeyType,
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

pub fn main(subcommand: &JPKI) {
    match subcommand {
        JPKI::Cert(args) => run_cert(args),
        JPKI::Pkey(cmd) => run_pkey_subcommand(cmd),
        JPKI::Cms(cms_cmd) => {
            run_cms_subcommand(cms_cmd);
        }
        JPKI::Pdf(pdf_cmd) => {
            crate::pdf::pdf_main(pdf_cmd);
        }
    }
}

fn run_pkey_subcommand(subcommand: &PkeySubcommand) {
    match subcommand {
        PkeySubcommand::Sign(args) => run_pkey_sign(args),
        PkeySubcommand::Verify(args) => {
            run_pkey_verify(args);
        }
    }
}

fn run_cms_subcommand(subcommand: &CmsSubcommand) {
    match subcommand {
        CmsSubcommand::Sign(args) => run_cms_sign(args),
        CmsSubcommand::Verify(args) => run_cms_verify(args),
    }
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

fn read_token(reader: &mut MynaReader) -> std::result::Result<String, Error> {
    reader
        .select_ef("0006")
        .map_err(|e| Error::with_source("トークンEFの選択に失敗しました", e))?;
    let data = reader
        .read_binary(0, 0x20)
        .map_err(|e| Error::with_source("READ BINARYに失敗しました", e))?;
    Ok(String::from_utf8_lossy(&data).trim_end().to_string())
}

fn validate_sign_password(password: &Option<String>) -> std::result::Result<String, Error> {
    let pass = password
        .clone()
        .ok_or_else(|| Error::from("署名用パスワードが必要です"))?;
    let pass = pass.to_uppercase();
    utils::validate_jpki_sign_password(&pass)?;
    Ok(pass)
}

fn validate_auth_pin(pin: &Option<String>) -> std::result::Result<String, Error> {
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

/// 指定種類の証明書をカードから読み取って返す
pub fn cert_read(
    cert_type: &CertType,
    password: &Option<String>,
    pin: &Option<String>,
) -> std::result::Result<X509, Error> {
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    reader.select_jpki_ap();
    let token = read_token(&mut reader)?;

    match cert_type {
        CertType::Sign => {
            let pass = validate_sign_password(password)?;
            reader
                .select_ef("001b")
                .map_err(|e| Error::with_source("署名用PIN EFの選択に失敗しました", e))?;
            reader
                .verify_pin(&pass)
                .map_err(|e| Error::with_source("パスワード認証に失敗しました", e))?;
            reader
                .select_ef("0001")
                .map_err(|e| Error::with_source("署名用証明書EFの選択に失敗しました", e))?;
        }
        CertType::SignCa => {
            reader
                .select_ef("0002")
                .map_err(|e| Error::with_source("署名用CA証明書EFの選択に失敗しました", e))?;
        }
        CertType::Auth => {
            if token == "JPKIAPGPSETOKEN" {
                let p = validate_auth_pin(pin)?;
                reader
                    .select_ef("0018")
                    .map_err(|e| Error::with_source("認証用PIN EFの選択に失敗しました", e))?;
                reader
                    .verify_pin(&p)
                    .map_err(|e| Error::with_source("PIN認証に失敗しました", e))?;
            }
            reader
                .select_ef("000a")
                .map_err(|e| Error::with_source("認証用証明書EFの選択に失敗しました", e))?;
        }
        CertType::AuthCa => {
            reader
                .select_ef("000b")
                .map_err(|e| Error::with_source("認証用CA証明書EFの選択に失敗しました", e))?;
        }
    }

    let cert_der = reader
        .read_binary_all()
        .map_err(|e| Error::with_source("READ BINARYに失敗しました", e))?;
    X509::from_der(&cert_der)
        .map_err(|e| Error::with_source("証明書のパースに失敗しました", e))
}

fn run_cert(args: &CertArgs) {
    let password = match args.cert_type {
        CertType::Sign => Some(prompt_sign_password(&args.password)),
        _ => args.password.clone(),
    };
    let pin = match args.cert_type {
        CertType::Auth if args.pin.is_none() => {
            let mut probe_reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
            probe_reader.connect().expect("カードへの接続に失敗しました");
            probe_reader.select_jpki_ap();
            let token = read_token(&mut probe_reader).expect("トークンの読み取りに失敗しました");
            if token == "JPKIAPGPSETOKEN" {
                Some(prompt_auth_pin(&args.pin))
            } else {
                None
            }
        }
        CertType::Auth => args.pin.clone(),
        _ => args.pin.clone(),
    };
    let cert = cert_read(&args.cert_type, &password, &pin).expect("証明書の取得に失敗しました");
    output_cert(&cert, &args.format);
}

/// 指定種類の鍵でデータに低レベルRSA署名して返す
pub fn pkey_sign(
    key_type: &RsaKeyType,
    credential: &Option<String>,
    content: &[u8],
) -> std::result::Result<Vec<u8>, Error> {
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    reader.select_jpki_ap();

    match key_type {
        RsaKeyType::Sign => {
            let pass = validate_sign_password(credential)?;
            reader
                .select_ef("001b")
                .map_err(|e| Error::with_source("署名用PIN EFの選択に失敗しました", e))?;
            reader
                .verify_pin(&pass)
                .map_err(|e| Error::with_source("パスワード認証に失敗しました", e))?;
        }
        RsaKeyType::Auth => {
            let pin = validate_auth_pin(credential)?;
            reader
                .select_ef("0018")
                .map_err(|e| Error::with_source("認証用PIN EFの選択に失敗しました", e))?;
            reader
                .verify_pin(&pin)
                .map_err(|e| Error::with_source("PIN認証に失敗しました", e))?;
        }
    }

    // 鍵EFを選択して署名
    match key_type {
        RsaKeyType::Sign => reader
            .select_ef("001a")
            .map_err(|e| Error::with_source("署名鍵EFの選択に失敗しました", e))?,
        RsaKeyType::Auth => reader
            .select_ef("0017")
            .map_err(|e| Error::with_source("認証鍵EFの選択に失敗しました", e))?,
    };
    reader
        .signature(content)
        .map_err(|e| Error::with_source("署名に失敗しました", e))
}

fn run_pkey_sign(args: &PkeySignArgs) {
    let content = fs::read(&args.input).expect("入力ファイルを読み込めませんでした");
    let credential = match args.key_type {
        RsaKeyType::Sign => Some(prompt_sign_password(&args.password)),
        RsaKeyType::Auth => Some(prompt_auth_pin(&args.password)),
    };
    let signature = pkey_sign(&args.key_type, &credential, &content).expect("署名に失敗しました");
    fs::write(&args.output, &signature).expect("出力ファイルへの書き込みに失敗しました");
    println!("署名を保存しました: {}", args.output);
}

fn run_pkey_verify(args: &PkeyVerifyArgs) {
    // カードから証明書を取得して公開鍵を得る
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();

    let cert_ef = match args.key_type {
        RsaKeyType::Sign => "0001",
        RsaKeyType::Auth => "000a",
    };
    reader.select_ef(cert_ef).unwrap();
    let cert_der = reader.read_binary_all().expect("READ BINARYに失敗しました");
    let cert = X509::from_der(&cert_der).expect("証明書のパースに失敗しました");
    let pubkey = cert.public_key().expect("公開鍵の取得に失敗しました");

    let sig = fs::read(&args.input).expect("署名ファイルを読み込めませんでした");

    // RSA公開鍵演算の結果をそのまま出力
    let rsa = pubkey.rsa().expect("RSA鍵の取得に失敗しました");
    let mut buf = vec![0u8; rsa.size() as usize];
    let len = rsa
        .public_decrypt(&sig, &mut buf, openssl::rsa::Padding::PKCS1)
        .expect("RSA公開鍵演算に失敗しました");
    let result = &buf[..len];
    if let Some(ref path) = args.output {
        fs::write(path, result).expect("出力ファイルへの書き込みに失敗しました");
    } else {
        std::io::stdout()
            .write_all(result)
            .expect("標準出力への書き込みに失敗しました");
    }
}

fn input_cms_password(args: &CmsSignArgs) -> String {
    let pass = utils::prompt_input("署名用パスワード(6-16桁): ", &args.password);
    let pass = pass.to_uppercase();
    utils::validate_jpki_sign_password(&pass).expect("パスワードが不正です");
    pass
}

pub fn to_message_digest(alg: &DigestAlgorithm) -> MessageDigest {
    match alg {
        DigestAlgorithm::Sha1 => MessageDigest::sha1(),
        DigestAlgorithm::Sha256 => MessageDigest::sha256(),
        DigestAlgorithm::Sha384 => MessageDigest::sha384(),
        DigestAlgorithm::Sha512 => MessageDigest::sha512(),
    }
}

fn run_cms_sign(args: &CmsSignArgs) {
    let password = input_cms_password(args);

    // 署名対象ファイルを読み込み
    let content = fs::read(&args.input).expect("署名対象ファイルを読み込めませんでした");

    // 署名用証明書を取得
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();
    reader.select_ef("001b").unwrap();
    reader
        .verify_pin(&password)
        .expect("パスワード認証に失敗しました");
    reader.select_ef("0001").unwrap();
    let cert_der = reader.read_binary_all().expect("READ BINARYに失敗しました");
    let cert = X509::from_der(&cert_der).expect("証明書のパースに失敗しました");

    let md = to_message_digest(&args.digest);

    // 認証属性を構築し、署名対象のハッシュを計算
    let (attrs_set, attrs_digest) = pkcs7::prepare_signing(&content, md);

    // DigestInfoを作成してカードで署名
    let digest_info = make_digest_info(&args.digest, &attrs_digest);
    reader.select_ef("001a").unwrap();
    let signature = reader.signature(&digest_info).expect("署名に失敗しました");

    // PKCS#7 SignedData構造を構築
    let pkcs7_der =
        pkcs7::build_signed_data(&content, &cert, &signature, md, &attrs_set, args.detached);

    // 出力形式に変換
    let output_data = match args.format {
        CmsFormat::Der => pkcs7_der,
        CmsFormat::Pem => {
            let b64 = openssl::base64::encode_block(&pkcs7_der);
            format!(
                "-----BEGIN PKCS7-----\n{}\n-----END PKCS7-----\n",
                b64.trim_end()
            )
            .into_bytes()
        }
    };

    fs::write(&args.output, &output_data).expect("出力ファイルへの書き込みに失敗しました");
    println!("署名を保存しました: {}", args.output);
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

fn run_cms_verify(args: &CmsVerifyArgs) {
    log::info!("Loading CMS signature from {}", args.signature);
    // 署名ファイルを読み込み
    let sig_data = fs::read(&args.signature).expect("署名ファイルを読み込めませんでした");

    let pkcs7_der = match args.format {
        CmsFormat::Der => sig_data,
        CmsFormat::Pem => {
            log::info!("Decoding PEM-encoded CMS signature");
            // PEMからDERに変換
            let pkcs7 = Pkcs7::from_pem(&sig_data).expect("PEMのパースに失敗しました");
            pkcs7.to_der().expect("DERへの変換に失敗しました")
        }
    };

    // PKCS7をパース
    let pkcs7 = match Pkcs7::from_der(&pkcs7_der) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("PKCS7のパースに失敗しました: {}", e);
            return;
        }
    };
    log::info!("Parsed PKCS#7 SignedData");
    verify::log_pkcs7_signers(&pkcs7).expect("署名証明書情報の取得に失敗しました");

    // 検証
    log::info!("Building certificate store for CMS verification");
    let (store, roots) =
        verify::build_sign_verifier().expect("埋め込みCA証明書の読み込みに失敗しました");
    verify::log_sign_trust_anchors(&roots).expect("埋め込みCA証明書情報の取得に失敗しました");
    verify::verify_signer_certificates(&pkcs7, &store, &roots)
        .expect("署名証明書の検証に失敗しました");

    let content = if args.detached {
        log::info!("Detached CMS signature: loading external content");
        let content_file = args
            .content
            .as_ref()
            .expect("デタッチ署名には-cオプションが必要です");
        Some(fs::read(content_file).expect("検証対象ファイルを読み込めませんでした"))
    } else {
        None
    };

    let mut flags = Pkcs7Flags::empty();
    if args.detached {
        flags |= Pkcs7Flags::DETACHED;
    }

    let certs = Stack::new().unwrap();
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
}
