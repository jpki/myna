use crate::pkcs7;
use crate::reader::MynaReader;
use crate::utils;
use clap::{Args, Subcommand, ValueEnum};
use openssl::hash::MessageDigest;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::X509;
use std::fs;
use std::io::Write;

#[derive(Clone, Debug, ValueEnum)]
#[clap(rename_all = "snake_case")]
enum CertType {
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
enum RsaKeyType {
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
    #[arg(short, long)]
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
    #[arg(short, long)]
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
    #[arg(short, long)]
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
    #[arg(short, long)]
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
    #[arg(short, long)]
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

pub fn main(_app: &crate::App, subcommand: &JPKI) {
    match subcommand {
        JPKI::Cert(args) => jpki_cert(args),
        JPKI::Pkey(cmd) => pkey_main(cmd),
        JPKI::Cms(cms_cmd) => cms_main(cms_cmd),
        JPKI::Pdf(pdf_cmd) => crate::pdf::pdf_main(pdf_cmd),
    }
}

fn pkey_main(subcommand: &PkeySubcommand) {
    match subcommand {
        PkeySubcommand::Sign(args) => pkey_sign(args),
        PkeySubcommand::Verify(args) => pkey_verify(args),
    }
}

fn cms_main(subcommand: &CmsSubcommand) {
    match subcommand {
        CmsSubcommand::Sign(args) => cms_sign(args),
        CmsSubcommand::Verify(args) => cms_verify(args),
    }
}

/// 証明書を指定フォーマットで出力する共通関数
fn output_cert(cert: &X509, format: &EnumFormat) {
    match format {
        EnumFormat::Text => {
            print!("{}", String::from_utf8(cert.to_text().unwrap()).unwrap());
        }
        EnumFormat::Pem => {
            print!("{}", String::from_utf8(cert.to_pem().unwrap()).unwrap());
        }
        EnumFormat::Der => {
            std::io::stdout()
                .write_all(&cert.to_der().unwrap())
                .unwrap();
        }
    }
}

fn read_token(reader: &mut MynaReader) -> String {
    reader.select_ef("0006").unwrap();
    let data = reader.read_binary(0, 0x20);
    String::from_utf8_lossy(&data).trim_end().to_string()
}

fn jpki_cert(args: &CertArgs) {
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();
    let token = read_token(&mut reader);

    match args.cert_type {
        CertType::Sign => {
            let pass = utils::prompt_input("署名用パスワード(6-16桁): ", &args.password);
            let pass = pass.to_uppercase();
            utils::validate_jpki_sign_password(&pass).expect("パスワードが不正です");
            reader.select_ef("001b").unwrap();
            reader.verify_pin(&pass).expect("パスワード認証に失敗しました");
            reader.select_ef("0001").unwrap();
        }
        CertType::SignCa => {
            reader.select_ef("0002").unwrap();
        }
        CertType::Auth => {
            if token == "JPKIAPGPSETOKEN" {
                let pin = utils::prompt_input("認証用PIN(4桁): ", &args.pin);
                let pin = pin.to_uppercase();
                utils::validate_4digit_pin(&pin).expect("PINが不正です");
                reader.select_ef("0018").unwrap();
                reader.verify_pin(&pin).expect("PIN認証に失敗しました");
            }
            reader.select_ef("000a").unwrap();
        }
        CertType::AuthCa => {
            reader.select_ef("000b").unwrap();
        }
    }

    let cert = X509::from_der(&reader.read_binary_all()).unwrap();
    output_cert(&cert, &args.format);
}

fn pkey_sign(args: &PkeySignArgs) {
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();

    match args.key_type {
        RsaKeyType::Sign => {
            let pass = utils::prompt_input("署名用パスワード(6-16桁): ", &args.password);
            let pass = pass.to_uppercase();
            utils::validate_jpki_sign_password(&pass).expect("パスワードが不正です");
            reader.select_ef("001b").unwrap();
            reader.verify_pin(&pass).expect("パスワード認証に失敗しました");
        }
        RsaKeyType::Auth => {
            let pin = utils::prompt_input("認証用PIN(4桁): ", &args.password);
            utils::validate_4digit_pin(&pin).expect("PINが不正です");
            reader.select_ef("0018").unwrap();
            reader.verify_pin(&pin).expect("PIN認証に失敗しました");
        }
    }

    let content = fs::read(&args.input).expect("入力ファイルを読み込めませんでした");

    // 鍵EFを選択して署名
    match args.key_type {
        RsaKeyType::Sign => reader.select_ef("001a").unwrap(),
        RsaKeyType::Auth => reader.select_ef("0017").unwrap(),
    };
    let signature = reader.signature(&content).expect("署名に失敗しました");

    fs::write(&args.output, &signature).expect("出力ファイルへの書き込みに失敗しました");
    println!("署名を保存しました: {}", args.output);
}

fn pkey_verify(args: &PkeyVerifyArgs) {
    // カードから証明書を取得して公開鍵を得る
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();

    let cert_ef = match args.key_type {
        RsaKeyType::Sign => "0001",
        RsaKeyType::Auth => "000a",
    };
    reader.select_ef(cert_ef).unwrap();
    let cert_der = reader.read_binary_all();
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

fn cms_sign(args: &CmsSignArgs) {
    let password = input_cms_password(args);

    // 署名対象ファイルを読み込み
    let content = fs::read(&args.input).expect("署名対象ファイルを読み込めませんでした");

    // 署名用証明書を取得
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();
    reader.select_ef("001b").unwrap();
    reader.verify_pin(&password).expect("パスワード認証に失敗しました");
    reader.select_ef("0001").unwrap();
    let cert_der = reader.read_binary_all();
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
            let b64 =
                openssl::base64::encode_block(&pkcs7_der);
            format!("-----BEGIN PKCS7-----\n{}\n-----END PKCS7-----\n", b64.trim_end()).into_bytes()
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

fn cms_verify(args: &CmsVerifyArgs) {
    // CA証明書を取得
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();
    reader.select_ef("0002").unwrap();
    let ca_cert_der = reader.read_binary_all();
    let ca_cert = X509::from_der(&ca_cert_der).expect("CA証明書のパースに失敗しました");

    // 署名ファイルを読み込み
    let sig_data = fs::read(&args.signature).expect("署名ファイルを読み込めませんでした");

    let pkcs7_der = match args.format {
        CmsFormat::Der => sig_data,
        CmsFormat::Pem => {
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

    // 検証
    let mut store_builder = openssl::x509::store::X509StoreBuilder::new().unwrap();
    store_builder.add_cert(ca_cert).unwrap();
    let store = store_builder.build();

    let content = if args.detached {
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
