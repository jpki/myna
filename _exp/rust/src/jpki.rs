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

#[derive(Debug, Args)]
pub struct PasswordArgs {
    /// 署名用パスワード(6-16桁)
    #[arg(short, long)]
    password: Option<String>,
    /// フォーマット
    #[arg(short, long, value_enum, default_value = "text")]
    format: EnumFormat,
}

#[derive(Debug, Args)]
pub struct PinArgs {
    /// 認証用パスワード(4桁)
    #[arg(short, long)]
    pin: Option<String>,
    /// フォーマット
    #[arg(short, long, value_enum, default_value = "text")]
    format: EnumFormat,
}

#[derive(Debug, Args)]
pub struct FormatArgs {
    /// フォーマット
    #[arg(short, long, value_enum, default_value = "text")]
    format: EnumFormat,
}

#[derive(Debug, Args)]
pub struct CmsSignArgs {
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
enum DigestAlgorithm {
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

#[derive(Subcommand)]
pub enum JPKI {
    /// Show Sign Certificate
    ReadSignCert(PasswordArgs),
    /// Show Sign CA Certificate
    ReadSignCACert(FormatArgs),
    /// Show Auth Certificate
    ReadAuthCert(FormatArgs),
    /// Show Auth CA Certificate
    ReadAuthCACert(FormatArgs),
    /// CMS署名と検証
    #[command(subcommand)]
    Cms(CmsSubcommand),
}

pub fn main(_app: &crate::App, subcommand: &JPKI) {
    match subcommand {
        JPKI::ReadSignCert(args) => read_sign_cert(args),
        JPKI::ReadSignCACert(args) => read_sign_ca_cert(args),
        JPKI::ReadAuthCert(args) => read_auth_cert(args),
        JPKI::ReadAuthCACert(args) => read_auth_ca_cert(args),
        JPKI::Cms(cms_cmd) => cms_main(cms_cmd),
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

fn input_password(args: &PasswordArgs) -> String {
    let pass = utils::prompt_input("パスワード(6-16桁): ", &args.password);
    let pass = pass.to_uppercase();
    utils::validate_jpki_sign_password(&pass).expect("パスワードが不正です");
    pass
}

fn read_sign_cert(args: &PasswordArgs) {
    let password = input_password(args);
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();
    reader.select_ef("001b").unwrap();
    reader.verify_pin(&password).expect("verify pin failed");
    reader.select_ef("0001").unwrap();
    let cert = X509::from_der(&reader.read_binary_all()).unwrap();
    output_cert(&cert, &args.format);
}

fn read_sign_ca_cert(args: &FormatArgs) {
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();
    reader.select_ef("0002").unwrap();
    let cert = X509::from_der(&reader.read_binary_all()).unwrap();
    output_cert(&cert, &args.format);
}

fn read_auth_cert(args: &FormatArgs) {
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();
    reader.select_ef("000a").unwrap();
    let cert = X509::from_der(&reader.read_binary_all()).unwrap();
    output_cert(&cert, &args.format);
}

fn read_auth_ca_cert(args: &FormatArgs) {
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();
    reader.select_ef("000B").unwrap();
    let cert = X509::from_der(&reader.read_binary_all()).unwrap();
    output_cert(&cert, &args.format);
}

fn input_cms_password(args: &CmsSignArgs) -> String {
    let pass = utils::prompt_input("署名用パスワード(6-16桁): ", &args.password);
    let pass = pass.to_uppercase();
    utils::validate_jpki_sign_password(&pass).expect("パスワードが不正です");
    pass
}

fn to_message_digest(alg: &DigestAlgorithm) -> MessageDigest {
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
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pkcs7_der);
            // 76文字ごとに改行を挿入
            let wrapped: String = b64
                .as_bytes()
                .chunks(76)
                .map(|chunk| std::str::from_utf8(chunk).unwrap())
                .collect::<Vec<&str>>()
                .join("\n");
            format!("-----BEGIN PKCS7-----\n{}\n-----END PKCS7-----\n", wrapped).into_bytes()
        }
    };

    fs::write(&args.output, &output_data).expect("出力ファイルへの書き込みに失敗しました");
    println!("署名を保存しました: {}", args.output);
}

fn make_digest_info(alg: &DigestAlgorithm, hash: &[u8]) -> Vec<u8> {
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
