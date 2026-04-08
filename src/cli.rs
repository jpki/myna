use clap::{ArgAction, Args, Subcommand, ValueEnum};
use der::EncodePem;
use myna::error::Error;
use myna::jpki::{CertType, KeyType};
use myna::pkcs7;
use myna::reader::MynaReader;
use myna::utils;
use std::fs;
use std::io::Write;
use x509_cert::Certificate;

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

#[derive(clap::Parser)]
#[command(author, version = version(), about, long_about = None)]
#[command(propagate_version = true)]
pub struct App {
    #[command(subcommand)]
    command: Commands,
    #[arg(short = 'v', action = ArgAction::Count, global = true)]
    verbose: u8,
    #[arg(short, long)]
    debug: bool,
}

impl App {
    pub fn run(&self) -> Result<(), Error> {
        match &self.command {
            Commands::Check(args) => crate::check::main(args.name.as_deref()),
            Commands::Text(cmd) => run_text(cmd),
            Commands::Visual(cmd) => run_visual(cmd),
            Commands::JPKI(cmd) => run_jpki(cmd),
            Commands::Pin(cmd) => run_pin(cmd),
            Commands::Unknown(cmd) => run_unknown(cmd),
        }
    }

    pub fn log_level(&self) -> log::LevelFilter {
        if self.verbose >= 3 {
            log::LevelFilter::Trace
        } else if self.debug || self.verbose >= 2 {
            log::LevelFilter::Debug
        } else if self.verbose >= 1 {
            log::LevelFilter::Info
        } else {
            log::LevelFilter::Warn
        }
    }
}

fn version() -> &'static str {
    use std::sync::OnceLock;
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| env!("CARGO_PKG_VERSION").to_string())
}

#[derive(Subcommand)]
enum Commands {
    /// 動作診断
    Check(CheckArgs),
    /// 券面入力補助AP
    #[command(subcommand)]
    Text(TextSubcommand),
    /// 券面確認AP
    #[command(subcommand)]
    Visual(VisualSubcommand),
    /// 公的個人認証
    #[command(subcommand)]
    #[allow(clippy::upper_case_acronyms)]
    JPKI(JpkiSubcommand),
    /// Pin operation
    #[command(subcommand)]
    Pin(PinSubcommand),
    /// 謎のAP
    #[command(subcommand)]
    Unknown(UnknownSubcommand),
}

#[derive(Args)]
struct CheckArgs {
    name: Option<String>,
}

// ---------------------------------------------------------------------------
// Text サブコマンド
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
struct TextPinArgs {
    /// 暗証番号(4桁)
    #[arg(short, long)]
    pin: Option<String>,
}

#[derive(Subcommand)]
enum TextSubcommand {
    /// AP基本情報を表示
    BasicInfo,
    /// 個人番号を表示
    Mynumber(TextPinArgs),
    /// 4属性を表示
    Attrs(TextPinArgs),
}

fn run_text(cmd: &TextSubcommand) -> Result<(), Error> {
    match cmd {
        TextSubcommand::BasicInfo => {
            let mut reader = MynaReader::new()?;
            reader.connect()?;
            let mut text = reader.text_ap()?;
            let info = text.basic_info()?;
            println!("APID: {}", info.apid);
            println!("公開鍵ID: {}", info.pubkey_id);
            Ok(())
        }
        TextSubcommand::Mynumber(args) => {
            let pin = input_4digit_pin("暗証番号(4桁): ", &args.pin)?;
            let mut reader = MynaReader::new()?;
            reader.connect()?;
            let mut text = reader.text_ap()?;
            let mynumber = text.mynumber(&pin)?;
            println!("{}", mynumber);
            Ok(())
        }
        TextSubcommand::Attrs(args) => {
            let pin = input_4digit_pin("暗証番号(4桁): ", &args.pin)?;
            let mut reader = MynaReader::new()?;
            reader.connect()?;
            let mut text = reader.text_ap()?;
            let attrs = text.attrs(&pin)?;
            println!("氏名    : {}", attrs.name);
            println!("住所    : {}", attrs.addr);
            println!("生年月日: {}", attrs.birth);
            println!("性別    : {}", attrs.sex);
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Visual サブコマンド
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
struct VisualOutputArgs {
    /// 暗証番号(4桁)
    #[arg(short, long)]
    pin: Option<String>,
    /// 出力ファイル
    #[arg(short, long)]
    output: String,
}

#[derive(Debug, Args)]
struct VisualPinArgs {
    /// 暗証番号(4桁)
    #[arg(short, long)]
    pin: Option<String>,
}

#[derive(Subcommand)]
enum VisualSubcommand {
    /// AP基本情報を表示
    BasicInfo,
    /// 券面の氏名画像を取得 (PNG画像)
    Name(VisualOutputArgs),
    /// 券面の住所画像を取得 (PNG画像)
    Addr(VisualOutputArgs),
    /// 生年月日を表示
    Birth(VisualPinArgs),
    /// 性別を表示
    Sex(VisualPinArgs),
    /// 顔写真を取得 (JPEG2000)
    Photo(VisualOutputArgs),
}

fn read_mynumber(pin: &str, reader: &mut MynaReader) -> Result<String, Error> {
    let mut text = reader.text_ap()?;
    let mynumber = text.mynumber(pin)?;
    text.close();
    Ok(mynumber)
}

fn write_binary_output(data: &[u8], output: &str, label: &str) -> Result<(), Error> {
    if output == "-" {
        std::io::stdout()
            .write_all(data)
            .map_err(|e| Error::new(format!("標準出力への書き込みに失敗しました: {}", e)))?;
    } else {
        fs::write(output, data)?;
        println!("{}を保存しました: {}", label, output);
    }
    Ok(())
}

fn run_visual(cmd: &VisualSubcommand) -> Result<(), Error> {
    match cmd {
        VisualSubcommand::BasicInfo => {
            let mut reader = MynaReader::new()?;
            reader.connect()?;
            let mut visual = reader.visual_ap()?;
            let info = visual.basic_info()?;
            println!("APID: {}", info.apid);
            println!("Version: {}", info.version);
            println!("City: {}", info.city);
            Ok(())
        }
        VisualSubcommand::Name(args) => {
            let pin = input_4digit_pin("暗証番号(4桁): ", &args.pin)?;
            let mut reader = MynaReader::new()?;
            reader.connect()?;
            let mynumber = read_mynumber(&pin, &mut reader)?;
            let mut visual = reader.visual_ap()?;
            let entries = visual.read_entries(&mynumber)?;
            write_binary_output(&entries.name, &args.output, "氏名画像")
        }
        VisualSubcommand::Addr(args) => {
            let pin = input_4digit_pin("暗証番号(4桁): ", &args.pin)?;
            let mut reader = MynaReader::new()?;
            reader.connect()?;
            let mynumber = read_mynumber(&pin, &mut reader)?;
            let mut visual = reader.visual_ap()?;
            let entries = visual.read_entries(&mynumber)?;
            write_binary_output(&entries.addr, &args.output, "住所画像")
        }
        VisualSubcommand::Birth(args) => {
            let pin = input_4digit_pin("暗証番号(4桁): ", &args.pin)?;
            let mut reader = MynaReader::new()?;
            reader.connect()?;
            let mynumber = read_mynumber(&pin, &mut reader)?;
            let mut visual = reader.visual_ap()?;
            let entries = visual.read_entries(&mynumber)?;
            println!("{}", entries.birth);
            Ok(())
        }
        VisualSubcommand::Sex(args) => {
            let pin = input_4digit_pin("暗証番号(4桁): ", &args.pin)?;
            let mut reader = MynaReader::new()?;
            reader.connect()?;
            let mynumber = read_mynumber(&pin, &mut reader)?;
            let mut visual = reader.visual_ap()?;
            let entries = visual.read_entries(&mynumber)?;
            println!("{}", entries.sex);
            Ok(())
        }
        VisualSubcommand::Photo(args) => {
            let pin = input_4digit_pin("暗証番号(4桁): ", &args.pin)?;
            let mut reader = MynaReader::new()?;
            reader.connect()?;
            let mynumber = read_mynumber(&pin, &mut reader)?;
            let mut visual = reader.visual_ap()?;
            let entries = visual.read_entries(&mynumber)?;
            write_binary_output(&entries.photo, &args.output, "写真")
        }
    }
}

// ---------------------------------------------------------------------------
// JPKI サブコマンド
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
#[command(arg_required_else_help = true)]
struct CertArgs {
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

#[derive(Debug, Args)]
struct PkeySignArgs {
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
struct PkeyVerifyArgs {
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
enum PkeySubcommand {
    /// 低レベルRSA署名を行います
    Sign(PkeySignArgs),
    /// 低レベルRSA署名を検証します
    Verify(PkeyVerifyArgs),
}

#[derive(Clone, Debug, ValueEnum)]
enum SignType {
    Sign,
}

#[derive(Debug, Args)]
struct CmsSignArgs {
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
struct CmsVerifyArgs {
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

#[derive(Clone, ValueEnum, Debug)]
enum EnumFormat {
    Text,
    Pem,
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
enum CmsSubcommand {
    /// CMS署名を行います
    Sign(CmsSignArgs),
    /// CMS署名を検証します
    Verify(CmsVerifyArgs),
}

#[derive(Debug, Args)]
struct PdfSignArgs {
    /// 入力PDFファイル
    #[arg(value_name = "INPUT")]
    input: String,
    /// 出力PDFファイル
    #[arg(short, long)]
    output: String,
    /// 署名用パスワード(6-16桁)
    #[arg(short, long)]
    password: Option<String>,
}

#[derive(Debug, Args)]
struct PdfVerifyArgs {
    /// 署名済みPDFファイル
    #[arg(value_name = "INPUT")]
    input: String,
}

#[derive(Subcommand)]
enum PdfSubcommand {
    /// PDFに電子署名を付与します
    Sign(PdfSignArgs),
    /// PDF電子署名を検証します
    Verify(PdfVerifyArgs),
}

#[derive(Subcommand)]
#[allow(clippy::upper_case_acronyms)]
enum JpkiSubcommand {
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

fn run_jpki(cmd: &JpkiSubcommand) -> Result<(), Error> {
    match cmd {
        JpkiSubcommand::Cert(args) => run_jpki_cert(args),
        JpkiSubcommand::Pkey(cmd) => match cmd {
            PkeySubcommand::Sign(args) => run_jpki_pkey_sign(args),
            PkeySubcommand::Verify(args) => run_jpki_pkey_verify(args),
        },
        JpkiSubcommand::Cms(cmd) => match cmd {
            CmsSubcommand::Sign(args) => run_jpki_cms_sign(args),
            CmsSubcommand::Verify(args) => run_jpki_cms_verify(args),
        },
        JpkiSubcommand::Pdf(cmd) => match cmd {
            PdfSubcommand::Sign(args) => run_jpki_pdf_sign(args),
            PdfSubcommand::Verify(args) => myna::pdf::pdf_verify(&args.input),
        },
    }
}

fn run_jpki_cert(args: &CertArgs) -> Result<(), Error> {
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let mut jpki = reader.jpki_ap()?;

    match args.cert_type {
        CertType::Sign => {
            jpki.verify(&KeyType::Sign, &prompt_sign_password(&args.password))?;
        }
        CertType::Auth if args.pin.is_none() && jpki.token() == "JPKIAPGPSETOKEN" => {
            jpki.verify(&KeyType::Auth, &prompt_auth_pin(&args.pin))?;
        }
        _ => {}
    };

    let cert = jpki.cert_read(&args.cert_type)?;
    cert_output(&cert, &args.format);
    Ok(())
}

fn run_jpki_pkey_sign(args: &PkeySignArgs) -> Result<(), Error> {
    let content = fs::read(&args.input)?;
    let credential = match args.key_type {
        KeyType::Sign => prompt_sign_password(&args.password),
        KeyType::Auth => prompt_auth_pin(&args.password),
    };
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let mut jpki = reader.jpki_ap()?;
    jpki.verify(&args.key_type, &credential)?;
    let signature = jpki.pkey_sign(&args.key_type, &content)?;
    fs::write(&args.output, &signature)?;
    println!("署名を保存しました: {}", args.output);
    Ok(())
}

fn run_jpki_pkey_verify(args: &PkeyVerifyArgs) -> Result<(), Error> {
    let sig = fs::read(&args.input)?;
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let mut jpki = reader.jpki_ap()?;
    let result = jpki.pkey_verify(&args.key_type, &sig)?;
    if let Some(ref path) = args.output {
        fs::write(path, &result)?;
    } else {
        std::io::stdout().write_all(&result)?;
    }
    Ok(())
}

fn run_jpki_cms_sign(args: &CmsSignArgs) -> Result<(), Error> {
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
    jpki.verify(&KeyType::Sign, &password)?;
    let pkcs7_der = jpki.cms_sign(&content, alg, args.detached)?;

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

fn run_jpki_cms_verify(args: &CmsVerifyArgs) -> Result<(), Error> {
    log::info!("Loading CMS signature from {}", args.signature);
    let sig_data = fs::read(&args.signature)?;

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

    match myna::jpki::cms_verify(&pkcs7_der, content.as_deref()) {
        Ok(()) => println!("Verification successful"),
        Err(e) => eprintln!("Verification failed: {}", e),
    }
    Ok(())
}

fn run_jpki_pdf_sign(args: &PdfSignArgs) -> Result<(), Error> {
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
    jpki.verify(&KeyType::Sign, &password)?;
    let signed_pdf = jpki.pdf_sign(&pdf_data)?;

    fs::write(&args.output, &signed_pdf)?;
    println!("PDF署名を保存しました: {}", args.output);
    Ok(())
}

// ---------------------------------------------------------------------------
// Pin サブコマンド
// ---------------------------------------------------------------------------

#[derive(Debug, Args)]
struct ChangeArgs {
    /// 現在の暗証番号
    #[arg(long)]
    pin: Option<String>,
    /// 新しい暗証番号
    #[arg(long)]
    newpin: Option<String>,
}

#[derive(Subcommand)]
enum PinSubcommand {
    /// Show pin status
    Status,
    /// Change card input helper PIN
    #[command(subcommand)]
    Change(ChangeSubcommand),
}

#[derive(Subcommand)]
enum ChangeSubcommand {
    /// 券面入力補助用PINを変更
    Card(ChangeArgs),
    /// JPKI認証用PINを変更
    Auth(ChangeArgs),
    /// JPKI署名用パスワードを変更
    Sign(ChangeArgs),
}

fn run_pin(cmd: &PinSubcommand) -> Result<(), Error> {
    match cmd {
        PinSubcommand::Status => run_pin_status(),
        PinSubcommand::Change(change_cmd) => match change_cmd {
            ChangeSubcommand::Card(args) => run_change_card(args),
            ChangeSubcommand::Auth(args) => run_change_auth(args),
            ChangeSubcommand::Sign(args) => run_change_sign(args),
        },
    }
}

fn run_pin_status() -> Result<(), Error> {
    let mut reader = MynaReader::new()?;
    reader.connect()?;

    let text = reader.text_ap()?;
    text.reader.select_ef("0011")?;
    let counter = text.reader.read_pin()?;
    println!("券面入力補助AP 暗証番号: {}", counter);
    text.reader.select_ef("0014")?;
    let counter = text.reader.read_pin()?;
    println!("券面入力補助AP 暗証番号A: {}", counter);
    text.reader.select_ef("0015")?;
    let counter = text.reader.read_pin()?;
    println!("券面入力補助AP 暗証番号B: {}", counter);
    text.close();

    let visual = reader.visual_ap()?;
    visual.reader.select_ef("0013")?;
    let counter = visual.reader.read_pin()?;
    println!("券面確認AP 暗証番号A: {}", counter);
    visual.reader.select_ef("0012")?;
    let counter = visual.reader.read_pin()?;
    println!("券面確認AP 暗証番号B: {}", counter);
    visual.close();

    let jpki = reader.jpki_ap()?;
    jpki.reader.select_ef("0018")?;
    let counter = jpki.reader.read_pin()?;
    println!("JPKIユーザー認証用 暗証番号: {}", counter);
    jpki.reader.select_ef("001b")?;
    let counter = jpki.reader.read_pin()?;
    println!("JPKIデジタル署名用 パスワード: {}", counter);
    Ok(())
}

fn run_change_card(args: &ChangeArgs) -> Result<(), Error> {
    let pin = input_4digit_pin("現在の暗証番号(4桁): ", &args.pin)?;
    let newpin = input_4digit_pin("新しい暗証番号(4桁): ", &args.newpin)?;

    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let text = reader.text_ap()?;
    text.reader.select_ef("0011")?;
    text.reader.verify_pin(&pin)?;
    text.reader.change_pin(&newpin)?;
    println!("券面入力補助用PINを変更しました");
    Ok(())
}

fn run_change_auth(args: &ChangeArgs) -> Result<(), Error> {
    let pin = input_4digit_pin("現在の暗証番号(4桁): ", &args.pin)?;
    let newpin = input_4digit_pin("新しい暗証番号(4桁): ", &args.newpin)?;

    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let jpki = reader.jpki_ap()?;
    jpki.reader.select_ef("0018")?;
    jpki.reader.verify_pin(&pin)?;
    jpki.reader.change_pin(&newpin)?;
    println!("JPKI認証用PINを変更しました");
    Ok(())
}

fn run_change_sign(args: &ChangeArgs) -> Result<(), Error> {
    let pin = {
        let p = utils::prompt_input("現在のパスワード(6-16文字): ", &args.pin);
        let p = p.to_uppercase();
        utils::validate_jpki_sign_password(&p)?;
        p
    };
    let newpin = {
        let p = utils::prompt_input("新しいパスワード(6-16文字): ", &args.newpin);
        let p = p.to_uppercase();
        utils::validate_jpki_sign_password(&p)?;
        p
    };

    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let jpki = reader.jpki_ap()?;
    jpki.reader.select_ef("001b")?;
    jpki.reader.verify_pin(&pin)?;
    jpki.reader.change_pin(&newpin)?;
    println!("JPKI署名用パスワードを変更しました");
    Ok(())
}

// ---------------------------------------------------------------------------
// Unknown サブコマンド
// ---------------------------------------------------------------------------

#[derive(Subcommand)]
enum UnknownSubcommand {
    /// 謎の番号
    Number,
    /// 謎の製造番号
    Manufacture,
}

fn run_unknown(cmd: &UnknownSubcommand) -> Result<(), Error> {
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let mut unknown = reader.unknown_ap()?;

    match cmd {
        UnknownSubcommand::Number => {
            let data = unknown.read_number()?;
            println!("{}", String::from_utf8_lossy(&data));
        }
        UnknownSubcommand::Manufacture => {
            let manufacture = unknown.read_manufacture()?;
            print!("{}", manufacture);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ヘルパー関数
// ---------------------------------------------------------------------------

fn input_4digit_pin(prompt: &str, pin: &Option<String>) -> Result<String, Error> {
    let pin = utils::prompt_input(prompt, pin);
    utils::validate_4digit_pin(&pin)?;
    Ok(pin)
}

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

fn digest_alg_to_hash_alg(alg: &DigestAlgorithm) -> pkcs7::HashAlgorithm {
    match alg {
        DigestAlgorithm::Sha1 => pkcs7::HashAlgorithm::Sha1,
        DigestAlgorithm::Sha256 => pkcs7::HashAlgorithm::Sha256,
        DigestAlgorithm::Sha384 => pkcs7::HashAlgorithm::Sha384,
        DigestAlgorithm::Sha512 => pkcs7::HashAlgorithm::Sha512,
    }
}

fn cert_output(cert: &Certificate, format: &EnumFormat) {
    use der::Encode;
    match format {
        EnumFormat::Text => {
            let tbs = &cert.tbs_certificate;
            println!("Subject: {}", tbs.subject);
            println!("Issuer:  {}", tbs.issuer);
            println!(
                "Serial:  {}",
                utils::hex_encode(tbs.serial_number.as_bytes())
            );
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
