use clap::{Args, Subcommand};

use myna::error::Error;
use myna::reader::MynaReader;
use myna::utils;

#[derive(Debug, Args)]
pub struct ChangeArgs {
    /// 現在の暗証番号
    #[arg(long)]
    pin: Option<String>,
    /// 新しい暗証番号
    #[arg(long)]
    newpin: Option<String>,
}

#[derive(Subcommand)]
pub enum Pin {
    /// Show pin status
    Status,
    /// Change card input helper PIN
    #[command(subcommand)]
    Change(ChangeSubcommand),
}

#[derive(Subcommand)]
pub enum ChangeSubcommand {
    /// 券面入力補助用PINを変更
    Card(ChangeArgs),
    /// JPKI認証用PINを変更
    Auth(ChangeArgs),
    /// JPKI署名用パスワードを変更
    Sign(ChangeArgs),
}

pub fn main(app: &crate::App, subcommand: &Pin) -> Result<(), Error> {
    match subcommand {
        Pin::Status => run_status(app),
        Pin::Change(change_cmd) => run_change(change_cmd),
    }
}

fn run_change(subcommand: &ChangeSubcommand) -> Result<(), Error> {
    match subcommand {
        ChangeSubcommand::Card(args) => run_change_card(args),
        ChangeSubcommand::Auth(args) => run_change_auth(args),
        ChangeSubcommand::Sign(args) => run_change_sign(args),
    }
}

fn run_change_card(args: &ChangeArgs) -> Result<(), Error> {
    let pin = utils::prompt_input("現在の暗証番号(4桁): ", &args.pin);
    utils::validate_4digit_pin(&pin)?;
    let newpin = utils::prompt_input("新しい暗証番号(4桁): ", &args.newpin);
    utils::validate_4digit_pin(&newpin)?;

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
    let pin = utils::prompt_input("現在の暗証番号(4桁): ", &args.pin);
    utils::validate_4digit_pin(&pin)?;
    let newpin = utils::prompt_input("新しい暗証番号(4桁): ", &args.newpin);
    utils::validate_4digit_pin(&newpin)?;

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
    let pin = utils::prompt_input("現在のパスワード(6-16文字): ", &args.pin);
    let pin = pin.to_uppercase();
    utils::validate_jpki_sign_password(&pin)?;
    let newpin = utils::prompt_input("新しいパスワード(6-16文字): ", &args.newpin);
    let newpin = newpin.to_uppercase();
    utils::validate_jpki_sign_password(&newpin)?;

    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let jpki = reader.jpki_ap()?;
    jpki.reader.select_ef("001b")?;
    jpki.reader.verify_pin(&pin)?;
    jpki.reader.change_pin(&newpin)?;
    println!("JPKI署名用パスワードを変更しました");
    Ok(())
}

fn run_status(_app: &crate::App) -> Result<(), Error> {
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
