use clap::{Args, Subcommand};

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

pub fn main(app: &crate::App, subcommand: &Pin) {
    match subcommand {
        Pin::Status => run_status(app),
        Pin::Change(change_cmd) => run_change(change_cmd),
    }
}

fn run_change(subcommand: &ChangeSubcommand) {
    match subcommand {
        ChangeSubcommand::Card(args) => run_change_card(args),
        ChangeSubcommand::Auth(args) => run_change_auth(args),
        ChangeSubcommand::Sign(args) => run_change_sign(args),
    }
}

fn run_change_card(args: &ChangeArgs) {
    let pin = utils::prompt_input("現在の暗証番号(4桁): ", &args.pin);
    utils::validate_4digit_pin(&pin).expect("暗証番号が不正です");
    let newpin = utils::prompt_input("新しい暗証番号(4桁): ", &args.newpin);
    utils::validate_4digit_pin(&newpin).expect("新しい暗証番号が不正です");

    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_text_ap();
    reader
        .select_ef("0011")
        .expect("EF 0011の選択に失敗しました");
    reader
        .verify_pin(&pin)
        .expect("暗証番号の認証に失敗しました");
    reader.change_pin(&newpin).expect("PINの変更に失敗しました");
    println!("券面入力補助用PINを変更しました");
}

fn run_change_auth(args: &ChangeArgs) {
    let pin = utils::prompt_input("現在の暗証番号(4桁): ", &args.pin);
    utils::validate_4digit_pin(&pin).expect("暗証番号が不正です");
    let newpin = utils::prompt_input("新しい暗証番号(4桁): ", &args.newpin);
    utils::validate_4digit_pin(&newpin).expect("新しい暗証番号が不正です");

    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();
    reader
        .select_ef("0018")
        .expect("EF 0018の選択に失敗しました");
    reader
        .verify_pin(&pin)
        .expect("暗証番号の認証に失敗しました");
    reader.change_pin(&newpin).expect("PINの変更に失敗しました");
    println!("JPKI認証用PINを変更しました");
}

fn run_change_sign(args: &ChangeArgs) {
    let pin = utils::prompt_input("現在のパスワード(6-16文字): ", &args.pin);
    let pin = pin.to_uppercase();
    utils::validate_jpki_sign_password(&pin).expect("パスワードが不正です");
    let newpin = utils::prompt_input("新しいパスワード(6-16文字): ", &args.newpin);
    let newpin = newpin.to_uppercase();
    utils::validate_jpki_sign_password(&newpin).expect("新しいパスワードが不正です");

    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_jpki_ap();
    reader
        .select_ef("001b")
        .expect("EF 001bの選択に失敗しました");
    reader
        .verify_pin(&pin)
        .expect("パスワードの認証に失敗しました");
    reader
        .change_pin(&newpin)
        .expect("パスワードの変更に失敗しました");
    println!("JPKI署名用パスワードを変更しました");
}

fn run_status(_app: &crate::App) {
    let mut reader = MynaReader::new().expect("リーダーの初期化に失敗しました");
    reader.connect().expect("カードへの接続に失敗しました");
    reader.select_text_ap();
    reader
        .select_ef("0011")
        .expect("EF 0011の選択に失敗しました");
    let counter = reader.read_pin().expect("PIN状態の読み取りに失敗しました");
    println!("券面入力補助AP 暗証番号: {}", counter);
    reader
        .select_ef("0014")
        .expect("EF 0014の選択に失敗しました");
    let counter = reader.read_pin().expect("PIN状態の読み取りに失敗しました");
    println!("券面入力補助AP 暗証番号A: {}", counter);
    reader
        .select_ef("0015")
        .expect("EF 0015の選択に失敗しました");
    let counter = reader.read_pin().expect("PIN状態の読み取りに失敗しました");
    println!("券面入力補助AP 暗証番号B: {}", counter);
    reader.select_visual_ap();
    reader
        .select_ef("0013")
        .expect("EF 0013の選択に失敗しました");
    let counter = reader.read_pin().expect("PIN状態の読み取りに失敗しました");
    println!("券面確認AP 暗証番号A: {}", counter);
    reader
        .select_ef("0012")
        .expect("EF 0012の選択に失敗しました");
    let counter = reader.read_pin().expect("PIN状態の読み取りに失敗しました");
    println!("券面確認AP 暗証番号B: {}", counter);
    reader.select_jpki_ap();
    reader
        .select_ef("0018")
        .expect("EF 0018の選択に失敗しました");
    let counter = reader.read_pin().expect("PIN状態の読み取りに失敗しました");
    println!("JPKIユーザー認証用 暗証番号: {}", counter);
    reader
        .select_ef("001b")
        .expect("EF 001bの選択に失敗しました");
    let counter = reader.read_pin().expect("PIN状態の読み取りに失敗しました");
    println!("JPKIデジタル署名用 パスワード: {}", counter);
}
