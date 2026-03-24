use crate::error::Error;
use crate::reader::MynaReader;
use crate::utils;
use clap::Subcommand;

const UNKNOWN_AID: &str = "D3921000310001010100";

#[derive(Subcommand)]
pub enum UnknownSubcommand {
    /// 謎の番号
    Number,
    /// 謎の製造番号
    Manufacture,
}

pub struct UnknownAP<'a> {
    pub reader: &'a mut MynaReader,
}

impl MynaReader {
    pub fn unknown_ap(&mut self) -> Result<UnknownAP<'_>, Error> {
        let aid = utils::hex_decode(UNKNOWN_AID)?;
        self.select_df(&aid)?;
        Ok(UnknownAP { reader: self })
    }
}

impl<'a> UnknownAP<'a> {
    pub fn close(self) {}

    pub fn read_number(&mut self) -> Result<Vec<u8>, Error> {
        let data = self.reader.read_record(1, 1)?;
        let (_, tlv) = crate::ber::parse_tlv(&data)
            .map_err(|e| Error::new(format!("BERデコードに失敗しました: {}", e)))?;
        Ok(tlv.data.to_vec())
    }
}

pub fn main(command: &UnknownSubcommand) -> Result<(), Error> {
    let mut reader = MynaReader::new()?;
    reader.connect()?;
    let mut unknown = reader.unknown_ap()?;

    match command {
        UnknownSubcommand::Number => {
            let data = unknown.read_number()?;
            println!("{}", String::from_utf8_lossy(&data));
        }
        UnknownSubcommand::Manufacture => {
            let data = unknown.read_number()?;
            let s = String::from_utf8_lossy(&data);
            print!("{}", &s[2..15]);
        }
    }
    Ok(())
}
