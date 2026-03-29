use crate::ber;
use crate::error::Error;
use crate::reader::MynaReader;
use crate::utils;

const VISUAL_AID: &str = "D3921000310001010402";

pub struct VisualAP<'a> {
    pub reader: &'a mut MynaReader,
}

pub struct VisualBasicInfo {
    pub apid: String,
    pub version: u8,
    pub city: String,
}

pub struct VisualEntries {
    pub name: Vec<u8>,
    pub addr: Vec<u8>,
    pub birth: String,
    pub sex: String,
    pub photo: Vec<u8>,
}

impl MynaReader {
    pub fn visual_ap(&mut self) -> Result<VisualAP<'_>, Error> {
        let aid = utils::hex_decode(VISUAL_AID)?;
        self.select_df(&aid)?;
        Ok(VisualAP { reader: self })
    }
}

fn ber_err(e: impl std::fmt::Display) -> Error {
    Error::new(format!("BERデコードに失敗しました: {}", e))
}

fn parse_utf8(data: &[u8], label: &str) -> Result<String, Error> {
    String::from_utf8(data.to_vec())
        .map_err(|e| Error::new(format!("{}のUTF-8変換に失敗しました: {}", label, e)))
}

impl<'a> VisualAP<'a> {
    pub fn close(self) {}

    pub fn basic_info(&mut self) -> Result<VisualBasicInfo, Error> {
        self.reader.select_ef("0003")?;
        let encoded = self.reader.read_binary_all()?;
        let (_rem, payload) = ber::parse(&encoded).map_err(ber_err)?;
        // 1番目: 識別情報(4バイト)
        let (rem, id) = ber::parse(payload.data).map_err(ber_err)?;
        // 2番目: スキップ
        let (rem, _) = ber::parse(rem).map_err(ber_err)?;
        // 3番目: バージョン(1バイト)
        let (rem, version) = ber::parse(rem).map_err(ber_err)?;
        // 4番目: city
        let (_rem, city) = ber::parse(rem).map_err(ber_err)?;

        Ok(VisualBasicInfo {
            apid: utils::hex_encode(id.data),
            version: *version.data.first().unwrap_or(&0),
            city: parse_utf8(city.data, "city")?,
        })
    }

    /// 券面確認APから券面情報を読み取る
    /// 構造: Header(33), Birth(34), Sex(35), PublicKey(36), Name(37), Addr(38), Photo(39), ...
    pub fn read_entries(&mut self, mynumber: &str) -> Result<VisualEntries, Error> {
        self.reader.select_ef("0013")?;
        self.reader.verify_pin(mynumber)?;
        self.reader.select_ef("0002")?;
        let encoded = self.reader.read_binary_all()?;

        let (_rem, payload) = ber::parse(&encoded).map_err(ber_err)?;
        let rem = payload.data;
        // Header(33) をスキップ
        let (rem, _) = ber::parse(rem).map_err(ber_err)?;
        // Birth(34), Sex(35)
        let (rem, birth) = ber::parse(rem).map_err(ber_err)?;
        let (rem, sex) = ber::parse(rem).map_err(ber_err)?;
        // PublicKey(36) をスキップ
        let (rem, _) = ber::parse(rem).map_err(ber_err)?;
        // Name(37), Addr(38), Photo(39)
        let (rem, name) = ber::parse(rem).map_err(ber_err)?;
        let (rem, addr) = ber::parse(rem).map_err(ber_err)?;
        let (_rem, photo) = ber::parse(rem).map_err(ber_err)?;

        Ok(VisualEntries {
            name: name.data.to_vec(),
            addr: addr.data.to_vec(),
            birth: parse_utf8(birth.data, "生年月日")?,
            sex: parse_utf8(sex.data, "性別")?,
            photo: photo.data.to_vec(),
        })
    }
}
