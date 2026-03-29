use crate::ber;
use crate::error::Error;
use crate::reader::MynaReader;
use crate::utils;

const TEXT_AID: &str = "D3921000310001010408";

pub struct TextAP<'a> {
    pub reader: &'a mut MynaReader,
}

pub struct BasicInfo {
    pub apid: String,
    pub pubkey_id: String,
}

pub struct TextAttrs {
    pub name: String,
    pub addr: String,
    pub birth: String,
    pub sex: String,
}

impl MynaReader {
    pub fn text_ap(&mut self) -> Result<TextAP<'_>, Error> {
        let aid = utils::hex_decode(TEXT_AID)?;
        self.select_df(&aid)?;
        Ok(TextAP { reader: self })
    }
}

fn ber_err(e: impl std::fmt::Display) -> Error {
    Error::new(format!("BERデコードに失敗しました: {}", e))
}

impl<'a> TextAP<'a> {
    pub fn close(self) {}

    pub fn basic_info(&mut self) -> Result<BasicInfo, Error> {
        self.reader.select_ef("0005")?;
        let encoded = self.reader.read_binary_all()?;
        let (_rem, payload) = ber::parse(&encoded).map_err(ber_err)?;
        let (rem, apid) = ber::parse(payload.data).map_err(ber_err)?;
        let (_rem, pubkey_id) = ber::parse(rem).map_err(ber_err)?;
        Ok(BasicInfo {
            apid: utils::hex_encode(apid.data),
            pubkey_id: utils::hex_encode(pubkey_id.data),
        })
    }

    pub fn mynumber(&mut self, pin: &str) -> Result<String, Error> {
        self.reader.select_ef("0011")?;
        self.reader.verify_pin(pin)?;
        self.reader.select_ef("0001")?;
        let encoded = self.reader.read_binary(0, 17)?;
        let (_rem, res) = ber::parse(&encoded).map_err(ber_err)?;
        let mynumber = std::str::from_utf8(res.data)
            .map_err(|e| Error::new(format!("個人番号のUTF-8変換に失敗しました: {}", e)))?;
        Ok(mynumber.to_string())
    }

    pub fn attrs(&mut self, pin: &str) -> Result<TextAttrs, Error> {
        self.reader.select_ef("0011")?;
        self.reader.verify_pin(pin)?;
        self.reader.select_ef("0002")?;
        let encoded = self.reader.read_binary_all()?;
        let (_rem, res) = ber::parse(&encoded).map_err(ber_err)?;
        let (rem, _res) = ber::parse(res.data).map_err(ber_err)?;
        let (rem, res) = ber::parse(rem).map_err(ber_err)?;
        let name = std::str::from_utf8(res.data)
            .map_err(|e| Error::new(format!("UTF-8変換に失敗しました: {}", e)))?;
        let (rem, res) = ber::parse(rem).map_err(ber_err)?;
        let addr = std::str::from_utf8(res.data)
            .map_err(|e| Error::new(format!("UTF-8変換に失敗しました: {}", e)))?;
        let (rem, res) = ber::parse(rem).map_err(ber_err)?;
        let birth = std::str::from_utf8(res.data)
            .map_err(|e| Error::new(format!("UTF-8変換に失敗しました: {}", e)))?;
        let (_rem, res) = ber::parse(rem).map_err(ber_err)?;
        let sex = std::str::from_utf8(res.data)
            .map_err(|e| Error::new(format!("UTF-8変換に失敗しました: {}", e)))?;
        Ok(TextAttrs {
            name: name.to_string(),
            addr: addr.to_string(),
            birth: birth.to_string(),
            sex: sex.to_string(),
        })
    }
}
