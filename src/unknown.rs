use crate::error::Error;
use crate::reader::MynaReader;
use crate::utils;

const UNKNOWN_AID: &str = "D3921000310001010100";

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
        let (_, tlv) = crate::ber::parse(&data)
            .map_err(|e| Error::new(format!("BERデコードに失敗しました: {}", e)))?;
        Ok(tlv.data.to_vec())
    }

    pub fn read_manufacture(&mut self) -> Result<String, Error> {
        let data = self.read_number()?;
        let s = std::str::from_utf8(&data)
            .map_err(|e| Error::new(format!("UTF-8変換に失敗しました: {}", e)))?;
        if s.len() < 15 {
            return Err(Error::new(format!(
                "製造番号データが短すぎます ({}バイト, 15バイト以上必要)",
                s.len()
            )));
        }
        Ok(s[2..15].to_string())
    }
}

#[cfg(all(test, feature = "dummy"))]
mod tests {
    use crate::reader::MynaReader;
    use crate::reader::dummy::UNKNOWN_AID;

    fn setup_unknown_reader(data: Vec<u8>) -> MynaReader {
        // read_record(1, 1) で返されるデータはBER TLVでラップされている
        MynaReader::new()
            .unwrap()
            .with_file(UNKNOWN_AID, "record_1_1", data)
    }

    #[test]
    fn test_read_manufacture_success() {
        // TLV: tag=0x30, length=15, value="AB1234567890123"
        let value = b"AB1234567890123";
        let mut tlv = vec![0x30, value.len() as u8];
        tlv.extend_from_slice(value);

        let mut reader = setup_unknown_reader(tlv);
        reader.connect().unwrap();
        let mut unknown = reader.unknown_ap().unwrap();
        let manufacture = unknown.read_manufacture().unwrap();
        assert_eq!(manufacture, "1234567890123");
    }

    #[test]
    fn test_read_manufacture_too_short() {
        // TLV: tag=0x30, length=5, value="ABCDE" (15バイト未満)
        let value = b"ABCDE";
        let mut tlv = vec![0x30, value.len() as u8];
        tlv.extend_from_slice(value);

        let mut reader = setup_unknown_reader(tlv);
        reader.connect().unwrap();
        let mut unknown = reader.unknown_ap().unwrap();
        let result = unknown.read_manufacture();
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("短すぎます"), "msg = {}", msg);
    }

    #[test]
    fn test_read_manufacture_exact_15_bytes() {
        // ちょうど15バイト: 境界値テスト
        let value = b"012345678901234";
        assert_eq!(value.len(), 15);
        let mut tlv = vec![0x30, value.len() as u8];
        tlv.extend_from_slice(value);

        let mut reader = setup_unknown_reader(tlv);
        reader.connect().unwrap();
        let mut unknown = reader.unknown_ap().unwrap();
        let manufacture = unknown.read_manufacture().unwrap();
        assert_eq!(manufacture, "2345678901234");
    }
}
