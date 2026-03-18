use crate::apdu::{APDUError, CommandAPDU, ResponseAPDU};
use crate::error::Error;
use crate::utils;

#[cfg(not(feature = "dummy"))]
use pcsc::*;

#[cfg(feature = "dummy")]
pub mod dummy;

pub struct MynaReader {
    #[cfg(not(feature = "dummy"))]
    ctx: Context,
    #[cfg(not(feature = "dummy"))]
    card: Option<Card>,
    #[cfg(feature = "dummy")]
    state: dummy::DummyCardState,
    pub timeout: Option<std::time::Duration>,
}

// --- pcsc backend ---

#[cfg(not(feature = "dummy"))]
impl MynaReader {
    pub fn new() -> Result<Self, Error> {
        let ctx = Context::establish(Scope::User)
            .map_err(|e| Error::with_source("Failed to establish context", e))?;
        Ok(Self {
            ctx,
            card: None,
            timeout: None,
        })
    }

    pub fn connect(&mut self) -> Result<(), Error> {
        log::debug!("CONNECT timeout={:?}", self.timeout);
        let mut reader_states = vec![ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE)];
        let readers = self
            .ctx
            .list_readers_owned()
            .map_err(|e| Error::with_source("Failed to list readers", e))?;
        for reader in readers {
            log::debug!("READER FOUND: {:?}", reader);
            reader_states.push(ReaderState::new(reader, State::UNAWARE));
        }

        loop {
            for rs in &mut reader_states {
                rs.sync_current_state();
            }
            self.ctx
                .get_status_change(self.timeout, &mut reader_states)
                .map_err(|e| match e {
                    pcsc::Error::Timeout => Error::from("Timeout: No smartcard found"),
                    err => Error::with_source("failed to get status change", err),
                })?;

            let found = reader_states
                .iter()
                .filter(|rs| rs.name() != PNP_NOTIFICATION())
                .find(|rs| rs.event_state().contains(State::PRESENT));

            if let Some(rs) = found {
                log::debug!(
                    "READER SELECTED: {:?} state={:?} atr={}",
                    rs.name(),
                    rs.event_state(),
                    utils::hex_encode(rs.atr())
                );
                let card = self
                    .ctx
                    .connect(rs.name(), ShareMode::Shared, Protocols::ANY)
                    .map_err(|e| match e {
                        pcsc::Error::NoSmartcard => {
                            Error::from("A smartcard is not present in the reader.")
                        }
                        err => Error::with_source("Failed to connect to card", err),
                    })?;

                log::debug!("CONNECTED");
                self.card = Some(card);
                return Ok(());
            }
        }
    }

    fn transmit(&mut self, cmd: CommandAPDU) -> ResponseAPDU {
        let card = self.card.as_ref().expect("Not connected to card");
        let capdu = cmd.to_bytes();
        let mut rbuf = [0; 4096];
        let rapdu = card
            .transmit(&capdu, &mut rbuf)
            .expect("Failed to transmit APDU command to card");
        ResponseAPDU::new(rapdu)
    }
}

// --- dummy backend ---

#[cfg(feature = "dummy")]
impl MynaReader {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            state: dummy::DummyCardState::new(),
            timeout: None,
        })
    }

    pub fn connect(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn transmit(&mut self, cmd: CommandAPDU) -> ResponseAPDU {
        self.state.process(cmd)
    }

    pub fn with_file(mut self, df: &str, ef: &str, data: Vec<u8>) -> Self {
        self.state.add_file(df, ef, data);
        self
    }

    pub fn with_pin(mut self, df: &str, ef: &str, pin: &str, attempts: u8) -> Self {
        self.state.add_pin(df, ef, pin, attempts);
        self
    }

    pub fn with_sign_fn(mut self, f: impl FnMut(&[u8]) -> Vec<u8> + 'static) -> Self {
        self.state.set_sign_fn(f);
        self
    }
}

// --- 共通メソッド ---

impl MynaReader {
    pub fn select_df(&mut self, aid: &[u8]) -> std::result::Result<(), APDUError> {
        log::debug!("SELECT DF aid={}", utils::hex_encode(aid));
        let cmd = CommandAPDU::case3(0x00, 0xA4, 0x04, 0x0C, aid);
        log::trace!("< {}", cmd);
        let res = self.transmit(cmd);
        log::trace!("> {}", res);
        if res.sw() == 0x9000 {
            Ok(())
        } else {
            Err(APDUError { res })
        }
    }

    pub fn select_ef(&mut self, fid: &str) -> std::result::Result<(), APDUError> {
        let bid = utils::hex_decode(fid).unwrap();
        log::debug!("SELECT EF fid={}", fid);
        let cmd = CommandAPDU::case3(0x00, 0xA4, 0x02, 0x0C, &bid);
        log::trace!("< {}", cmd);
        let res = self.transmit(cmd);
        log::trace!("> {}", res);
        if res.sw() == 0x9000 {
            Ok(())
        } else {
            Err(APDUError { res })
        }
    }

    pub fn read_binary(&mut self, pos: u16, size: u16) -> std::result::Result<Vec<u8>, APDUError> {
        log::debug!("READ BINARY pos={} size={}", pos, size);
        let mut result = Vec::new();
        let mut pos = pos;
        let end = pos + size;
        while pos < end {
            let remaining = end - pos;
            let le: u16 = if remaining > 0xff { 0 } else { remaining };
            let p1: u8 = (pos >> 8) as u8;
            let p2: u8 = (pos & 0xff) as u8;
            let cmd = CommandAPDU::case2(0x00, 0xB0, p1, p2, le);
            log::trace!("< {}", cmd);
            let res = self.transmit(cmd);
            log::trace!("> {}", res);
            if res.sw() != 0x9000 {
                return Err(APDUError { res });
            }
            let n = res.data.len() as u16;
            if n == 0 {
                break;
            }
            result.extend(res.data);
            pos += n;
        }
        Ok(result)
    }

    pub fn read_binary_all(&mut self) -> std::result::Result<Vec<u8>, APDUError> {
        use asn1_rs::FromBer;
        let mut head = self.read_binary(0, 7)?;
        let res = asn1_rs::Any::from_ber(&head);
        let len: u16 = match res {
            Err(asn1_rs::Err::Incomplete(asn1_rs::Needed::Size(size))) => size.get() as u16,
            _ => 0,
        };
        let data = self.read_binary(7, len)?;
        head.extend(data);
        Ok(head)
    }

    pub fn read_pin(&mut self) -> std::result::Result<u8, APDUError> {
        log::debug!("READ PIN");
        let cmd = CommandAPDU::case1(0x00, 0x20, 0x00, 0x80);
        log::trace!("< {}", cmd);
        let res = self.transmit(cmd);
        log::trace!("> {}", res);
        if res.sw1 == 0x63 {
            Ok(res.sw2 & 0x0f)
        } else {
            Err(APDUError { res })
        }
    }

    pub fn verify_pin(&mut self, pin: &str) -> std::result::Result<(), APDUError> {
        log::debug!("VERIFY PIN");
        let cmd = CommandAPDU::case3(0x00, 0x20, 0x00, 0x80, pin.as_bytes());
        log::trace!("< {}", cmd);
        let res = self.transmit(cmd);
        log::trace!("> {}", res);
        if res.sw() == 0x9000 {
            Ok(())
        } else {
            Err(APDUError { res })
        }
    }

    pub fn change_pin(&mut self, newpin: &str) -> std::result::Result<(), APDUError> {
        log::debug!("CHANGE PIN");
        let cmd = CommandAPDU::case3(0x00, 0x24, 0x01, 0x80, newpin.as_bytes());
        log::trace!("< {}", cmd);
        let res = self.transmit(cmd);
        log::trace!("> {}", res);
        if res.sw() == 0x9000 {
            Ok(())
        } else {
            Err(APDUError { res })
        }
    }

    pub fn read_record(&mut self, record: u8, sfi: u8) -> std::result::Result<Vec<u8>, APDUError> {
        log::debug!("READ RECORD record={} sfi={}", record, sfi);
        let p2 = (sfi << 3) | 0x04;
        let cmd = CommandAPDU::case2(0x00, 0xB2, record, p2, 0);
        log::trace!("< {}", cmd);
        let res = self.transmit(cmd);
        log::trace!("> {}", res);
        if res.sw() == 0x9000 {
            Ok(res.data)
        } else {
            Err(APDUError { res })
        }
    }

    pub fn signature(&mut self, data: &[u8]) -> std::result::Result<Vec<u8>, APDUError> {
        log::debug!("SIGNATURE data_len={}", data.len());
        let cmd = CommandAPDU::case4(0x80, 0x2A, 0x00, 0x80, data, 0);
        log::trace!("< {}", cmd);
        let res = self.transmit(cmd);
        log::trace!("> {}", res);
        if res.sw() == 0x9000 {
            Ok(res.data)
        } else {
            Err(APDUError { res })
        }
    }
}

#[test]
fn partial_decode() {
    use asn1_rs::FromBer;
    let bytes = [0xff, 0x40, 0x82, 0x00, 0x9f];
    let res = asn1_rs::Any::from_ber(&bytes);
    let len = match res {
        Err(asn1_rs::Err::Incomplete(asn1_rs::Needed::Size(size))) => size.get(),
        _ => 0,
    };
    assert_eq!(159, len);
}

#[cfg(all(test, feature = "dummy"))]
mod dummy_tests {
    use super::*;
    use dummy::JPKI_AID;

    fn select_jpki(r: &mut MynaReader) {
        let aid = utils::hex_decode(JPKI_AID).unwrap();
        r.select_df(&aid).unwrap();
    }

    #[test]
    fn test_select_ef_found() {
        let mut r = MynaReader::new()
            .unwrap()
            .with_file(JPKI_AID, "000a", vec![1, 2, 3]);
        r.connect().unwrap();
        select_jpki(&mut r);
        r.select_ef("000a").unwrap();
    }

    #[test]
    fn test_select_ef_not_found() {
        let mut r = MynaReader::new().unwrap();
        r.connect().unwrap();
        select_jpki(&mut r);
        let err = r.select_ef("ffff").unwrap_err();
        assert_eq!(err.res.sw(), 0x6A82);
    }

    #[test]
    fn test_read_binary() {
        let data = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        let mut r = MynaReader::new()
            .unwrap()
            .with_file(JPKI_AID, "000a", data.clone());
        r.connect().unwrap();
        select_jpki(&mut r);
        r.select_ef("000a").unwrap();
        assert_eq!(r.read_binary(0, 5).unwrap(), data);
    }

    #[test]
    fn test_read_binary_all() {
        let data = vec![0x30, 0x03, 0x01, 0x02, 0x03];
        let mut r = MynaReader::new()
            .unwrap()
            .with_file(JPKI_AID, "000a", data.clone());
        r.connect().unwrap();
        select_jpki(&mut r);
        r.select_ef("000a").unwrap();
        assert_eq!(r.read_binary_all().unwrap(), data);
    }

    #[test]
    fn test_verify_pin_success() {
        let mut r = MynaReader::new()
            .unwrap()
            .with_pin(JPKI_AID, "0018", "1234", 3);
        r.connect().unwrap();
        select_jpki(&mut r);
        r.select_ef("0018").unwrap();
        r.verify_pin("1234").unwrap();
    }

    #[test]
    fn test_verify_pin_failure_decrements() {
        let mut r = MynaReader::new()
            .unwrap()
            .with_pin(JPKI_AID, "0018", "1234", 3);
        r.connect().unwrap();
        select_jpki(&mut r);
        r.select_ef("0018").unwrap();
        let err = r.verify_pin("0000").unwrap_err();
        assert_eq!(err.res.sw1, 0x63);
        assert_eq!(err.res.sw2 & 0x0f, 2);
    }

    #[test]
    fn test_read_pin() {
        let mut r = MynaReader::new()
            .unwrap()
            .with_pin(JPKI_AID, "0018", "1234", 3);
        r.connect().unwrap();
        select_jpki(&mut r);
        r.select_ef("0018").unwrap();
        assert_eq!(r.read_pin().unwrap(), 3);
    }

    #[test]
    fn test_signature() {
        let mut r = MynaReader::new().unwrap().with_sign_fn(|data| {
            let mut sig = vec![0xAA; 256];
            sig[..data.len().min(256)].copy_from_slice(&data[..data.len().min(256)]);
            sig
        });
        r.connect().unwrap();
        select_jpki(&mut r);
        let result = r.signature(&[0x01, 0x02]).unwrap();
        assert_eq!(result.len(), 256);
    }

    #[test]
    fn test_change_pin() {
        let mut r = MynaReader::new()
            .unwrap()
            .with_pin(JPKI_AID, "0018", "1234", 3);
        r.connect().unwrap();
        select_jpki(&mut r);
        r.select_ef("0018").unwrap();
        r.verify_pin("1234").unwrap();
        r.change_pin("5678").unwrap();
        // 新しいPINで認証できること
        r.verify_pin("5678").unwrap();
        // 古いPINで認証できないこと
        let err = r.verify_pin("1234").unwrap_err();
        assert_eq!(err.res.sw1, 0x63);
    }

    #[test]
    fn test_read_record() {
        let mut r = MynaReader::new().unwrap().with_file(
            dummy::UNKNOWN_AID,
            "record_1_1",
            vec![0x30, 0x05, 0x0C, 0x03, 0x41, 0x42, 0x43],
        );
        r.connect().unwrap();
        let aid = utils::hex_decode(dummy::UNKNOWN_AID).unwrap();
        r.select_df(&aid).unwrap();
        let data = r.read_record(1, 1).unwrap();
        assert_eq!(data, vec![0x30, 0x05, 0x0C, 0x03, 0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_select_df_unknown() {
        let mut r = MynaReader::new().unwrap();
        r.connect().unwrap();
        // 存在する AID
        let aid = utils::hex_decode(JPKI_AID).unwrap();
        r.select_df(&aid).unwrap();
    }

    #[test]
    fn test_read_binary_offset() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut r = MynaReader::new()
            .unwrap()
            .with_file(JPKI_AID, "000a", data);
        r.connect().unwrap();
        select_jpki(&mut r);
        r.select_ef("000a").unwrap();
        // offset 2, size 3
        let result = r.read_binary(2, 3).unwrap();
        assert_eq!(result, vec![0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_verify_pin_multiple_failures() {
        let mut r = MynaReader::new()
            .unwrap()
            .with_pin(JPKI_AID, "0018", "1234", 3);
        r.connect().unwrap();
        select_jpki(&mut r);
        r.select_ef("0018").unwrap();

        // 1回目失敗: 残り2
        let err = r.verify_pin("0000").unwrap_err();
        assert_eq!(err.res.sw2 & 0x0f, 2);

        // 2回目失敗: 残り1
        let err = r.verify_pin("0000").unwrap_err();
        assert_eq!(err.res.sw2 & 0x0f, 1);

        // 3回目失敗: 残り0
        let err = r.verify_pin("0000").unwrap_err();
        assert_eq!(err.res.sw2 & 0x0f, 0);

        // ロック後も0のまま (saturating)
        let err = r.verify_pin("0000").unwrap_err();
        assert_eq!(err.res.sw2 & 0x0f, 0);
    }
}
