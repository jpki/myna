use crate::apdu::{APDUError, CommandAPDU, ResponseAPDU};
use pcsc::*;

pub struct MynaReader {
    ctx: Context,
    card: Option<Card>,
}

impl MynaReader {
    pub fn new() -> Result<Self, String> {
        let ctx = Context::establish(Scope::User)
            .map_err(|err| format!("Failed to establish context: {}", err))?;
        Ok(Self {
            ctx,
            card: None,
        })
    }

    pub fn connect(&mut self) -> Result<(), String> {
        log::debug!("# CONNECT");
        let mut reader_states = vec![ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE)];
        let mut readers_buf = [0; 2048];
        let readers = self
            .ctx
            .list_readers(&mut readers_buf)
            .map_err(|err| format!("Failed to list readers: {}", err))?;
        for reader in readers {
            log::debug!("# READER FOUND: {:?}", reader);
            reader_states.push(ReaderState::new(reader, State::UNAWARE));
        }

        loop {
            for rs in &mut reader_states {
                rs.sync_current_state();
            }
            self.ctx
                .get_status_change(None, &mut reader_states)
                .expect("failed to get status change");

            for rs in &reader_states {
                if rs.name() == PNP_NOTIFICATION() {
                    continue;
                }

                if State::PRESENT & rs.event_state() != State::PRESENT {
                    continue;
                }

                let atr = hex::encode(rs.atr());

                // FIDOデバイス?
                if atr.starts_with("3b888001") {
                    continue;
                }

                let card = match self
                    .ctx
                    .connect(rs.name(), ShareMode::Shared, Protocols::ANY)
                {
                    Ok(card) => card,
                    Err(Error::NoSmartcard) => {
                        return Err("A smartcard is not present in the reader.".to_string());
                    }
                    Err(err) => {
                        return Err(format!("Failed to connect to card: {}", err));
                    }
                };

                log::debug!("# CONNECTED");
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

    fn select_df(&mut self, bid: &[u8]) {
        log::debug!("# SELECT DF");
        let cmd = CommandAPDU::case3(0x00, 0xA4, 0x04, 0x0C, bid);
        log::debug!("< {}", cmd);
        let res = self.transmit(cmd);
        log::debug!("> {}", res);
    }

    pub fn select_ef(&mut self, fid: &str) -> Result<(), APDUError> {
        let bid = hex::decode(fid).unwrap();
        log::debug!("# SELECT EF");
        let cmd = CommandAPDU::case3(0x00, 0xA4, 0x02, 0x0C, &bid);
        log::debug!("< {}", cmd);
        let res = self.transmit(cmd);
        log::debug!("> {}", res);
        if res.sw() == 0x9000 {
            Ok(())
        } else {
            Err(APDUError { res })
        }
    }

    pub fn select_visual_ap(&mut self) {
        let bid = hex::decode("D3921000310001010402").unwrap();
        self.select_df(&bid);
    }

    pub fn select_text_ap(&mut self) {
        let bid = hex::decode("D3921000310001010408").unwrap();
        self.select_df(&bid);
    }

    pub fn select_jpki_ap(&mut self) {
        let bid = hex::decode("D392f000260100000001").unwrap();
        self.select_df(&bid);
    }

    pub fn read_binary(&mut self, pos: u16, len: u16) -> Vec<u8> {
        log::debug!("# READ BINARY");
        let p1: u8 = (pos >> 8) as u8;
        let p2: u8 = (pos & 0xff) as u8;
        let cmd = CommandAPDU::case2(0x00, 0xB0, p1, p2, len);
        log::debug!("< {}", cmd);
        let res = self.transmit(cmd);
        log::debug!("> {}", res);
        res.data
    }

    pub fn read_binary_all(&mut self) -> Vec<u8> {
        let mut head = self.read_binary(0, 5);
        let res = asn1_rs::Any::from_ber(&head);
        let len: u16 = match res {
            Err(asn1_rs::Err::Incomplete(nom::Needed::Size(size))) => size.get() as u16,
            _ => 0,
        };
        let data = self.read_binary(5, len);
        head.extend(data);
        head
    }

    pub fn read_pin(&mut self) -> Result<u8, APDUError> {
        log::debug!("# READ PIN");
        let cmd = CommandAPDU::case1(0x00, 0x20, 0x00, 0x80);
        log::debug!("< {}", cmd);
        let res = self.transmit(cmd);
        log::debug!("> {}", res);
        if res.sw1 == 0x63 {
            Ok(res.sw2 & 0x0f)
        } else {
            Err(APDUError { res })
        }
    }

    pub fn verify_pin(&mut self, pin: &str) -> Result<(), APDUError> {
        log::debug!("# VERIFY PIN");
        let cmd = CommandAPDU::case3(0x00, 0x20, 0x00, 0x80, pin.as_bytes());
        log::debug!("< {}", cmd);
        let res = self.transmit(cmd);
        log::debug!("> {}", res);
        if res.sw() == 0x9000 {
            Ok(())
        } else {
            Err(APDUError { res })
        }
    }

    pub fn change_pin(&mut self, newpin: &str) -> Result<(), APDUError> {
        log::debug!("# CHANGE PIN");
        let cmd = CommandAPDU::case3(0x00, 0x24, 0x01, 0x80, newpin.as_bytes());
        log::debug!("< {}", cmd);
        let res = self.transmit(cmd);
        log::debug!("> {}", res);
        if res.sw() == 0x9000 {
            Ok(())
        } else {
            Err(APDUError { res })
        }
    }

    pub fn signature(&mut self, data: &[u8]) -> Result<Vec<u8>, APDUError> {
        log::debug!("# SIGNATURE");
        let cmd = CommandAPDU::case4(0x80, 0x2A, 0x00, 0x80, data, 0);
        log::debug!("< {}", cmd);
        let res = self.transmit(cmd);
        log::debug!("> {}", res);
        if res.sw() == 0x9000 {
            Ok(res.data)
        } else {
            Err(APDUError { res })
        }
    }
}

use asn1_rs::FromBer;

#[test]
fn partial_decode() {
    let bytes = [0xff, 0x40, 0x82, 0x00, 0x9f];
    let res = asn1_rs::Any::from_ber(&bytes);
    let len = match res {
        Err(asn1_rs::Err::Incomplete(nom::Needed::Size(size))) => size.get(),
        _ => 0,
    };
    assert_eq!(159, len);
}
