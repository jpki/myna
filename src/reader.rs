use crate::apdu::{APDUError, CommandAPDU, ResponseAPDU};
use crate::error::Error;
use crate::utils;
use pcsc::*;

pub struct MynaReader {
    ctx: Context,
    card: Option<Card>,
    pub timeout: Option<std::time::Duration>,
}

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

            let found = reader_states.iter()
                .filter(|rs| rs.name() != PNP_NOTIFICATION())
                .find(|rs| rs.event_state().contains(State::PRESENT));

            if let Some(rs) = found {
                log::debug!(
                    "READER SELECTED: {:?} state={:?} atr={}",
                    rs.name(),
                    rs.event_state(),
                    utils::hex_encode(rs.atr())
                );
                let card = self.ctx.connect(rs.name(), ShareMode::Shared, Protocols::ANY)
                    .map_err(|e| match e {
                        pcsc::Error::NoSmartcard => Error::from("A smartcard is not present in the reader."),
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

use asn1_rs::FromBer;

#[test]
fn partial_decode() {
    let bytes = [0xff, 0x40, 0x82, 0x00, 0x9f];
    let res = asn1_rs::Any::from_ber(&bytes);
    let len = match res {
        Err(asn1_rs::Err::Incomplete(asn1_rs::Needed::Size(size))) => size.get(),
        _ => 0,
    };
    assert_eq!(159, len);
}
