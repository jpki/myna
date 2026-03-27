use crate::error::Error;
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

const SIGN_CA_2015_PEM: &[u8] = include_bytes!("ta/sign_ca_2015.pem");
const SIGN_CA_2023_PEM: &[u8] = include_bytes!("ta/sign_ca_2023.pem");
const AUTH_CA_2015_PEM: &[u8] = include_bytes!("ta/auth_ca_2015.pem");
const AUTH_CA_2023_PEM: &[u8] = include_bytes!("ta/auth_ca_2023.pem");

const SIGN_ROOT_SPECS: [(&str, &[u8]); 2] = [
    ("sign_ca_2015", SIGN_CA_2015_PEM),
    ("sign_ca_2023", SIGN_CA_2023_PEM),
];
const AUTH_ROOT_SPECS: [(&str, &[u8]); 2] = [
    ("auth_ca_2015", AUTH_CA_2015_PEM),
    ("auth_ca_2023", AUTH_CA_2023_PEM),
];

pub(crate) struct EmbeddedTrustAnchor {
    pub(crate) name: &'static str,
    pub(crate) cert: Certificate,
}

pub(crate) fn build_sign_store() -> Result<Vec<EmbeddedTrustAnchor>, Error> {
    load_roots(&SIGN_ROOT_SPECS)
}

#[allow(dead_code)]
pub(crate) fn load_auth_roots() -> Result<Vec<EmbeddedTrustAnchor>, Error> {
    load_roots(&AUTH_ROOT_SPECS)
}

pub(crate) fn cert_fingerprint(cert: &Certificate) -> Result<String, Error> {
    let der = cert
        .to_der()
        .map_err(|e| Error::with_source("証明書のDER変換に失敗しました", e))?;
    let digest = Sha256::digest(&der);
    Ok(join_hex(digest.as_ref()))
}

pub(crate) fn describe_cert(cert: &Certificate) -> String {
    let tbs = &cert.tbs_certificate;
    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();
    let serial = format!(
        "{:X}",
        tbs.serial_number
            .as_bytes()
            .iter()
            .fold(0u128, |acc, &b| (acc << 8) | b as u128)
    );
    format!(
        "subject=\"{}\", issuer=\"{}\", serial={}",
        subject, issuer, serial
    )
}

fn load_roots(specs: &[(&'static str, &'static [u8])]) -> Result<Vec<EmbeddedTrustAnchor>, Error> {
    use der::pem::PemLabel;
    specs
        .iter()
        .map(|(name, pem)| {
            let pem_str = std::str::from_utf8(pem)
                .map_err(|e| Error::with_source("PEMのUTF-8デコードに失敗しました", e))?;
            let (label, der) = ::der::pem::decode_vec(pem_str.as_bytes())
                .map_err(|e| Error::with_source("PEMのデコードに失敗しました", e))?;
            if label != Certificate::PEM_LABEL {
                return Err(Error::new("PEMラベルが CERTIFICATE ではありません"));
            }
            let cert = Certificate::from_der(&der)
                .map_err(|e| Error::with_source("証明書のパースに失敗しました", e))?;
            Ok(EmbeddedTrustAnchor { name, cert })
        })
        .collect()
}

fn join_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}
