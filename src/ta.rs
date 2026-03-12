use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509NameRef, X509Ref, X509};

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
    pub(crate) cert: X509,
}

pub(crate) fn build_sign_store() -> Result<(X509Store, Vec<EmbeddedTrustAnchor>), ErrorStack> {
    let roots = load_roots(&SIGN_ROOT_SPECS)?;
    let mut builder = X509StoreBuilder::new()?;
    for root in &roots {
        builder.add_cert(duplicate_cert(&root.cert)?)?;
    }
    Ok((builder.build(), roots))
}

#[allow(dead_code)]
pub(crate) fn load_auth_roots() -> Result<Vec<EmbeddedTrustAnchor>, ErrorStack> {
    load_roots(&AUTH_ROOT_SPECS)
}

pub(crate) fn cert_fingerprint(cert: &X509Ref) -> Result<String, ErrorStack> {
    let digest = cert.digest(MessageDigest::sha256())?;
    Ok(join_hex(digest.as_ref()))
}

pub(crate) fn describe_cert(cert: &X509Ref) -> String {
    let subject = format_x509_name(cert.subject_name());
    let issuer = format_x509_name(cert.issuer_name());
    let serial = cert
        .serial_number()
        .to_bn()
        .and_then(|bn| bn.to_hex_str())
        .map(|serial| serial.to_string())
        .unwrap_or_else(|_| "<unavailable>".to_string());
    format!(
        "subject=\"{}\", issuer=\"{}\", serial={}",
        subject, issuer, serial
    )
}

pub(crate) fn root_name_for_cert(
    roots: &[EmbeddedTrustAnchor],
    cert: &X509Ref,
) -> Result<Option<&'static str>, ErrorStack> {
    let fingerprint = cert_fingerprint(cert)?;
    for root in roots {
        if cert_fingerprint(&root.cert)? == fingerprint {
            return Ok(Some(root.name));
        }
    }
    Ok(None)
}

pub(crate) fn duplicate_cert(cert: &X509Ref) -> Result<X509, ErrorStack> {
    X509::from_der(&cert.to_der()?)
}

fn load_roots(
    specs: &[(&'static str, &'static [u8])],
) -> Result<Vec<EmbeddedTrustAnchor>, ErrorStack> {
    specs
        .iter()
        .map(|(name, pem)| {
            let cert = X509::from_pem(pem)?;
            Ok(EmbeddedTrustAnchor { name, cert })
        })
        .collect()
}

fn format_x509_name(name: &X509NameRef) -> String {
    let parts: Vec<String> = name
        .entries()
        .map(|entry| {
            let key = entry.object().nid().short_name().unwrap_or("UNKNOWN");
            let value = entry
                .data()
                .as_utf8()
                .map(|value| value.to_string())
                .unwrap_or_else(|_| hex::encode(entry.data().as_slice()));
            format!("{key}={value}")
        })
        .collect();

    if parts.is_empty() {
        "<empty>".to_string()
    } else {
        parts.join(", ")
    }
}

fn join_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}
