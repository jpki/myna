use crate::ta::{self, EmbeddedTrustAnchor};
use openssl::error::ErrorStack;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreRef};
use openssl::x509::{X509Ref, X509StoreContext, X509VerifyResult, X509};

pub(crate) fn build_sign_verifier() -> Result<(X509Store, Vec<EmbeddedTrustAnchor>), ErrorStack> {
    ta::build_sign_store()
}

pub(crate) fn log_sign_trust_anchors(roots: &[EmbeddedTrustAnchor]) -> Result<(), ErrorStack> {
    log::info!(
        "Using {} embedded sign trust anchor(s); card CA certificates are not used for verification",
        roots.len()
    );
    for root in roots {
        log::debug!(
            "Trust anchor {}: {}",
            root.name,
            ta::describe_cert(&root.cert)
        );
        log::trace!(
            "Trust anchor {} SHA-256 fingerprint: {}",
            root.name,
            ta::cert_fingerprint(&root.cert)?
        );
    }
    Ok(())
}

pub(crate) fn log_pkcs7_signers(pkcs7: &Pkcs7) -> Result<(), ErrorStack> {
    let external_certs = Stack::new()?;
    let signers = pkcs7.signers(&external_certs, Pkcs7Flags::empty())?;
    log::info!("Found {} signer certificate(s) in PKCS#7", signers.len());
    if let Some(certificates) = pkcs7.signed().and_then(|signed| signed.certificates()) {
        log::debug!("PKCS#7 includes {} certificate(s)", certificates.len());
    }
    for (index, signer) in signers.iter().enumerate() {
        log::info!(
            "Signer certificate {}: {}",
            index + 1,
            ta::describe_cert(signer)
        );
        log::trace!(
            "Signer certificate {} SHA-256 fingerprint: {}",
            index + 1,
            ta::cert_fingerprint(signer)?
        );
    }
    Ok(())
}

pub(crate) fn verify_signer_certificates(
    pkcs7: &Pkcs7,
    store: &X509StoreRef,
    roots: &[EmbeddedTrustAnchor],
) -> Result<(), ErrorStack> {
    let external_certs = Stack::new()?;
    let signers = pkcs7.signers(&external_certs, Pkcs7Flags::empty())?;

    for (index, signer) in signers.iter().enumerate() {
        log::info!(
            "Validating signer certificate {} against embedded trust anchors",
            index + 1
        );
        let untrusted_chain = build_untrusted_chain(pkcs7, signer)?;
        log::debug!(
            "Signer certificate {} untrusted chain length: {}",
            index + 1,
            untrusted_chain.len()
        );

        let mut ctx = X509StoreContext::new()?;
        let mut verify_error = X509VerifyResult::OK;
        let mut error_depth = 0u32;
        let mut failing_cert = None;
        let mut matched_root = None;
        let mut validated_chain = None;

        let verified = ctx.init(store, signer, &untrusted_chain, |context| {
            let verified = context.verify_cert()?;
            verify_error = context.error();
            error_depth = context.error_depth();
            failing_cert = context.current_cert().map(ta::describe_cert);
            if let Some(chain) = context.chain() {
                validated_chain = Some(
                    chain
                        .iter()
                        .map(ta::describe_cert)
                        .collect::<Vec<_>>()
                        .join(" -> "),
                );
                if !chain.is_empty() {
                    matched_root =
                        ta::root_name_for_cert(roots, chain.get(chain.len() - 1).unwrap())?;
                }
            }
            Ok(verified)
        })?;

        if let Some(chain) = &validated_chain {
            log::debug!("Signer certificate {} chain: {}", index + 1, chain);
        }

        if verified {
            if let Some(root_name) = matched_root {
                log::info!("Signer certificate {} verified by {}", index + 1, root_name);
            } else {
                log::info!(
                    "Signer certificate {} verified by an embedded trust anchor",
                    index + 1
                );
            }
        } else {
            log::warn!(
                "Signer certificate {} validation failed at depth {}: {} ({})",
                index + 1,
                error_depth,
                verify_error.error_string(),
                failing_cert.unwrap_or_else(|| ta::describe_cert(signer))
            );
        }
    }

    Ok(())
}

fn build_untrusted_chain(pkcs7: &Pkcs7, signer: &X509Ref) -> Result<Stack<X509>, ErrorStack> {
    let mut chain = Stack::new()?;
    let signer_fingerprint = ta::cert_fingerprint(signer)?;

    if let Some(certificates) = pkcs7.signed().and_then(|signed| signed.certificates()) {
        for cert in certificates {
            if ta::cert_fingerprint(cert)? != signer_fingerprint {
                chain.push(ta::duplicate_cert(cert)?)?;
            }
        }
    }

    Ok(chain)
}
