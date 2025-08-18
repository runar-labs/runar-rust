#![cfg(all(feature = "openssl-x509", feature = "pure-x509"))]

use runar_keys::certificate::{
    CertificateAuthority, CertificateRequest, EcdsaKeyPair, X509Certificate,
};
use runar_keys::error::Result;
use x509_parser::extensions::{GeneralName as XpGeneralName, ParsedExtension};
use x509_parser::prelude::*;

fn get_subject() -> &'static str {
    "C=US,O=Runar,CN=Runar User CA"
}

fn parse_cert(cert: &X509Certificate) -> X509Certificate<'_> {
    let (_, c) = X509Certificate::from_der(cert.der_bytes()).expect("parse cert");
    c
}

#[test]
fn compare_issuance_parity() -> Result<()> {
    // Prepare CA via OpenSSL path
    let ca_subj = get_subject();
    let ca = CertificateAuthority::new(ca_subj)?;
    let ca_der = ca.ca_certificate().der_bytes().to_vec();

    // Generate CSR (CN set; our issuance policy will include SAN=DNS:CN)
    let node_pair = EcdsaKeyPair::new()?;
    let subject = "CN=testnode.example,O=Runar Node,C=US";
    let csr_der = CertificateRequest::create(&node_pair, subject)?;

    // Fixed serial for parity
    let serial = 4242u64;

    // Issue via OpenSSL CA
    let cert_openssl = ca.sign_certificate_request_with_serial(&csr_der, 365, Some(serial))?;

    // Issue via pure-x509 using the same CA private key and CA DER
    let cert_pure = runar_keys::pure_x509::sign_csr_with_ca(
        ca.ca_key_pair(),
        ca_subj,
        &ca_der,
        &csr_der,
        365,
        Some(serial),
    )?;

    // Basic: both validate under CA public key
    let ca_pub = ca.ca_public_key();
    cert_openssl.validate(ca_pub)?;
    cert_pure.validate(ca_pub)?;

    // Parse both
    let x_op = parse_cert(&cert_openssl);
    let x_pr = parse_cert(&cert_pure);

    // Subject/issuer equality
    assert_eq!(
        x_op.tbs_certificate.subject.to_string(),
        x_pr.tbs_certificate.subject.to_string()
    );
    assert_eq!(
        x_op.tbs_certificate.issuer.to_string(),
        x_pr.tbs_certificate.issuer.to_string()
    );

    // Extensions parity: BasicConstraints, KeyUsage, EKU, SAN, SKI, AKI
    fn find_ext<'a>(c: &'a X509Certificate<'a>, oid: &Oid<'a>) -> &'a ParsedExtension<'a> {
        c.tbs_certificate
            .extensions()
            .expect("ext")
            .iter()
            .find(|e| e.oid == *oid)
            .map(|e| e.parsed_extension())
            .expect("ext present")
    }

    let oid_bc = OID_X509_EXT_BASIC_CONSTRAINTS;
    let oid_ku = OID_X509_EXT_KEY_USAGE;
    let oid_eku = OID_X509_EXT_EXTENDED_KEY_USAGE;
    let oid_san = OID_X509_EXT_SUBJECT_ALT_NAME;
    let oid_ski = OID_X509_EXT_SUBJECT_KEY_IDENTIFIER;
    let oid_aki = OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER;

    // BasicConstraints: CA=false
    match (find_ext(&x_op, &oid_bc), find_ext(&x_pr, &oid_bc)) {
        (ParsedExtension::BasicConstraints(bc1), ParsedExtension::BasicConstraints(bc2)) => {
            assert_eq!(bc1.ca, false);
            assert_eq!(bc2.ca, false);
            assert_eq!(bc1.path_len_constraint, bc2.path_len_constraint);
        }
        _ => panic!("BC missing or mismatched"),
    }

    // KeyUsage: digitalSignature
    match (find_ext(&x_op, &oid_ku), find_ext(&x_pr, &oid_ku)) {
        (ParsedExtension::KeyUsage(ku1), ParsedExtension::KeyUsage(ku2)) => {
            assert_eq!(ku1.digital_signature(), true);
            assert_eq!(ku2.digital_signature(), true);
        }
        _ => panic!("KU missing or mismatched"),
    }

    // EKU: serverAuth + clientAuth
    match (find_ext(&x_op, &oid_eku), find_ext(&x_pr, &oid_eku)) {
        (ParsedExtension::ExtendedKeyUsage(eku1), ParsedExtension::ExtendedKeyUsage(eku2)) => {
            assert_eq!(eku1.any, eku2.any);
            assert_eq!(eku1.oids, eku2.oids);
        }
        _ => panic!("EKU missing or mismatched"),
    }

    // SAN: must contain DNS=testnode.example
    match (find_ext(&x_op, &oid_san), find_ext(&x_pr, &oid_san)) {
        (
            ParsedExtension::SubjectAlternativeName(s1),
            ParsedExtension::SubjectAlternativeName(s2),
        ) => {
            let has_dns = |s: &Vec<XpGeneralName>| {
                s.iter().any(
                    |g| matches!(g, XpGeneralName::DNSName(d) if d.as_str() == "testnode.example"),
                )
            };
            assert!(has_dns(&s1.general_names));
            assert!(has_dns(&s2.general_names));
        }
        _ => panic!("SAN missing or mismatched"),
    }

    // SKI equality
    match (find_ext(&x_op, &oid_ski), find_ext(&x_pr, &oid_ski)) {
        (ParsedExtension::SubjectKeyIdentifier(a), ParsedExtension::SubjectKeyIdentifier(b)) => {
            assert_eq!(a.0, b.0);
        }
        _ => panic!("SKI missing/mismatch"),
    }

    // AKI issuer/serial and keyid equality
    match (find_ext(&x_op, &oid_aki), find_ext(&x_pr, &oid_aki)) {
        (
            ParsedExtension::AuthorityKeyIdentifier(a),
            ParsedExtension::AuthorityKeyIdentifier(b),
        ) => {
            assert_eq!(a.key_identifier, b.key_identifier);
            assert_eq!(a.authority_cert_serial, b.authority_cert_serial);
            let i1 = a
                .authority_cert_issuer
                .as_ref()
                .map(|v| v.iter().map(|g| g.to_string()).collect::<Vec<_>>());
            let i2 = b
                .authority_cert_issuer
                .as_ref()
                .map(|v| v.iter().map(|g| g.to_string()).collect::<Vec<_>>());
            assert_eq!(i1, i2);
        }
        _ => panic!("AKI missing/mismatch"),
    }

    // Serial equality
    assert_eq!(
        x_op.tbs_certificate.raw_serial(),
        x_pr.tbs_certificate.raw_serial()
    );

    // Signature algorithm OID must be ecdsa-with-SHA256 and match
    let sig_oid = x_op.signature_algorithm.algorithm;
    assert_eq!(sig_oid, x_pr.signature_algorithm.algorithm);
    assert_eq!(sig_oid, OID_SIG_ECDSA_WITH_SHA256);

    // SPKI algorithm OID must be id-ecPublicKey and match; and public key bytes must match
    assert_eq!(
        x_op.tbs_certificate.subject_pki.algorithm.algorithm,
        x_pr.tbs_certificate.subject_pki.algorithm.algorithm
    );
    assert_eq!(
        x_op.tbs_certificate.subject_pki.algorithm.algorithm,
        OID_PKCS1_EC_PUBLIC_KEY
    );
    assert_eq!(
        x_op.tbs_certificate.subject_pki.subject_public_key.data,
        x_pr.tbs_certificate.subject_pki.subject_public_key.data
    );

    Ok(())
}
