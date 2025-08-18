#![cfg(feature = "pure-x509")]

use crate::certificate::{EcdsaKeyPair, X509Certificate};
use crate::error::{KeyError, Result};
use der::asn1::{BitString, Ia5String, OctetString, UtcTime};
use der::{Any, DateTime, Decode, Encode};
use sha1::{Digest, Sha1};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use std::str::FromStr;
use std::time::SystemTime;
use x509_cert::ext::pkix::{
    name::GeneralName, AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
    SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};

const OID_ID_EC_PUBLIC_KEY: spki::ObjectIdentifier =
    spki::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP256R1: spki::ObjectIdentifier =
    spki::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_ECDSA_SHA256: spki::ObjectIdentifier =
    spki::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

fn spki_from_verifying_key(key: &p256::ecdsa::VerifyingKey) -> Result<SubjectPublicKeyInfoOwned> {
    let algorithm = AlgorithmIdentifier::<Any> {
        oid: OID_ID_EC_PUBLIC_KEY,
        parameters: Some(Any::from(&OID_SECP256R1)),
    };
    let subject_public_key = BitString::from_bytes(key.to_encoded_point(false).as_bytes()).unwrap();
    Ok(SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key,
    })
}

fn compute_ski(spki: &SubjectPublicKeyInfoOwned) -> SubjectKeyIdentifier {
    let mut hasher = Sha1::new();
    hasher.update(spki.subject_public_key.as_bytes().unwrap_or(&[]));
    let digest = hasher.finalize();
    SubjectKeyIdentifier(OctetString::new(digest.to_vec()).unwrap())
}

fn serial_from_u64(value: u64) -> Result<SerialNumber> {
    let bytes = value.to_be_bytes();
    let serial_bytes = if bytes[0] & 0x80 != 0 {
        let mut v = Vec::with_capacity(9);
        v.push(0);
        v.extend_from_slice(&bytes);
        v
    } else {
        bytes.to_vec()
    };
    SerialNumber::new(&serial_bytes)
        .map_err(|e| KeyError::CertificateError(format!("Invalid serial: {e}")))
}

fn now_time() -> Time {
    let unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let dt = DateTime::from_unix_duration(unix).unwrap();
    Time::UtcTime(UtcTime::from_date_time(dt).unwrap())
}

fn days_from_now(days: u32) -> Time {
    let unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        + std::time::Duration::from_secs(days as u64 * 24 * 3600);
    let dt = DateTime::from_unix_duration(unix).unwrap();
    Time::UtcTime(UtcTime::from_date_time(dt).unwrap())
}

fn sign_tbs_with_p256(
    signing_key: &p256::ecdsa::SigningKey,
    tbs: &[u8],
) -> (AlgorithmIdentifier<der::Any>, Vec<u8>) {
    use p256::ecdsa::{signature::Signer, Signature};
    let sig: Signature = signing_key.sign(tbs);
    let der = sig.to_der();
    (
        AlgorithmIdentifier::<der::Any> {
            oid: OID_ECDSA_SHA256,
            parameters: None,
        },
        der.as_bytes().to_vec(),
    )
}

pub fn create_self_signed_ca(
    key_pair: &EcdsaKeyPair,
    subject_str: &str,
) -> Result<X509Certificate> {
    let subject = Name::from_str(subject_str)
        .map_err(|e| KeyError::CertificateError(format!("Failed to build CA subject: {e}")))?;

    let spki = spki_from_verifying_key(key_pair.verifying_key())?;
    let ski = compute_ski(&spki);

    use const_oid::ObjectIdentifier;
    const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
    const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
    const OID_SKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
    const OID_AKI: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

    let bc = BasicConstraints {
        ca: true,
        path_len_constraint: Some(0),
    };
    let ext_basic = Extension {
        extn_id: OID_BASIC_CONSTRAINTS,
        critical: true,
        extn_value: OctetString::new(bc.to_der().unwrap()).unwrap(),
    };

    let ku = KeyUsage(
        (x509_cert::ext::pkix::KeyUsages::KeyCertSign | x509_cert::ext::pkix::KeyUsages::CRLSign)
            .into(),
    );
    let ext_ku = Extension {
        extn_id: OID_KEY_USAGE,
        critical: true,
        extn_value: OctetString::new(ku.to_der().unwrap()).unwrap(),
    };

    let ext_ski = Extension {
        extn_id: OID_SKI,
        critical: false,
        extn_value: OctetString::new(ski.to_der().unwrap()).unwrap(),
    };
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(ski.0.clone()),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };
    let ext_aki = Extension {
        extn_id: OID_AKI,
        critical: false,
        extn_value: OctetString::new(aki.to_der().unwrap()).unwrap(),
    };

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[1]).unwrap(),
        signature: AlgorithmIdentifier {
            oid: OID_ECDSA_SHA256,
            parameters: None,
        },
        issuer: subject.clone(),
        validity: Validity {
            not_before: now_time(),
            not_after: days_from_now(3650),
        },
        subject: subject.clone(),
        subject_public_key_info: spki.clone(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![ext_basic, ext_ku, ext_ski, ext_aki]),
    };

    let tbs_der = tbs
        .to_der()
        .map_err(|e| KeyError::CertificateError(format!("Failed to encode TBS: {e}")))?;
    let (alg, sig) = sign_tbs_with_p256(key_pair.signing_key(), &tbs_der);

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: alg,
        signature: BitString::from_bytes(&sig).unwrap(),
    };

    let cert_der = cert
        .to_der()
        .map_err(|e| KeyError::CertificateError(format!("Failed to encode certificate: {e}")))?;
    X509Certificate::from_der(cert_der)
}

pub fn sign_csr_with_ca(
    ca_key_pair: &EcdsaKeyPair,
    ca_subject_str: &str,
    ca_der: &[u8],
    csr_der: &[u8],
    validity_days: u32,
    serial_override: Option<u64>,
) -> Result<X509Certificate> {
    let csr = x509_cert::request::CertReq::from_der(csr_der)
        .map_err(|e| KeyError::CertificateError(format!("Failed to parse CSR DER: {e}")))?;
    // Manual verify
    {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let info_der = csr
            .info
            .to_der()
            .map_err(|e| KeyError::CertificateError(format!("Failed to encode CSR info: {e}")))?;
        let sig = Signature::from_der(csr.signature.as_bytes().unwrap_or(&[]))
            .map_err(|e| KeyError::CertificateError(format!("Invalid CSR signature DER: {e}")))?;
        let pubkey_bytes = csr
            .info
            .public_key
            .subject_public_key
            .as_bytes()
            .unwrap_or(&[]);
        let vk = VerifyingKey::from_sec1_bytes(pubkey_bytes)
            .map_err(|e| KeyError::CertificateError(format!("Invalid CSR public key: {e}")))?;
        vk.verify(&info_der, &sig).map_err(|e| {
            KeyError::CertificateError(format!("CSR signature verification failed: {e}"))
        })?;
    }

    let subject =
        Name::from_der(&csr.info.subject.to_der().map_err(|e| {
            KeyError::CertificateError(format!("Failed to encode CSR subject: {e}"))
        })?)
        .map_err(|e| KeyError::CertificateError(format!("Failed to import CSR subject: {e}")))?;

    // Extract SPKI DER once to avoid temporary lifetime issues
    let spki_der = csr
        .info
        .public_key
        .to_der()
        .map_err(|e| KeyError::CertificateError(format!("Failed to encode CSR SPKI: {e}")))?;
    let spki_ref = SubjectPublicKeyInfoRef::from_der(&spki_der)
        .map_err(|e| KeyError::CertificateError(format!("Failed to import CSR SPKI: {e}")))?;
    // Convert to owned by rebuilding from SEC1 bytes
    let pubkey_bytes = spki_ref.subject_public_key.as_bytes().unwrap_or(&[]);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey_bytes)
        .map_err(|e| KeyError::InvalidKeyFormat(format!("Invalid CSR public key: {e}")))?;
    let spki = spki_from_verifying_key(&vk)?;

    let leaf_ski = compute_ski(&spki);
    let issuer = Name::from_str(ca_subject_str)
        .map_err(|e| KeyError::CertificateError(format!("Failed to build issuer subject: {e}")))?;

    let serial = match serial_override {
        Some(s) => serial_from_u64(s)?,
        None => SerialNumber::new(&[2]).unwrap(),
    };

    const OID_BASIC_CONSTRAINTS: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("2.5.29.19");
    const OID_KEY_USAGE: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("2.5.29.15");
    const OID_EKU: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("2.5.29.37");
    const OID_SKI: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("2.5.29.14");
    const OID_AKI: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("2.5.29.35");
    const OID_SAN: const_oid::ObjectIdentifier =
        const_oid::ObjectIdentifier::new_unwrap("2.5.29.17");

    let bc = BasicConstraints {
        ca: false,
        path_len_constraint: None,
    };
    let ext_basic = Extension {
        extn_id: OID_BASIC_CONSTRAINTS,
        critical: true,
        extn_value: OctetString::new(bc.to_der().unwrap()).unwrap(),
    };
    let ku = KeyUsage(x509_cert::ext::pkix::KeyUsages::DigitalSignature.into());
    let ext_ku = Extension {
        extn_id: OID_KEY_USAGE,
        critical: true,
        extn_value: OctetString::new(ku.to_der().unwrap()).unwrap(),
    };
    let eku = ExtendedKeyUsage(vec![
        const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1"),
        const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2"),
    ]);
    let ext_eku = Extension {
        extn_id: OID_EKU,
        critical: false,
        extn_value: OctetString::new(eku.to_der().unwrap()).unwrap(),
    };

    let mut extensions = vec![ext_basic, ext_ku, ext_eku];
    // Strict: require SAN in CSR and copy raw DER into cert
    {
        use x509_parser::certification_request::X509CertificationRequest as XpCsr;
        use x509_parser::prelude::FromDer;
        let (_, xp) = XpCsr::from_der(csr_der).map_err(|e| {
            KeyError::CertificateError(format!("Failed to parse CSR (x509-parser): {e}"))
        })?;
        let mut san_added = false;
        if let Some(exts) = xp.requested_extensions() {
            for ext in exts {
                if ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME {
                    // Reconstruct SAN extension DER from parsed content
                    if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                        ext.parsed_extension()
                    {
                        // Encode SAN as DER from names
                        let mut dns_list: Vec<String> = Vec::new();
                        let mut ip_list: Vec<Vec<u8>> = Vec::new();
                        for g in &san.general_names {
                            match g {
                                x509_parser::extensions::GeneralName::DNSName(dns) => {
                                    dns_list.push(dns.to_string())
                                }
                                x509_parser::extensions::GeneralName::IPAddress(ip) => {
                                    ip_list.push(ip.to_vec())
                                }
                                _ => {
                                    return Err(KeyError::CertificateError(
                                        "Unsupported SAN type in CSR".to_string(),
                                    ))
                                }
                            }
                        }
                        // Build SAN ext using x509-cert types
                        let mut names = Vec::<GeneralName>::new();
                        for d in dns_list {
                            names.push(GeneralName::DnsName(Ia5String::new(&d).unwrap()));
                        }
                        for ip in ip_list {
                            names.push(GeneralName::IpAddress(OctetString::new(ip).unwrap()));
                        }
                        let san_enc = SubjectAltName(names);
                        let ext_san = Extension {
                            extn_id: const_oid::ObjectIdentifier::new_unwrap("2.5.29.17"),
                            critical: ext.critical,
                            extn_value: OctetString::new(san_enc.to_der().unwrap()).unwrap(),
                        };
                        extensions.push(ext_san);
                        san_added = true;
                        break;
                    }
                }
            }
        }
        if !san_added {
            return Err(KeyError::CertificateError(
                "CSR missing SAN extension".to_string(),
            ));
        }
    }

    let ext_ski = Extension {
        extn_id: OID_SKI,
        critical: false,
        extn_value: OctetString::new(leaf_ski.to_der().unwrap()).unwrap(),
    };
    extensions.push(ext_ski);

    let ca_ski = compute_ski(&spki_from_verifying_key(ca_key_pair.verifying_key())?);
    let ca_cert = x509_cert::Certificate::from_der(ca_der)
        .map_err(|e| KeyError::CertificateError(format!("Failed to parse CA DER for AKI: {e}")))?;
    let ext_aki = Extension {
        extn_id: OID_AKI,
        critical: false,
        extn_value: OctetString::new(
            AuthorityKeyIdentifier {
                key_identifier: Some(ca_ski.0.clone()),
                authority_cert_issuer: Some(vec![GeneralName::DirectoryName(
                    ca_cert.tbs_certificate.issuer.clone(),
                )]),
                authority_cert_serial_number: Some(ca_cert.tbs_certificate.serial_number.clone()),
            }
            .to_der()
            .unwrap(),
        )
        .unwrap(),
    };
    extensions.push(ext_aki);

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: serial,
        signature: AlgorithmIdentifier::<der::Any> {
            oid: OID_ECDSA_SHA256,
            parameters: None,
        },
        issuer,
        validity: Validity {
            not_before: now_time(),
            not_after: days_from_now(validity_days),
        },
        subject,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    let tbs_der = tbs
        .to_der()
        .map_err(|e| KeyError::CertificateError(format!("Failed to encode TBS: {e}")))?;
    let (alg, sig) = sign_tbs_with_p256(ca_key_pair.signing_key(), &tbs_der);

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: alg,
        signature: BitString::from_bytes(&sig).unwrap(),
    };
    let cert_der = cert
        .to_der()
        .map_err(|e| KeyError::CertificateError(format!("Failed to encode certificate: {e}")))?;

    X509Certificate::from_der(cert_der)
}
