import XCTest
@testable import RunarKeys

final class CertificateTests: XCTestCase {
    
    func testX509CertificateCreation() throws {
        // Test basic X509Certificate creation with real certificate
        let keyPair = try ECDHKeyPair()
        let ca = try CertificateAuthority(subject: "CN=Test CA, O=Runar, C=US")
        
        let certificate = ca.getCaCertificate()
        XCTAssertFalse(certificate.getDerBytes().isEmpty, "Certificate should have real DER data")
        XCTAssertNotEqual(certificate.getSubject(), "CN=Placeholder")
        XCTAssertNotEqual(certificate.getIssuer(), "CN=Placeholder CA")
    }
    
    func testCertificateAuthorityCreation() throws {
        // Test CertificateAuthority creation
        let ca = try CertificateAuthority(subject: "CN=Test CA, O=Runar, C=US")
        
        XCTAssertNotNil(ca.getCaCertificate())
        XCTAssertNotNil(ca.caPublicKey())
        XCTAssertNotNil(ca.getCaKeyPair())
        
        // Verify the certificate has real data
        let cert = ca.getCaCertificate()
        XCTAssertFalse(cert.getDerBytes().isEmpty)
    }
    
    func testCertificateValidatorCreation() throws {
        // Test CertificateValidator creation
        let ca = try CertificateAuthority(subject: "CN=Test CA, O=Runar, C=US")
        let validator = CertificateValidator(trustedCaCertificates: [ca.getCaCertificate()])
        
        XCTAssertEqual(validator.trustedCaCertificates.count, 1)
    }
    
    func testCertificateRequestCreation() throws {
        // Test CertificateRequest creation
        let keyPair = try ECDHKeyPair()
        let csrData = try CertificateRequest.create(keyPair: keyPair, subject: "CN=Test Subject, O=Runar, C=US")
        
        // Verify it creates real CSR data
        XCTAssertFalse(csrData.isEmpty, "CSR should have real data")
    }
    
    func testCertificateSigning() throws {
        // Test certificate signing workflow
        let ca = try CertificateAuthority(subject: "CN=Test CA, O=Runar, C=US")
        let keyPair = try ECDHKeyPair()
        let csrData = try CertificateRequest.create(keyPair: keyPair, subject: "CN=Test Subject, O=Runar, C=US")
        
        let signedCert = try ca.signCertificateRequest(csrDer: csrData, validityDays: 365)
        
        XCTAssertNotNil(signedCert)
        XCTAssertFalse(signedCert.getDerBytes().isEmpty, "Signed certificate should have real DER data")
    }
} 