# Full Transport E2E Test - Sequence Diagrams

## 1. Enrollment Flow Sequence Diagram

```mermaid
sequenceDiagram
    participant MN as Mobile Node
    participant MT as QUIC Transport
    participant CS as CA Server
    participant CN as CA Node
    participant EA as Enrollment Authority

    Note over MN,EA: Phase 4: Mobile Node Enrollment

    MN->>MN: Generate CSR
    MN->>EA: Get Enrollment Token
    EA->>MN: Signed Token

    MN->>MT: QUIC Connection + mTLS
    Note over MT: Establish secure connection

    MN->>MT: Enrollment Request (CSR + Token)
    MT->>CS: Forward Enrollment Request
    CS->>CN: Process Enrollment

    CN->>CN: Validate Token
    CN->>CN: Validate CSR
    CN->>CN: Generate Certificate
    CN->>CS: Certificate Response

    CS->>MT: Certificate Response
    MT->>MN: Certificate Response

    MN->>MN: Install Certificate
    Note over MN: Certificate ready for use
```

## 2. Renewal Flow Sequence Diagram

```mermaid
sequenceDiagram
    participant MN as Mobile Node
    participant MT as QUIC Transport
    participant CS as CA Server
    participant CN as CA Node

    Note over MN,CN: Phase 5: Certificate Renewal

    MN->>MN: Generate Renewal CSR
    MN->>MT: QUIC Connection + mTLS
    Note over MT: Using existing certificate for auth

    MN->>MT: Renewal Request (CSR)
    MT->>CS: Forward Renewal Request
    CS->>CN: Process Renewal

    CN->>CN: Validate Certificate
    CN->>CN: Validate CSR
    CN->>CN: Generate New Certificate
    CN->>CS: Certificate Response

    CS->>MT: Certificate Response
    MT->>MN: Certificate Response

    MN->>MN: Install New Certificate
    Note over MN: Certificate renewed successfully
```

## 3. Revocation Flow Sequence Diagram

```mermaid
sequenceDiagram
    participant MN as Mobile Node
    participant MT as QUIC Transport
    participant CS as CA Server
    participant CN as CA Node

    Note over MN,CN: Phase 6: Certificate Revocation

    MN->>MN: Extract Certificate SKI
    MN->>CS: Add SKI to Admin Config
    CS->>CS: Update Admin SKIs

    MN->>MT: Revocation Request (Serial)
    MT->>CS: Forward Revocation Request
    CS->>CN: Process Revocation

    CN->>CN: Validate Admin Authorization
    CN->>CN: Revoke Certificate
    CN->>CN: Update Revocation List
    CN->>CS: Revocation Response

    CS->>MT: Revocation Response
    MT->>MN: Revocation Response

    Note over CN: Phase 7: CRL-lite Generation
    CN->>CN: Generate CRL-lite
    MN->>MT: Fetch CRL Request
    MT->>CS: CRL Request
    CS->>CN: Get CRL-lite
    CN->>CS: CRL-lite
    CS->>MT: CRL Response
    MT->>MN: CRL Response
```

## 4. Rate Limiting Sequence Diagram

```mermaid
sequenceDiagram
    participant MN as Mobile Node
    participant MT as QUIC Transport
    participant CS as CA Server
    participant CN as CA Node
    participant RL as Rate Limiter

    Note over MN,RL: Phase 10: Rate Limiting Test

    loop Multiple Requests (1-6)
        MN->>MT: Enrollment Request
        MT->>CS: Forward Request
        CS->>RL: Check Rate Limit
        
        alt Rate Limit OK
            RL->>CS: Allow
            CS->>CN: Process Request
            CN->>CS: Success Response
            CS->>MT: Success Response
            MT->>MN: Success Response
        else Rate Limit Exceeded
            RL->>CS: Deny
            CS->>MT: Rate Limit Error
            MT->>MN: Rate Limit Error
        end
    end
```

## 5. Token Revocation Sequence Diagram

```mermaid
sequenceDiagram
    participant MN as Mobile Node
    participant MT as QUIC Transport
    participant CS as CA Server
    participant CN as CA Node
    participant EA as Enrollment Authority

    Note over EA,CN: Phase 11: Token Revocation

    EA->>CN: Revoke Token
    CN->>CN: Mark Token as Revoked

    Note over MN,CN: Attempt to use revoked token

    MN->>MT: Enrollment Request (Revoked Token)
    MT->>CS: Forward Request
    CS->>CN: Process Enrollment

    CN->>CN: Check Token Status
    CN->>CN: Token is Revoked
    CN->>CS: Token Rejected Error
    CS->>MT: Error Response
    MT->>MN: Error Response

    Note over MN: Enrollment fails with revoked token
```

## 6. Error Handling Sequence Diagram

```mermaid
sequenceDiagram
    participant MN as Mobile Node
    participant MT as QUIC Transport
    participant CS as CA Server
    participant CN as CA Node

    Note over MN,CN: Phase 12: Error Handling

    Note over MN: Test 1: Invalid Token
    MN->>MT: Enrollment Request (Invalid Token)
    MT->>CS: Forward Request
    CS->>CN: Process Enrollment
    CN->>CN: Validate Token
    CN->>CN: Token Invalid
    CN->>CS: Token Error
    CS->>MT: Error Response
    MT->>MN: Error Response

    Note over MN: Test 2: Unauthorized Renewal
    MN->>MT: Renewal Request (No Valid Cert)
    MT->>CS: Forward Request
    CS->>CN: Process Renewal
    CN->>CN: Validate Certificate
    CN->>CN: No Valid Certificate
    CN->>CS: Authorization Error
    CS->>MT: Error Response
    MT->>MN: Error Response
```

## 7. Complete End-to-End Flow

```mermaid
sequenceDiagram
    participant MN as Mobile Node
    participant MT as QUIC Transport
    participant CS as CA Server
    participant CN as CA Node
    participant EA as Enrollment Authority
    participant RC as Root CA
    participant IC as Issuing CA

    Note over RC,IC: Phase 1: Infrastructure Setup
    RC->>IC: Create Issuing CA
    IC->>CN: Configure CA Node
    EA->>CN: Configure Enrollment Authority

    Note over CS,MT: Phase 2: QUIC Transport Setup
    CS->>MT: Start QUIC Server
    MT->>CS: Server Ready
    CS->>MN: Server Addresses

    Note over EA,MN: Phase 3: Token Generation
    EA->>EA: Generate Enrollment Token
    EA->>MN: Signed Token

    Note over MN,CN: Phase 4: Enrollment
    MN->>MN: Generate CSR
    MN->>MT: QUIC Connection + mTLS
    MT->>CS: Enrollment Request
    CS->>CN: Process Enrollment
    CN->>IC: Sign Certificate
    IC->>CN: Signed Certificate
    CN->>CS: Certificate Response
    CS->>MT: Certificate Response
    MT->>MN: Certificate Response
    MN->>MN: Install Certificate

    Note over MN,CN: Phase 5: Renewal
    MN->>MN: Generate Renewal CSR
    MN->>MT: QUIC mTLS (with cert)
    MT->>CS: Renewal Request
    CS->>CN: Process Renewal
    CN->>IC: Sign New Certificate
    IC->>CN: Signed Certificate
    CN->>CS: Certificate Response
    CS->>MT: Certificate Response
    MT->>MN: Certificate Response
    MN->>MN: Install New Certificate

    Note over MN,CN: Phase 6: Revocation
    MN->>MN: Extract Certificate SKI
    MN->>CS: Add SKI to Admin Config
    MN->>MT: Revocation Request
    MT->>CS: Revocation Request
    CS->>CN: Process Revocation
    CN->>CN: Revoke Certificate
    CN->>CS: Revocation Response
    CS->>MT: Revocation Response
    MT->>MN: Revocation Response

    Note over MN,CN: Phase 7: CRL-lite
    CN->>CN: Generate CRL-lite
    MN->>MT: Fetch CRL Request
    MT->>CS: CRL Request
    CS->>CN: Get CRL-lite
    CN->>CS: CRL-lite
    CS->>MT: CRL Response
    MT->>MN: CRL Response

    Note over MN,CN: Phase 8: Status & Chain
    MN->>MT: Status Request
    MT->>CS: Status Request
    CS->>CN: Get Status
    CN->>CS: Status Response
    CS->>MT: Status Response
    MT->>MN: Status Response

    Note over MN: Phase 9: Profile Keys
    MN->>MN: Derive Profile Keys
    MN->>MN: Test Encryption/Decryption

    Note over MN,CS: Phase 10: Rate Limiting
    loop Multiple Requests
        MN->>MT: Enrollment Request
        MT->>CS: Enrollment Request
        CS->>CS: Check Rate Limit
        CS->>MT: Response (Allow/Deny)
        MT->>MN: Response
    end

    Note over EA,CN: Phase 11: Token Revocation
    EA->>CN: Revoke Token
    MN->>MT: Enrollment with Revoked Token
    MT->>CS: Enrollment Request
    CS->>CN: Process Enrollment
    CN->>CS: Token Rejected
    CS->>MT: Error Response
    MT->>MN: Error Response

    Note over MN,CS: Phase 12: Error Handling
    MN->>MT: Invalid Request
    MT->>CS: Invalid Request
    CS->>CS: Validate Request
    CS->>MT: Error Response
    MT->>MN: Error Response
```

## 8. Component Architecture Diagram

```mermaid
graph TB
    subgraph "Mobile Device"
        MA[Mobile App<br/>MobileKeyManager]
        MN[Mobile Node<br/>NodeKeyManager]
        DK[Device Keystore<br/>OS Integration]
    end

    subgraph "Network Transport"
        QUIC[QUIC Protocol<br/>mTLS Authentication]
    end

    subgraph "CA Infrastructure"
        CS[CA Server<br/>QUIC Endpoints]
        CN[CA Node<br/>Certificate Operations]
        EA[Enrollment Authority<br/>Token Signing]
    end

    subgraph "Certificate Authority"
        IC[Issuing CA<br/>Intermediate Authority]
        RC[Root CA<br/>Root Authority]
    end

    subgraph "Security Features"
        RL[Rate Limiter<br/>Abuse Prevention]
        CRL[CRL-lite<br/>Revocation List]
        SKI[Admin SKIs<br/>Authorization]
    end

    MA --> MN
    MN --> DK
    MN --> QUIC
    QUIC --> CS
    CS --> CN
    CS --> RL
    CN --> EA
    CN --> IC
    CN --> CRL
    CN --> SKI
    IC --> RC

    classDef mobile fill:#e1f5fe
    classDef transport fill:#f3e5f5
    classDef ca fill:#e8f5e8
    classDef security fill:#fff3e0

    class MA,MN,DK mobile
    class QUIC transport
    class CS,CN,EA,IC,RC ca
    class RL,CRL,SKI security
```

## 9. Data Flow Architecture

```mermaid
graph LR
    subgraph "Input Data"
        CSR[Certificate Signing Request]
        TOKEN[Enrollment Token]
        CERT[Certificate]
        SERIAL[Certificate Serial]
    end

    subgraph "Processing"
        VAL[Validation]
        SIGN[Signing]
        REV[Revocation]
        GEN[Generation]
    end

    subgraph "Output Data"
        CERT_OUT[Certificate]
        CRL_OUT[CRL-lite]
        STATUS[Status Response]
        ERROR[Error Response]
    end

    CSR --> VAL
    TOKEN --> VAL
    VAL --> SIGN
    SIGN --> CERT_OUT

    CERT --> REV
    SERIAL --> REV
    REV --> GEN
    GEN --> CRL_OUT

    VAL --> ERROR
    REV --> ERROR

    classDef input fill:#e3f2fd
    classDef process fill:#f1f8e9
    classDef output fill:#fce4ec

    class CSR,TOKEN,CERT,SERIAL input
    class VAL,SIGN,REV,GEN process
    class CERT_OUT,CRL_OUT,STATUS,ERROR output
```

## 10. Security Model

```mermaid
graph TB
    subgraph "Authentication"
        mTLS[mTLS Authentication]
        CERT_AUTH[Certificate Authentication]
        TOKEN_AUTH[Token Authentication]
    end

    subgraph "Authorization"
        SKI_AUTH[SKI-based Authorization]
        ROLE_AUTH[Role-based Authorization]
        RATE_AUTH[Rate-based Authorization]
    end

    subgraph "Encryption"
        QUIC_ENC[QUIC Encryption]
        CERT_ENC[Certificate Encryption]
        PROFILE_ENC[Profile Key Encryption]
    end

    subgraph "Validation"
        CERT_VAL[Certificate Validation]
        TOKEN_VAL[Token Validation]
        REV_VAL[Revocation Validation]
    end

    mTLS --> SKI_AUTH
    CERT_AUTH --> ROLE_AUTH
    TOKEN_AUTH --> RATE_AUTH

    QUIC_ENC --> CERT_VAL
    CERT_ENC --> TOKEN_VAL
    PROFILE_ENC --> REV_VAL

    classDef auth fill:#e8f5e8
    classDef authz fill:#fff3e0
    classDef enc fill:#e1f5fe
    classDef val fill:#f3e5f5

    class mTLS,CERT_AUTH,TOKEN_AUTH auth
    class SKI_AUTH,ROLE_AUTH,RATE_AUTH authz
    class QUIC_ENC,CERT_ENC,PROFILE_ENC enc
    class CERT_VAL,TOKEN_VAL,REV_VAL val
```
