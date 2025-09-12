# Component Architecture Diagrams

## 1. High-Level System Architecture

```mermaid
graph TB
    subgraph "Mobile Device"
        MA[Mobile App<br/>MobileKeyManager]
        MN[Mobile Node<br/>NodeKeyManager]
        DK[Device Keystore<br/>OS Integration]
    end

    subgraph "Network Layer"
        QUIC[QUIC Protocol<br/>mTLS Authentication]
        TLS[TLS 1.3<br/>Encryption]
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

    subgraph "Security & Control"
        RL[Rate Limiter<br/>Abuse Prevention]
        CRL[CRL-lite<br/>Revocation List]
        SKI[Admin SKIs<br/>Authorization]
        VAL[Validation Engine<br/>Certificate & Token]
    end

    MA --> MN
    MN --> DK
    MN --> QUIC
    QUIC --> TLS
    TLS --> CS
    CS --> CN
    CS --> RL
    CN --> EA
    CN --> IC
    CN --> CRL
    CN --> SKI
    CN --> VAL
    IC --> RC

    classDef mobile fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef network fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef ca fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef security fill:#fff3e0,stroke:#e65100,stroke-width:2px

    class MA,MN,DK mobile
    class QUIC,TLS network
    class CS,CN,EA,IC,RC ca
    class RL,CRL,SKI,VAL security
```

## 2. Detailed CA Node Architecture

```mermaid
graph TB
    subgraph "CA Node Core"
        CN[CA Node<br/>Main Controller]
        CM[Certificate Manager<br/>Issuance & Validation]
        RM[Revocation Manager<br/>CRL Generation]
        TM[Token Manager<br/>Enrollment Tokens]
    end

    subgraph "Certificate Operations"
        CSR[CSR Processing<br/>Request Validation]
        SIGN[Certificate Signing<br/>X.509 Generation]
        VAL[Certificate Validation<br/>Chain Verification]
        REV[Certificate Revocation<br/>Status Management]
    end

    subgraph "Security Controls"
        AUTH[Authentication<br/>SKI-based Auth]
        RATE[Rate Limiting<br/>Request Throttling]
        ANTI[Anti-Replay<br/>Token Replay Protection]
        AUDIT[Audit Logging<br/>Operation Tracking]
    end

    subgraph "External Interfaces"
        API[CA API<br/>REST/QUIC Endpoints]
        STORE[Certificate Store<br/>Persistent Storage]
        CACHE[Revocation Cache<br/>CRL-lite Storage]
    end

    CN --> CM
    CN --> RM
    CN --> TM

    CM --> CSR
    CM --> SIGN
    CM --> VAL
    RM --> REV

    CN --> AUTH
    CN --> RATE
    CN --> ANTI
    CN --> AUDIT

    CN --> API
    CN --> STORE
    CN --> CACHE

    classDef core fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef ops fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef security fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef interface fill:#f3e5f5,stroke:#4a148c,stroke-width:2px

    class CN,CM,RM,TM core
    class CSR,SIGN,VAL,REV ops
    class AUTH,RATE,ANTI,AUDIT security
    class API,STORE,CACHE interface
```

## 3. QUIC Transport Architecture

```mermaid
graph TB
    subgraph "QUIC Server"
        QS[QUIC Server<br/>Main Server]
        BS[Bootstrap Endpoint<br/>Initial Enrollment]
        AS[Authenticated Endpoint<br/>Renewal/Revocation]
    end

    subgraph "Connection Management"
        CM[Connection Manager<br/>Session Handling]
        PM[Protocol Manager<br/>QUIC Protocol]
        SM[Security Manager<br/>mTLS Integration]
    end

    subgraph "Request Processing"
        RP[Request Processor<br/>Message Routing]
        VAL[Request Validator<br/>Input Validation]
        AUTH[Request Authenticator<br/>Client Auth]
    end

    subgraph "Response Generation"
        RG[Response Generator<br/>Message Creation]
        SER[Serializer<br/>CBOR Encoding]
        COMP[Compressor<br/>Data Compression]
    end

    QS --> BS
    QS --> AS
    QS --> CM
    CM --> PM
    CM --> SM
    QS --> RP
    RP --> VAL
    RP --> AUTH
    QS --> RG
    RG --> SER
    RG --> COMP

    classDef server fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef connection fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef processing fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef response fill:#f3e5f5,stroke:#4a148c,stroke-width:2px

    class QS,BS,AS server
    class CM,PM,SM connection
    class RP,VAL,AUTH processing
    class RG,SER,COMP response
```

## 4. Mobile Node Architecture

```mermaid
graph TB
    subgraph "Mobile Application"
        MA[Mobile App<br/>User Interface]
        MK[Mobile Key Manager<br/>User Root Key]
        PK[Profile Keys<br/>User Profiles]
    end

    subgraph "Node Operations"
        MN[Node Key Manager<br/>Node Identity]
        CSR[CSR Generation<br/>Certificate Requests]
        CERT[Certificate Management<br/>Installation & Validation]
        QUIC[QUIC Client<br/>Network Communication]
    end

    subgraph "Key Storage"
        DK[Device Keystore<br/>OS Integration]
        ENC[Encryption<br/>Data Protection]
        PER[Persistence<br/>State Management]
    end

    subgraph "Security Features"
        AUTH[Authentication<br/>Certificate Auth]
        ENV[Envelope Encryption<br/>Data Encryption]
        ISO[Key Isolation<br/>Profile Separation]
    end

    MA --> MK
    MA --> PK
    MA --> MN
    MK --> PK
    MN --> CSR
    MN --> CERT
    MN --> QUIC
    MN --> DK
    DK --> ENC
    DK --> PER
    MN --> AUTH
    MN --> ENV
    MN --> ISO

    classDef app fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef node fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef storage fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef security fill:#fff3e0,stroke:#e65100,stroke-width:2px

    class MA,MK,PK app
    class MN,CSR,CERT,QUIC node
    class DK,ENC,PER storage
    class AUTH,ENV,ISO security
```

## 5. Data Flow Architecture

```mermaid
graph LR
    subgraph "Input Sources"
        CSR[CSR Requests]
        TOKEN[Enrollment Tokens]
        CERT[Certificates]
        REV[Revocation Requests]
    end

    subgraph "Processing Pipeline"
        VAL[Validation Layer]
        AUTH[Authentication Layer]
        PROC[Processing Layer]
        SIGN[Signing Layer]
    end

    subgraph "Output Generation"
        CERT_OUT[Certificate Output]
        CRL_OUT[CRL-lite Output]
        STATUS[Status Responses]
        ERROR[Error Responses]
    end

    subgraph "Storage & Cache"
        STORE[Certificate Store]
        CACHE[Revocation Cache]
        LOG[Audit Logs]
    end

    CSR --> VAL
    TOKEN --> AUTH
    CERT --> PROC
    REV --> PROC

    VAL --> PROC
    AUTH --> PROC
    PROC --> SIGN

    SIGN --> CERT_OUT
    PROC --> CRL_OUT
    PROC --> STATUS
    VAL --> ERROR
    AUTH --> ERROR

    CERT_OUT --> STORE
    CRL_OUT --> CACHE
    PROC --> LOG

    classDef input fill:#e3f2fd,stroke:#01579b,stroke-width:2px
    classDef process fill:#f1f8e9,stroke:#1b5e20,stroke-width:2px
    classDef output fill:#fce4ec,stroke:#c2185b,stroke-width:2px
    classDef storage fill:#fff8e1,stroke:#f57c00,stroke-width:2px

    class CSR,TOKEN,CERT,REV input
    class VAL,AUTH,PROC,SIGN process
    class CERT_OUT,CRL_OUT,STATUS,ERROR output
    class STORE,CACHE,LOG storage
```

## 6. Security Model Architecture

```mermaid
graph TB
    subgraph "Authentication Layers"
        mTLS[mTLS Authentication<br/>Transport Security]
        CERT_AUTH[Certificate Authentication<br/>Identity Verification]
        TOKEN_AUTH[Token Authentication<br/>Enrollment Authorization]
    end

    subgraph "Authorization Controls"
        SKI_AUTH[SKI-based Authorization<br/>Admin Operations]
        ROLE_AUTH[Role-based Authorization<br/>Operation Permissions]
        RATE_AUTH[Rate-based Authorization<br/>Usage Limits]
    end

    subgraph "Encryption & Protection"
        QUIC_ENC[QUIC Encryption<br/>Transport Security]
        CERT_ENC[Certificate Encryption<br/>Data Protection]
        PROFILE_ENC[Profile Key Encryption<br/>User Data]
    end

    subgraph "Validation & Verification"
        CERT_VAL[Certificate Validation<br/>Chain Verification]
        TOKEN_VAL[Token Validation<br/>Signature Verification]
        REV_VAL[Revocation Validation<br/>Status Checking]
    end

    subgraph "Audit & Monitoring"
        AUDIT[Audit Logging<br/>Operation Tracking]
        MONITOR[Security Monitoring<br/>Threat Detection]
        ALERT[Alert System<br/>Security Notifications]
    end

    mTLS --> SKI_AUTH
    CERT_AUTH --> ROLE_AUTH
    TOKEN_AUTH --> RATE_AUTH

    QUIC_ENC --> CERT_VAL
    CERT_ENC --> TOKEN_VAL
    PROFILE_ENC --> REV_VAL

    CERT_VAL --> AUDIT
    TOKEN_VAL --> MONITOR
    REV_VAL --> ALERT

    classDef auth fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef authz fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef enc fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef val fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef audit fill:#fce4ec,stroke:#c2185b,stroke-width:2px

    class mTLS,CERT_AUTH,TOKEN_AUTH auth
    class SKI_AUTH,ROLE_AUTH,RATE_AUTH authz
    class QUIC_ENC,CERT_ENC,PROFILE_ENC enc
    class CERT_VAL,TOKEN_VAL,REV_VAL val
    class AUDIT,MONITOR,ALERT audit
```

## 7. Network Topology

```mermaid
graph TB
    subgraph "Mobile Device Network"
        MD1[Mobile Device 1]
        MD2[Mobile Device 2]
        MD3[Mobile Device N]
    end

    subgraph "Internet/Network"
        QUIC[QUIC Connections<br/>mTLS Secured]
    end

    subgraph "CA Infrastructure"
        LB[Load Balancer<br/>Traffic Distribution]
        CS1[CA Server 1<br/>Bootstrap + Auth]
        CS2[CA Server 2<br/>Bootstrap + Auth]
        CS3[CA Server N<br/>Bootstrap + Auth]
    end

    subgraph "CA Backend"
        CN[CA Node<br/>Certificate Operations]
        DB[Database<br/>Certificate Store]
        CACHE[Redis Cache<br/>Revocation Cache]
    end

    MD1 --> QUIC
    MD2 --> QUIC
    MD3 --> QUIC

    QUIC --> LB
    LB --> CS1
    LB --> CS2
    LB --> CS3

    CS1 --> CN
    CS2 --> CN
    CS3 --> CN

    CN --> DB
    CN --> CACHE

    classDef mobile fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef network fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef server fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef backend fill:#fff3e0,stroke:#e65100,stroke-width:2px

    class MD1,MD2,MD3 mobile
    class QUIC,LB network
    class CS1,CS2,CS3 server
    class CN,DB,CACHE backend
```

## 8. Certificate Lifecycle

```mermaid
stateDiagram-v2
    [*] --> CSR_Generation: Mobile Node
    CSR_Generation --> Enrollment: Send CSR + Token
    Enrollment --> Certificate_Issued: CA Signs Certificate
    Certificate_Issued --> Certificate_Active: Install Certificate
    Certificate_Active --> Certificate_Renewal: Before Expiry
    Certificate_Renewal --> Certificate_Issued: New Certificate
    Certificate_Active --> Certificate_Revoked: Revocation Request
    Certificate_Revoked --> CRL_Updated: Update CRL-lite
    Certificate_Active --> Certificate_Expired: Natural Expiry
    Certificate_Expired --> [*]
    Certificate_Revoked --> [*]
    CRL_Updated --> [*]

    note right of CSR_Generation: Generate Certificate Signing Request
    note right of Enrollment: QUIC mTLS enrollment
    note right of Certificate_Issued: X.509 certificate created
    note right of Certificate_Active: Certificate in use
    note right of Certificate_Renewal: Renewal via QUIC mTLS
    note right of Certificate_Revoked: Revoked by admin
    note right of CRL_Updated: CRL-lite updated
    note right of Certificate_Expired: Natural expiration
```

## 9. Security Threat Model

```mermaid
graph TB
    subgraph "External Threats"
        MITM[Man-in-the-Middle<br/>Network Attacks]
        REPLAY[Replay Attacks<br/>Token Reuse]
        BRUTE[Brute Force<br/>Credential Attacks]
        DOS[Denial of Service<br/>Resource Exhaustion]
    end

    subgraph "Internal Threats"
        INSIDER[Insider Threats<br/>Privileged Access]
        LEAK[Data Leakage<br/>Information Disclosure]
        CORRUPT[Data Corruption<br/>Integrity Violations]
    end

    subgraph "Security Controls"
        mTLS[mTLS Protection<br/>Transport Security]
        RATE[Rate Limiting<br/>DoS Prevention]
        ANTI[Anti-Replay<br/>Token Protection]
        AUDIT[Audit Logging<br/>Threat Detection]
    end

    subgraph "Mitigation Strategies"
        DETECT[Threat Detection<br/>Anomaly Detection]
        RESPOND[Incident Response<br/>Automated Response]
        RECOVER[Recovery Procedures<br/>Service Restoration]
    end

    MITM --> mTLS
    REPLAY --> ANTI
    BRUTE --> RATE
    DOS --> RATE

    INSIDER --> AUDIT
    LEAK --> AUDIT
    CORRUPT --> AUDIT

    mTLS --> DETECT
    RATE --> DETECT
    ANTI --> DETECT
    AUDIT --> DETECT

    DETECT --> RESPOND
    RESPOND --> RECOVER

    classDef threat fill:#ffebee,stroke:#c62828,stroke-width:2px
    classDef control fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef mitigation fill:#e3f2fd,stroke:#01579b,stroke-width:2px

    class MITM,REPLAY,BRUTE,DOS,INSIDER,LEAK,CORRUPT threat
    class mTLS,RATE,ANTI,AUDIT control
    class DETECT,RESPOND,RECOVER mitigation
```

## 10. Performance Architecture

```mermaid
graph TB
    subgraph "Performance Monitoring"
        METRICS[Performance Metrics<br/>Response Times]
        THROUGHPUT[Throughput Monitoring<br/>Requests/Second]
        LATENCY[Latency Tracking<br/>End-to-End Delays]
    end

    subgraph "Optimization Strategies"
        CACHE[Response Caching<br/>Frequent Queries]
        POOL[Connection Pooling<br/>Resource Reuse]
        COMP[Compression<br/>Data Reduction]
    end

    subgraph "Scalability Features"
        LB[Load Balancing<br/>Traffic Distribution]
        SCALE[Horizontal Scaling<br/>Server Replication]
        PART[Data Partitioning<br/>Distributed Storage]
    end

    subgraph "Resource Management"
        CPU[CPU Optimization<br/>Processing Efficiency]
        MEM[Memory Management<br/>Resource Allocation]
        NET[Network Optimization<br/>Bandwidth Usage]
    end

    METRICS --> CACHE
    THROUGHPUT --> POOL
    LATENCY --> COMP

    CACHE --> LB
    POOL --> SCALE
    COMP --> PART

    LB --> CPU
    SCALE --> MEM
    PART --> NET

    classDef monitor fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef optimize fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef scale fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef resource fill:#f3e5f5,stroke:#4a148c,stroke-width:2px

    class METRICS,THROUGHPUT,LATENCY monitor
    class CACHE,POOL,COMP optimize
    class LB,SCALE,PART scale
    class CPU,MEM,NET resource
```
