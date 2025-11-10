# Runar Framework End-to-End Test Specification

## Overview

This document specifies a comprehensive end-to-end test that demonstrates the complete Runar framework lifecycle, combining all major components:

1. **Mobile Key Management** (`runar-keys/tests/end_to_end_test.rs`)
2. **CA Node Infrastructure** (`runar-transporter/tests/full_transport_e2e_test.rs`) 
3. **P2P Node Communication** (`runar-node-tests/src/network/remote_test.rs`)

The test will showcase the entire framework working together: from mobile key store initialization, through CA node setup, to secure P2P communication between nodes.

## Key Architecture Distinctions

### Two Distinct Mobile App Roles

#### 1. Network Admin Mobile App
- **Purpose**: One-time network setup and administration
- **Role**: Creates the Certificate Authority (CA) and configures ALL network nodes
- **Usage**: Used by network administrators to:
  - Generate the Root CA for the network
  - Create enrollment tokens for nodes and mobile apps
  - **Set up ALL network nodes** (including the CA Node)
  - Configure the CA Node to also run CA services on additional ports
  - Manage network policies and security settings
- **Communication**: Connects to nodes for initial setup and configuration

#### 2. Regular Mobile Apps
- **Purpose**: Run end-user applications that participate in the P2P network
- **Role**: Connect directly to network nodes to run applications
- **Usage**: Used by end users to:
  - Obtain certificates from CA Node (one-time enrollment)
  - Connect directly to network nodes for application data
  - Communicate with other mobile apps through network nodes
  - Run distributed applications and services
- **Key Management**: 
  - **Use NodeKeyManager** (enhanced with mobile functionality) for P2P communication
  - **MobileKeyManager is NOT used** for P2P - only for CA operations
- **Communication**: 
  - **CA Node**: Only for certificate management (enrollment, renewal, CRL)
  - **Network Nodes**: Direct P2P connection for all application data

### Communication Flow Clarification

```
Network Admin Mobile App
         ↓ (One-time setup of ALL nodes)
    ┌─────────────────────────────────────────┐
    │         ALL NETWORK NODES               │
    │                                         │
    │  CA Node (Node 1)                       │
    │  ├─ P2P Network Node (port X)           │
    │  └─ CA Services (port Y)                │
    │                                         │
    │  Regular Node (Node 2)                  │
    │  └─ P2P Network Node (port Z)           │
    │                                         │
    │  Regular Node (Node 3)                  │
    │  └─ P2P Network Node (port W)           │
    │                                         │
    │  Regular Node (Node 4)                  │
    │  └─ P2P Network Node (port V)           │
    └─────────────────────────────────────────┘
         ↑
    (Certificate enrollment only)
Regular Mobile Apps ←→ ALL Network Nodes
         ↑
    (Direct P2P for application data)
```

**Important**: 
- **Network Admin Mobile App** sets up ALL network nodes initially
- **CA Node** is a regular P2P network node that ALSO runs CA services on additional ports
- **Regular Mobile Apps** use **NodeKeyManager** (enhanced with mobile functionality) for P2P communication
- **Regular Mobile Apps** connect to CA Node only for certificate management
- **Regular Mobile Apps** connect directly to ALL network nodes (including CA Node) for application data

## Test Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           NETWORK ADMIN MOBILE APP                              │
│  (One-time setup: Creates CA, configures network, enrolls initial nodes)       │
│                                                                                 │
│ ┌─────────────────────────────────────────────────────────────────────────────┐ │
│ │                    Network Admin Mobile Key Manager                        │ │
│ │  • User Root Key (ECIES P-256)                                            │ │
│ │  • User-Owned CA (Certificate Authority)                                  │ │
│ │  • Network Data Key                                                        │ │
│ │  • Enrollment Authority (EA) Key                                          │ │
│ │  • Enrollment Token Generation                                            │ │
│ └─────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────┬───────────────────────────────────────────────────────┘
                          │
                          │ QUIC mTLS (One-time setup)
                          │
┌─────────────────────────▼───────────────────────────────────────────────────────┐
│                            ALL NETWORK NODES                                   │
│                    (All set up by Network Admin Mobile App)                    │
│                                                                                 │
│ ┌─────────────────────────────────────────────────────────────────────────────┐ │
│ │                        CA NODE (Node 1)                                    │ │
│ │  ┌─────────────────────────────────────────────────────────────────────────┐ │ │
│ │  │                    P2P Network Node                                    │ │ │
│ │  │  • Node Key Manager                                                   │ │ │
│ │  │  • QUIC mTLS (P2P port)                                               │ │ │
│ │  │  • Service Discovery                                                   │ │ │
│ │  │  • Remote Service Calls                                                │ │ │
│ │  └─────────────────────────────────────────────────────────────────────────┘ │ │
│ │  ┌─────────────────────────────────────────────────────────────────────────┐ │ │
│ │  │                    CA Services                                         │ │ │
│ │  │  • QUIC mTLS Server (Bootstrap + Authenticated endpoints)             │ │ │
│ │  │  • Certificate Authority (Issuing CA)                                 │ │ │
│ │  │  • Enrollment Authority (EA) Key Management                           │ │ │
│ │  │  • Enrollment Token Validation                                        │ │ │
│ │  │  • CRL-lite Generation                                                │ │ │
│ │  └─────────────────────────────────────────────────────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                 │
│ ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                          │
│ │   Node 2    │    │   Node 3    │    │   Node 4    │                          │
│ │             │    │             │    │             │                          │
│ │ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │                          │
│ │ │Node Key │ │    │ │Node Key │ │    │ │Node Key │ │                          │
│ │ │Manager  │ │    │ │Manager  │ │    │ │Manager  │ │                          │
│ │ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │                          │
│ │ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │                          │
│ │ │P2P QUIC │ │    │ │P2P QUIC │ │    │ │P2P QUIC │ │                          │
│ │ │mTLS     │ │    │ │mTLS     │ │    │ │mTLS     │ │                          │
│ │ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │                          │
│ └─────────────┘    └─────────────┘    └─────────────┘                          │
└─────────────────────────────────────────────────────────────────────────────────┘
                          ▲
                          │ Direct P2P QUIC mTLS
                          │ (After certificate enrollment)
                          │
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           REGULAR MOBILE APPS                                  │
│  (Run applications, connect directly to network nodes)                         │
│                                                                                 │
│ ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                          │
│ │ Mobile App  │    │ Mobile App  │    │ Mobile App  │                          │
│ │ Simulator 1 │    │ Simulator 2 │    │ Simulator 3 │                          │
│ │             │    │             │    │             │                          │
│ │ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │                          │
│ │ │Node     │ │    │ │Node     │ │    │ │Node     │ │                          │
│ │ │Key      │ │    │ │Key      │ │    │ │Key      │ │                          │
│ │ │Manager  │ │    │ │Manager  │ │    │ │Manager  │ │                          │
│ │ │(Mobile) │ │    │ │(Mobile) │ │    │ │(Mobile) │ │                          │
│ │ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │                          │
│ └─────────────┘    └─────────────┘    └─────────────┘                          │
└─────────────────────────────────────────────────────────────────────────────────┘
                          ▲
                          │ QUIC mTLS (Certificate enrollment only)
                          │
┌─────────────────────────▼───────────────────────────────────────────────────────┐
│                              CA NODE                                           │
│                    (For certificate enrollment only)                           │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Enrollment Token Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           ENROLLMENT TOKEN FLOW                                │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Network Admin │    │   Enrollment    │    │   Mobile App    │
│   Mobile App    │    │     Token       │    │   Simulator     │
│                 │    │                 │    │                 │
│ 1. Creates EA   │───▶│ 2. Signs token  │    │ 3. Registers    │
│    key pair     │    │    with EA key  │    │    for network  │
│                 │    │                 │    │                 │
│ 2. Generates    │    │ • token_id      │    │ 4. Receives     │
│    token        │    │ • network_id    │    │    deep link    │
│                 │    │ • nonce         │    │                 │
│ 3. Configures   │    │ • expires_at    │    │ 5. Processes    │
│    EA on CA     │    │ • permissions   │    │    deep link    │
│                 │    │                 │    │                 │
│ 4. Creates      │───▶│ 5. Embeds in    │───▶│ 6. Extracts     │
│    deep link    │    │    deep link    │    │    token & CA   │
│                 │    │ • CA Node addr  │    │    address      │
│                 │    │ • Network info  │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │     CA Node     │
                       │                 │
                       │ 7. Validates    │
                       │    token:       │
                       │    • Signature  │
                       │    • Time window│
                       │    • Network ID │
                       │    • Anti-replay│
                       │    • Rate limit │
                       │                 │
                       │ 8. Issues       │
                       │    certificate  │
                       └─────────────────┘
```

## Deep Link Structure

The deep link simulates real-world user registration and network joining flow:

```
runar://join-network?token=<base64_enrollment_token>&ca=<ca_node_address>&network=<network_id>&expires=<expires_at>
```

**Example Deep Link**:
```
runar://join-network?token=eyJ0b2tlbl9pZCI6IjEyMzQiLCJuZXR3b3JrX2lkIjoibmV0MSIsIm5vbmNlIjoiYWJjZCIsImV4cGlyZXNfYXQiOjE2MDAwMDAwMDB9&ca=192.168.1.100:8443&network=net1&expires=1600000000
```

**Deep Link Components**:
- **Scheme**: `runar://` (custom URL scheme for the mobile app)
- **Path**: `join-network` (action identifier)
- **Query Parameters**:
  - `token`: Base64-encoded enrollment token (contains all token fields)
  - `ca`: CA Node bootstrap server address (IP:port)
  - `network`: Network identifier for validation
  - `expires`: Token expiration timestamp for client-side validation

**Real-World Flow Simulation**:
1. **User Registration**: Mobile app simulators "register" for network (simulate email validation, user verification, etc.)
2. **Backend Validation**: Network backend validates user registration and generates enrollment token
3. **Deep Link Generation**: Backend creates deep link with token and network information
4. **Deep Link Delivery**: Deep link is "delivered" via push notification, email, or SMS (simulated in test)
5. **Deep Link Processing**: Mobile app processes deep link and extracts enrollment information
6. **Network Joining**: Mobile app uses extracted information to join the network

## Test Phases

### Phase 1: Network Admin Mobile App Setup
**Components**: Network Admin Mobile Key Manager, User CA

#### 1.1 Initialize Network Admin Mobile App
- Create Network Admin `MobileKeyManager` instance
- Generate user root agreement key (ECIES P-256)
- Generate user-owned CA (Certificate Authority) - **This becomes the Root CA for the network**
- Create network data key for the test network (one network key for this test)

#### 1.2 Validate Admin Key Generation
- Verify user root key format (65 bytes, uncompressed ECDSA P-256)
- Verify CA public key format (33 bytes, compressed ECDSA P-256)
- Verify network key generation
- Test key serialization/deserialization

**Expected Outcomes**:
- ✅ Network Admin mobile app fully initialized
- ✅ User-owned CA created (becomes network Root CA)
- ✅ Network data key generated for the test network
- ✅ All cryptographic keys generated and validated
- ✅ Key persistence validated

---

### Phase 2: CA Node Infrastructure Setup
**Components**: CA Node, QUIC mTLS Server, Certificate Authority

#### 2.1 Create Certificate Authority Hierarchy
- Use Network Admin's user-owned CA as the **Root CA** for the network
- Generate Issuing CA certificate (signed by Network Admin's Root CA)
- **Set up Node 1 as a regular P2P network node first** (by Network Admin)
- **Then configure Node 1 to ALSO run CA services** on additional ports
- Configure enrollment authority with Network Admin's CA public key

#### 2.2 Start CA Node QUIC mTLS Server
- Configure CA Server with bootstrap and authenticated endpoints
- Start QUIC mTLS server on dynamic ports
- Validate server startup and port binding
- Test server health endpoints

#### 2.3 Configure CA Node Services
- Start CA Node QUIC mTLS server on additional ports
- Configure enrollment authority with Network Admin's CA public key
- Validate CA Node server startup and port binding
- Test server health endpoints

**Expected Outcomes**:
- ✅ CA hierarchy established (Network Admin Root CA → Issuing CA)
- ✅ CA Node QUIC mTLS server running on additional ports
- ✅ CA Node configured with enrollment authority
- ✅ Server endpoints accessible

---

### Phase 3: Node Network Setup (4 Nodes)
**Components**: Node Key Managers, Network Admin Mobile App

#### 3.1 Create Four Node Instances (All by Network Admin)
- **Network Admin Mobile App** creates `NodeKeyManager` for each of the 4 nodes
- Generate unique node identities (ECDSA key pairs) for each node
- Generate CSRs for each node
- **Each node generates a setup token (QR code) containing its CSR**

#### 3.2 Network Admin Sets Up Each Node (Automated in Test)
**This process is fully automated in the test, simulating the real-world QR code scanning workflow:**

1. **Node generates setup token**:
   - Node creates `SetupToken` containing CSR and node public key
   - Node serializes setup token to bytes
   - Node encrypts setup token using Network Admin's public key (ECIES)

2. **Network Admin processes setup token**:
   - Network Admin decrypts setup token using its private key
   - Network Admin deserializes `SetupToken` from decrypted bytes
   - Network Admin calls `process_setup_token()` to sign CSR and create certificate

3. **Certificate transmission back to node**:
   - Network Admin serializes `NodeCertificateMessage`
   - Network Admin encrypts certificate message for node using node's agreement public key
   - Node decrypts certificate message using its private key
   - Node deserializes and installs certificate via `install_certificate()`

4. **Validation**:
   - Node certificate status becomes `CertificateStatus::Valid`
   - Node can generate QUIC certificate configuration
   - Node is ready for secure P2P communication

**This simulates the QR code scanning process** (automated in test, manual in real deployment)

#### 3.3 Install Network Keys on All Nodes
- **Network Admin Mobile App** creates network key message for each node
- **Network Admin Mobile App** installs the network data key on each node
- All nodes now have certificates and network keys
- All nodes are ready to participate in the P2P network

#### 3.4 Start Node Network
- Start all 4 nodes with QUIC networking enabled
- Configure multicast discovery for node discovery
- Wait for nodes to discover each other
- Establish QUIC mTLS connections between nodes
- Deploy test services on each node
- Test service registration and discovery
- Validate service endpoints are accessible

**Expected Outcomes**:
- ✅ Four nodes created with unique identities (all by Network Admin)
- ✅ All nodes set up via automated QR code simulation process
- ✅ Node 1 configured as CA Node (P2P + CA services on different ports)
- ✅ Nodes 2, 3, 4 configured as regular network nodes
- ✅ All nodes have valid certificates and network keys
- ✅ P2P network formed with 4 nodes (1 CA Node + 3 regular nodes)
- ✅ All nodes can communicate via QUIC mTLS
- ✅ Service discovery working correctly
- ✅ Test services deployed and accessible

---

### Phase 4: Regular Mobile App Simulators
**Components**: Node Key Managers (with mobile functionality), CA Clients, Enrollment Authority, Enrollment Tokens

#### 4.1 Create Regular Mobile App Simulators
- Create 3 regular mobile app simulators (mimicking end-user mobile apps)
- Each simulator has its own `NodeKeyManager` (mobile apps behave like nodes in the network and use NodeKeyManager - but they don't have Network private keys.. they have profile private keys so they decrypt user data, not system/network only data)
- Generate device identity keypairs for each simulator
- **Mobile apps use NodeKeyManager for P2P communication** (not MobileKeyManager)

#### 4.2 Create Enrollment Authority (EA) Key
- **Network Admin Mobile App** creates an **Enrollment Authority (EA)** key pair
- EA key is used to sign enrollment tokens for mobile apps
- EA public key is configured on the CA Node via `configure_enrollment_authority()`
- **Key Point**: EA key is separate from the CA keys and is used only for token signing

#### 4.3 Generate Enrollment Tokens and Deep Links for Mobile Apps
- **Network Admin Mobile App** creates enrollment tokens for each mobile app simulator
- Each token contains: `token_id`, `network_id`, `subject_hint`, `not_before`, `expires_at`, `nonce`, `permissions:["enroll"]`
- Tokens are signed by the **Enrollment Authority (EA)** key using `EnrollmentToken::generate()`
- Each token has a unique `token_id` and `nonce` for anti-replay protection
- **Simulate Deep Link Creation**: Create deep link URLs containing:
  - Enrollment token (base64 encoded)
  - CA Node bootstrap server address (IP:port)
  - Network discovery endpoints
  - Token expiration information
- **Simulate User Registration Flow**: 
  - Mobile app simulators "register" for the network (simulate email validation, etc.)
  - Network backend validates registration and generates deep link
  - Deep link is "delivered" to mobile app simulators (simulate push notification, email, etc.)
- **Key Point**: Enrollment tokens are created by Network Admin Mobile App and delivered via deep links, not by mobile apps themselves

#### 4.4 Process Deep Links and Enroll Mobile Apps
- **Mobile app simulators process deep links**:
  - Parse deep link URL to extract enrollment token, CA Node address, and network info
  - Decode base64-encoded enrollment token
  - Validate deep link format and extract bootstrap server address
  - Store network discovery endpoints for later use
- **Generate CSR for enrollment**:
  - Each mobile app simulator generates device identity keypair (if not already done)
  - Create CSR with CN = compact_id(device_public_key)
  - Prepare enrollment request with CSR + enrollment token
- **Enroll via CA Node Bootstrap Server**:
  - Connect to CA Node bootstrap server using address from deep link (server-auth only)
  - Send enrollment request: CSR + enrollment token
  - CA Node validates:
    - Token signature against EA public key
    - Token not revoked or replayed (anti-replay ledger)
    - Token within time window (`not_before` to `expires_at`)
    - Token for correct network ID
    - Rate limiting not exceeded
    - CSR CN matches compact_id of public key
  - CA Node issues device certificates to mobile app simulators
  - Mobile app simulators install certificates and become mTLS-capable

#### 4.5 Test Mobile-to-CA Communication (Certificate Management Only)
- Test certificate renewal requests from mobile apps (mTLS required)
- Test certificate revocation requests (admin operations, mTLS required)
- Test CRL-lite fetching from mobile apps (mTLS required)
- **Note**: Mobile apps only use CA Node for certificate management, not for application data

**Expected Outcomes**:
- ✅ Three regular mobile app simulators created with NodeKeyManager
- ✅ Enrollment Authority (EA) key created and configured on CA Node
- ✅ Enrollment tokens generated by Network Admin Mobile App with EA signature
- ✅ Deep links created with enrollment tokens and CA Node addresses
- ✅ User registration flow simulated (email validation, backend validation)
- ✅ Deep links delivered to mobile app simulators (simulated push notification/email)
- ✅ Mobile app simulators successfully process deep links and extract enrollment information
- ✅ All mobile app simulators successfully enrolled via CA Node bootstrap server
- ✅ Mobile apps can perform certificate management operations via mTLS
- ✅ Mobile apps are mTLS-capable for P2P communication

---

### Phase 5: P2P Network Validation
**Components**: Node instances, QUIC mTLS, Service Discovery

#### 5.1 Validate P2P Connections
- Verify all nodes can reach each other
- Test certificate validation in P2P connections
- Validate mTLS handshake between nodes
- Test connection resilience and reconnection
- Test dynamic service addition
- Validate cross-node service calls work correctly

**Expected Outcomes**:
- ✅ All nodes can communicate via QUIC mTLS
- ✅ Certificate validation working in P2P connections
- ✅ mTLS handshake validated between all nodes
- ✅ Connection resilience and reconnection working
- ✅ Cross-node service calls validated

---

### Phase 6: End-to-End Communication Testing
**Components**: Mobile App Simulators, Network Nodes, Action Chain Testing

#### 6.1 Mobile App Action Chain Test (Repeat for Each Simulator)
**Test Pattern**: Mobile App → Node1 → Node2 → Node3 (Action Chain)
- **Test 1**: **Mobile App Simulator 1** initiates action chain
  - Mobile App 1 calls `service1/action1` on **Node 1**
  - **Node 1** service calls `service2/action2` on **Node 2** 
  - **Node 2** service calls `service3/action3` on **Node 3**
  - **Node 3** returns result back through the chain
  - **Mobile App 1** receives final result and validates action chain completion

- **Test 2**: **Mobile App Simulator 2** initiates action chain
  - Mobile App 2 calls `service1/action1` on **Node 1**
  - Same action chain execution as Test 1
  - **Mobile App 2** receives final result and validates action chain completion

- **Test 3**: **Mobile App Simulator 3** initiates action chain
  - Mobile App 3 calls `service1/action1` on **Node 1**
  - Same action chain execution as Test 1
  - **Mobile App 3** receives final result and validates action chain completion

#### 6.2 Event Chain Validation (Repeat for Each Simulator)
**Test Pattern**: All services fire events, Each Mobile App listens to all
- **Mobile App 1** subscribes to events: `service1/events/*`, `service2/events/*`, `service3/events/*`
- **Mobile App 2** subscribes to events: `service1/events/*`, `service2/events/*`, `service3/events/*`
- **Mobile App 3** subscribes to events: `service1/events/*`, `service2/events/*`, `service3/events/*`
- Each service in the action chain fires events when called
- **Each Mobile App** validates it receives all expected events in correct order
- **Each Mobile App** validates event data matches action chain execution

#### 6.3 Cross-Node Communication Validation
- Validate QUIC mTLS connections between all nodes in the chain
- Validate certificate validation across multiple hops
- Validate service discovery and routing across nodes
- Validate envelope encryption for mobile app communication
- **Key Point**: Tests complete P2P network communication from mobile app through multiple nodes

**Expected Outcomes**:
- ✅ All 3 mobile app simulators successfully initiate action chains across multiple nodes
- ✅ All nodes in chain can communicate via QUIC mTLS
- ✅ All 3 mobile app simulators receive all expected events from action chains
- ✅ Certificate validation works across multiple hops for all mobile apps
- ✅ Service discovery and routing works correctly for all mobile apps
- ✅ Envelope encryption works for all mobile app communication
- ✅ Multiple mobile apps can simultaneously communicate with the P2P network

---

### Phase 7: Security and Resilience Testing
**Components**: All components under stress

#### 7.1 Certificate Lifecycle Testing
- Test certificate renewal workflows
- Test certificate revocation and CRL updates
- Validate certificate validation after revocation
- Test token revocation and re-enrollment

#### 7.2 Network Resilience Testing
- Test node stop/restart scenarios
- Test network partition recovery
- Test connection failure and reconnection
- Validate service availability during failures

#### 7.3 Security Policy Testing
- Test rate limiting enforcement
- Test unauthorized access attempts
- Test certificate validation failures
- Test encryption/decryption with invalid keys

#### 7.4 Performance and Scalability
- Test concurrent mobile client connections
- Test high-frequency service calls
- Validate memory usage and resource management
- Test network throughput and latency

**Expected Outcomes**:
- ✅ Certificate lifecycle management working
- ✅ Network resilience validated
- ✅ Security policies enforced
- ✅ Performance meets requirements

---

### Phase 8: State Persistence and Recovery
**Components**: Key managers, node state

#### 8.1 State Serialization Testing
- Test mobile key manager state serialization
- Test node key manager state serialization
- Test CA node state serialization
- Validate state consistency after serialization

#### 8.2 State Recovery Testing
- Test mobile key manager state recovery
- Test node key manager state recovery
- Test CA node state recovery
- Validate functionality after state recovery

#### 8.3 Cross-Session Persistence
- Test key persistence across application restarts
- Test certificate persistence across restarts
- Test service state persistence
- Validate network reconnection after restart

**Expected Outcomes**:
- ✅ State serialization working correctly
- ✅ State recovery validated
- ✅ Cross-session persistence working
- ✅ Network reconnection after restart

---

## Test Implementation Details

### Test Structure
```rust
#[tokio::test]
async fn test_complete_runar_framework_e2e() -> Result<()> {
    // Phase 1: Network Admin Mobile App Setup
    let network_admin_mobile = setup_network_admin_mobile_app().await?;
    
    // Phase 2: CA Node Infrastructure Setup  
    let ca_node = setup_ca_node_infrastructure(&network_admin_mobile).await?;
    
    // Phase 3: Node Network Setup (4 nodes: 1 CA Node + 3 regular nodes)
    let nodes = setup_node_network(4, &ca_node).await?;
    
    // Phase 4: Regular Mobile App Simulators
    let regular_mobile_apps = setup_regular_mobile_app_simulators(3, &ca_node).await?;
    
    // Phase 5: P2P Network Formation
    let p2p_network = form_p2p_network(&nodes).await?;
    
    // Phase 6: End-to-End Communication Testing
    test_end_to_end_communication(&regular_mobile_apps, &nodes).await?;
    
    // Phase 7: Security and Resilience Testing
    test_security_and_resilience(&regular_mobile_apps, &nodes, &ca_node).await?;
    
    // Phase 8: State Persistence and Recovery
    test_state_persistence_and_recovery(&regular_mobile_apps, &nodes, &ca_node).await?;
    
    Ok(())
}
```

### Key Test Utilities

#### Network Configuration
- Dynamic port allocation for all services
- Proper certificate chain validation
- QUIC mTLS configuration for all connections
- Multicast discovery configuration

#### Service Fixtures
- Math services for testing remote calls
- Event services for testing subscriptions
- File services for testing data transfer
- Admin services for testing CA operations

#### Validation Helpers
- Certificate validation utilities
- Encryption/decryption test helpers
- Network connectivity validators
- Performance measurement tools

### Test Data and Scenarios

#### Test Data Sets
- Small data (1KB) for basic functionality
- Medium data (1MB) for performance testing
- Large data (10MB) for stress testing
- Binary data for encryption validation

#### Test Scenarios
- Happy path scenarios (normal operation)
- Error scenarios (network failures, invalid certificates)
- Edge cases (boundary conditions, timeouts)
- Stress scenarios (high load, concurrent operations)

## Success Criteria

### Functional Requirements
- ✅ All mobile clients can enroll via CA Node
- ✅ All nodes can communicate via P2P QUIC mTLS
- ✅ Mobile clients can call services on nodes
- ✅ Cross-node service calls work correctly
- ✅ Certificate lifecycle management works
- ✅ State persistence and recovery works

### Security Requirements
- ✅ All communications use QUIC mTLS
- ✅ Certificate validation works end-to-end
- ✅ Envelope encryption works correctly
- ✅ Rate limiting and access control enforced
- ✅ Certificate revocation works correctly

### Performance Requirements
- ✅ Test completes within 30 minutes
- ✅ Memory usage stays within limits
- ✅ Network latency acceptable (< 100ms)
- ✅ Throughput meets requirements (> 1MB/s)

### Reliability Requirements
- ✅ Network failures handled gracefully
- ✅ Node restarts work correctly
- ✅ Service discovery resilient to failures
- ✅ State recovery works after failures

## Test Environment

### Hardware Requirements
- Minimum 8GB RAM
- Minimum 4 CPU cores
- Network connectivity for multicast
- Sufficient disk space for logs

### Software Requirements
- Rust toolchain (latest stable)
- All Runar framework dependencies
- Test utilities and fixtures
- Logging and monitoring tools

### Network Configuration
- Multicast enabled for service discovery
- Dynamic port allocation
- Firewall rules for test ports
- Network isolation for security testing

## Monitoring and Logging

### Test Monitoring
- Real-time test progress tracking
- Performance metrics collection
- Error rate monitoring
- Resource usage tracking

### Logging Strategy
- Structured logging for all components
- Log level configuration per phase
- Centralized log collection
- Log analysis and reporting

### Debugging Support
- Detailed error messages
- Stack traces for failures
- Network packet capture
- Certificate inspection tools

## Test Execution

### Pre-Test Setup
1. Verify all dependencies installed
2. Configure test environment
3. Initialize logging and monitoring
4. Validate network configuration

### Test Execution
1. Run test with timeout (45 minutes)
2. Monitor progress and performance
3. Collect logs and metrics
4. Handle failures gracefully

### Post-Test Analysis
1. Analyze test results
2. Generate test report
3. Identify performance bottlenecks
4. Document any issues found

## Maintenance and Updates

### Test Maintenance
- Regular updates for framework changes
- Performance baseline updates
- Security test updates
- Documentation updates

### Test Evolution
- Add new test scenarios as framework evolves
- Update success criteria as requirements change
- Enhance monitoring and logging
- Improve test reliability and performance

---

This comprehensive end-to-end test will serve as the definitive validation of the Runar framework's capabilities, demonstrating how all components work together to provide a secure, scalable, and reliable distributed system platform.
