# Runar CLI

A command-line interface for initializing and managing Runar nodes.

## Features

- **Node Initialization**: Complete setup flow for new Runar nodes
- **Key Management**: Secure key generation and certificate management
- **QR Code Generation**: Mobile device setup via QR codes
- **Configuration Management**: Persistent configuration storage
- **Node Startup**: Start and manage running nodes

## Installation

The CLI is part of the Runar workspace. Build it with:

```bash
cargo build -p runar-cli
```

## Usage

### Initialize a New Node

```bash
# Initialize a new node (interactive setup)
runar init

# Force re-initialization if config exists
runar init --force
```

The initialization process:

1. **Key Generation**: Creates node identity keys and certificate signing request
2. **QR Code**: Generates QR code for mobile device setup
3. **Setup Server**: Starts temporary server to receive certificate from mobile
4. **Certificate Installation**: Installs received certificate
5. **Configuration Storage**: Saves configuration and keys

### Start a Node

```bash
# Start node with default configuration
runar start

# Start node with specific configuration
runar start --config /path/to/config.json
```

### Configuration

Configuration is stored in `~/.runar/` by default:

- `config.json`: Node configuration
- `node_keys.bin`: Serialized node keys (should be moved to OS key store)
- `setup_qr.png`: QR code for mobile setup

## Architecture

### Components

- **config.rs**: Configuration management and storage
- **init.rs**: Node initialization flow
- **setup_server.rs**: TCP server for mobile certificate exchange
- **start.rs**: Node startup and management

### Key Features

#### Node Initialization Flow

1. **Key Generation**: Uses `runar-keys::NodeKeyManager` to generate:
   - Node identity key pair
   - Storage encryption key
   - Certificate signing request

2. **QR Code Generation**: Creates QR code containing:
   - Setup token with CSR
   - Server address for certificate exchange

3. **Setup Server**: TCP server that:
   - Listens for mobile device connections
   - Receives encrypted certificate messages
   - Handles secure certificate exchange

4. **Certificate Installation**: 
   - Validates received certificate
   - Installs in node key manager
   - Verifies QUIC compatibility

#### Configuration Management

- JSON-based configuration storage
- Secure key serialization
- Cross-platform configuration paths
- Configuration validation

#### Node Startup

- Loads saved configuration and keys
- Creates Runar node instance
- Handles graceful shutdown
- Signal handling (Ctrl+C)

## Security

- All keys are generated using cryptographically secure random number generators
- Certificates use proper X.509 format with ECDSA P-256
- Setup tokens are encrypted for secure transmission
- Configuration files contain only public information
- Private keys are serialized but should be moved to OS key store

## Development

### Dependencies

- `runar-keys`: Key management and certificate operations
- `runar-node`: Node runtime and service management
- `runar-common`: Logging and common utilities
- `clap`: Command-line argument parsing
- `qrcode`: QR code generation
- `tokio`: Async runtime

### Testing

```bash
# Run tests
cargo test -p runar-cli

# Run with logging
RUST_LOG=debug cargo test -p runar-cli
```

## Future Enhancements

- [ ] OS key store integration (keyring, keychain, etc.)
- [ ] Network configuration support
- [ ] Service management commands
- [ ] Node monitoring and health checks
- [ ] Backup and restore functionality
- [ ] Multi-node management 