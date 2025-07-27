# 🔐 Secure File Transfer System

A zero-knowledge, network-enabled secure file sharing system implementing AES-256-GCM encryption with PBKDF2 key derivation. Based on cybersecurity internship research focused on secure data handling and cryptographic best practices.

## 🌟 Features

- **🔒 Zero-Knowledge Architecture**: Files are encrypted/decrypted entirely on the client side
- **🛡️ Military-Grade Encryption**: AES-256-GCM with authentication and integrity protection
- **🔑 Strong Key Derivation**: PBKDF2 with SHA-256 and 100,000 iterations
- **🌐 Network Sharing**: Share encrypted files across local networks
- **⏰ Auto-Expiration**: Files automatically expire after 7 days
- **📱 Cross-Platform**: Works on Windows, macOS, and Linux
- **🚫 No Password Recovery**: True zero-knowledge - server never sees passwords
- **📊 File Management**: List, download, and delete files with metadata

## 🏗️ Architecture

```
┌─────────────┐    Encrypted File    ┌─────────────┐    Encrypted File    ┌─────────────┐
│   Client A  │ ◄──────────────────► │   Server    │ ◄──────────────────► │   Client B  │
│ (Encrypt)   │                      │ (Storage)   │                      │ (Decrypt)   │
└─────────────┘                      └─────────────┘                      └─────────────┘
      ▲                                      │                                      ▲
      │ Password                             │ No Access to:                       │ Password
      │ (Local Only)                        │ • Plaintext Files                   │ (Local Only)
      └──────────────────────────────────────┤ • Passwords                       └──────────
                                             │ • Encryption Keys
                                             └─ Only Stores Encrypted Data
```
The system implements a zero-knowledge architecture where:
- **Clients** handle all encryption/decryption locally
- **Server** stores only encrypted data and metadata
- **Network** transmits only encrypted content
- **Passwords** never leave the client device

![Secure File Transfer Architecture](architecture.svg)

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/secure-file-transfer.git
   cd secure-file-transfer
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Make scripts executable** (Linux/macOS)
   ```bash
   chmod +x secure_server.py secure_client.py
   ```

### Basic Usage

1. **Start the server** (on one computer)
   ```bash
   python secure_server.py --host 0.0.0.0 --port 5000
   ```

2. **Upload a file** (from any computer on the network)
   ```bash
   python secure_client.py upload document.pdf --server http://192.168.1.100:5000
   ```

3. **Download the file** (from any other computer)
   ```bash
   python secure_client.py download <FILE_ID> --server http://192.168.1.100:5000
   ```

## 📖 Detailed Usage

### Server Commands

```bash
# Start server with default settings
python secure_server.py

# Start server accessible to entire network
python secure_server.py --host 0.0.0.0 --port 5000

# Custom storage directory
python secure_server.py --storage /path/to/storage

# Enable debug mode
python secure_server.py --debug

# Get help
python secure_server.py --help
```

**Server will be accessible at:** `http://YOUR_IP_ADDRESS:5000`

### Client Commands

#### Upload Files
```bash
# Basic upload
python secure_client.py upload file.pdf

# Upload to specific server
python secure_client.py upload file.pdf --server http://192.168.1.100:5000

# Upload will prompt for password
Enter encryption password: ********
Confirm password: ********
✅ File uploaded successfully!
ℹ️  File ID: abc123-def456-ghi789
ℹ️  Share this ID with others to download the file
```

#### Download Files
```bash
# Download with file ID
python secure_client.py download abc123-def456-ghi789 --server http://192.168.1.100:5000

# Download to specific location
python secure_client.py download abc123-def456-ghi789 -o /path/to/save/file.pdf --server http://192.168.1.100:5000
```

#### File Management
```bash
# List all files on server
python secure_client.py list --server http://192.168.1.100:5000

# Get file information
python secure_client.py info abc123-def456-ghi789 --server http://192.168.1.100:5000

# Delete a file
python secure_client.py delete abc123-def456-ghi789 --server http://192.168.1.100:5000

# Check server health
python secure_client.py health --server http://192.168.1.100:5000
```

## 🌐 Network Setup Examples

### Home Network Example
```bash
# Computer A (192.168.1.100) - Server
python secure_server.py --host 0.0.0.0 --port 5000

# Computer B - Upload
python secure_client.py upload family_photos.zip --server http://192.168.1.100:5000

# Computer C - Download
python secure_client.py download abc123-def456 --server http://192.168.1.100:5000
```

### Office Network Example
```bash
# Server Machine (10.0.0.50)
python secure_server.py --host 0.0.0.0 --port 8080 --storage /shared/secure_files

# Employee A
python secure_client.py upload quarterly_report.pdf --server http://10.0.0.50:8080

# Employee B
python secure_client.py list --server http://10.0.0.50:8080
python secure_client.py download xyz789-abc123 --server http://10.0.0.50:8080
```

## 🔧 Configuration

### Server Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `0.0.0.0` | Server bind address |
| `--port` | `5000` | Server port |
| `--storage` | `./server_storage` | Storage directory |
| `--debug` | `False` | Enable debug logging |

### Security Settings

| Setting | Value | Purpose |
|---------|-------|---------|
| **Encryption** | AES-256-GCM | Confidentiality + Authentication |
| **Key Derivation** | PBKDF2-SHA256 | Password-based key generation |
| **Iterations** | 100,000 | Resistance to brute-force attacks |
| **Salt Length** | 16 bytes | Prevent rainbow table attacks |
| **IV Length** | 12 bytes | GCM mode initialization vector |
| **File Expiry** | 7 days | Automatic cleanup |
| **Max File Size** | 50 MB | Configurable limit |

## 🔒 Security Features

### Cryptographic Implementation

- **AES-256-GCM**: Advanced Encryption Standard with Galois/Counter Mode
  - Provides both confidentiality and authenticity
  - Detects tampering through authentication tags
  
- **PBKDF2 Key Derivation**:
  - Uses SHA-256 hash function
  - 100,000 iterations for computational cost
  - Unique salt per file prevents rainbow table attacks

- **Zero-Knowledge Design**:
  - All encryption/decryption happens client-side
  - Server never receives plaintext data or passwords
  - Even server compromise doesn't expose file contents

### Security Best Practices

1. **Use Strong Passwords**: 12+ characters with mixed case, numbers, and symbols
2. **Secure Networks**: Only use on trusted networks
3. **Regular Updates**: Keep dependencies updated
4. **Access Control**: Restrict server access to authorized users
5. **Monitoring**: Monitor server logs for suspicious activity

## 📁 File Structure

```
secure-file-transfer/
├── secure_server.py          # Server application
├── secure_client.py          # Client application
├── requirements.txt          # Python dependencies
├── README.md                # This file
└── server_storage/          # Server storage (created automatically)
    ├── metadata.json        # File metadata and expiration
    ├── abc123-def456.enc    # Encrypted file 1
    └── xyz789-ghi012.enc    # Encrypted file 2
```

## 🛠️ Development

### API Endpoints

The server exposes RESTful API endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/upload` | Upload encrypted file |
| `GET` | `/api/download/<id>` | Download encrypted file |
| `GET` | `/api/list` | List all files |
| `GET` | `/api/info/<id>` | Get file metadata |
| `DELETE` | `/api/delete/<id>` | Delete file |

### Dependencies

- **cryptography**: Cryptographic primitives and algorithms
- **flask**: Web server framework
- **requests**: HTTP client library

## 🐛 Troubleshooting

### Common Issues

#### Server Won't Start
```bash
# Check if port is in use
netstat -tulpn | grep :5000

# Use different port
python secure_server.py --port 8080
```

#### Cannot Connect to Server
```bash
# Test server connectivity
python secure_client.py health --server http://SERVER_IP:PORT

# Check firewall settings
sudo ufw allow 5000  # Linux
# Windows: Check Windows Firewall
```

#### Permission Denied
```bash
# Make scripts executable
chmod +x *.py

# Check file permissions
ls -la *.py
```

#### Decryption Fails
- Verify you're using the correct password
- Ensure the encrypted file hasn't been corrupted
- Check that file hasn't expired (7-day limit)

### Finding Your Server IP

```bash
# Linux/macOS
ip addr show | grep inet
hostname -I

# Windows
ipconfig
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/secure-file-transfer.git
cd secure-file-transfer

# Install development dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/  # (if tests are added)
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Based on cybersecurity internship research at First Vidya Pvt. Ltd.
- Implements security principles from Task 2: Secure File Sharing Systems
- Thanks to the cryptography community for robust security libraries
- Inspired by zero-knowledge security architectures

## Contributors

- **Prathamesh Chandekar**: [LinkedIn](https://www.linkedin.com/in/prathameshc/)
- **Mansi Mehta**: [LinkedIn](https://www.linkedin.com/in/mansismehta/)

## 🔗 Related Projects

- [Cryptography Library](https://cryptography.io/)
- [Flask Framework](https://flask.palletsprojects.com/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/)

---

**⚠️ Security Notice**: This software is provided for educational and research purposes. While it implements industry-standard cryptographic practices, please conduct your own security audit before using in production environments.

**🛡️ Zero-Knowledge Guarantee**: Your files and passwords never leave your device in plaintext form. The server acts only as encrypted storage and cannot access your data.
