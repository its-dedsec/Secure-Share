#!/usr/bin/env python3
"""
Secure File Transfer Network Client
Encrypts files locally and uploads to secure server
Downloads encrypted files and decrypts locally
"""

import os
import sys
import json
import base64
import getpass
import argparse
import requests
import tempfile
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag

class SecureFileClient:
    """
    Network client for secure file transfer
    Handles encryption/decryption locally and communicates with server
    """
    
    def __init__(self, server_url="http://localhost:5000"):
        self.server_url = server_url.rstrip('/')
        self.key_iterations = 100000
        self.salt_length = 16
        self.iv_length = 12
        self.session = requests.Session()
        self.session.timeout = 30
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive AES-256 key from password using PBKDF2 with SHA-256"""
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.key_iterations,
        )
        return kdf.derive(password_bytes)
    
    def encrypt_file_data(self, file_data: bytes, password: str, filename: str) -> dict:
        """Encrypt file data and return encrypted bundle"""
        # Generate random salt and IV
        salt = os.urandom(self.salt_length)
        iv = os.urandom(self.iv_length)
        
        # Derive encryption key
        key = self.derive_key(password, salt)
        
        # Initialize AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Encrypt the file
        ciphertext = aesgcm.encrypt(iv, file_data, None)
        
        # Create encrypted file bundle
        encrypted_bundle = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'metadata': {
                'original_filename': filename,
                'algorithm': 'AES-256-GCM',
                'kdf': 'PBKDF2-SHA256',
                'iterations': self.key_iterations,
                'encrypted_at': datetime.now().isoformat()
            }
        }
        
        return encrypted_bundle
    
    def decrypt_file_data(self, encrypted_bundle: dict, password: str) -> bytes:
        """Decrypt encrypted bundle and return file data"""
        # Extract components
        salt = base64.b64decode(encrypted_bundle['salt'])
        iv = base64.b64decode(encrypted_bundle['iv'])
        ciphertext = base64.b64decode(encrypted_bundle['ciphertext'])
        
        # Derive decryption key
        key = self.derive_key(password, salt)
        
        # Initialize AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Decrypt the file
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        
        return plaintext
    
    def check_server_health(self):
        """Check if server is accessible"""
        try:
            response = self.session.get(f"{self.server_url}/api/health")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Cannot connect to server: {e}")
    
    def upload_file(self, file_path: str, password: str) -> dict:
        """Upload and encrypt file to server"""
        try:
            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            filename = os.path.basename(file_path)
            
            # Encrypt file locally
            encrypted_bundle = self.encrypt_file_data(file_data, password, filename)
            
            # Create temporary file for upload
            with tempfile.NamedTemporaryFile(mode='w', suffix='.encrypted', delete=False) as temp_file:
                json.dump(encrypted_bundle, temp_file, indent=2)
                temp_file_path = temp_file.name
            
            try:
                # Upload to server
                with open(temp_file_path, 'rb') as f:
                    files = {'file': (f"{filename}.encrypted", f, 'application/json')}
                    response = self.session.post(f"{self.server_url}/api/upload", files=files)
                
                response.raise_for_status()
                return response.json()
                
            finally:
                # Clean up temp file
                os.unlink(temp_file_path)
                
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {file_path}")
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Upload failed: {e}")
    
    def download_file(self, file_id: str, password: str, output_path: str = None) -> str:
        """Download and decrypt file from server"""
        try:
            # Download from server
            response = self.session.get(f"{self.server_url}/api/download/{file_id}")
            response.raise_for_status()
            
            result = response.json()
            if not result.get('success'):
                raise Exception(result.get('error', 'Download failed'))
            
            encrypted_bundle = result['encrypted_data']
            original_filename = result['metadata']['original_filename']
            
            # Decrypt file locally
            file_data = self.decrypt_file_data(encrypted_bundle, password)
            
            # Determine output path
            if output_path is None:
                output_path = f"downloaded_{original_filename}"
            
            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            return output_path
            
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Download failed: {e}")
        except InvalidTag:
            raise ValueError("Decryption failed: Invalid password or corrupted file")
    
    def list_files(self) -> dict:
        """List all files on server"""
        try:
            response = self.session.get(f"{self.server_url}/api/list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to list files: {e}")
    
    def get_file_info(self, file_id: str) -> dict:
        """Get file information from server"""
        try:
            response = self.session.get(f"{self.server_url}/api/info/{file_id}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to get file info: {e}")
    
    def delete_file(self, file_id: str) -> dict:
        """Delete file from server"""
        try:
            response = self.session.delete(f"{self.server_url}/api/delete/{file_id}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to delete file: {e}")

def print_banner():
    """Print application banner"""
    print("\n" + "="*60)
    print("    SECURE FILE TRANSFER CLIENT v1.0")
    print("    Network-Enabled Zero-Knowledge File Sharing")
    print("="*60 + "\n")

def print_success(message: str):
    """Print success message"""
    print(f"✅ {message}")

def print_error(message: str):
    """Print error message"""
    print(f"❌ ERROR: {message}")

def print_info(message: str):
    """Print info message"""
    print(f"ℹ️  {message}")

def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

def format_datetime(iso_string: str) -> str:
    """Format ISO datetime string"""
    try:
        dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return iso_string

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="Secure File Transfer Network Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s upload document.pdf --server http://192.168.1.100:5000
  %(prog)s download abc123-def456-789 --server http://192.168.1.100:5000
  %(prog)s list --server http://192.168.1.100:5000
        """
    )
    
    parser.add_argument(
        'command',
        choices=['upload', 'download', 'list', 'info', 'delete', 'health'],
        help='Command to execute'
    )
    
    parser.add_argument(
        'target',
        nargs='?',
        help='File path (for upload) or File ID (for download/info/delete)'
    )
    
    parser.add_argument(
        '-s', '--server',
        default='http://localhost:5000',
        help='Server URL (default: http://localhost:5000)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file path (for download)'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress banner display'
    )
    
    args = parser.parse_args()
    
    # Print banner unless suppressed
    if not args.no_banner:
        print_banner()
    
    # Initialize client
    client = SecureFileClient(args.server)
    
    try:
        if args.command == 'health':
            # Check server health
            print_info(f"Checking server health: {args.server}")
            health_info = client.check_server_health()
            print_success(f"Server is healthy: {health_info.get('message', 'OK')}")
            
        elif args.command == 'upload':
            if not args.target:
                print_error("File path required for upload")
                return 1
            
            if not os.path.exists(args.target):
                print_error(f"File not found: {args.target}")
                return 1
            
            print_info(f"Uploading file: {args.target}")
            print_info(f"Server: {args.server}")
            
            password = getpass.getpass("Enter encryption password: ")
            if len(password) < 8:
                print_error("Password must be at least 8 characters long")
                return 1
            
            confirm_password = getpass.getpass("Confirm password: ")
            if password != confirm_password:
                print_error("Passwords do not match")
                return 1
            
            result = client.upload_file(args.target, password)
            
            if result.get('success'):
                print_success(f"File uploaded successfully!")
                print_info(f"File ID: {result['file_id']}")
                print_info(f"Share this ID with others to download the file")
                metadata = result.get('metadata', {})
                if metadata.get('file_size'):
                    print_info(f"Encrypted size: {format_file_size(metadata['file_size'])}")
            else:
                print_error(f"Upload failed: {result.get('error', 'Unknown error')}")
                return 1
            
        elif args.command == 'download':
            if not args.target:
                print_error("File ID required for download")
                return 1
            
            print_info(f"Downloading file ID: {args.target}")
            print_info(f"Server: {args.server}")
            
            password = getpass.getpass("Enter decryption password: ")
            
            output_path = client.download_file(args.target, password, args.output)
            print_success(f"File downloaded and decrypted: {output_path}")
            
            file_size = os.path.getsize(output_path)
            print_info(f"Decrypted file size: {format_file_size(file_size)}")
            
        elif args.command == 'list':
            print_info(f"Listing files from server: {args.server}")
            
            result = client.list_files()
            if result.get('success'):
                files = result.get('files', {})
                print_success(f"Found {result.get('count', 0)} files:")
                
                if files:
                    print("\n" + "="*80)
                    print(f"{'File ID':<40} {'Filename':<25} {'Size':<10} {'Upload Time'}")
                    print("="*80)
                    
                    for file_id, metadata in files.items():
                        filename = metadata['original_filename'][:24]
                        size = format_file_size(metadata['file_size'])
                        upload_time = format_datetime(metadata['upload_time'])
                        print(f"{file_id:<40} {filename:<25} {size:<10} {upload_time}")
                else:
                    print_info("No files found on server")
            else:
                print_error(f"Failed to list files: {result.get('error', 'Unknown error')}")
                return 1
                
        elif args.command == 'info':
            if not args.target:
                print_error("File ID required for info")
                return 1
            
            print_info(f"Getting info for file ID: {args.target}")
            
            result = client.get_file_info(args.target)
            if result.get('success'):
                metadata = result['metadata']
                print_success("File Information:")
                print(f"  File ID: {metadata['file_id']}")
                print(f"  Original filename: {metadata['original_filename']}")
                print(f"  Algorithm: {metadata['algorithm']}")
                print(f"  File size: {format_file_size(metadata['file_size'])}")
                print(f"  Upload time: {format_datetime(metadata['upload_time'])}")
                print(f"  Expires at: {format_datetime(metadata['expires_at'])}")
            else:
                print_error(f"Failed to get file info: {result.get('error', 'Unknown error')}")
                return 1
                
        elif args.command == 'delete':
            if not args.target:
                print_error("File ID required for delete")
                return 1
            
            print_info(f"Deleting file ID: {args.target}")
            confirm = input("Are you sure? (y/N): ")
            
            if confirm.lower() != 'y':
                print_info("Delete cancelled")
                return 0
            
            result = client.delete_file(args.target)
            if result.get('success'):
                print_success("File deleted successfully")
            else:
                print_error(f"Failed to delete file: {result.get('error', 'Unknown error')}")
                return 1
    
    except KeyboardInterrupt:
        print_error("Operation cancelled by user")
        return 1
    except Exception as e:
        print_error(str(e))
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
