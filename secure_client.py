#!/usr/bin/env python3
"""
Enhanced Secure File Transfer Network Client
Encrypts files locally and uploads to secure server with owner token support
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
    Enhanced network client for secure file transfer with owner token support
    """
    
    def __init__(self, server_url="http://localhost:5000"):
        self.server_url = server_url.rstrip('/')
        self.key_iterations = 100000
        self.salt_length = 16
        self.iv_length = 12
        self.session = requests.Session()
        self.session.timeout = 30
        self.owner_tokens_file = Path.home() / ".secure_file_client_tokens.json"
        self.owner_tokens = self.load_owner_tokens()
    
    def load_owner_tokens(self):
        """Load owner tokens from local file"""
        if self.owner_tokens_file.exists():
            try:
                with open(self.owner_tokens_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_owner_tokens(self):
        """Save owner tokens to local file"""
        try:
            with open(self.owner_tokens_file, 'w') as f:
                json.dump(self.owner_tokens, f, indent=2)
            # Set file permissions to be readable only by owner
            os.chmod(self.owner_tokens_file, 0o600)
        except Exception as e:
            print_error(f"Failed to save owner tokens: {e}")
    
    def store_owner_token(self, file_id, owner_token):
        """Store owner token for a file"""
        self.owner_tokens[file_id] = {
            'token': owner_token,
            'stored_at': datetime.now().isoformat()
        }
        self.save_owner_tokens()
    
    def get_owner_token(self, file_id):
        """Get owner token for a file"""
        return self.owner_tokens.get(file_id, {}).get('token')
    
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
                result = response.json()
                
                # Store owner token if upload was successful
                if result.get('success') and result.get('owner_token'):
                    self.store_owner_token(result['file_id'], result['owner_token'])
                
                return result
                
            finally:
                # Clean up temp file
                os.unlink(temp_file_path)
                
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {file_path}")
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 429:
                    error_msg = e.response.json().get('error', 'Rate limit exceeded')
                    raise ConnectionError(f"Rate limit exceeded: {error_msg}")
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
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 429:
                    error_msg = e.response.json().get('error', 'Rate limit exceeded')
                    raise ConnectionError(f"Rate limit exceeded: {error_msg}")
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
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 429:
                    error_msg = e.response.json().get('error', 'Rate limit exceeded')
                    raise ConnectionError(f"Rate limit exceeded: {error_msg}")
            raise ConnectionError(f"Failed to list files: {e}")
    
    def get_file_info(self, file_id: str) -> dict:
        """Get file information from server"""
        try:
            response = self.session.get(f"{self.server_url}/api/info/{file_id}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 429:
                    error_msg = e.response.json().get('error', 'Rate limit exceeded')
                    raise ConnectionError(f"Rate limit exceeded: {error_msg}")
            raise ConnectionError(f"Failed to get file info: {e}")
    
    def delete_file(self, file_id: str, owner_token: str = None) -> dict:
        """Delete file from server using owner token"""
        try:
            # Use provided token or get stored token
            token = owner_token or self.get_owner_token(file_id)
            
            if not token:
                raise ValueError("No owner token available for this file. Cannot delete.")
            
            # Send delete request with owner token
            headers = {'X-Owner-Token': token}
            response = self.session.delete(f"{self.server_url}/api/delete/{file_id}", headers=headers)
            response.raise_for_status()
            
            result = response.json()
            
            # Remove stored token if deletion was successful
            if result.get('success') and file_id in self.owner_tokens:
                del self.owner_tokens[file_id]
                self.save_owner_tokens()
            
            return result
            
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                if e.response.status_code == 429:
                    error_msg = e.response.json().get('error', 'Rate limit exceeded')
                    raise ConnectionError(f"Rate limit exceeded: {error_msg}")
                elif e.response.status_code == 403:
                    error_msg = e.response.json().get('error', 'Access denied')
                    raise PermissionError(f"Access denied: {error_msg}")
            raise ConnectionError(f"Failed to delete file: {e}")
    
    def list_owned_files(self) -> dict:
        """List files that this client has owner tokens for"""
        owned_files = {}
        for file_id, token_info in self.owner_tokens.items():
            try:
                # Try to get file info to see if it still exists
                info_result = self.get_file_info(file_id)
                if info_result.get('success'):
                    owned_files[file_id] = {
                        **info_result['metadata'],
                        'token_stored_at': token_info['stored_at']
                    }
            except:
                # File might not exist anymore, skip it
                continue
        return owned_files

def print_banner():
    """Print application banner"""
    print("\n" + "="*60)
    print("    ENHANCED SECURE FILE TRANSFER CLIENT v1.1")
    print("    Network-Enabled Zero-Knowledge File Sharing")
    print("    with Owner-based Access Control")
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

def print_warning(message: str):
    """Print warning message"""
    print(f"⚠️  WARNING: {message}")

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
        description="Enhanced Secure File Transfer Network Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s upload document.pdf --server http://192.168.1.100:5000
  %(prog)s download abc123-def456-789 --server http://192.168.1.100:5000
  %(prog)s list --server http://192.168.1.100:5000
  %(prog)s owned --server http://192.168.1.100:5000
  %(prog)s delete abc123-def456-789 --server http://192.168.1.100:5000
        """
    )
    
    parser.add_argument(
        'command',
        choices=['upload', 'download', 'list', 'info', 'delete', 'health', 'owned'],
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
        '--owner-token',
        help='Owner token for file operations (if not stored locally)'
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
                print_info(f"Owner token stored locally for future operations")
                print_info(f"Share the File ID with others to download the file")
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
                        
                        # Mark files we own
                        owned_marker = " [OWNED]" if client.get_owner_token(file_id) else ""
                        print(f"{file_id:<40} {filename:<25} {size:<10} {upload_time}{owned_marker}")
                else:
                    print_info("No files found on server")
            else:
                print_error(f"Failed to list files: {result.get('error', 'Unknown error')}")
                return 1
        
        elif args.command == 'owned':
            print_info("Listing files you own (have owner tokens for):")
            
            owned_files = client.list_owned_files()
            if owned_files:
                print_success(f"Found {len(owned_files)} owned files:")
                print("\n" + "="*80)
                print(f"{'File ID':<40} {'Filename':<25} {'Size':<10} {'Upload Time'}")
                print("="*80)
                
                for file_id, metadata in owned_files.items():
                    filename = metadata['original_filename'][:24]
                    size = format_file_size(metadata['file_size'])
                    upload_time = format_datetime(metadata['upload_time'])
                    print(f"{file_id:<40} {filename:<25} {size:<10} {upload_time}")
            else:
                print_info("No owned files found")
                
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
                
                # Show ownership status
                if client.get_owner_token(args.target):
                    print_info("You own this file (can delete it)")
                else:
                    print_warning("You don't own this file (cannot delete it)")
            else:
                print_error(f"Failed to get file info: {result.get('error', 'Unknown error')}")
                return 1
                
        elif args.command == 'delete':
            if not args.target:
                print_error("File ID required for delete")
                return 1
            
            print_info(f"Deleting file ID: {args.target}")
            
            # Check if we have owner token
            owner_token = args.owner_token or client.get_owner_token(args.target)
            if not owner_token:
                print_error("No owner token found for this file. You can only delete files you uploaded.")
                print_info("If you have the owner token, use --owner-token parameter")
                return 1
            
            confirm = input("Are you sure you want to delete this file? (y/N): ")
            
            if confirm.lower() != 'y':
                print_info("Delete cancelled")
                return 0
            
            result = client.delete_file(args.target, owner_token)
            if result.get('success'):
                print_success("File deleted successfully")
            else:
                print_error(f"Failed to delete file: {result.get('error', 'Unknown error')}")
                return 1
    
    except KeyboardInterrupt:
        print_error("Operation cancelled by user")
        return 1
    except PermissionError as e:
        print_error(str(e))
        return 1
    except Exception as e:
        print_error(str(e))
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())