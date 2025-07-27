#!/usr/bin/env python3
"""
Secure File Transfer Server
Zero-knowledge file sharing server that stores only encrypted files
"""

import os
import json
import uuid
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
import tempfile

class SecureFileServer:
    """
    Zero-knowledge file server that stores only encrypted files
    Server never has access to plaintext data or encryption keys
    """
    
    def __init__(self, storage_dir="./server_storage", max_file_size=50*1024*1024):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        self.max_file_size = max_file_size
        self.files_metadata = {}
        self.load_metadata()
    
    def load_metadata(self):
        """Load file metadata from disk"""
        metadata_file = self.storage_dir / "metadata.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    self.files_metadata = json.load(f)
            except:
                self.files_metadata = {}
    
    def save_metadata(self):
        """Save file metadata to disk"""
        metadata_file = self.storage_dir / "metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(self.files_metadata, f, indent=2)
    
    def store_file(self, encrypted_file_data, original_filename=None):
        """
        Store encrypted file on server
        Args:
            encrypted_file_data: Encrypted file content (JSON string)
            original_filename: Original filename for reference
        Returns:
            dict: File ID and metadata
        """
        try:
            # Parse encrypted data to validate format
            encrypted_json = json.loads(encrypted_file_data)
            required_fields = ['salt', 'iv', 'ciphertext', 'metadata']
            
            if not all(field in encrypted_json for field in required_fields):
                raise ValueError("Invalid encrypted file format")
            
            # Generate unique file ID
            file_id = str(uuid.uuid4())
            
            # Store encrypted file
            file_path = self.storage_dir / f"{file_id}.enc"
            with open(file_path, 'w') as f:
                json.dump(encrypted_json, f)
            
            # Calculate file hash for integrity
            file_hash = hashlib.sha256(encrypted_file_data.encode()).hexdigest()
            
            # Store metadata
            metadata = {
                'file_id': file_id,
                'original_filename': original_filename or encrypted_json['metadata'].get('original_filename', 'unknown'),
                'upload_time': datetime.now().isoformat(),
                'file_hash': file_hash,
                'file_size': len(encrypted_file_data),
                'algorithm': encrypted_json['metadata'].get('algorithm', 'unknown'),
                'expires_at': (datetime.now() + timedelta(days=7)).isoformat()  # 7 day expiry
            }
            
            self.files_metadata[file_id] = metadata
            self.save_metadata()
            
            return {
                'success': True,
                'file_id': file_id,
                'message': 'File uploaded successfully',
                'metadata': metadata
            }
            
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON format")
        except Exception as e:
            raise Exception(f"Failed to store file: {str(e)}")
    
    def retrieve_file(self, file_id):
        """
        Retrieve encrypted file from server
        Args:
            file_id: Unique file identifier
        Returns:
            dict: Encrypted file data and metadata
        """
        if file_id not in self.files_metadata:
            raise FileNotFoundError("File not found")
        
        metadata = self.files_metadata[file_id]
        
        # Check if file has expired
        expires_at = datetime.fromisoformat(metadata['expires_at'])
        if datetime.now() > expires_at:
            self.delete_file(file_id)
            raise FileNotFoundError("File has expired")
        
        file_path = self.storage_dir / f"{file_id}.enc"
        
        if not file_path.exists():
            raise FileNotFoundError("File data not found on disk")
        
        with open(file_path, 'r') as f:
            encrypted_data = json.load(f)
        
        return {
            'success': True,
            'file_id': file_id,
            'encrypted_data': encrypted_data,
            'metadata': metadata
        }
    
    def list_files(self):
        """List all files on server with their metadata"""
        current_time = datetime.now()
        active_files = {}
        
        for file_id, metadata in self.files_metadata.items():
            expires_at = datetime.fromisoformat(metadata['expires_at'])
            if current_time <= expires_at:
                active_files[file_id] = {
                    'file_id': file_id,
                    'original_filename': metadata['original_filename'],
                    'upload_time': metadata['upload_time'],
                    'file_size': metadata['file_size'],
                    'algorithm': metadata['algorithm'],
                    'expires_at': metadata['expires_at']
                }
        
        return active_files
    
    def delete_file(self, file_id):
        """Delete file from server"""
        if file_id in self.files_metadata:
            file_path = self.storage_dir / f"{file_id}.enc"
            if file_path.exists():
                file_path.unlink()
            
            del self.files_metadata[file_id]
            self.save_metadata()
            return True
        return False

# Flask application
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Initialize server
server = SecureFileServer()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'Secure File Transfer Server is running',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """
    Upload encrypted file to server
    Expects: multipart/form-data with 'file' field containing encrypted JSON
    """
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Read encrypted file content
        encrypted_content = file.read().decode('utf-8')
        
        # Store the file
        result = server.store_file(encrypted_content, file.filename)
        
        return jsonify(result), 200
        
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/download/<file_id>', methods=['GET'])
def download_file(file_id):
    """
    Download encrypted file from server
    Returns: JSON response with encrypted file data
    """
    try:
        result = server.retrieve_file(file_id)
        return jsonify(result), 200
        
    except FileNotFoundError as e:
        return jsonify({'success': False, 'error': str(e)}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': f'Download failed: {str(e)}'}), 500

@app.route('/api/list', methods=['GET'])
def list_files():
    """List all available files on server"""
    try:
        files = server.list_files()
        return jsonify({
            'success': True,
            'files': files,
            'count': len(files)
        }), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to list files: {str(e)}'}), 500

@app.route('/api/delete/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete file from server"""
    try:
        success = server.delete_file(file_id)
        if success:
            return jsonify({'success': True, 'message': 'File deleted successfully'}), 200
        else:
            return jsonify({'success': False, 'error': 'File not found'}), 404
            
    except Exception as e:
        return jsonify({'success': False, 'error': f'Delete failed: {str(e)}'}), 500

@app.route('/api/info/<file_id>', methods=['GET'])
def file_info(file_id):
    """Get file information without downloading"""
    try:
        if file_id not in server.files_metadata:
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        metadata = server.files_metadata[file_id]
        
        # Check if expired
        expires_at = datetime.fromisoformat(metadata['expires_at'])
        if datetime.now() > expires_at:
            return jsonify({'success': False, 'error': 'File has expired'}), 404
        
        return jsonify({
            'success': True,
            'metadata': metadata
        }), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to get info: {str(e)}'}), 500

def print_server_info():
    """Print server startup information"""
    print("\n" + "="*60)
    print("    SECURE FILE TRANSFER SERVER")
    print("    Zero-Knowledge Encrypted File Storage")
    print("="*60)
    print(f"Storage Directory: {server.storage_dir.absolute()}")
    print(f"Max File Size: {app.config['MAX_CONTENT_LENGTH'] // (1024*1024)}MB")
    print(f"File Expiry: 7 days")
    print("\nAPI Endpoints:")
    print("  POST /api/upload     - Upload encrypted file")
    print("  GET  /api/download/<id> - Download encrypted file")
    print("  GET  /api/list       - List all files")
    print("  GET  /api/info/<id>  - Get file information")
    print("  DELETE /api/delete/<id> - Delete file")
    print("  GET  /api/health     - Health check")
    print("\n" + "="*60 + "\n")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure File Transfer Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to (default: 5000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--storage', default='./server_storage', help='Storage directory')
    
    args = parser.parse_args()
    
    # Initialize server with custom storage directory
    server = SecureFileServer(storage_dir=args.storage)
    
    print_server_info()
    
    try:
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n⏹️  Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")
