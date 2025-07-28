#!/usr/bin/env python3
"""
Enhanced Secure File Transfer Server
Zero-knowledge file sharing server with audit logging, rate limiting, and owner-based access control
"""

import os
import json
import uuid
import hashlib
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
import tempfile

class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self, requests_per_minute=60, requests_per_hour=1000):
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.minute_requests = defaultdict(deque)
        self.hour_requests = defaultdict(deque)
    
    def is_allowed(self, client_ip):
        """Check if request is allowed for this IP"""
        now = time.time()
        
        # Clean old entries
        self._clean_old_entries(client_ip, now)
        
        # Check minute limit
        if len(self.minute_requests[client_ip]) >= self.requests_per_minute:
            return False, "Rate limit exceeded: too many requests per minute"
        
        # Check hour limit
        if len(self.hour_requests[client_ip]) >= self.requests_per_hour:
            return False, "Rate limit exceeded: too many requests per hour"
        
        # Add current request
        self.minute_requests[client_ip].append(now)
        self.hour_requests[client_ip].append(now)
        
        return True, "OK"
    
    def _clean_old_entries(self, client_ip, now):
        """Remove old entries outside the time windows"""
        minute_cutoff = now - 60
        hour_cutoff = now - 3600
        
        # Clean minute requests
        while (self.minute_requests[client_ip] and 
               self.minute_requests[client_ip][0] < minute_cutoff):
            self.minute_requests[client_ip].popleft()
        
        # Clean hour requests
        while (self.hour_requests[client_ip] and 
               self.hour_requests[client_ip][0] < hour_cutoff):
            self.hour_requests[client_ip].popleft()

class AuditLogger:
    """Audit logging for security events"""
    
    def __init__(self, log_dir="./logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup audit logger
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)
        
        # File handler for audit logs
        audit_file = self.log_dir / "audit.log"
        file_handler = logging.FileHandler(audit_file)
        file_handler.setLevel(logging.INFO)
        
        # JSON format for structured logging
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}'
        )
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
    
    def log_event(self, event_type, client_ip, user_agent=None, file_id=None, 
                  status="success", error=None, additional_data=None):
        """Log security event"""
        event_data = {
            "event_type": event_type,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "file_id": file_id,
            "status": status,
            "error": error,
            "additional_data": additional_data or {}
        }
        
        self.logger.info(json.dumps(event_data))

class SecureFileServer:
    """
    Enhanced zero-knowledge file server with security features
    """
    
    def __init__(self, storage_dir="./server_storage", max_file_size=50*1024*1024):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        self.max_file_size = max_file_size
        self.files_metadata = {}
        self.rate_limiter = RateLimiter()
        self.audit_logger = AuditLogger()
        self.load_metadata()
    
    def _generate_owner_token(self, client_ip, user_agent, timestamp):
        """Generate owner token based on client fingerprint"""
        fingerprint = f"{client_ip}:{user_agent}:{timestamp}"
        return hashlib.sha256(fingerprint.encode()).hexdigest()[:32]
    
    def _get_client_fingerprint(self, request):
        """Get client fingerprint for owner verification"""
        client_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        # For better security, you could also include:
        # - X-Forwarded-For header (if behind proxy)
        # - Accept-Language header
        # - Other stable headers
        
        return f"{client_ip}:{hashlib.md5(user_agent.encode()).hexdigest()[:16]}"
    
    def load_metadata(self):
        """Load file metadata from disk"""
        metadata_file = self.storage_dir / "metadata.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    self.files_metadata = json.load(f)
            except Exception as e:
                self.audit_logger.log_event(
                    "metadata_load_error", "system", 
                    error=str(e), status="error"
                )
                self.files_metadata = {}
    
    def save_metadata(self):
        """Save file metadata to disk"""
        metadata_file = self.storage_dir / "metadata.json"
        try:
            with open(metadata_file, 'w') as f:
                json.dump(self.files_metadata, f, indent=2)
        except Exception as e:
            self.audit_logger.log_event(
                "metadata_save_error", "system", 
                error=str(e), status="error"
            )
    
    def check_rate_limit(self, client_ip):
        """Check rate limit for client"""
        allowed, message = self.rate_limiter.is_allowed(client_ip)
        if not allowed:
            self.audit_logger.log_event(
                "rate_limit_exceeded", client_ip, 
                status="blocked", error=message
            )
        return allowed, message
    
    def store_file(self, encrypted_file_data, original_filename, request_obj):
        """
        Store encrypted file on server with owner tracking
        """
        client_ip = request_obj.remote_addr
        user_agent = request_obj.headers.get('User-Agent', '')
        
        try:
            # Parse encrypted data to validate format
            encrypted_json = json.loads(encrypted_file_data)
            required_fields = ['salt', 'iv', 'ciphertext', 'metadata']
            
            if not all(field in encrypted_json for field in required_fields):
                raise ValueError("Invalid encrypted file format")
            
            # Generate unique file ID and owner token
            file_id = str(uuid.uuid4())
            timestamp = datetime.now().isoformat()
            owner_token = self._generate_owner_token(client_ip, user_agent, timestamp)
            client_fingerprint = self._get_client_fingerprint(request_obj)
            
            # Store encrypted file
            file_path = self.storage_dir / f"{file_id}.enc"
            with open(file_path, 'w') as f:
                json.dump(encrypted_json, f)
            
            # Calculate file hash for integrity
            file_hash = hashlib.sha256(encrypted_file_data.encode()).hexdigest()
            
            # Store metadata with owner information
            metadata = {
                'file_id': file_id,
                'original_filename': original_filename or encrypted_json['metadata'].get('original_filename', 'unknown'),
                'upload_time': timestamp,
                'file_hash': file_hash,
                'file_size': len(encrypted_file_data),
                'algorithm': encrypted_json['metadata'].get('algorithm', 'unknown'),
                'expires_at': (datetime.now() + timedelta(days=7)).isoformat(),
                'owner_token': owner_token,
                'client_fingerprint': client_fingerprint,
                'uploader_ip': client_ip
            }
            
            self.files_metadata[file_id] = metadata
            self.save_metadata()
            
            # Log successful upload
            self.audit_logger.log_event(
                "file_upload", client_ip, user_agent, file_id,
                additional_data={
                    "filename": original_filename,
                    "file_size": len(encrypted_file_data)
                }
            )
            
            return {
                'success': True,
                'file_id': file_id,
                'owner_token': owner_token,  # Return to client for future operations
                'message': 'File uploaded successfully',
                'metadata': {k: v for k, v in metadata.items() 
                           if k not in ['owner_token', 'client_fingerprint']}  # Don't expose sensitive data
            }
            
        except json.JSONDecodeError as e:
            self.audit_logger.log_event(
                "file_upload", client_ip, user_agent, None,
                status="error", error="Invalid JSON format"
            )
            raise ValueError("Invalid JSON format")
        except Exception as e:
            self.audit_logger.log_event(
                "file_upload", client_ip, user_agent, None,
                status="error", error=str(e)
            )
            raise Exception(f"Failed to store file: {str(e)}")
    
    def retrieve_file(self, file_id, request_obj):
        """Retrieve encrypted file from server"""
        client_ip = request_obj.remote_addr
        user_agent = request_obj.headers.get('User-Agent', '')
        
        try:
            if file_id not in self.files_metadata:
                raise FileNotFoundError("File not found")
            
            metadata = self.files_metadata[file_id]
            
            # Check if file has expired
            expires_at = datetime.fromisoformat(metadata['expires_at'])
            if datetime.now() > expires_at:
                self.delete_file(file_id, request_obj, force=True)
                raise FileNotFoundError("File has expired")
            
            file_path = self.storage_dir / f"{file_id}.enc"
            
            if not file_path.exists():
                raise FileNotFoundError("File data not found on disk")
            
            with open(file_path, 'r') as f:
                encrypted_data = json.load(f)
            
            # Log successful download
            self.audit_logger.log_event(
                "file_download", client_ip, user_agent, file_id,
                additional_data={"filename": metadata['original_filename']}
            )
            
            return {
                'success': True,
                'file_id': file_id,
                'encrypted_data': encrypted_data,
                'metadata': {k: v for k, v in metadata.items() 
                           if k not in ['owner_token', 'client_fingerprint']}
            }
            
        except Exception as e:
            self.audit_logger.log_event(
                "file_download", client_ip, user_agent, file_id,
                status="error", error=str(e)
            )
            raise
    
    def verify_owner(self, file_id, provided_token, request_obj):
        """Verify if client is the owner of the file"""
        if file_id not in self.files_metadata:
            return False
        
        metadata = self.files_metadata[file_id]
        
        # Check owner token
        if provided_token and provided_token == metadata.get('owner_token'):
            return True
        
        # Fallback: check client fingerprint (less secure but user-friendly)
        client_fingerprint = self._get_client_fingerprint(request_obj)
        if client_fingerprint == metadata.get('client_fingerprint'):
            return True
        
        return False
    
    def delete_file(self, file_id, request_obj, owner_token=None, force=False):
        """Delete file from server with owner verification"""
        client_ip = request_obj.remote_addr
        user_agent = request_obj.headers.get('User-Agent', '')
        
        try:
            if file_id not in self.files_metadata:
                raise FileNotFoundError("File not found")
            
            # Skip owner check if force=True (for expiry cleanup)
            if not force and not self.verify_owner(file_id, owner_token, request_obj):
                self.audit_logger.log_event(
                    "file_delete", client_ip, user_agent, file_id,
                    status="forbidden", error="Not authorized to delete this file"
                )
                raise PermissionError("Not authorized to delete this file")
            
            # Delete file
            file_path = self.storage_dir / f"{file_id}.enc"
            if file_path.exists():
                file_path.unlink()
            
            filename = self.files_metadata[file_id]['original_filename']
            del self.files_metadata[file_id]
            self.save_metadata()
            
            # Log successful deletion
            self.audit_logger.log_event(
                "file_delete", client_ip, user_agent, file_id,
                additional_data={"filename": filename, "forced": force}
            )
            
            return True
            
        except Exception as e:
            if not isinstance(e, (FileNotFoundError, PermissionError)):
                self.audit_logger.log_event(
                    "file_delete", client_ip, user_agent, file_id,
                    status="error", error=str(e)
                )
            raise
    
    def list_files(self, request_obj):
        """List all files on server with their metadata"""
        client_ip = request_obj.remote_addr
        user_agent = request_obj.headers.get('User-Agent', '')
        
        try:
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
            
            # Log file listing
            self.audit_logger.log_event(
                "file_list", client_ip, user_agent,
                additional_data={"files_count": len(active_files)}
            )
            
            return active_files
            
        except Exception as e:
            self.audit_logger.log_event(
                "file_list", client_ip, user_agent,
                status="error", error=str(e)
            )
            raise

# Flask application
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Initialize server
server = SecureFileServer()

def rate_limit_check():
    """Decorator for rate limiting"""
    client_ip = request.remote_addr
    allowed, message = server.check_rate_limit(client_ip)
    if not allowed:
        return jsonify({'success': False, 'error': message}), 429
    return None

@app.before_request
def before_request():
    """Rate limiting middleware"""
    # Skip rate limiting for health check
    if request.endpoint == 'health_check':
        return None
    
    result = rate_limit_check()
    if result:
        return result

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
    """Upload encrypted file to server"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Read encrypted file content
        encrypted_content = file.read().decode('utf-8')
        
        # Store the file with owner tracking
        result = server.store_file(encrypted_content, file.filename, request)
        
        return jsonify(result), 200
        
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': f'Upload failed: {str(e)}'}), 500

@app.route('/api/download/<file_id>', methods=['GET'])
def download_file(file_id):
    """Download encrypted file from server"""
    try:
        result = server.retrieve_file(file_id, request)
        return jsonify(result), 200
        
    except FileNotFoundError as e:
        return jsonify({'success': False, 'error': str(e)}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': f'Download failed: {str(e)}'}), 500

@app.route('/api/list', methods=['GET'])
def list_files():
    """List all available files on server"""
    try:
        files = server.list_files(request)
        return jsonify({
            'success': True,
            'files': files,
            'count': len(files)
        }), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to list files: {str(e)}'}), 500

@app.route('/api/delete/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    """Delete file from server with owner verification"""
    try:
        # Get owner token from request
        owner_token = request.headers.get('X-Owner-Token') or request.json.get('owner_token') if request.json else None
        
        success = server.delete_file(file_id, request, owner_token)
        if success:
            return jsonify({'success': True, 'message': 'File deleted successfully'}), 200
        else:
            return jsonify({'success': False, 'error': 'File not found'}), 404
            
    except PermissionError as e:
        return jsonify({'success': False, 'error': str(e)}), 403
    except FileNotFoundError as e:
        return jsonify({'success': False, 'error': str(e)}), 404
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
        
        # Log info request
        server.audit_logger.log_event(
            "file_info", request.remote_addr, 
            request.headers.get('User-Agent', ''), file_id
        )
        
        return jsonify({
            'success': True,
            'metadata': {k: v for k, v in metadata.items() 
                        if k not in ['owner_token', 'client_fingerprint']}
        }), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to get info: {str(e)}'}), 500

def print_server_info():
    """Print server startup information"""
    print("\n" + "="*60)
    print("    ENHANCED SECURE FILE TRANSFER SERVER")
    print("    Zero-Knowledge with Security Features")
    print("="*60)
    print(f"Storage Directory: {server.storage_dir.absolute()}")
    print(f"Log Directory: {server.audit_logger.log_dir.absolute()}")
    print(f"Max File Size: {app.config['MAX_CONTENT_LENGTH'] // (1024*1024)}MB")
    print(f"File Expiry: 7 days")
    print(f"Rate Limits: 60/min, 1000/hour per IP")
    print("\nSecurity Features:")
    print("  ✅ Rate Limiting (DDoS protection)")
    print("  ✅ Audit Logging (all actions logged)")
    print("  ✅ Owner-based Access Control")
    print("  ✅ Client Fingerprinting")
    print("\nAPI Endpoints:")
    print("  POST /api/upload     - Upload encrypted file")
    print("  GET  /api/download/<id> - Download encrypted file")
    print("  GET  /api/list       - List all files")
    print("  GET  /api/info/<id>  - Get file information")
    print("  DELETE /api/delete/<id> - Delete file (owner only)")
    print("  GET  /api/health     - Health check")
    print("\n" + "="*60 + "\n")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Secure File Transfer Server')
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
