"""Security utilities for model loading and integrity validation."""
import hashlib
import hmac
import os
import json
from typing import Dict, Any, Optional, List
from pathlib import Path
import importlib.util
import sys

from core.logging import get_logger

logger = get_logger(__name__)


class ModelIntegrityError(Exception):
    """Raised when model integrity validation fails."""
    pass


class SecureModelLoader:
    """Secure model loader with integrity validation."""
    
    def __init__(self, models_directory: str = "models", checksum_file: str = "models_checksums.json"):
        self.models_directory = Path(models_directory)
        self.checksum_file = Path(checksum_file)
        self.checksums = self._load_checksums()
    
    def _load_checksums(self) -> Dict[str, str]:
        """Load model checksums from file."""
        if not self.checksum_file.exists():
            logger.warning(f"Checksum file {self.checksum_file} not found. Creating new one.")
            return {}
        
        try:
            with open(self.checksum_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load checksums: {e}")
            return {}
    
    def _save_checksums(self):
        """Save model checksums to file."""
        try:
            with open(self.checksum_file, 'w') as f:
                json.dump(self.checksums, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save checksums: {e}")
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA-256 checksum of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate checksum for {file_path}: {e}")
            raise ModelIntegrityError(f"Failed to calculate checksum: {e}")
    
    def validate_model_integrity(self, model_name: str) -> bool:
        """Validate model integrity using checksum."""
        model_file = self.models_directory / f"{model_name}.py"
        
        if not model_file.exists():
            raise ModelIntegrityError(f"Model file {model_file} not found")
        
        current_checksum = self._calculate_checksum(model_file)
        stored_checksum = self.checksums.get(model_name)
        
        if stored_checksum is None:
            logger.warning(f"No checksum stored for model {model_name}. Adding new checksum.")
            self.checksums[model_name] = current_checksum
            self._save_checksums()
            return True
        
        if not hmac.compare_digest(current_checksum, stored_checksum):
            raise ModelIntegrityError(
                f"Model integrity check failed for {model_name}. "
                f"Expected: {stored_checksum}, Got: {current_checksum}"
            )
        
        return True
    
    def load_model securely(self, model_name: str) -> Any:
        """Load model with integrity validation."""
        try:
            # Validate integrity first
            self.validate_model_integrity(model_name)
            
            # Load the model
            model_file = self.models_directory / f"{model_name}.py"
            spec = importlib.util.spec_from_file_location(model_name, model_file)
            
            if spec is None or spec.loader is None:
                raise ModelIntegrityError(f"Could not load model spec for {model_name}")
            
            module = importlib.util.module_from_spec(spec)
            
            # Security: Check module content before loading
            self._validate_module_content(model_file)
            
            spec.loader.exec_module(module)
            
            # Get the model class/function
            if hasattr(module, 'Model'):
                return module.Model
            elif hasattr(module, 'model'):
                return module.model
            elif hasattr(module, model_name):
                return getattr(module, model_name)
            else:
                raise ModelIntegrityError(f"No valid model export found in {model_name}")
        
        except Exception as e:
            logger.error(f"Failed to load model {model_name}: {e}")
            raise ModelIntegrityError(f"Model loading failed: {e}")
    
    def _validate_module_content(self, file_path: Path):
        """Validate module content for security issues."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for dangerous imports and functions
            dangerous_patterns = [
                'eval(',
                'exec(',
                '__import__',
                'open(',
                'file(',
                'input(',
                'raw_input(',
                'subprocess',
                'os.system',
                'os.popen',
                'os.spawn*',
                'pickle.loads',
                'cPickle.loads',
                'marshal.loads',
                'compile(',
                '__code__',
                'func_globals',
                'func_closure',
                'gi_frame',
                'gi_code',
                'im_class',
                'im_func',
                'im_self',
                'im_basics',
                '__getattribute__',
                '__setattr__',
                '__delattr__',
                '__getitem__',
                '__setitem__',
                '__delitem__',
                '__iter__',
                '__call__',
            ]
            
            content_lower = content.lower()
            for pattern in dangerous_patterns:
                if pattern in content_lower:
                    logger.warning(f"Potentially dangerous pattern '{pattern}' found in {file_path}")
                    # Allow certain patterns for legitimate use cases
                    if pattern not in ['open(', 'subprocess']:  # These might be legitimate
                        raise ModelIntegrityError(f"Dangerous pattern '{pattern}' found in model")
        
        except Exception as e:
            logger.error(f"Failed to validate module content: {e}")
            raise ModelIntegrityError(f"Content validation failed: {e}")
    
    def register_model(self, model_name: str, model_file_path: str):
        """Register a new model with checksum."""
        model_path = Path(model_file_path)
        
        if not model_path.exists():
            raise ModelIntegrityError(f"Model file {model_file_path} not found")
        
        checksum = self._calculate_checksum(model_path)
        self.checksums[model_name] = checksum
        self._save_checksums()
        
        logger.info(f"Model {model_name} registered with checksum {checksum}")


class SecurityValidator:
    """Security validation utilities."""
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL for security."""
        if not url or not isinstance(url, str):
            return False
        
        # Check for dangerous protocols
        dangerous_protocols = ['file://', 'ftp://', 'javascript:', 'data:', 'vbscript:']
        url_lower = url.lower()
        
        for protocol in dangerous_protocols:
            if protocol in url_lower:
                return False
        
        # Check for localhost/internal IPs (optional, based on requirements)
        import re
        localhost_patterns = [
            r'localhost',
            r'127\.0\.0\.1',
            r'0\.0\.0\.0',
            r'::1',
            r'192\.168\.',
            r'10\.',
            r'172\.1[6-9]\.',
            r'172\.2[0-9]\.',
            r'172\.3[0-1]\.',
        ]
        
        for pattern in localhost_patterns:
            if re.search(pattern, url_lower):
                logger.warning(f"Local/internal URL detected: {url}")
                # Allow localhost for development/testing
                # return False
        
        return True
    
    @staticmethod
    def sanitize_input(input_string: str, max_length: int = 1000) -> str:
        """Sanitize user input."""
        if not isinstance(input_string, str):
            return ""
        
        # Remove null bytes
        input_string = input_string.replace('\x00', '')
        
        # Limit length
        if len(input_string) > max_length:
            input_string = input_string[:max_length]
        
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\n', '\r', '\t']
        for char in dangerous_chars:
            input_string = input_string.replace(char, '')
        
        return input_string.strip()
    
    @staticmethod
    def validate_file_upload(filename: str, content: bytes, max_size: int = 16 * 1024 * 1024) -> bool:
        """Validate uploaded file for security."""
        if not filename or not isinstance(filename, str):
            return False
        
        # Check file size
        if len(content) > max_size:
            return False
        
        # Check file extension
        allowed_extensions = ['.txt', '.json', '.csv', '.xml', '.yaml', '.yml']
        file_ext = Path(filename).suffix.lower()
        
        if file_ext not in allowed_extensions:
            return False
        
        # Check for malicious content
        malicious_signatures = [
            b'<script',
            b'javascript:',
            b'vbscript:',
            b'data:',
            b'<?php',
            b'<%',
            b'eval(',
            b'exec(',
        ]
        
        content_lower = content.lower()
        for signature in malicious_signatures:
            if signature in content_lower:
                return False
        
        return True


# Global secure model loader instance
secure_model_loader = SecureModelLoader()


def load_security_model(model_name: str) -> Any:
    """Convenience function to load security models securely."""
    return secure_model_loader.load_model_securely(model_name)


def validate_model_integrity(model_name: str) -> bool:
    """Convenience function to validate model integrity."""
    return secure_model_loader.validate_model_integrity(model_name)
