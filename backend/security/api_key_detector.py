"""API Key and Secret Detection Module."""

import re
from typing import Dict, List, Tuple, Optional, Pattern
import os

class APIKeyDetector:
    """Detect potential API keys and secrets in code or text."""
    
    # Common API key patterns
    PATTERNS = {
        'google_api': r'AIza[0-9A-Za-z\\-_]{35}'
    }
    
    def __init__(self):
        """Initialize the detector with common patterns."""
        self.compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for better performance."""
        for key, pattern in self.PATTERNS.items():
            self.compiled_patterns[key] = re.compile(pattern)
    
    def scan_text(self, text: str) -> List[Dict]:
        """
        Scan text for potential API keys and secrets.
        
        Args:
            text: The text to scan
            
        Returns:
            List of dictionaries containing found secrets and their types
        """
        results = []
        
        for key, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(text):
                results.append({
                    'type': key,
                    'value': match.group(0),
                    'start': match.start(),
                    'end': match.end(),
                    'line': text.count('\n', 0, match.start()) + 1
                })
        
        return results
    
    def scan_file(self, file_path: str) -> Dict:
        """
        Scan a file for potential API keys and secrets.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary containing scan results
        """
        results = {
            'file': file_path,
            'secrets': [],
            'error': None
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                secrets = self.scan_text(content)
                
                # Add line content to each secret
                lines = content.split('\n')
                for secret in secrets:
                    line_num = secret['line'] - 1  # Convert to 0-based index
                    if 0 <= line_num < len(lines):
                        secret['line_content'] = lines[line_num].strip()
                
                results['secrets'] = secrets
                
        except Exception as e:
            results['error'] = f"Error scanning file: {str(e)}"
        
        return results
    
    def scan_directory(self, directory: str, extensions: List[str] = None) -> Dict:
        """
        Recursively scan a directory for files containing potential API keys.
        
        Args:
            directory: Directory path to scan
            extensions: List of file extensions to include (None for all)
            
        Returns:
            Dictionary containing scan results
        """
        results = {
            'directory': directory,
            'scanned_files': 0,
            'files_with_secrets': 0,
            'secrets_found': 0,
            'files': []
        }
        
        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    # Skip files not in the extensions list if specified
                    if extensions and not any(file.endswith(ext) for ext in extensions):
                        continue
                    
                    file_path = os.path.join(root, file)
                    file_result = self.scan_file(file_path)
                    
                    results['scanned_files'] += 1
                    
                    if file_result['secrets']:
                        results['files_with_secrets'] += 1
                        results['secrets_found'] += len(file_result['secrets'])
                        
                        # Only include files with secrets in the results
                        results['files'].append({
                            'path': file_path,
                            'secrets': file_result['secrets'],
                            'secret_count': len(file_result['secrets'])
                        })
                        
        except Exception as e:
            results['error'] = f"Error scanning directory: {str(e)}"
        
        return results

# Example usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Scan for API keys and secrets')
    parser.add_argument('path', help='File or directory path to scan')
    parser.add_argument('--extensions', nargs='+', default=None, 
                       help='File extensions to include (e.g., .py .js .env)')
    
    args = parser.parse_args()
    
    detector = APIKeyDetector()
    
    if os.path.isfile(args.path):
        results = detector.scan_file(args.path)
        
        print(f"\nScan results for file: {results['file']}")
        if results.get('error'):
            print(f"Error: {results['error']}")
        else:
            for secret in results['secrets']:
                print(f"\nPotential {secret['type']} found on line {secret['line']}:")
                print(f"{secret['line_content']}")
    
    elif os.path.isdir(args.path):
        results = detector.scan_directory(args.path, args.extensions)
        
        print(f"\nScan results for directory: {results['directory']}")
        print(f"Scanned files: {results['scanned_files']}")
        print(f"Files with secrets: {results['files_with_secrets']}")
        print(f"Total secrets found: {results['secrets_found']}")
        
        if results.get('error'):
            print(f"Error: {results['error']}")
        
        if results['files']:
            print("\nFiles containing secrets:")
            for file in results['files']:
                print(f"\n{file['path']} ({file['secret_count']} secrets):")
                for secret in file['secrets']:
                    print(f"  - Line {secret['line']}: {secret['type']}")
    
    else:
        print(f"Error: Path '{args.path}' does not exist or is not accessible.")
