"""XSS Vulnerability Scanner Module."""

import re
from typing import List, Dict, Optional
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class XSSScanner:
    """Scanner for detecting XSS vulnerabilities."""
    
    def __init__(self, target_url: str):
        """Initialize the XSS scanner with a target URL."""
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })
        
    def scan(self) -> Dict[str, any]:
        """
        Scan for XSS vulnerabilities.
        
        Returns:
            Dict containing scan results
        """
        result = {
            'url': self.target_url,
            'vulnerable': False,
            'vulnerable_parameters': [],
            'details': []
        }
        
        try:
            # Check if URL has query parameters
            parsed_url = urlparse(self.target_url)
            if not parsed_url.query:
                result['details'].append('No query parameters found to test for XSS')
                return result
                
            # Extract parameters
            from urllib.parse import parse_qs
            params = parse_qs(parsed_url.query)
            
            # Test each parameter
            for param in params:
                test_payload = f'<script>alert("XSS-Test-{param}")</script>'
                test_url = self._inject_payload(self.target_url, param, test_payload)
                
                response = self.session.get(test_url, timeout=10)
                if test_payload in response.text:
                    result['vulnerable'] = True
                    result['vulnerable_parameters'].append(param)
                    result['details'].append(f"Reflected XSS found in parameter: {param}")
                    
        except Exception as e:
            result['error'] = f"Error during XSS scan: {str(e)}"
            
        return result
    
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject XSS payload into URL parameter."""
        from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
        
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        
        # Replace all values of the target parameter with our payload
        if param in query_dict:
            query_dict[param] = [payload] * len(query_dict[param])
        
        # Rebuild the URL
        new_query = urlencode(query_dict, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        
        return new_url

# Example usage
if __name__ == "__main__":
    test_url = input("Enter URL to test for XSS: ")
    scanner = XSSScanner(test_url)
    result = scanner.scan()
    print("\nXSS Scan Results:")
    print(f"URL: {result['url']}")
    print(f"Vulnerable: {result['vulnerable']}")
    if result['vulnerable']:
        print("Vulnerable Parameters:", ", ".join(result['vulnerable_parameters']))
    for detail in result.get('details', []):
        print(f"- {detail}")
