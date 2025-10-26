"""DNS Analysis Module."""

import dns.resolver
import dns.reversename
import socket
import whois
from typing import Dict, List, Optional, Tuple
from datetime import datetime

class DNSAnalyzer:
    """Class for performing DNS analysis on domains."""
    
    def __init__(self, domain: str):
        """Initialize with a domain name."""
        self.domain = domain.strip().lower()
        self.results = {
            'domain': self.domain,
            'dns_records': {},
            'whois': {},
            'security': {}
        }
    
    def analyze(self) -> Dict:
        """Perform comprehensive DNS analysis."""
        try:
            self._get_dns_records()
            self._get_whois_info()
            self._check_security()
        except Exception as e:
            self.results['error'] = f"Analysis failed: {str(e)}"
        
        return self.results
    
    def _get_dns_records(self) -> None:
        """Retrieve common DNS records for the domain."""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type, raise_on_no_answer=False)
                if answers.rrset:
                    self.results['dns_records'][record_type] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
    
    def _get_whois_info(self) -> None:
        """Retrieve WHOIS information for the domain."""
        try:
            whois_info = whois.whois(self.domain)
            
            # Convert datetime objects to strings
            for key, value in whois_info.items():
                if isinstance(value, list):
                    self.results['whois'][key] = [str(v) for v in value]
                elif hasattr(value, 'isoformat'):  # Handle datetime objects
                    self.results['whois'][key] = value.isoformat()
                else:
                    self.results['whois'][key] = str(value)
        except Exception as e:
            self.results['whois']['error'] = f"WHOIS lookup failed: {str(e)}"
    
    def _check_security(self) -> None:
        """Perform security checks on DNS configuration."""
        self._check_dmarc()
        self._check_dkim()
        self._check_spf()
        self._check_dnssec()
    
    def _check_dmarc(self) -> None:
        """Check for DMARC record."""
        try:
            answers = dns.resolver.resolve(f"_dmarc.{self.domain}", 'TXT', raise_on_no_answer=False)
            if answers.rrset:
                self.results['security']['dmarc'] = {
                    'exists': True,
                    'records': [str(r) for r in answers]
                }
            else:
                self.results['security']['dmarc'] = {
                    'exists': False,
                    'recommendation': 'Consider adding a DMARC record to prevent email spoofing.'
                }
        except Exception as e:
            self.results['security']['dmarc'] = {
                'error': f"DMARC check failed: {str(e)}"
            }
    
    def _check_dkim(self) -> None:
        """Check for DKIM record (common selectors)."""
        common_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mxvault']
        found = False
        
        for selector in common_selectors:
            try:
                answers = dns.resolver.resolve(f"{selector}._domainkey.{self.domain}", 'TXT', raise_on_no_answer=False)
                if answers.rrset:
                    if 'dkim' not in self.results['security']:
                        self.results['security']['dkim'] = {'exists': True, 'selectors': {}}
                    self.results['security']['dkim']['selectors'][selector] = [str(r) for r in answers]
                    found = True
            except:
                continue
        
        if not found:
            self.results['security']['dkim'] = {
                'exists': False,
                'recommendation': 'Consider adding DKIM records to authenticate your email.'
            }
    
    def _check_spf(self) -> None:
        """Check for SPF record."""
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT', raise_on_no_answer=False)
            spf_records = [r for r in answers if 'v=spf1' in str(r).lower()]
            
            if spf_records:
                self.results['security']['spf'] = {
                    'exists': True,
                    'records': [str(r) for r in spf_records]
                }
            else:
                self.results['security']['spf'] = {
                    'exists': False,
                    'recommendation': 'Consider adding an SPF record to prevent email spoofing.'
                }
        except Exception as e:
            self.results['security']['spf'] = {
                'error': f"SPF check failed: {str(e)}"
            }
    
    def _check_dnssec(self) -> None:
        """Check if DNSSEC is enabled for the domain."""
        try:
            # Check for DS record
            try:
                dns.resolver.resolve(self.domain, 'DS', raise_on_no_answer=False)
                dnssec_enabled = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                dnssec_enabled = False
            
            self.results['security']['dnssec'] = {
                'enabled': dnssec_enabled,
                'recommendation': 'Enable DNSSEC to protect against DNS spoofing.' if not dnssec_enabled else None
            }
        except Exception as e:
            self.results['security']['dnssec'] = {
                'error': f"DNSSEC check failed: {str(e)}"
            }

# Example usage
if __name__ == "__main__":
    domain = input("Enter domain to analyze: ")
    analyzer = DNSAnalyzer(domain)
    results = analyzer.analyze()
    
    print("\nDNS Analysis Results:")
    print(f"Domain: {results['domain']}")
    
    print("\nDNS Records:")
    for rtype, records in results['dns_records'].items():
        print(f"{rtype}:")
        for record in records:
            print(f"  - {record}")
    
    print("\nSecurity Checks:")
    for check, data in results['security'].items():
        print(f"\n{check.upper()}:")
        if 'exists' in data:
            print(f"  - Exists: {data['exists']}")
        if 'enabled' in data:
            print(f"  - Enabled: {data['enabled']}")
        if 'recommendation' in data and data['recommendation']:
            print(f"  - Recommendation: {data['recommendation']}")
        if 'records' in data:
            print("  - Records:")
            for record in data['records']:
                print(f"    - {record}")
