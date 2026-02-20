"""Tools service for network reconnaissance utilities."""
import socket
import json
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import requests

from core.database import DatabaseManager
from core.schemas import SubdomainRequest, SubdomainResponse, PortScanRequest, PortScanResponse, PortScanResult
from core.logging import get_logger

logger = get_logger(__name__)


class ToolsService:
    """Service for network reconnaissance tools."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.5',
        })
    
    def find_subdomains(self, request: SubdomainRequest) -> SubdomainResponse:
        """Find subdomains using multiple sources."""
        domain = self._normalize_domain(request.domain)
        subdomains = set()
        
        logger.info(f"Starting subdomain enumeration for {domain}")
        
        # Query different sources based on request
        for source in request.sources:
            try:
                if source == 'otx':
                    subdomains.update(self._query_otx(domain))
                elif source == 'crt':
                    subdomains.update(self._query_crt_sh(domain))
                elif source == 'dnsdumpster':
                    subdomains.update(self._query_dnsdumpster(domain))
                else:
                    logger.warning(f"Unknown subdomain source: {source}")
            
            except Exception as e:
                logger.error(f"Error querying {source} for {domain}: {e}")
        
        # Filter and sort results
        filtered_subdomains = self._filter_subdomains(subdomains, domain)
        
        logger.info(f"Found {len(filtered_subdomains)} subdomains for {domain}")
        
        return SubdomainResponse(
            domain=domain,
            subdomains=sorted(filtered_subdomains),
            count=len(filtered_subdomains),
            sources_used=request.sources
        )
    
    def port_scan(self, request: PortScanRequest) -> PortScanResponse:
        """Perform port scan on target."""
        target = request.target.strip()
        results = []
        open_ports = 0
        start_time = time.time()
        
        logger.info(f"Starting port scan on {target} for {len(request.ports)} ports")
        
        for port in request.ports:
            try:
                result = self._scan_port(target, port, request.scan_type)
                results.append(result)
                
                if result.status == "open":
                    open_ports += 1
                
                logger.debug(f"Port {port} on {target}: {result.status}")
            
            except Exception as e:
                logger.error(f"Error scanning port {port} on {target}: {e}")
                results.append(PortScanResult(
                    port=port,
                    status="error",
                    service=None,
                    banner=f"Error: {str(e)}"
                ))
        
        scan_time = time.time() - start_time
        
        logger.info(f"Port scan completed for {target} in {scan_time:.2f}s. Found {open_ports} open ports")
        
        return PortScanResponse(
            target=target,
            scan_type=request.scan_type,
            results=results,
            total_ports=len(request.ports),
            open_ports=open_ports,
            scan_time=scan_time
        )
    
    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain name."""
        if '://' in domain:
            # If it's a URL, extract the domain
            domain = urlparse(domain).netloc
        
        # Remove www. prefix and clean up
        domain = domain.lower().replace('www.', '').strip()
        
        return domain
    
    def _query_otx(self, domain: str) -> List[str]:
        """Query AlienVault OTX for subdomains."""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "").lower().strip()
                    if hostname and (hostname == domain or hostname.endswith(f".{domain}")):
                        subdomains.add(hostname)
                
                logger.info(f"OTX returned {len(subdomains)} subdomains for {domain}")
                return list(subdomains)
            else:
                logger.warning(f"OTX API returned status {response.status_code}")
                return []
        
        except Exception as e:
            logger.error(f"OTX query failed: {e}")
            return []
    
    def _query_crt_sh(self, domain: str) -> List[str]:
        """Query crt.sh for subdomains."""
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for entry in data:
                    name = entry.get('name_value', '').lower().strip()
                    if name and (name == domain or name.endswith(f".{domain}")):
                        # Handle multiple names in one entry
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip()
                            if subdomain and (subdomain == domain or subdomain.endswith(f".{domain}")):
                                subdomains.add(subdomain)
                
                logger.info(f"crt.sh returned {len(subdomains)} subdomains for {domain}")
                return list(subdomains)
            else:
                logger.warning(f"crt.sh API returned status {response.status_code}")
                return []
        
        except Exception as e:
            logger.error(f"crt.sh query failed: {e}")
            return []
    
    def _query_dnsdumpster(self, domain: str) -> List[str]:
        """Query DNS Dumpster for subdomains."""
        try:
            # Note: DNS Dumpster requires authentication and may have rate limits
            # This is a placeholder implementation
            logger.info("DNS Dumpster query not implemented - requires authentication")
            return []
        
        except Exception as e:
            logger.error(f"DNS Dumpster query failed: {e}")
            return []
    
    def _filter_subdomains(self, subdomains: set, domain: str) -> List[str]:
        """Filter and clean subdomain list."""
        filtered = set()
        
        for subdomain in subdomains:
            subdomain = subdomain.strip().lower()
            
            # Skip wildcards and invalid entries
            if not subdomain or subdomain.startswith('*') or subdomain.startswith('.'):
                continue
            
            # Ensure it's actually a subdomain of the target domain
            if subdomain == domain or subdomain.endswith(f".{domain}"):
                filtered.add(subdomain)
        
        return list(filtered)
    
    def _scan_port(self, target: str, port: int, scan_type: str) -> PortScanResult:
        """Scan a single port."""
        try:
            if scan_type.lower() == 'tcp':
                return self._scan_tcp_port(target, port)
            else:
                # For now, only TCP scanning is implemented
                return self._scan_tcp_port(target, port)
        
        except Exception as e:
            return PortScanResult(
                port=port,
                status="error",
                service=None,
                banner=f"Scan error: {str(e)}"
            )
    
    def _scan_tcp_port(self, target: str, port: int) -> PortScanResult:
        """Scan TCP port using socket connection."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # 3 second timeout
        
        try:
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # Port is open
                service = self._identify_service(port)
                banner = self._grab_banner(sock, port)
                
                return PortScanResult(
                    port=port,
                    status="open",
                    service=service,
                    banner=banner
                )
            else:
                # Port is closed
                return PortScanResult(
                    port=port,
                    status="closed",
                    service=None,
                    banner=None
                )
        
        except socket.timeout:
            return PortScanResult(
                port=port,
                status="filtered",
                service=None,
                banner="Timeout"
            )
        
        except Exception as e:
            return PortScanResult(
                port=port,
                status="error",
                service=None,
                banner=f"Error: {str(e)}"
            )
        
        finally:
            sock.close()
    
    def _identify_service(self, port: int) -> Optional[str]:
        """Identify common services by port number."""
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt"
        }
        
        return common_ports.get(port, "Unknown")
    
    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """Grab service banner from open port."""
        try:
            # Try to receive data
            sock.settimeout(2)
            data = sock.recv(1024)
            
            if data:
                banner = data.decode('utf-8', 'ignore').strip()
                # Clean up banner
                if len(banner) > 100:
                    banner = banner[:100] + "..."
                return banner
            
            return None
        
        except Exception:
            return None
    
    def get_dns_info(self, domain: str) -> Dict[str, Any]:
        """Get DNS information for a domain."""
        try:
            import dns.resolver
            import dns.exception
            
            dns_info = {
                'domain': domain,
                'a_records': [],
                'aaaa_records': [],
                'mx_records': [],
                'ns_records': [],
                'txt_records': [],
                'soa_record': None,
                'errors': []
            }
            
            # A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                dns_info['a_records'] = [str(rdata) for rdata in answers]
            except dns.exception.DNSException as e:
                dns_info['errors'].append(f"A record lookup failed: {e}")
            
            # AAAA records
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                dns_info['aaaa_records'] = [str(rdata) for rdata in answers]
            except dns.exception.DNSException as e:
                dns_info['errors'].append(f"AAAA record lookup failed: {e}")
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                dns_info['mx_records'] = [
                    {'preference': rdata.preference, 'exchange': str(rdata.exchange)}
                    for rdata in answers
                ]
            except dns.exception.DNSException as e:
                dns_info['errors'].append(f"MX record lookup failed: {e}")
            
            # NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                dns_info['ns_records'] = [str(rdata) for rdata in answers]
            except dns.exception.DNSException as e:
                dns_info['errors'].append(f"NS record lookup failed: {e}")
            
            # TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                dns_info['txt_records'] = [str(rdata) for rdata in answers]
            except dns.exception.DNSException as e:
                dns_info['errors'].append(f"TXT record lookup failed: {e}")
            
            # SOA record
            try:
                answers = dns.resolver.resolve(domain, 'SOA')
                if answers:
                    soa = answers[0]
                    dns_info['soa_record'] = {
                        'mname': str(soa.mname),
                        'rname': str(soa.rname),
                        'serial': soa.serial,
                        'refresh': soa.refresh,
                        'retry': soa.retry,
                        'expire': soa.expire,
                        'minimum': soa.minimum
                    }
            except dns.exception.DNSException as e:
                dns_info['errors'].append(f"SOA record lookup failed: {e}")
            
            return dns_info
        
        except ImportError:
            logger.error("dnspython not installed - DNS info not available")
            return {'error': 'dnspython not installed'}
        except Exception as e:
            logger.error(f"DNS info lookup failed: {e}")
            return {'error': str(e)}


# Import time for port scan timing
import time
