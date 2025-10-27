import os
import sys
import requests
import socket
import json
import logging
from flask import Flask, request, jsonify, make_response, send_from_directory
from flask_cors import CORS
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session as DBSession
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, asdict
import uuid

# Add security modules to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from security.vulnerability_scanner import VulnerabilityScanner
from security.api_key_detector import APIKeyDetector
from security.dns_analyzer import DNSAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('albus_recon.log')
    ]
)
logger = logging.getLogger(__name__)

# Application configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-please-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///albus_recon.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET') or 'jwt-secret-please-change-in-production'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload size

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Enable CORS with specific settings
cors = CORS()
cors.init_app(
    app,
    resources={
        r"/api/*": {
            "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
            "methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
            "supports_credentials": True,
            "expose_headers": ["Content-Type", "Authorization"],
            "max_age": 3600,
        }
    },
)

# Database setup - SQLAlchemy 2.0 compatible
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)
Base = declarative_base()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)


class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, index=True, nullable=True)
    target = Column(String(500), nullable=False)
    scan_type = Column(String(50), nullable=False)  # e.g., 'full', 'xss', 'dns', etc.
    status = Column(String(20), default='pending')  # pending, running, completed, failed
    findings = Column(Text)  # JSON string of scan results
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)


class ReconResult(Base):
    __tablename__ = "recon_results"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True, nullable=False)
    status_code = Column(Integer, nullable=False)
    title = Column(String, default="")
    headers = Column(Text, nullable=True)  # Store headers as JSON string
    technologies = Column(Text, nullable=True)  # Store detected technologies as JSON
    screenshot_path = Column(String, nullable=True)
    fetched_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    scan_id = Column(String(36), index=True, nullable=True)  # Reference to ScanResult
    owner_id = Column(Integer, index=True, nullable=True)
    
    @property
    def headers_dict(self):
        return json.loads(self.headers) if self.headers else {}
    
    @property
    def technologies_dict(self):
        return json.loads(self.technologies) if self.technologies else {}


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(36), index=True, nullable=False)
    target = Column(String(500), nullable=False)
    type = Column(String(100), nullable=False)  # e.g., 'xss', 'sqli', 'misconfiguration', etc.
    severity = Column(String(20), default='medium')  # low, medium, high, critical
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    payload = Column(Text, nullable=True)
    request = Column(Text, nullable=True)
    response = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String(50), nullable=True)
    status = Column(String(20), default='open')  # open, in_progress, resolved, false_positive
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    reported_by = Column(Integer, index=True, nullable=True)  # User ID who reported
    assigned_to = Column(Integer, index=True, nullable=True)  # User ID assigned to fix

# Helper functions
def normalize_url(url: str) -> str:
    """
    Normalize URL by removing protocols and www prefix.
    
    Args:
        url: The URL to normalize
        
    Returns:
        str: Normalized domain name
    """
    if not url:
        raise ValueError("URL cannot be empty")
        
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
            
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
            
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        return domain
    except Exception as e:
        logger.error(f"Error normalizing URL {url}: {str(e)}")
        raise ValueError(f"Invalid URL: {str(e)}")

def get_page_title(html: str) -> str:
    """
    Extract title from HTML content.
    
    Args:
        html: The HTML content to parse
        
    Returns:
        str: The page title or a default message
    """
    try:
        if not html:
            return "No content"
            
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.title
        return title.string.strip() if title else "No title found"
    except Exception as e:
        logger.error(f"Error extracting page title: {str(e)}")
        return "Error extracting title"

def make_request(
    url: str, 
    method: str = 'get', 
    timeout: int = 15,
    allow_redirects: bool = True,
    verify_ssl: bool = True,
    **kwargs
) -> Optional[requests.Response]:
    """
    Make HTTP request with enhanced error handling and security.
    
    Args:
        url: The URL to request
        method: HTTP method (get, post, etc.)
        timeout: Request timeout in seconds
        allow_redirects: Whether to follow redirects
        verify_ssl: Whether to verify SSL certificates
        **kwargs: Additional arguments to pass to requests
        
    Returns:
        requests.Response or None if the request failed
    """
    try:
        session = requests.Session()
        
        # Default headers
        headers = kwargs.pop('headers', {})
        headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
        })
        
        # Set default timeout if not provided
        if 'timeout' not in kwargs:
            kwargs['timeout'] = timeout
            
        # Make the request
        response = session.request(
            method=method.upper(),
            url=url,
            headers=headers,
            allow_redirects=allow_redirects,
            verify=verify_ssl,
            **kwargs
        )
        
        # Log the request
        logger.info(f"{method.upper()} {url} - {response.status_code}")
        
        return response
        
    except requests.exceptions.SSLError as e:
        logger.error(f"SSL error for {url}: {str(e)}")
        # Optionally retry without SSL verification
        if verify_ssl and 'verify_ssl' not in kwargs:
            logger.warning("Retrying request with SSL verification disabled")
            return make_request(url, method, timeout=timeout, verify_ssl=False, **kwargs)
        return None
        
    except requests.exceptions.Timeout:
        logger.error(f"Request to {url} timed out after {timeout} seconds")
        return None
        
    except requests.exceptions.TooManyRedirects:
        logger.error(f"Too many redirects for {url}")
        return None
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed for {url}: {str(e)}")
        return None

# Create tables
Base.metadata.create_all(bind=engine)

# Routes
@app.route('/')
def home():
    return jsonify({
        "message": "✅ Albus Recon Backend is running successfully!",
        "status": "OK",
        "developer": "Abhishek Khadse",
        "usage": "Use /api endpoints from the frontend.",
        "documentation": "https://github.com/abhishek-khadse/Albus-Recon---Intern-Project"
    })

@app.route('/api/recon', methods=['POST'])
def create_recon():
    """Create a new URL scan."""
    db = None
    try:
        # Try to get JSON data
{{ ... }}
        data = request.get_json()
        
        # If no JSON data, try form data
        if data is None:
            data = request.form
            
        # If still no data, check URL parameters
        if not data and request.args:
            data = request.args
            
        # If we still don't have a URL, return an error
        if not data or "url" not in data:
            app.logger.error(f"Missing URL in request. Data received: {data}")
            return jsonify({
                "error": "URL is required",
                "received_data": str(data) if data else "No data received"
            }), 400
        
        url = data["url"].strip()
        if not url:
            return jsonify({"error": "URL cannot be empty"}), 400
            
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        # Create database session
        db = sessionmaker(bind=engine)()
        
        # Common headers to mimic a browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        # Common headers to mimic a browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Enhanced headers to better mimic a real browser
        headers.update({
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Referer': 'https://www.google.com/',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        })
        
        try:
            # First try with session to handle cookies
            session = requests.Session()
            response = session.get(
                url,
                headers=headers,
                timeout=15,
                allow_redirects=True,
                verify=False  # Disable SSL verification to avoid certificate errors
            )
            
            status_code = response.status_code
            
            # If we get a 403, try with different user agent
            if status_code == 403:
                headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0'
                response = session.get(url, headers=headers, timeout=15, verify=False)
                status_code = response.status_code
                
            # Check for common issues
            if status_code >= 400:
                error_details = {
                    "error": f"Failed to fetch URL: {status_code} {response.reason}",
                    "status_code": status_code,
                    "details": "The website might be blocking automated requests or require JavaScript to render content.",
                    "url": url
                }
                
                # Add more specific error messages for common status codes
                if status_code == 403:
                    error_details["details"] = "Access to this resource is forbidden. The website is likely blocking automated requests."
                elif status_code == 429:
                    error_details["details"] = "Too many requests. Please try again later."
                elif status_code == 502 or status_code == 503 or status_code == 504:
                    error_details["details"] = "The website is currently unavailable. Please try again later."
                
                # Log the error for debugging
                app.logger.warning(f"Failed to fetch {url}: {error_details}")
                
                # Save the error to the database for tracking
                recon = ReconResult(
                    url=url,
                    status_code=status_code,
                    title=f"[Error: {status_code} {response.reason}]"
                )
                db.add(recon)
                db.commit()
                
                return jsonify(error_details), 400
                
        except requests.exceptions.SSLError as e:
            return jsonify({
                "error": "SSL Certificate verification failed",
                "details": str(e),
                "url": url
            }), 400
            
        except requests.exceptions.Timeout:
            return jsonify({
                "error": "Request timed out",
                "details": "The server took too long to respond. The website might be slow or unavailable.",
                "url": url
            }), 408
            
        except requests.exceptions.RequestException as e:
            return jsonify({
                "error": "Failed to fetch URL",
                "details": str(e),
                "url": url
            }), 400
        
        # Extract title
        title = ""
        content_type = response.headers.get('content-type', '').lower()
        if 'text/html' in content_type:
            try:
                soup = BeautifulSoup(response.text, 'html.parser')
                title_tag = soup.find('title')
                if title_tag:
                    title = title_tag.text.strip()
                
                # Check for common JavaScript frameworks or login requirements
                if not title and any(js_indicator in response.text.lower() for js_indicator in ['react', 'vue', 'angular', 'next.js', 'nuxt.js']):
                    title = "[JavaScript Application - Content requires JavaScript to be enabled]"
            except Exception as e:
                title = f"[Error parsing content: {str(e)}]"
        
        recon = ReconResult(
            url=url,
            status_code=status_code,
            title=title or "[No title found]"
        )
        db.add(recon)
        db.commit()
        
        result = {
            "id": recon.id,
            "url": recon.url,
            "title": recon.title,
            "fetched_at": recon.fetched_at.isoformat()
        }
        
        return jsonify(result), 201

    except requests.RequestException as e:
        return jsonify({"error": f"Failed to fetch URL: {str(e)}"}), 400
    except Exception as e:
        if db:
            db.rollback()
        app.logger.error(f"Error in create_recon: {str(e)}", exc_info=True)
        return jsonify({"error": "An internal server error occurred"}), 500
    finally:
        if db:
            db.close()

@app.route("/api/recon", methods=["GET"])
def list_recon():
    """List all URL scans."""
    try:
        db = sessionmaker(bind=engine)()
        results = db.query(ReconResult).order_by(ReconResult.fetched_at.desc()).all()
        return jsonify([{
            "id": r.id,
            "url": r.url,
            "status_code": r.status_code,
            "title": r.title,
            "fetched_at": r.fetched_at.isoformat()
        } for r in results])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

# Serve React App
@app.route("/<path:path>")
def serve(path):
    """Serve the React app."""
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")

# Health Check Endpoint
@app.route("/api/health")
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "Albus Recon API"
    })

@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    """Get detailed results for a specific scan."""
    try:
        db = SessionLocal()
        scan = db.query(ScanResult).filter_by(id=scan_id).first()
        
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        
        # Get related vulnerabilities
        vulnerabilities = db.query(Vulnerability).filter_by(scan_id=scan_id).all()
        
        # Format response
        result = {
            'id': scan.id,
            'target': scan.target,
            'scan_type': scan.scan_type,
            'status': scan.status,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'error': scan.error,
            'findings': json.loads(scan.findings) if scan.findings else {},
            'vulnerabilities': [{
                'id': vuln.id,
                'type': vuln.type,
                'severity': vuln.severity,
                'title': vuln.title,
                'status': vuln.status,
                'created_at': vuln.created_at.isoformat() if vuln.created_at else None
            } for vuln in vulnerabilities]
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.exception(f"Error getting scan {scan_id}")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/vulnerabilities", methods=["GET"])
def list_vulnerabilities():
    """List all vulnerabilities with filtering and pagination."""
    try:
        # Get pagination parameters
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('per_page', 20))))
        
        db = SessionLocal()
        
        # Build base query
        query = db.query(Vulnerability)
        
        # Apply filters
        if 'severity' in request.args:
            severities = request.args.get('severity').split(',')
            query = query.filter(Vulnerability.severity.in_(severities))
            
        if 'type' in request.args:
            types = request.args.get('type').split(',')
            query = query.filter(Vulnerability.type.in_(types))
            
        if 'status' in request.args:
            statuses = request.args.get('status').split(',')
            query = query.filter(Vulnerability.status.in_(statuses))
            
        if 'scan_id' in request.args:
            query = query.filter(Vulnerability.scan_id == request.args.get('scan_id'))
        
        # Apply sorting
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        if hasattr(Vulnerability, sort_by):
            column = getattr(Vulnerability, sort_by)
            if sort_order.lower() == 'asc':
                query = query.order_by(column.asc())
            else:
                query = query.order_by(column.desc())
        
        # Apply pagination
        total = query.count()
        items = query.offset((page - 1) * per_page).limit(per_page).all()
        
        # Format response
        result = {
            'items': [{
                'id': vuln.id,
                'scan_id': vuln.scan_id,
                'target': vuln.target,
                'type': vuln.type,
                'severity': vuln.severity,
                'title': vuln.title,
                'status': vuln.status,
                'created_at': vuln.created_at.isoformat() if vuln.created_at else None,
                'updated_at': vuln.updated_at.isoformat() if vuln.updated_at else None
            } for vuln in items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            },
            'summary': {
                'total': total,
                'by_severity': dict(
                    db.query(Vulnerability.severity, db.func.count(Vulnerability.id))
                    .group_by(Vulnerability.severity)
                    .all()
                ),
                'by_status': dict(
                    db.query(Vulnerability.status, db.func.count(Vulnerability.id))
                    .group_by(Vulnerability.status)
                    .all()
                )
            }
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.exception("Error listing vulnerabilities")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/vulnerabilities/<vuln_id>", methods=["GET"])
def get_vulnerability(vuln_id: int):
    """Get details for a specific vulnerability."""
    try:
        db = SessionLocal()
        vuln = db.query(Vulnerability).filter_by(id=vuln_id).first()
        
        if not vuln:
            return jsonify({"error": "Vulnerability not found"}), 404
        
        # Format response
        result = {
            'id': vuln.id,
            'scan_id': vuln.scan_id,
            'target': vuln.target,
            'type': vuln.type,
            'severity': vuln.severity,
            'title': vuln.title,
            'description': vuln.description,
            'payload': vuln.payload,
            'request': vuln.request,
            'response': vuln.response,
            'cvss_score': vuln.cvss_score,
            'cve_id': vuln.cve_id,
            'status': vuln.status,
            'created_at': vuln.created_at.isoformat() if vuln.created_at else None,
            'updated_at': vuln.updated_at.isoformat() if vuln.updated_at else None,
            'reported_by': vuln.reported_by,
            'assigned_to': vuln.assigned_to
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.exception(f"Error getting vulnerability {vuln_id}")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/vulnerabilities/<int:vuln_id>", methods=["PUT"])
def update_vulnerability(vuln_id: int):
    """Update a vulnerability (e.g., change status, assign to user)."""
    try:
        data = request.get_json() or {}
        
        db = SessionLocal()
        vuln = db.query(Vulnerability).filter_by(id=vuln_id).first()
        
        if not vuln:
            return jsonify({"error": "Vulnerability not found"}), 404
        
        # Update allowed fields
        allowed_fields = ['status', 'assigned_to', 'severity', 'title', 'description']
        for field in allowed_fields:
            if field in data:
                setattr(vuln, field, data[field])
        
        # Add a note if provided
        if 'note' in data and data['note'].strip():
            # In a real app, you might have a separate VulnerabilityNote model
            logger.info(f"Note added to vulnerability {vuln_id}: {data['note']}")
        
        vuln.updated_at = datetime.utcnow()
        db.commit()
        
        return jsonify({
            'id': vuln.id,
            'status': vuln.status,
            'updated_at': vuln.updated_at.isoformat()
        })
        
    except Exception as e:
        db.rollback()
        logger.exception(f"Error updating vulnerability {vuln_id}")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/api/tools/subdomains", methods=["GET"])
def get_subdomains():
    """
    Find subdomains using multiple sources.
    
    Query parameters:
    - domain: The domain to find subdomains for (required)
    - sources: Comma-separated list of sources to use (otx, crt, dnsdumpster)
    """
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "Domain parameter is required"}), 400

    try:
        # Clean and validate domain - handle both URLs and plain domains
        if '://' in domain:
            # If it's a URL, extract the domain
            domain = urlparse(domain).netloc
        
        # Remove www. if present and clean up
        domain = domain.lower().replace('www.', '').strip()
        
        logger.info(f"[SUBDOMAINS] Looking up subdomains for {domain}")
        
        subdomains = set()
        
        # Get sources to use (default to all)
        sources = request.args.get('sources', 'otx,crt,dnsdumpster').split(',')
        
        # Query AlienVault OTX API
        if 'otx' in sources:
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
                response = make_request(url)
                
                if response:
                    data = response.json()
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname", "").lower().strip()
                        if hostname and (hostname == domain or hostname.endswith(f".{domain}")):
                            subdomains.add(hostname)
            except Exception as e:
                logger.error(f"OTX subdomain lookup failed: {str(e)}")
        
        # Query crt.sh (Certificate Transparency logs)
        if 'crt' in sources:
            try:
                url = f"https://crt.sh/?q=%25.{domain}&output=json"
                response = make_request(url)
                
                if response:
                    data = response.json()
                    for entry in data:
                        name = entry.get('name_value', '').lower().strip()
                        if name and (name == domain or name.endswith(f".{domain}")):
                            subdomains.add(name)
            except Exception as e:
                logger.error(f"crt.sh subdomain lookup failed: {str(e)}")
        
        # Query DNS Dumpster (if API key is available)
        if 'dnsdumpster' in sources and os.environ.get('DNSDUMPSTER_API_KEY'):
            try:
                # This is a placeholder - DNS Dumpster requires authentication
                # and may have rate limits or terms of service
                pass
            except Exception as e:
                logger.error(f"DNS Dumpster lookup failed: {str(e)}")
        
        # Sort and return results
        return jsonify({
            "domain": domain,
            "subdomains": sorted(list(subdomains)),
            "count": len(subdomains),
            "sources_used": sources
        })

    except Exception as e:
        logger.exception("Subdomain lookup failed")
        return jsonify({"error": f"Failed to process subdomains: {str(e)}"}), 500


@app.route("/api/tools/port-scan", methods=["POST"])
def port_scan():
    """
    Perform a port scan on a target.
    
    Request body:
    {
        "target": "example.com",
        "ports": [80, 443, 8080],  # Optional, defaults to common ports
        "scan_type": "tcp"  # tcp, syn, udp, etc.
    }
    """
    data = request.get_json() or {}
    
    if "target" not in data:
        return jsonify({"error": "Target is required"}), 400
    
    target = data["target"].strip()
    if not target:
        return jsonify({"error": "Target cannot be empty"}), 400
    
    # Default to common ports if not specified
    ports = data.get("ports", [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    ])
    
    scan_type = data.get("scan_type", "tcp").lower()
    
    try:
        # In a real app, you'd use a proper port scanner like python-nmap
        # This is a simplified example that just tries to connect to each port
        
        results = []
        
        for port in ports:
            try:
                # Create a socket object
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # 1 second timeout
                
                # Try to connect
                result = sock.connect_ex((target, port))
                
                # Determine port status
                if result == 0:
                    status = "open"
                    
                    # Try to get service banner
                    try:
                        banner = sock.recv(1024).decode('utf-8', 'ignore').strip()
                        if not banner:
                            banner = "No banner received"
                    except:
                        banner = "Could not retrieve banner"
                    
                    # Try to determine service
                    service = "unknown"
                    if port == 80:
                        service = "http"
                    elif port == 443:
                        service = "https"
                    elif port == 22:
                        service = "ssh"
                    # Add more port mappings as needed
                    
                    results.append({
                        "port": port,
                        "status": status,
                        "service": service,
                        "banner": banner
                    })
                
                sock.close()
                
            except Exception as e:
                logger.warning(f"Error scanning port {port}: {str(e)}")
                results.append({
                    "port": port,
                    "status": "error",
                    "error": str(e)
                })
        
        return jsonify({
            "target": target,
            "scan_type": scan_type,
            "results": results
        })
        
    except Exception as e:
        logger.exception("Port scan failed")
        return jsonify({"error": f"Port scan failed: {str(e)}"}), 500
    hostname = parsed.netloc or parsed.path
    
    # Common ports to scan
    common_ports = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        115,   # SFTP
        135,   # MS RPC
        139,   # NetBIOS
        143,   # IMAP
        194,   # IRC
        443,   # HTTPS
        445,   # SMB
        1433,  # MS SQL
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        8080,  # HTTP Proxy
    ]
    
    results = []
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # 1 second timeout
            result = sock.connect_ex((hostname, port))
            if result == 0:
                # Port is open
                service = socket.getservbyport(port, 'tcp') if port <= 10000 else 'unknown'
                results.append({
                    'host': hostname,
                    'protocol': 'tcp',
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'version': ''
                })
            sock.close()
        except (socket.error, socket.gaierror, socket.timeout, socket.herror, OSError):
            continue
    
    return jsonify(results)

@app.route("/api/tech-detect", methods=["GET"])
def tech_detect():
    """Detect technologies used by a website."""
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        print(f"[TECH DETECT] Analyzing {url}")
        response = make_request(url)
        
        if not response:
            return jsonify({"error": "Failed to fetch URL"}), 400

        # Parse HTML to find common technology indicators
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Initialize technologies object with basic info
        technologies = {
            'server': response.headers.get('Server', ''),
            'x_powered_by': response.headers.get('X-Powered-By', ''),
            'content_type': response.headers.get('Content-Type', ''),
            'status_code': response.status_code,
            'url': url,
            'detected_technologies': {
                'cms': [],
                'javascript_frameworks': [],
                'css_frameworks': [],
                'analytics': [],
                'languages': [],
                'web_servers': []
            }
        }
        
        # Check for common CMS
        if 'wp-content' in response.text or 'wp-includes' in response.text:
            technologies['detected_technologies']['cms'].append('WordPress')
        if 'Joomla' in response.text or 'joomla' in response.text.lower():
            technologies['detected_technologies']['cms'].append('Joomla')
        if 'Drupal' in response.text or 'drupal' in response.text.lower():
            technologies['detected_technologies']['cms'].append('Drupal')
            
        # Check for common JS frameworks
        if 'react' in response.text.lower() or 'react-dom' in response.text.lower():
            technologies['detected_technologies']['javascript_frameworks'].append('React')
        if 'jquery' in response.text.lower():
            technologies['detected_technologies']['javascript_frameworks'].append('jQuery')
        if 'vue' in response.text.lower():
            technologies['detected_technologies']['javascript_frameworks'].append('Vue.js')
            
        # Check for common CSS frameworks
        if 'bootstrap' in response.text.lower():
            technologies['detected_technologies']['css_frameworks'].append('Bootstrap')
        if 'tailwind' in response.text.lower() or 'tw-' in response.text.lower():
            technologies['detected_technologies']['css_frameworks'].append('Tailwind CSS')
            
        # Check for analytics
        if 'google-analytics' in response.text.lower() or 'ga(' in response.text.lower():
            technologies['detected_technologies']['analytics'].append('Google Analytics')
        if 'googletagmanager' in response.text.lower() or 'GTM-' in response.text.upper():
            technologies['detected_technologies']['analytics'].append('Google Tag Manager')
            
        # Detect server technologies
        server = response.headers.get('Server', '').lower()
        if 'apache' in server:
            technologies['detected_technologies']['web_servers'].append('Apache')
        elif 'nginx' in server:
            technologies['detected_technologies']['web_servers'].append('Nginx')
        elif 'iis' in server:
            technologies['detected_technologies']['web_servers'].append('Microsoft IIS')
            
        # Detect programming languages
        if '.php' in response.text or '?php' in response.text:
            technologies['detected_technologies']['languages'].append('PHP')
        if 'asp.net' in response.text.lower() or 'aspx' in response.text.lower():
            technologies['detected_technologies']['languages'].append('ASP.NET')
        if 'node' in response.headers.get('X-Powered-By', '').lower():
            technologies['detected_technologies']['languages'].append('Node.js')
            
        # Clean up empty arrays
        for key in list(technologies['detected_technologies'].keys()):
            if not technologies['detected_technologies'][key]:
                del technologies['detected_technologies'][key]
                
        return jsonify(technologies)
        
    except Exception as e:
        return jsonify({
            'error': 'An error occurred while detecting technologies',
            'details': str(e),
            'type': 'detection_error',
            'url': url,
            'recommendation': 'Please try again later or check if the URL is correct.'
        }), 500

@app.route("/api/export/csv")
def export_csv():
    """Export scan results to CSV."""
    db = sessionmaker(bind=engine)()
    try:
        results = db.query(ReconResult).all()
        
        # Convert results to list of dicts
        data = [{
            'id': r.id,
            'url': r.url,
            'status_code': r.status_code,
            'title': r.title,
            'fetched_at': r.fetched_at.isoformat() if r.fetched_at else ''
        } for r in results]
        
        # Create CSV in memory
        si = io.StringIO()
        if data:
            fieldnames = data[0].keys()
            writer = csv.DictWriter(si, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        
        # Create response with CSV
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = "attachment; filename=scan_results.csv"
        output.headers["Content-type"] = "text/csv"
        return output
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close(), 200

if __name__ == "__main__":
    # Create database tables if they don't exist
    Base.metadata.create_all(engine)
    
    # Run the app
    app.run(host="0.0.0.0", port=5000, debug=True)
