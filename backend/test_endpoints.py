"""Test script to verify all endpoints are functional after refactoring."""
import asyncio
import aiohttp
import json
from typing import Dict, Any, List
import sys

# Test configuration
BASE_URL = "http://localhost:8000"
TEST_USER = {
    "username": "testuser",
    "email": "test@example.com",
    "password": "TestPassword123!",
    "full_name": "Test User"
}

class EndpointTester:
    """Test all API endpoints to verify functionality."""
    
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.session = None
        self.auth_token = None
        self.test_results = []
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def test_endpoint(self, method: str, path: str, data: Dict = None, 
                           headers: Dict = None, expected_status: int = 200) -> Dict[str, Any]:
        """Test a single endpoint."""
        url = f"{self.base_url}{path}"
        headers = headers or {}
        
        try:
            if method.upper() == "GET":
                async with self.session.get(url, headers=headers) as response:
                    result = {
                        "method": method,
                        "path": path,
                        "status": response.status,
                        "success": response.status == expected_status,
                        "response": await response.text() if response.status < 500 else "Server Error"
                    }
            elif method.upper() == "POST":
                async with self.session.post(url, json=data, headers=headers) as response:
                    result = {
                        "method": method,
                        "path": path,
                        "status": response.status,
                        "success": response.status == expected_status,
                        "response": await response.text() if response.status < 500 else "Server Error"
                    }
            elif method.upper() == "PUT":
                async with self.session.put(url, json=data, headers=headers) as response:
                    result = {
                        "method": method,
                        "path": path,
                        "status": response.status,
                        "success": response.status == expected_status,
                        "response": await response.text() if response.status < 500 else "Server Error"
                    }
            else:
                result = {
                    "method": method,
                    "path": path,
                    "status": 0,
                    "success": False,
                    "response": f"Unsupported method: {method}"
                }
        
        except Exception as e:
            result = {
                "method": method,
                "path": path,
                "status": 0,
                "success": False,
                "response": f"Connection error: {str(e)}"
            }
        
        self.test_results.append(result)
        return result
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run comprehensive endpoint tests."""
        print("🚀 Starting endpoint functionality tests...")
        
        # Test basic endpoints
        await self.test_basic_endpoints()
        
        # Test authentication
        await self.test_authentication()
        
        # Test reconnaissance
        await self.test_reconnaissance()
        
        # Test scanning
        await self.test_scanning()
        
        # Test tools
        await self.test_tools()
        
        # Test vulnerabilities
        await self.test_vulnerabilities()
        
        # Generate summary
        return self.generate_summary()
    
    async def test_basic_endpoints(self):
        """Test basic health and root endpoints."""
        print("\n📋 Testing basic endpoints...")
        
        # Test root endpoint
        await self.test_endpoint("GET", "/", expected_status=200)
        
        # Test health endpoint
        await self.test_endpoint("GET", "/api/health", expected_status=200)
        
        # Test docs (should be available in debug mode)
        await self.test_endpoint("GET", "/docs", expected_status=200)
    
    async def test_authentication(self):
        """Test authentication endpoints."""
        print("\n🔐 Testing authentication endpoints...")
        
        # Test user registration
        result = await self.test_endpoint("POST", "/api/auth/register", TEST_USER, expected_status=201)
        if result["success"]:
            print("✅ User registration successful")
        
        # Test user login
        login_data = {"username": TEST_USER["username"], "password": TEST_USER["password"]}
        result = await self.test_endpoint("POST", "/api/auth/login", login_data, expected_status=200)
        
        if result["success"]:
            try:
                response_data = json.loads(result["response"])
                self.auth_token = response_data.get("access_token")
                print("✅ User login successful")
            except:
                print("❌ Failed to parse login response")
        else:
            print("❌ User login failed")
        
        # Test getting current user profile (requires auth)
        if self.auth_token:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            await self.test_endpoint("GET", "/api/auth/me", headers=headers, expected_status=200)
            await self.test_endpoint("PUT", "/api/auth/me", {"full_name": "Updated Name"}, headers=headers, expected_status=200)
        
        # Test token validation
        if self.auth_token:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            await self.test_endpoint("GET", "/api/auth/validate-token", headers=headers, expected_status=200)
    
    async def test_reconnaissance(self):
        """Test reconnaissance endpoints."""
        print("\n🔍 Testing reconnaissance endpoints...")
        
        if not self.auth_token:
            print("❌ No auth token available, skipping reconnaissance tests")
            return
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test creating reconnaissance
        recon_data = {"url": "https://example.com"}
        result = await self.test_endpoint("POST", "/api/recon", recon_data, headers=headers, expected_status=201)
        
        if result["success"]:
            print("✅ Reconnaissance creation successful")
        
        # Test listing reconnaissance
        await self.test_endpoint("GET", "/api/recon", headers=headers, expected_status=200)
        
        # Test reconnaissance statistics
        await self.test_endpoint("GET", "/api/recon/statistics/summary", headers=headers, expected_status=200)
    
    async def test_scanning(self):
        """Test scanning endpoints."""
        print("\n🔬 Testing scanning endpoints...")
        
        if not self.auth_token:
            print("❌ No auth token available, skipping scanning tests")
            return
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test creating scan
        scan_data = {"target": "example.com", "scan_type": "dns"}
        result = await self.test_endpoint("POST", "/api/scans", scan_data, headers=headers, expected_status=201)
        
        if result["success"]:
            print("✅ Scan creation successful")
        
        # Test listing scans
        await self.test_endpoint("GET", "/api/scans", headers=headers, expected_status=200)
        
        # Test scan statistics
        await self.test_endpoint("GET", "/api/scans/statistics/summary", headers=headers, expected_status=200)
        
        # Test running scans
        await self.test_endpoint("GET", "/api/scans/running/list", headers=headers, expected_status=200)
    
    async def test_tools(self):
        """Test tools endpoints."""
        print("\n🛠️ Testing tools endpoints...")
        
        if not self.auth_token:
            print("❌ No auth token available, skipping tools tests")
            return
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test subdomain enumeration
        subdomain_data = {"domain": "example.com", "sources": ["otx", "crt"]}
        await self.test_endpoint("POST", "/api/tools/subdomains", subdomain_data, headers=headers, expected_status=200)
        
        # Test subdomain enumeration (GET)
        await self.test_endpoint("GET", "/api/tools/subdomains?domain=example.com", headers=headers, expected_status=200)
        
        # Test port scanning
        port_data = {"target": "example.com", "ports": [80, 443], "scan_type": "tcp"}
        await self.test_endpoint("POST", "/api/tools/port-scan", port_data, headers=headers, expected_status=200)
        
        # Test DNS info
        await self.test_endpoint("GET", "/api/tools/dns-info/example.com", headers=headers, expected_status=200)
        
        # Test HTTP headers
        await self.test_endpoint("GET", "/api/tools/http-headers/example.com", headers=headers, expected_status=200)
    
    async def test_vulnerabilities(self):
        """Test vulnerability endpoints."""
        print("\n🛡️ Testing vulnerability endpoints...")
        
        if not self.auth_token:
            print("❌ No auth token available, skipping vulnerability tests")
            return
        
        headers = {"Authorization": f"Bearer {self.auth_token}"}
        
        # Test listing vulnerabilities
        await self.test_endpoint("GET", "/api/vulnerabilities", headers=headers, expected_status=200)
        
        # Test vulnerability statistics
        await self.test_endpoint("GET", "/api/vulnerabilities/statistics/summary", headers=headers, expected_status=200)
        
        # Test critical vulnerabilities
        await self.test_endpoint("GET", "/api/vulnerabilities/critical/list", headers=headers, expected_status=200)
        
        # Test unassigned vulnerabilities
        await self.test_endpoint("GET", "/api/vulnerabilities/unassigned/list", headers=headers, expected_status=200)
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate test summary."""
        total_tests = len(self.test_results)
        successful_tests = sum(1 for result in self.test_results if result["success"])
        failed_tests = total_tests - successful_tests
        
        summary = {
            "total_tests": total_tests,
            "successful_tests": successful_tests,
            "failed_tests": failed_tests,
            "success_rate": (successful_tests / total_tests * 100) if total_tests > 0 else 0,
            "results": self.test_results
        }
        
        print(f"\n📊 Test Summary:")
        print(f"   Total Tests: {total_tests}")
        print(f"   Successful: {successful_tests}")
        print(f"   Failed: {failed_tests}")
        print(f"   Success Rate: {summary['success_rate']:.1f}%")
        
        if failed_tests > 0:
            print(f"\n❌ Failed Tests:")
            for result in self.test_results:
                if not result["success"]:
                    print(f"   {result['method']} {result['path']} - Status: {result['status']}")
                    print(f"     Response: {result['response'][:100]}...")
        
        return summary


async def main():
    """Main test function."""
    print("🧪 Albus Recon Backend - Endpoint Functionality Test")
    print("=" * 60)
    
    try:
        async with EndpointTester() as tester:
            results = await tester.run_all_tests()
            
            if results["success_rate"] >= 80:
                print(f"\n✅ Tests passed! ({results['success_rate']:.1f}% success rate)")
                return 0
            else:
                print(f"\n❌ Tests failed! ({results['success_rate']:.1f}% success rate)")
                return 1
    
    except Exception as e:
        print(f"\n💥 Test execution failed: {e}")
        return 1


if __name__ == "__main__":
    # Run tests
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
