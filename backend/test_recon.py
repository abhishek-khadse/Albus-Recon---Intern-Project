import requests

BASE = "http://127.0.0.1:5000"

# STEP 1: Login
login_resp = requests.post(f"{BASE}/api/login", json={
    "username": "alice",
    "password": "S3cureP@ss"
})
print("[+] Login response:", login_resp.status_code, login_resp.json())

token = login_resp.json()["access_token"]

# STEP 2: Recon test
recon_resp = requests.post(
    f"{BASE}/api/recon",
    json={"url": "https://example.com"},
    headers={"Authorization": f"Bearer {token}"}
)
print("[+] Recon response:", recon_resp.status_code, recon_resp.json())

# STEP 3: Fetch all recon results
list_resp = requests.get(
    f"{BASE}/api/recon",
    headers={"Authorization": f"Bearer {token}"}
)
print("[+] List response:", list_resp.status_code, list_resp.json())
