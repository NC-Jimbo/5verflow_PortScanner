#!/usr/bin/env python3
import requests
import json

target = "http://localhost:8888"

print("="*60)
print("[*] crAPI - API Reconnaissance Script")
print(f"[*] Target: {target}")
print("="*60)

# Phase 1: API 문서 찾기
print("\n[+] Phase 1: Looking for API Documentation")
swagger_paths = [
    "/swagger.json",
    "/api-docs",
    "/v2/api-docs",
    "/openapi.json",
    "/docs",
    "/api/docs",
    "/identity/api/swagger",
    "/community/api/swagger",
    "/workshop/api/swagger"
]

found_docs = []
for path in swagger_paths:
    try:
        r = requests.get(f"{target}{path}", timeout=3)
        if r.status_code == 200:
            print(f"  [✓] Found: {path}")
            print(f"      Size: {len(r.content)} bytes")
            found_docs.append(path)
            # 파일로 저장
            filename = f"swagger_{path.replace('/', '_')}.json"
            with open(filename, "w") as f:
                f.write(r.text)
            print(f"      Saved to: {filename}")
        elif r.status_code != 404:
            print(f"  [!] {path} -> Status {r.status_code}")
    except Exception as e:
        pass

# Phase 2: 일반 엔드포인트 탐색
print("\n[+] Phase 2: Probing Common Endpoints")
endpoints = [
    "/",
    "/api",
    "/health",
    "/identity/api/v2/user/login",
    "/identity/api/v2/user/signup",
    "/identity/api/v2/vehicle/vehicles",
    "/community/api/v2/community/posts",
    "/workshop/api/shop/products"
]

accessible = []
for ep in endpoints:
    try:
        r = requests.get(f"{target}{ep}", timeout=3)
        status_icon = "✓" if r.status_code == 200 else "!"
        print(f"  [{status_icon}] {ep} -> {r.status_code}")
        if r.status_code in [200, 401, 403]:
            accessible.append(ep)
    except Exception as e:
        print(f"  [✗] {ep} -> Error")

# Phase 3: 회원가입 테스트
print("\n[+] Phase 3: Testing User Registration")
signup_url = f"{target}/identity/api/v2/user/signup"
signup_data = {
    "email": "redteam@hacker.com",
    "name": "Red Team",
    "number": "9876543210",
    "password": "RedTeam123!"
}

try:
    r = requests.post(signup_url, json=signup_data)
    print(f"  [*] Signup Status: {r.status_code}")
    if r.status_code == 200:
        print(f"  [✓] Account Created!")
        response = r.json()
        if 'token' in str(response):
            print(f"  [✓] JWT Token received!")
            print(f"      Token: {str(response)[:100]}...")
    else:
        print(f"  [!] Response: {r.text[:200]}")
except Exception as e:
    print(f"  [✗] Error: {e}")

# Summary
print("\n" + "="*60)
print("[*] Reconnaissance Summary")
print(f"  - API Docs Found: {len(found_docs)}")
print(f"  - Accessible Endpoints: {len(accessible)}")
print("="*60)
