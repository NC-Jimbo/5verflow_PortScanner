#!/usr/bin/env python3
"""
Advanced API Discovery Tool
Target: Juice Shop & crAPI
Author: Red Team Training
"""
import requests
import json
import time
from datetime import datetime
from urllib.parse import urljoin
import re

class APIDiscovery:
    def __init__(self, base_url):
        self.base_url = base_url
        self.discovered_apis = []
        self.session = requests.Session()
        
    def print_banner(self):
        print("""
╔════════════════════════════════════════════════════════════╗
║          🔍 Advanced API Discovery Tool v2.0              ║
║          API 엔드포인트 자동 탐색 및 문서화                ║
╚════════════════════════════════════════════════════════════╝
        """)
    
    def discover_from_javascript(self):
        """JavaScript 파일에서 API 엔드포인트 추출"""
        print("\n[1] 📜 JavaScript 파일 분석")
        print("=" * 60)
        
        # 메인 페이지에서 JS 파일 찾기
        try:
            response = self.session.get(self.base_url)
            
            # <script src="..."> 태그 찾기
            js_files = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text)
            
            print(f"✅ {len(js_files)}개의 JavaScript 파일 발견")
            
            api_patterns = [
                r'/api/[a-zA-Z0-9/_-]+',
                r'/rest/[a-zA-Z0-9/_-]+',
                r'"/[a-zA-Z]+/[a-zA-Z0-9/_-]+"',
                r"'/[a-zA-Z]+/[a-zA-Z0-9/_-]+'",
            ]
            
            discovered_endpoints = set()
            
            for js_file in js_files[:10]:  # 처음 10개만 분석
                js_url = urljoin(self.base_url, js_file)
                print(f"\n🔍 분석 중: {js_url}")
                
                try:
                    js_response = self.session.get(js_url, timeout=5)
                    js_content = js_response.text
                    
                    # API 패턴 검색
                    for pattern in api_patterns:
                        matches = re.findall(pattern, js_content)
                        for match in matches:
                            endpoint = match.strip('"').strip("'")
                            if endpoint not in discovered_endpoints:
                                discovered_endpoints.add(endpoint)
                                print(f"  📍 발견: {endpoint}")
                                
                except Exception as e:
                    print(f"  ⚠️  에러: {e}")
            
            return list(discovered_endpoints)
            
        except Exception as e:
            print(f"❌ JavaScript 분석 실패: {e}")
            return []
    
    def discover_common_endpoints(self):
        """일반적인 API 엔드포인트 탐색"""
        print("\n[2] 🎯 일반 API 엔드포인트 탐색")
        print("=" * 60)
        
        common_apis = [
            # 인증 관련
            '/rest/user/login',
            '/rest/user/register',
            '/api/login',
            '/api/auth',
            '/api/token',
            
            # 사용자 관련
            '/api/users',
            '/rest/user/whoami',
            '/api/profile',
            '/rest/user/data-export',
            
            # 제품/상품 관련
            '/api/products',
            '/rest/products/search',
            '/api/items',
            
            # 주문 관련
            '/api/orders',
            '/api/basket',
            '/rest/basket',
            
            # 리뷰/피드백
            '/api/feedbacks',
            '/rest/products/reviews',
            
            # 관리자
            '/api/admin',
            '/rest/admin/application-version',
            
            # 기타
            '/api/config',
            '/api/version',
            '/rest/track-order',
            '/api/challenges',
        ]
        
        results = []
        
        for endpoint in common_apis:
            url = urljoin(self.base_url, endpoint)
            
            try:
                # GET 요청
                response = self.session.get(url, timeout=3)
                status = response.status_code
                
                if status != 404:
                    result = {
                        'endpoint': endpoint,
                        'url': url,
                        'method': 'GET',
                        'status': status,
                        'auth_required': status == 401,
                        'response_length': len(response.text),
                        'content_type': response.headers.get('Content-Type', 'N/A')
                    }
                    results.append(result)
                    
                    icon = "🔓" if status == 200 else "🔒" if status == 401 else "⚠️"
                    print(f"{icon} {endpoint:40} | Status: {status} | Auth: {status == 401}")
                    
                time.sleep(0.1)  # Rate limiting 방지
                
            except Exception as e:
                print(f"❌ {endpoint:40} | Error: {str(e)[:30]}")
        
        return results
    
    def test_http_methods(self, endpoint):
        """다양한 HTTP 메서드 테스트"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        results = {}
        
        url = urljoin(self.base_url, endpoint)
        
        for method in methods:
            try:
                response = self.session.request(method, url, timeout=3)
                results[method] = response.status_code
            except:
                results[method] = 'Error'
        
        return results
    
    def discover_api_parameters(self, endpoint):
        """API 파라미터 추측"""
        common_params = [
            'id', 'user_id', 'username', 'email',
            'page', 'limit', 'offset', 'sort',
            'q', 'search', 'query',
            'token', 'key', 'api_key'
        ]
        
        url = urljoin(self.base_url, endpoint)
        valid_params = []
        
        for param in common_params[:5]:  # 처음 5개만 테스트
            try:
                response = self.session.get(url, params={param: 'test'}, timeout=2)
                if response.status_code != 404:
                    valid_params.append(param)
            except:
                pass
        
        return valid_params
    
    def analyze_api_security(self, endpoint):
        """API 보안 분석"""
        url = urljoin(self.base_url, endpoint)
        security_issues = []
        
        try:
            response = self.session.get(url, timeout=3)
            
            # CORS 체크
            if 'Access-Control-Allow-Origin' in response.headers:
                cors = response.headers['Access-Control-Allow-Origin']
                if cors == '*':
                    security_issues.append("⚠️  CORS: 모든 출처 허용 (위험)")
            
            # 보안 헤더 체크
            security_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ]
            
            for header in security_headers:
                if header not in response.headers:
                    security_issues.append(f"⚠️  {header} 헤더 없음")
            
            # Rate Limiting 체크
            if 'X-RateLimit-Limit' not in response.headers:
                security_issues.append("⚠️  Rate Limiting 없음")
            
        except:
            pass
        
        return security_issues
    
    def generate_swagger_like_doc(self, apis):
        """Swagger 스타일 문서 생성"""
        print("\n[5] 📚 API 문서 생성")
        print("=" * 60)
        
        doc = {
            "openapi": "3.0.0",
            "info": {
                "title": f"Discovered API - {self.base_url}",
                "version": "1.0.0",
                "description": "Auto-discovered API endpoints"
            },
            "servers": [
                {"url": self.base_url}
            ],
            "paths": {}
        }
        
        for api in apis:
            endpoint = api['endpoint']
            doc['paths'][endpoint] = {
                "get": {
                    "summary": f"Endpoint: {endpoint}",
                    "responses": {
                        str(api['status']): {
                            "description": f"Status: {api['status']}"
                        }
                    }
                }
            }
        
        # JSON 파일로 저장
        filename = f"api_documentation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(doc, f, indent=2)
        
        print(f"💾 API 문서 저장: {filename}")
        return filename
    
    def generate_report(self, all_results):
        """최종 보고서 생성"""
        print("\n" + "=" * 60)
        print("📊 API Discovery 최종 보고서")
        print("=" * 60)
        
        total_apis = len(all_results)
        open_apis = len([r for r in all_results if r['status'] == 200])
        auth_required = len([r for r in all_results if r['auth_required']])
        
        print(f"\n✅ 총 발견된 API: {total_apis}")
        print(f"🔓 인증 불필요: {open_apis}")
        print(f"🔒 인증 필요: {auth_required}")
        
        print("\n📋 발견된 API 목록:")
        print("-" * 60)
        
        for idx, api in enumerate(all_results, 1):
            print(f"\n[{idx}] {api['endpoint']}")
            print(f"    URL: {api['url']}")
            print(f"    Status: {api['status']}")
            print(f"    Auth Required: {api['auth_required']}")
            print(f"    Content-Type: {api['content_type']}")
        
        # 텍스트 보고서 저장
        report_file = f"api_discovery_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write("API Discovery Report\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target: {self.base_url}\n")
            f.write(f"Time: {datetime.now()}\n")
            f.write(f"Total APIs: {total_apis}\n\n")
            
            for api in all_results:
                f.write(f"Endpoint: {api['endpoint']}\n")
                f.write(f"Status: {api['status']}\n")
                f.write(f"Auth: {api['auth_required']}\n")
                f.write("-" * 60 + "\n")
        
        print(f"\n💾 보고서 저장: {report_file}")
        return report_file

def main():
    print("🎯 API Discovery 시작!\n")
    
    targets = [
        ("Juice Shop", "http://localhost:3000"),
        ("crAPI", "http://localhost:8888")
    ]
    
    for name, url in targets:
        print(f"\n{'='*60}")
        print(f"🎯 Target: {name} ({url})")
        print('='*60)
        
        discovery = APIDiscovery(url)
        discovery.print_banner()
        
        # 1. JavaScript 분석
        js_endpoints = discovery.discover_from_javascript()
        
        # 2. 일반 엔드포인트 탐색
        common_endpoints = discovery.discover_common_endpoints()
        
        # 3. 보안 분석
        print("\n[3] 🔒 보안 분석")
        print("=" * 60)
        for api in common_endpoints[:5]:  # 처음 5개만
            print(f"\n분석 중: {api['endpoint']}")
            issues = discovery.analyze_api_security(api['endpoint'])
            for issue in issues:
                print(f"  {issue}")
        
        # 4. HTTP 메서드 테스트
        print("\n[4] 🔧 HTTP 메서드 테스트")
        print("=" * 60)
        for api in common_endpoints[:3]:  # 처음 3개만
            methods = discovery.test_http_methods(api['endpoint'])
            print(f"\n{api['endpoint']}:")
            for method, status in methods.items():
                print(f"  {method:8} → {status}")
        
        # 5. 문서 생성
        discovery.generate_swagger_like_doc(common_endpoints)
        
        # 6. 최종 보고서
        discovery.generate_report(common_endpoints)
        
        print(f"\n✅ {name} API Discovery 완료!\n")
        time.sleep(2)

if __name__ == "__main__":
    main()
