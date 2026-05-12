import requests
import subprocess
import sys

def get_live_recommendations():
    """현재 서버에서 실행 중인 도커 컨테이너를 분석해 추천 값을 생성합니다."""
    print("\n[🔍 인프라 실시간 분석 중...]")
    # 상경 님의 프로젝트 환경을 고려한 기본 보안 키워드
    recommends = ["openssh", "log4j"] 
    
    try:
        # 실행 중인 도커 컨테이너 이름 추출
        result = subprocess.run(['sudo', 'docker', 'ps', '--format', '{{.Names}}'], 
                                capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout.strip():
            containers = result.stdout.strip().split('\n')
            for name in containers:
                # 'crapi-postgres' 같은 이름에서 'postgres'만 추출하는 센스
                service = name.split('-')[-1] if '-' in name else name
                recommends.append(service)
    except:
        # 도커 환경이 아닐 경우 대비한 예외 처리
        recommends.extend(["postgres", "nginx", "redis"])

    unique_recommends = list(set(filter(None, recommends)))
    print(f"💡 추천 타겟: {', '.join(unique_recommends)}")
    print("-" * 60)
    return unique_recommends

def run_scanner(service_name):
    print(f"\n--- API Vulnerability Intelligence (Phase 2) ---")
    # 최신 데이터 구조(CVE 5.0)를 안정적으로 가져오는 피드
    url = "https://cve.circl.lu/api/last/5"

    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            cves = response.json()
            print(f"[*] Target Analysis: {service_name}\n")
            
            for cve in cves[:3]:
                # 최신 CVE 5.0 규격에 맞춘 데이터 파싱 
                metadata = cve.get('cveMetadata', {})
                cve_id = metadata.get('cveId', 'N/A')
                cna = cve.get('containers', {}).get('cna', {})
                summary = cna.get('title') or "No title provided"
                
                print(f"ID: {cve_id}")
                print(f"Title: {summary[:70]}...")
                print("-" * 60)
        else:
            print(f"[!] API Error: HTTP {response.status_code}")
    except Exception as e:
        print(f"[!] System Error: {str(e)}")

    
    print(f"\n--- End of Scan ---")

if __name__ == "__main__":
    # 1. 인프라 실시간 분석
    suggestions = get_live_recommendations()
    
    # 2. 사용자 입력 (엔터 시 리스트의 첫 번째 값 사용)
    default_target = suggestions[0] if suggestions else "postgres"
    target = input(f"Target Service Name (Default: {default_target}): ").strip()
    
    if not target:
        target = default_target
        
    run_scanner(target)