import socket
import pandas as pd
from datetime import datetime
import time

def run_standalone_scanner(target_ip="127.0.0.1"):
    
    target_ports = {
        80: {"name": "HTTP", "threat": "Insecure API", "severity": "MEDIUM"},
        8025: {"name": "Mailhog", "threat": "Email Leak", "severity": "LOW"},
        8080: {"name": "crAPI Gateway", "threat": "BOLA Vulnerability", "severity": "HIGH"},
        8888: {"name": "Admin Panel", "threat": "Full System Access", "severity": "CRITICAL"}
    }
    
    print(f"🚀 [5verflow] {target_ip} 대상 위협 시뮬레이션 스캔 시작...")
    results = []

    for port, info in target_ports.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        
        # 포트 스캔 실행
        start_time = time.time()
        is_open = s.connect_ex((target_ip, port)) == 0
        s.close()
        
        status = "VULNERABLE" if is_open else "SAFE"
        print(f"[*] Port {port} ({info['name']}): {status}")

        # 2. 데이터 파이프라인 규격화 (모든 팀원 통합용)
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': 'RECON_SCAN',
            'detail': f"{info['name']} - {info['threat']}",
            'status': status,
            'severity': info['severity'] if is_open else "NONE",
            'attacker_ip': '192.168.0.100' # 시연용 공격자 IP
        }
        results.append(log_entry)

    # 3. 메인 대시보드 데이터베이스(CSV)에 즉시 저장
    df = pd.DataFrame(results)
    df.to_csv('scan_results.csv', mode='a', header=False, index=False)
    print(f"✅ 스캔 완료! 결과가 'scan_results.csv'에 병합되었습니다.")

if __name__ == "__main__":
    run_standalone_scanner()