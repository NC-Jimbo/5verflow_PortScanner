import pandas as pd
import os
import time
import random
from datetime import datetime

# 파일명 통일
SCAN_FILE = 'scan_results.csv'

def save_result_realtime(endpoint, attack_type, result, severity):
    attacker_ip = "192.168.0.15"  # 시연용 공격자 고정 IP
    
    new_data = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'attacker_ip': attacker_ip,
        'endpoint': endpoint,
        'attack_type': attack_type,
        'result': result,
        'severity': severity
    }
    
    # 실시간으로 CSV에 추가 저장
    df = pd.DataFrame([new_data])
    df.to_csv(SCAN_FILE, mode='a', index=False, header=not os.path.exists(SCAN_FILE))
    print(f"[FOUND] {endpoint} | {attack_type} | {result}", flush=True)

def start_scan():
    target_apis = [
        ('/api/v1/user/profile', 'BOLA'),
        ('/api/v1/login', 'Brute Force'),
        ('/api/v1/data/export', 'Mass Assignment'),
        ('/api/v1/admin/config', 'Broken Auth'),
        ('/api/v1/check/health', 'Safe')
    ]
    
    print("🚀 [Red-Team] crAPI 전수 스캔 가동...", flush=True)
    for api, attack in target_apis:
        time.sleep(1.2) 
        is_vuln = any(kw in api for kw in ['admin', 'profile', 'export'])
        res = "Critical" if is_vuln else "Safe"
        sev = round(random.uniform(8.0, 9.9), 1) if res == "Critical" else 0.0
        save_result_realtime(api, attack, res, sev)
    print("✅ 스캔 완료.", flush=True)

if __name__ == "__main__":
    if os.path.exists(SCAN_FILE): os.remove(SCAN_FILE)
    start_scan()