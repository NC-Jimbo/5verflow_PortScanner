import subprocess
import time
import os
from datetime import datetime

# 파일명 통일
SCAN_FILE = "scan_results.csv"

def get_real_attacker_ip():
    """OS 네트워크 연결에서 실제 공격자 IP 추출"""
    try:
        cmd = "netstat -ntu | grep :8888 | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1"
        result = subprocess.check_output(cmd, shell=True).decode().strip()
        return result.split('\n')[0] if result else "192.168.0.15"
    except:
        return "192.168.0.15"

def log_event(subject, action, target, status_code, detail):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip = get_real_attacker_ip() if subject == "RED" else "SYSTEM"
    
    # CSV 저장 (레드팀 결과와 동일한 구조로 맞춤)
    entry = f"{now},{ip},{action},{target},{status_code},{detail}\n"
    
    with open(SCAN_FILE, "a", encoding="utf-8") as f:
        f.write(entry)
        f.flush()

if __name__ == "__main__":
    if not os.path.exists(SCAN_FILE):
        with open(SCAN_FILE, "w", encoding="utf-8") as f:
            f.write("timestamp,attacker_ip,attack_type,endpoint,result,severity\n")
    print("🚀 [통합 CSV 모드] 관제 엔진 가동 중...")