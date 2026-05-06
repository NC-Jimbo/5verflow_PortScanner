import time
import subprocess
import re
from datetime import datetime

# 설정 경로
LOG_PATH = "/var/log/nginx/access.log"
MATRIX_PATH = "attack_detection_matrix.md"

def get_fw_rules():
    """현재 방화벽(iptables)의 차단 목록을 가져옵니다."""
    result = subprocess.run(['sudo', 'iptables', '-L', 'INPUT', '-n'], capture_output=True, text=True)
    return result.stdout

def monitor_combat():
    print("🛰️ [System] 공방 탐지 관제 모드 가동 중...")
    last_fw_rules = get_fw_rules()
    
    with open(LOG_PATH, "r") as f:
        f.seek(0, 2)
        while True:
            # 1. 공격 탐지 (Red)
            line = f.readline()
            if line:
                if any(p in line.lower() for p in ["union", "select", "../", "etc/passwd"]):
                    attacker_ip = line.split()[0]
                    log_event("RED", "Attack", attacker_ip, "Launched", "위험 패턴 감지")

            # 2. 방어 탐지 (Blue) - 5초마다 방화벽 변화 감시
            current_fw_rules = get_fw_rules()
            if current_fw_rules != last_fw_rules:
                # 새로 추가된 차단 IP 탐색 (단순 예시 로직)
                new_rules = [r for r in current_fw_rules.split('\n') if r not in last_fw_rules.split('\n')]
                for rule in new_rules:
                    if "DROP" in rule:
                        log_event("BLUE", "Defense", "IP Filter", "Blocked", "방화벽 차단 확인")
                last_fw_rules = current_fw_rules
            
            time.sleep(0.1)

def log_event(subject, action, target, result, detail):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    emoji = "🔴" if subject == "RED" else "🔵"
    entry = f"| {now} | {emoji} {subject} | {action} | {target} | **{result}** | {detail} |\n"
    with open(MATRIX_PATH, "a", encoding="utf-8") as f:
        f.write(entry)
    print(f"📝 {emoji} {subject} 활동 기록 완료")

if __name__ == "__main__":
    monitor_combat()