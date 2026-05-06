import time
import re
import os
from datetime import datetime

# 1. 감시할 로그 및 기록할 파일 경로 설정
LOG_PATH = "/var/log/nginx/access.log" # crAPI가 돌고 있는 Nginx 로그
MATRIX_PATH = "attack_detection_matrix.md"

# 2. 공격 탐지 패턴 (시그니처 기반)
ATTACK_PATTERNS = {
    "SQL Injection": r"(union|select|insert|update|delete|drop|where|from)",
    "Path Traversal": r"(\.\.\/|\/etc\/passwd|\/windows\/win\.ini)",
    "XSS": r"(<script|alert|onclick|onerror)",
    "API Brute Force": r"(404|401|403)" # 짧은 시간에 발생하는 에러 패턴
}

def log_to_matrix(subject, action, target, result, detail):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    emoji = "🔵" if subject == "BLUE" else "🔴"
    entry = f"| {now} | {emoji} {subject} | {action} | {target} | {result} | {detail} |\n"
    with open(MATRIX_PATH, "a", encoding="utf-8") as f:
        f.write(entry)

def block_ip(ip):
    # 실제 방어 동작: iptables를 이용한 IP 차단
    print(f"🛡️ [DEFENSE] 차단 실행: {ip}")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    return True

def start_monitoring():
    print("🕵️ [System] 실시간 은밀한 탐지 모드 가동 시작...")
    
    # 로그 파일 끝으로 이동 (실시간 감시 준비)
    try:
        with open(LOG_PATH, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                # 공격 패턴 매칭 확인
                for attack_name, pattern in ATTACK_PATTERNS.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        # 공격자 IP 추출 (Nginx 로그 첫 번째 필드)
                        attacker_ip = line.split()[0]
                        print(f"🚨 [DETECTION] {attack_name} 감지! IP: {attacker_ip}")
                        
                        # 1. 공격 탐지 로그 남기기
                        log_to_matrix("BLUE", "Detection", attacker_ip, "**Success**", f"{attack_name} 패턴 식별")
                        
                        # 2. 실시간 방어 (IP 차단)
                        if block_ip(attacker_ip):
                            # 3. 방어 결과 로그 남기기
                            log_to_matrix("BLUE", "Defense", attacker_ip, "**Blocked**", "iptables DROP 정책 적용 완료")
    except FileNotFoundError:
        print(f"❌ [Error] 로그 파일을 찾을 수 없습니다: {LOG_PATH}")

if __name__ == "__main__":
    start_monitoring()