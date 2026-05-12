import subprocess
import os
from datetime import datetime
import sys

# 1. 설정 (방금 확인한 컨테이너 이름 적용)
CONTAINER_NAME = "crapi-web"
MATRIX_PATH = "attack_detection_matrix.md"

# 2. 공격 탐지 패턴
ATTACK_PATTERNS = {
    "SQL Injection": ["union", "select", "insert", "drop", "--", "' or '", "%27"],
    "XSS": ["<script", "alert(", "onclick", "<img"],
    "BOLA/API": ["/api/v1/user/", "/api/v1/admin/"]
}

def log_event(subject, action, target, status_code, detail):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    emoji = "🔴" if subject == "RED" else "🔵"
    result = "⚠️ Success" if status_code == "200" else f"Blocked({status_code})"
    
    entry = f"| {now} | {emoji} {subject} | {action} | {target} | **{result}** | {detail} |\n"
    with open(MATRIX_PATH, "a", encoding="utf-8") as f:
        f.write(entry)
        f.flush()
    
    # 터미널에 즉시 출력 (지연 없음)
    print(f"\n🚀 [REAL-TIME DETECTED] {detail} | Status: {status_code}", flush=True)

def monitor_direct():
    print(f"🛰️ [System] Docker 다이렉트 스트리밍 가동 중... ({CONTAINER_NAME})", flush=True)
    
    if not os.path.exists(MATRIX_PATH):
        with open(MATRIX_PATH, "w", encoding="utf-8") as f:
            f.write("| 일시 | 주체 | 행위 | 타겟 | 결과 | 상세 내용 |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")

    # [핵심] Docker 로그를 실시간 파이프로 직접 가져옵니다. (파일 시스템 우회)
    cmd = ["sudo", "docker", "logs", "-f", "--tail", "0", CONTAINER_NAME]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    print("🔍 분석 대기 중... 공격을 날려보세요.", flush=True)

    try:
        for line in process.stdout:
            line = line.strip()
            if not line: continue
            
            # 실시간 데이터 흐름 시각화
            sys.stdout.write(f"\r📡 [Streaming] {line[:70]}...")
            sys.stdout.flush()

            # 상태 코드 추출 로직
            parts = line.split()
            status_code = "???"
            for p in parts:
                if p.isdigit() and len(p) == 3:
                    status_code = p
                    break
            
            line_lower = line.lower()
            for attack_name, keywords in ATTACK_PATTERNS.items():
                if any(key in line_lower for key in keywords):
                    attacker_ip = parts[0] if parts else "Unknown"
                    log_event("RED", "Attack", attacker_ip, status_code, attack_name)
                    break
                    
    except KeyboardInterrupt:
        process.terminate()
        print("\n👋 종료")

if __name__ == "__main__":
    monitor_direct()
    #test