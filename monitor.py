import subprocess
import time
import os
from datetime import datetime

# 설정
CONTAINER_NAME = "crapi-web"
MATRIX_PATH = "attack_detection_matrix.md"

# 탐지 패턴 (Velog 시나리오 기반)
ATTACK_PATTERNS = {
    "Nmap Scanning": ["nmap", "nmap/"],
    "SQL Injection": ["union", "select", "insert", "drop", "--", "' or '", "%27"],
    "XSS Attack": ["<script", "alert(", "onclick"],
    "BOLA (API Abuse)": ["/api/v1/user/", "/api/v1/admin/"]
}

def log_event(subject, action, target, status_code, detail):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    emoji = "🔴" if subject == "RED" else "🔵"
    result = "⚠️ Success" if status_code == "200" else f"Blocked({status_code})"
    
    entry = f"| {now} | {emoji} {subject} | {action} | {target} | **{result}** | {detail} |\n"
    # "a" 모드로 열어야 기존 기록 뒤에 누적됩니다.
    with open(MATRIX_PATH, "a", encoding="utf-8") as f:
        f.write(entry)
        f.flush()

def run_optimized():
    # [수정 포인트] 실행 시 파일을 새로 만들지(w) 않고, 없을 때만 헤더를 생성합니다.
    if not os.path.exists(MATRIX_PATH):
        with open(MATRIX_PATH, "w", encoding="utf-8") as f:
            f.write("| 일시 | 주체 | 행위 | 타겟 | 결과 | 상세 내용 |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
        print(f"📁 새 로그 파일을 생성했습니다.")
    else:
        print(f"📚 기존 로그에 이어서 기록을 시작합니다. (누적 모드)")

    print(f"🚀 [최적화 가동] 서버 보호 로직이 적용된 관제 엔진 시작...")

    # 1. --tail 0: 실행 시점부터 들어오는 공격만 분석 (서버 부하 방지)
    cmd = ["sudo", "docker", "logs", "-f", "--tail", "0", CONTAINER_NAME]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        for line in process.stdout:
            time.sleep(0.03) # 2. CPU 가용성 확보
            
            line = line.strip().lower()
            if not line or len(line) > 500: continue # 3. 비정상 로그 무시

            parts = line.split()
            status_code = next((p for p in parts if p.isdigit() and len(p) == 3), "???")

            for attack_name, keywords in ATTACK_PATTERNS.items():
                if any(key in line for key in keywords):
                    log_event("RED", "Attack", "crAPI-Target", status_code, attack_name)
                    time.sleep(0.01) # 4. 폭주 방지 브레이크
                    break
                    
    except KeyboardInterrupt:
        process.terminate()
    except Exception as e:
        print(f"⚠️ 긴급: 엔진 일시 정지: {e}")

if __name__ == "__main__":
    run_optimized()