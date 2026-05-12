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
    with open(MATRIX_PATH, "a", encoding="utf-8") as f:
        f.write(entry)
        f.flush()

def run_optimized():
    # 실행 시 파일 초기화
    with open(MATRIX_PATH, "w", encoding="utf-8") as f:
        f.write("| 일시 | 주체 | 행위 | 타겟 | 결과 | 상세 내용 |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")

    print(f"🚀 [최적화 가동] 서버 보호 로직이 적용된 관제 엔진 시작...")

    # 1. --tail 0: 이전 로그를 무시하고 실행 시점부터 분석하여 초기 과부하 방지
    cmd = ["sudo", "docker", "logs", "-f", "--tail", "0", CONTAINER_NAME]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        for line in process.stdout:
            # 2. [서버 생존 핵심] CPU 가용성 확보를 위한 미세 지연
            time.sleep(0.03) 
            
            line = line.strip().lower()
            if not line or len(line) > 500: continue # 3. 너무 긴 비정상 로그(DDoS 등)는 무시하여 메모리 보호

            # 상태 코드 추출 (공백 기준 분할 후 3자리 숫자 탐색)
            parts = line.split()
            status_code = next((p for p in parts if p.isdigit() and len(p) == 3), "???")

            # 탐지 로직 실행
            for attack_name, keywords in ATTACK_PATTERNS.items():
                if any(key in line for key in keywords):
                    log_event("RED", "Attack", "crAPI-Target", status_code, attack_name)
                    # 4. 동일 패턴 폭주 시 시스템 마비를 막기 위한 브레이크
                    time.sleep(0.01) 
                    break
                    
    except KeyboardInterrupt:
        process.terminate()
    except Exception as e:
        print(f"⚠️ 긴급: 시스템 보호를 위해 엔진이 일시 정지되었습니다: {e}")

if __name__ == "__main__":
    run_optimized()