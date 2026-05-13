import streamlit as st
import pandas as pd
import os
import subprocess
import time
import socket
from datetime import datetime

st.set_page_config(page_title="Red-Team Console", layout="wide")
SCAN_FILE = 'scan_results.csv'

# [데이터 보존형 포트 스캔 로직]
def run_port_scan_logic():
    target_ip = "127.0.0.1"
    targets = {
        80: {"name": "HTTP", "sev": "MEDIUM"},
        8080: {"name": "crAPI Gateway", "sev": "HIGH"},
        8888: {"name": "Admin Panel", "sev": "CRITICAL"}
    }
    new_results = []
    for port, info in targets.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        if s.connect_ex((target_ip, port)) == 0:
            new_results.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'type': 'PORT_SCAN',
                'detail': f"{info['name']} (Port {port})",
                'status': 'VULNERABLE',
                'severity': info['sev'],
                'attacker_ip': '172.31.34.20'
            })
        s.close()
    
    if new_results:
        df_new = pd.DataFrame(new_results)
        file_exists = os.path.exists(SCAN_FILE)
        # mode='a'로 기존 데이터를 보존하며 하단에 추가
        df_new.to_csv(SCAN_FILE, mode='a', header=not file_exists, index=False)

# 메인 타이틀
st.title("🎯 Target: crAPI 취약점 분석")
st.markdown("---")

col1, col2 = st.columns([1, 3])

with col1:
    st.subheader("🔍 위협 분석 리포트")
    st.info("SQL Injection: 대기 중")
    st.warning("Nmap: 대기 중")
    
    # 1. 포트 스캔 버튼 (항상 노출)
    if st.button("🔍 네트워크 포트 스캔"):
        with st.spinner('포트 분석 중...'):
            run_port_scan_logic()
        st.success("포트 결과가 추가되었습니다.")
        time.sleep(0.5)
        st.rerun()

    st.divider()
    
    # 2. [변경] 데이터 초기화 -> 대시보드 새로고침
    if st.button("🔄 대시보드 새로고침"):
        st.toast("데이터를 새로고침합니다...")
        time.sleep(0.5)
        st.rerun()

with col2:
    # 전수 조사 버튼은 데이터 유무와 관계없이 상단에 항상 배치
    st.subheader("🚀 침투 테스트 엔진")
    if st.button("🔥 전수 취약점 스캔 가동"):
        with st.status("🕵️ 실시간 침투 분석 수행 중...", expanded=True) as status:
            process = subprocess.Popen(["python3", "-u", "api_scanner.py"], stdout=subprocess.PIPE, text=True)
            for line in iter(process.stdout.readline, ""):
                st.code(line.strip())
            process.wait()
            status.update(label="✅ 분석 완료!", state="complete")
        time.sleep(1)
        st.rerun()

    st.divider()

    # 결과 테이블 표시 영역
    if os.path.exists(SCAN_FILE):
        df = pd.read_csv(SCAN_FILE)
        if not df.empty:
            st.subheader("📑 실시간 공격 탐지 매트릭스")
            # 모든 공격 데이터(API + PORT)를 한 표에 깔끔하게 표시
            st.table(df)
    else:
        st.info("현재 누적된 공격 데이터가 없습니다. 스캔 버튼을 눌러 분석을 시작하세요.")