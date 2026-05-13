import streamlit as st
import pandas as pd
import os
import subprocess
import time

st.set_page_config(page_title="Red-Team Console", layout="wide")
SCAN_FILE = 'scan_results.csv'

# 메인 타이틀
st.title("🎯 Target: crAPI 취약점 분석")
st.markdown("---")

# 레이아웃 설정 (image_46f8ba.png 스타일)
col1, col2 = st.columns([1, 3])

with col1:
    st.subheader("🔍 위협 분석 리포트")
    # 이전 UI UX 스타일 반영
    st.info("SQL Injection: 대기 중")
    st.warning("Nmap: 대기 중")
    st.divider()
    
    if st.button("🔄 데이터 초기화"):
        if os.path.exists(SCAN_FILE):
            os.remove(SCAN_FILE)
            st.rerun()

with col2:
    if not os.path.exists(SCAN_FILE):
        # [중요] 데이터가 없으면 스캔 버튼 표시
        st.error("데이터 파일(scan_results.csv)이 존재하지 않습니다.")
        if st.button("🚀 전수 취약점 스캔 가동"):
            with st.status("🕵️ 실시간 침투 분석 수행 중...", expanded=True) as status:
                # api_scanner.py 실행
                process = subprocess.Popen(["python3", "-u", "api_scanner.py"], stdout=subprocess.PIPE, text=True)
                for line in iter(process.stdout.readline, ""):
                    st.code(line.strip())
                process.wait()
                status.update(label="✅ 분석 완료!", state="complete")
            time.sleep(1)
            st.rerun()
    else:
        # 데이터가 있으면 결과 표시
        df = pd.read_csv(SCAN_FILE)
        if not df.empty:
            st.subheader("📑 실시간 공격 탐지 매트릭스")
            st.table(df) # image_46f8ba.png 처럼 깔끔한 표 형식

time.sleep(2)
st.rerun()