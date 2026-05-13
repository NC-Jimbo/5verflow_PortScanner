import streamlit as st
import pandas as pd
import time
import os
from datetime import datetime

# 페이지 설정
st.set_page_config(page_title="Purple-Team Control Tower", layout="wide")

# 세션 상태 초기화 (차단 리스트 보존용)
if 'blocked_ips' not in st.session_state:
    st.session_state.blocked_ips = []

st.title("🛡️ 퍼플팀 통합 보안 관제 및 능동 대응 컨트롤 타워")

# --- 사이드바: 분석 및 대응 도구 ---
with st.sidebar:
    st.header("🔍 위협 분석 리포트")
    st.error("🔴 **SQL Injection**: 위험 (패치 필요)")
    st.warning("🟡 **Nmap**: 주의 (정찰 포착)")
    
    st.markdown("---")
    st.header("🚫 실시간 차단 관리")
    if st.session_state.blocked_ips:
        for ip in st.session_state.blocked_ips:
            st.code(f"Blocked: {ip}")
    else:
        st.write("현재 차단된 IP가 없습니다.")
        
    if st.button("♻️ 차단 리스트 초기화"):
        st.session_state.blocked_ips = []
        st.rerun()

# --- 메인 화면: 관측 및 제어 ---
LOG_FILE = 'attack_detection_matrix.md'
col1, col2 = st.columns([3, 1])

with col1:
    st.subheader("📑 실시간 공격 탐지 매트릭스")
    placeholder = st.empty()

with col2:
    st.subheader("⚡ 즉각 대응 조치")
    # 시연용 IP 선택 (실제로는 로그에서 추출)
    target_ip = st.text_input("차단할 공격 IP 입력", value="192.168.0.15")
    
    if st.button("🚨 해당 IP 즉시 차단"):
        if target_ip not in st.session_state.blocked_ips:
            st.session_state.blocked_ips.append(target_ip)
            # [시연 핵심] 실제 시스템에 명령을 내리는 부분 (시뮬레이션)
            st.success(f"IP {target_ip} 가 방화벽에 등록되었습니다.")
            # 실제 운영 환경이라면 여기서 os.system("iptables...") 등을 실행
        else:
            st.info("이미 차단된 IP입니다.")

# 로그 갱신 루프
while True:
    try:
        if os.path.exists(LOG_FILE):
            df = pd.read_csv(LOG_FILE, sep='|', skipinitialspace=True).dropna(axis=1, how='all').iloc[1:]
            df.columns = [c.strip() for c in df.columns]
            
            with placeholder.container():
                # 최신 로그 50개만 표시 (성능 최적화)
                st.dataframe(df.sort_index(ascending=False).head(50), use_container_width=True, height=500)
                st.caption(f"최종 업데이트: {datetime.now().strftime('%H:%M:%S')} (누적 로그: {len(df)}건)")
    except:
        pass
    
    time.sleep(1.5)