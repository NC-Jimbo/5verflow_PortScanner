import streamlit as st
import pandas as pd
import os
import time

st.set_page_config(page_title="Purple-Team Tower", layout="wide")
SCAN_FILE = 'scan_results.csv'

# 1. 세션 상태로 차단 목록 유지
if 'blocked_ips' not in st.session_state:
    st.session_state.blocked_ips = []

st.title("🛡️ 퍼플팀 통합 보안 관제 및 능동 대응 컨트롤 타워")
st.markdown("---")

# 데이터 로드
def load_data():
    if os.path.exists(SCAN_FILE):
        try: return pd.read_csv(SCAN_FILE)
        except: return pd.DataFrame()
    return pd.DataFrame()

df = load_data()

# --- 좌측 사이드바: 실시간 차단 목록 및 새로 고침 ---
with st.sidebar:
    st.header("🚫 실시간 차단 목록")
    
    # [지시 반영] 초기화 버튼 삭제 및 새로 고침 버튼 추가
    if st.button("🔄 화면 새로 고침"):
        st.rerun()
    
    st.divider()

    # 차단 리스트 출력 로직 (image_46f1b9.png 모순 해결)
    if not st.session_state.blocked_ips:
        st.info("현재 차단된 IP가 없습니다.")
    else:
        # 차단된 IP가 하나라도 있으면 위 메시지는 사라지고 목록만 표시됨
        for ip in st.session_state.blocked_ips:
            st.error(f"차단됨: {ip}")

# --- 우측 메인 영역 ---
col_main, col_action = st.columns([3, 1])

with col_main:
    st.subheader("📑 실시간 공격 탐지 매트릭스")
    if not df.empty:
        st.table(df.iloc[::-1])
    else:
        st.info("탐지된 위협이 없습니다. 레드팀 콘솔에서 스캔을 시작하십시오.")

with col_action:
    st.subheader("⚡ 즉각 대응")
    detected_ip = df.iloc[-1]['attacker_ip'] if not df.empty else "192.168.0.15"
    target_ip = st.text_input("차단할 공격 IP", value=detected_ip)
    
    if st.button("🚨 해당 IP 즉시 차단"):
        if target_ip not in st.session_state.blocked_ips:
            st.session_state.blocked_ips.append(target_ip)
            # 성공 메시지 출력 후 즉시 새로고침하여 사이드바 업데이트
            st.success(f"{target_ip} 차단 완료")
            time.sleep(0.5)
            st.rerun()

# 실시간 자동 갱신 (2초 간격)
time.sleep(2)
st.rerun()