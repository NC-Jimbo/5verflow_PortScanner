import streamlit as st
import pandas as pd
import os
import time
import plotly.express as px

# 1. 설정 및 파일 경로
st.set_page_config(page_title="5verflow Purple-Team Tower", layout="wide")
SCAN_FILE = 'scan_results.csv'
BLACKLIST_FILE = 'blacklist.txt'

# 2. 데이터 로드 (팀장님 로그 포맷: 시간, 유형, 상세, 결과, 위험도, IP)
def load_safe_data():
    if not os.path.exists(SCAN_FILE) or os.path.getsize(SCAN_FILE) == 0:
        return pd.DataFrame()
    try:
        df = pd.read_csv(SCAN_FILE, header=None)
        if len(df.columns) >= 6:
            df = df.iloc[:, :6]
            # 팀장님 로그 순서대로 이름 붙이기
            df.columns = ['timestamp', 'type', 'detail', 'result', 'severity', 'attacker_ip']
            # 대시보드 출력용 순서 재배치 (IP를 두 번째로)
            df = df[['timestamp', 'attacker_ip', 'detail', 'type', 'result', 'severity']]
            
            if "timestamp" in str(df.iloc[0, 0]):
                df = df.iloc[1:].reset_index(drop=True)
        
        df['type'] = df['type'].astype(str).str.strip()
        df['attacker_ip'] = df['attacker_ip'].astype(str).str.strip()
        return df
    except:
        return pd.DataFrame()

def block_ip(ip):
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'w') as f: pass
    with open(BLACKLIST_FILE, 'a') as f:
        f.write(f"{ip}\n")

# 데이터 및 블랙리스트 로드
df = load_safe_data()
blacklist = []
if os.path.exists(BLACKLIST_FILE):
    with open(BLACKLIST_FILE, 'r') as f:
        blacklist = [l.strip() for l in f.readlines()]

# 3. [복구] 사이드바 제어 센터
with st.sidebar:
    st.title("🎮 제어 센터")
    if st.button("🔄 대시보드 새로고침"):
        st.rerun()
    
    st.divider()
    st.subheader("🚀 레드팀 액션")
    if st.button("🔍 네트워크 포트 스캔 실행"):
        with st.spinner("Nmap 스캔 중..."):
            now = time.strftime('%Y-%m-%d %H:%M:%S')
            # 팀장님 규격: 시간, 유형, 상세, 결과, 위험도, IP
            log = f"{now},PORT_SCAN,HTTP (Port 80),VULNERABLE,MEDIUM,172.31.34.20\n"
            with open(SCAN_FILE, 'a') as f:
                f.write(log)
            st.success("스캔 성공!")
            time.sleep(0.5)
            st.rerun()

    st.divider()
    st.subheader("🚫 차단된 IP 목록")
    if blacklist:
        for ip in blacklist:
            st.code(ip)
        if st.button("🗑️ 전체 차단 해제"):
            if os.path.exists(BLACKLIST_FILE): os.remove(BLACKLIST_FILE)
            st.rerun()
    else:
        st.write("차단 내역 없음")

# 4. 메인 화면 지표 및 분류
st.title("🛡️ 5verflow 통합 보안 관제 플랫폼")
st.markdown("---")

if not df.empty:
    # 유형에 'PORT'가 포함되면 정찰 탭으로
    is_recon = df['type'].str.contains('PORT|SCAN|NMAP', case=False, na=False)
    recon_df = df[is_recon]
    api_df = df[~is_recon]
else:
    recon_df = pd.DataFrame()
    api_df = pd.DataFrame()

c1, c2, c3, c4 = st.columns(4)
c1.metric("총 활동 로그", len(df))
c2.metric("탐지된 취약 포트", len(recon_df))

# 고위험 산출
high_count = 0
if not df.empty:
    def is_high(v):
        try: return str(v).upper() in ['HIGH', 'CRITICAL'] or float(v) >= 7.0
        except: return False
    high_count = len(df[df['severity'].apply(is_high)])
c3.metric("고위험 탐지", high_count)
c4.metric("시스템 상태", "⚠️ 위협 탐지" if not df.empty else "✅ 정상")

# 5. 탭 구성
st.markdown("### 📊 실시간 보안 분석 매트릭스")
tab1, tab2, tab3 = st.tabs(["🔴 서비스 침투 로그", "🔍 네트워크 정찰 현황", "📈 공격 통계"])

def render_table(data, key_tag):
    if not data.empty:
        h = st.columns([2, 2, 3, 2, 1, 1.5])
        labels = ["시간", "공격자 IP", "상세 정보", "유형", "결과", "위험도"]
        for col, label in zip(h, labels): col.write(f"**{label}**")
        
        for i, row in data.tail(10)[::-1].iterrows():
            r = st.columns([2, 2, 3, 2, 1, 1.5])
            r[0].write(row['timestamp'])
            ip = str(row['attacker_ip'])
            r[1].write(f"🚫 {ip}" if ip in blacklist else ip)
            r[2].write(row['detail'])
            r[3].write(row['type'])
            r[4].write(row['result'])
            
            # 위험도 및 차단 버튼
            btn_col = r[5].columns([1, 2])
            btn_col[0].write(row['severity'])
            if ip not in blacklist:
                if btn_col[1].button("차단", key=f"{key_tag}_{i}"):
                    block_ip(ip)
                    st.rerun()
            else: btn_col[1].write("✅")
    else:
        st.info("데이터가 없습니다.")

with tab1: render_table(api_df, "api")
with tab2: render_table(recon_df, "recon")
with tab3:
    if not df.empty:
        st.plotly_chart(px.bar(df, x='type', color='type'))