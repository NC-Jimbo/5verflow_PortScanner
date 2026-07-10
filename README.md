# 5verflow_PortScanner - Blue Team

## 1. R&R (Roles)
- **JIMBO**: Infrastructure & System Integration
- **서영님**: Suricata Rules & Detection Policy
- **승윤님**: Flask Dashboard & Log Parsing

## 2. Data Pipeline
- **Log Source**: /project/blueteam/defense/suricata/eve.json
- **Format**: JSON Lines (Line-by-line parsing 필요)
- **Process**: Suricata Alert 발생 → eve.json 적재 → Flask에서 실시간 파싱 → UI 시각화

## 3. Work Directory
- **Main**: /project/blueteam/defense/
- **Target**: /project/crapi/ (방어 대상 서버)

## 4. Note
- **Account**: `user02` / `1234`
- **Test**: `eve.json` 내 샘플 데이터 10줄 삽입됨 (엔진 구동 전 활용 가능)
- **Config**: `suricata.yaml` (파일명 주의)


# 5verflow_PortScanner

**팀 CTF 형식 Red Team vs Blue Team 포트 스캐닝 및 공격/방어 연습 프로젝트**

## 프로젝트 개요
- **팀 규모**: 총 7명 (Blue Team 3명, Red Team 3명, Purple Team 1명)
- **진행 방식**: CTF 스타일 공격/방어 연습
  - Red Team: Port Scanner를 활용해 정보 수집 → Brute Force 공격
  - Blue Team: 서버 환경을 강화하고 공격을 방어
  - Purple Team: 중립 및 전체 지원

**목적**: 실제 공격 시나리오를 기반으로 포트 스캐닝, 정보 탈취, 방어 전략을 실습

## 🛠 사용 기술
- AWS EC2 (Ubuntu)
- Python
- Docker
- MSSQL
- OpenSSH (VSCode Remote-SSH)
- Port Scanner

## 👷‍♂️ 나의 주요 역할 (Blue Team - 인프라 담당)
- AWS EC2 Ubuntu 서버 구축 및 운영
- 팀원들을 위한 **VSCode Remote-SSH 접속 가이드** 작성 및 교육
- 개발 환경 구성
  - Python 패키지 설치 및 Docker 컨테이너 환경 구축
  - MSSQL 포트 오픈 및 Port Scanner 연동 준비
  - 팀원별 사용자 계정 생성 및 권한 격리 (계정 충돌 방지)
- 이전 OSINT 프로젝트 경험을 바탕으로 **안정적인 다중 사용자 환경** 구축

## 프로젝트 흐름
1. Blue Team이 서버 환경 구축 및 강화
2. Red Team이 Port Scanner로 취약점 탐지
3. Brute Force 공격 시도 및 방어

---
