# Service Web App

이 폴더는 IDS 대시보드와 분리된 업무용 웹 서비스입니다.

## 역할

- `flask/`: IDS / Suricata 모니터링 대시보드
- `service/`: MSSQL `Employees` 데이터를 사용하는 업무 웹앱

## 기능

- 로그인 페이지와 세션 기반 인증
- 역할 기반 권한 분리
- 직원 목록 조회
- 이름, 이메일, 전화번호 검색
- 직원 상세 조회
- 관리자 전용 연락처, 이메일, 주소 수정
- `/health` 헬스체크

민감정보는 화면에서 마스킹해서 표시합니다.

## 권한 모델

- `admin`: 직원 목록, 상세 조회, 연락처 수정 가능
- `viewer`: 직원 목록, 마스킹된 상세 정보 조회만 가능

기본 계정은 환경변수로 바꿀 수 있습니다.

- `admin / Admin123!`
- `viewer / Viewer123!`

## 실행 방법

루트에서 서비스 전용 스택 실행:

```bash
docker compose -f docker-compose.service.yml up --build
```

접속 주소:

- 업무 서비스: `http://localhost:8000`
- IDS 대시보드: 기존 `flask/` 앱을 별도로 실행

서비스 컨테이너는 `secure_app.py`를 진입점으로 사용합니다.

## 로컬 실행

```bash
cd service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
export $(grep -v '^#' .env | xargs)
python3 secure_app.py
```

로컬 실행 시 MSSQL은 별도로 떠 있어야 합니다.