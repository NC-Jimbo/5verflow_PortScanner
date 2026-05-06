# 승윤님 Flask Dashboard & Log Parsing

## 파일 구조
```
defense/flask/
├── app.py           ← Flask 앱 + REST API + 대시보드 UI
├── parser.py        ← eve.json 파서 (LogParser 클래스)
└── requirements.txt ← 의존성 목록
```

## 빠른 시작

### 1. 의존성 설치
```bash
cd defense/flask
pip install -r requirements.txt
```

### 2. 실행
```bash
python app.py
```

### 3. 브라우저에서 열기
```
http://localhost:5000
```

---

## eve.json 경로 설정

기본값: `../suricata/eve.json` (상대 경로)

다른 경로로 변경하려면 환경변수로 설정:
```bash
# Linux/Mac
EVE_JSON_PATH=/var/log/suricata/eve.json python app.py

# Windows
set EVE_JSON_PATH=C:\path\to\eve.json && python app.py
```

---

## API 엔드포인트

| 경로 | 설명 |
|------|------|
| `GET /` | 대시보드 메인 페이지 |
| `GET /api/alerts` | 전체 알럿 목록 (JSON) |
| `GET /api/stats` | 통계 요약 (카테고리/심각도/IP/타임라인) |
| `GET /api/timeline` | 시간대별 공격 건수 |

### /api/stats 응답 예시
```json
{
  "total": 10,
  "risk_score": 22,
  "category": { "Injection": 2, "Broken Object Level Authorization": 3, ... },
  "severity": { "1": 5, "2": 3, "3": 2 },
  "top_ips": [["1.2.3.4", 3], ["5.6.7.8", 3]],
  "timeline": { "10:00": 1, "10:05": 1, ... }
}
```

---

## 대시보드 기능

- **요약 카드**: 전체 알럿 수, 심각도별 카운트, 위험도 점수
- **카테고리 차트**: 공격 유형별 가로 막대 차트 (D3.js)
- **타임라인 차트**: 시간대별 공격 발생 현황 라인 차트
- **상위 공격자 IP**: IP별 공격 횟수 가로 막대 차트
- **알럿 테이블**: 최근 50건 알럿 목록 (심각도 배지 포함)
- **5초 자동 갱신**: Suricata가 eve.json에 새 로그 추가 시 자동 반영

---

## 위험도 점수 계산

```
위험도 점수 = (Severity 1 건수 × 3) + (Severity 2 건수 × 2) + (Severity 3 건수 × 1)
```

- Severity 1 (긴급): BOLA, SQL Injection, Brute Force 등
- Severity 2 (높음): Mass Assignment, Directory Traversal, XSS 등
- Severity 3 (낮음): DoS, 미탐지 접근 등

---

## Docker 연동 (JIMBO님과 협업 시)

```dockerfile
# defense/flask/Dockerfile 생성 예시
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
ENV EVE_JSON_PATH=/suricata/eve.json
CMD ["python", "app.py"]
```

```yaml
# docker-compose에 추가
flask-dashboard:
  build: ./defense/flask
  ports:
    - "5000:5000"
  volumes:
    - ./defense/suricata:/suricata:ro
```
