# 5verflow_PortScanner - Blue Team

## 1. R&R (Roles)
**JIMBO**: Infrastructure & System Integration
**서영님**: Suricata Rules & Detection Policy
**승윤님**: Flask Dashboard & Log Parsing

## 2. Data Pipeline
**Log Source**: /project/blueteam/defense/suricata/eve.json
**Format**: JSON Lines (Line-by-line parsing 필요)
**Process**: Suricata Alert 발생 → eve.json 적재 → Flask에서 실시간 파싱 → UI 시각화

## 3. Work Directory
**Main**: /project/blueteam/defense/
**Target**: /project/crapi/ (방어 대상 서버)

## 4. Note
- **Account**: `user02` / `1234`
- **Test**: `eve.json` 내 샘플 데이터 10줄 삽입됨 (엔진 구동 전 활용 가능)
- **Config**: `suricata.yaml` (파일명 주의)
