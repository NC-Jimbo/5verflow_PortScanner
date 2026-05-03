# sy99 - 2025-05-03 Training Report
## 📚 Today's Objectives
- [x] SQL Injection 공격 실습
- [x] API Discovery 자동화
- [x] BOLA 취약점 분석

---

## 🎯 1. SQL Injection Attack

### Target
- **Application:** OWASP Juice Shop
- **Endpoint:** `/rest/user/login`

### Attack Method
```sql
Email: ' OR 1=1--
Password: anything


