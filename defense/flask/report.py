"""
보안 리포트 생성기
스캔 결과 + 전파 분석을 합산해 JSON/HTML 보고서를 생성한다.
"""
from __future__ import annotations
import time
from propagation import get_all_propagations, NODES


def generate_report(scan_result: dict) -> dict:
    """
    스캐너 결과와 전파 분석을 합쳐 종합 보안 리포트를 반환.
    """
    propagations = get_all_propagations()

    # 전파별 영향도 맵
    impact_map = {p["entry"]: p["impact_percent"] for p in propagations}

    # 취약점 전체 목록 (우선순위 정렬)
    all_vulns = []
    for api_id, tests in scan_result.get("results", {}).items():
        for test in tests:
            if test.get("passed"):
                all_vulns.append({
                    "api": api_id,
                    "test": test["test"],
                    "cve": test.get("cve", "N/A"),
                    "severity": test.get("severity", 3),
                    "detail": test.get("detail", ""),
                    "system_impact": impact_map.get(api_id, 0),
                })

    all_vulns.sort(key=lambda x: (x["severity"], -x["system_impact"]))

    # 우선순위 리포트
    priority_fixes = []
    seen_apis: set[str] = set()
    for v in all_vulns:
        if v["api"] not in seen_apis:
            seen_apis.add(v["api"])
            impact = impact_map.get(v["api"], 0)
            priority_fixes.append({
                "api": v["api"],
                "impact_if_fixed": f"전체 시스템의 {impact}% 보호",
                "top_vuln": v["test"],
                "severity_label": {1: "🔴 긴급", 2: "🟠 높음", 3: "🟡 낮음"}.get(v["severity"], ""),
            })

    # 전체 위험도 점수
    total_cvss = 0.0
    vuln_count = 0
    for node in NODES:
        for v in node.vulnerabilities:
            total_cvss += v.get("cvss", 0)
            vuln_count += 1
    avg_cvss = round(total_cvss / vuln_count, 1) if vuln_count else 0

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "project": "5verflow Blue Team – API 취약점 전파 분석",
        "summary": {
            "total_apis": len(NODES),
            "total_vulnerabilities": vuln_count,
            "detected_by_scanner": scan_result.get("summary", {}).get("vulnerabilities_found", 0),
            "average_cvss": avg_cvss,
            "highest_impact_entry": max(impact_map, key=impact_map.get) if impact_map else "N/A",
        },
        "priority_fixes": priority_fixes,
        "all_vulnerabilities": all_vulns,
        "propagation_analysis": propagations,
        "executive_summary": _executive_summary(all_vulns, impact_map),
        "technical_summary": _technical_summary(scan_result),
    }


def _executive_summary(all_vulns: list[dict], impact_map: dict) -> dict:
    """경영진용 요약."""
    critical = [v for v in all_vulns if v["severity"] == 1]
    return {
        "risk_level": "🔴 위험" if critical else "🟡 주의",
        "key_message": (
            f"총 {len(all_vulns)}개 취약점 발견. "
            f"긴급 조치 필요 {len(critical)}건. "
            f"user-api 보안 강화 시 전체 시스템의 {impact_map.get('user-api', 0)}% 보호 가능."
        ),
        "business_impact": "카드 결제 정보 노출 및 전체 사용자 계정 탈취 위험",
        "recommended_timeline": "긴급 항목 48시간 내 조치 권고",
    }


def _technical_summary(scan_result: dict) -> dict:
    """개발팀용 기술 요약."""
    fixes = []
    for api, tests in scan_result.get("results", {}).items():
        for t in tests:
            if t.get("passed"):
                cve = t.get("cve", "")
                fixes.append({
                    "api": api,
                    "vulnerability": t["test"],
                    "cve": cve,
                    "fix": _fix_guide(t["test"]),
                })
    return {"fixes": fixes}


def _fix_guide(test_name: str) -> str:
    guides = {
        "JWT Weak Secret": "os.urandom(32).hex() 등으로 강력한 secret 생성, 환경변수로 관리",
        "JWT None Algorithm": "algorithms=['HS256'] 처럼 허용 알고리즘 명시, none 제외",
        "No Token Expiry": "jwt.encode({'exp': datetime.utcnow() + timedelta(hours=1), ...})",
        "SQL Injection": "cursor.execute('SELECT ... WHERE name LIKE ?', ('%' + q + '%',))",
        "Error Info Disclosure": "try/except에서 제네릭 에러 메시지 반환, 쿼리 내용 숨기기",
        "BFLA - Unprotected Internal Endpoint": "/internal/ 경로에 IP 화이트리스트 또는 내부 네트워크 전용 미들웨어",
        "Sensitive Data Exposure (Card Numbers)": "카드번호 AES-256 암호화, PCI-DSS 준수",
        "BOLA - Unauthorized User List Access": "JWT 인증 데코레이터 추가, 자신의 데이터만 조회 가능하도록 제한",
    }
    return guides.get(test_name, "보안 코드 리뷰 및 OWASP API Security Top 10 가이드 참조")
