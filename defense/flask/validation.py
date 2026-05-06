"""
스캐너 결과와 Suricata 알럿을 연결해 탐지 커버리지를 계산한다.
"""
from __future__ import annotations

from typing import Iterable


# 테스트별 알럿 매칭 키워드 (signature/category에서 검색)
TEST_ALERT_KEYWORDS: dict[str, list[str]] = {
    "JWT Weak Secret": ["jwt", "token", "auth", "credential"],
    "JWT None Algorithm Bypass": ["jwt", "none", "token", "auth bypass"],
    "SQL Injection": ["sql", "sqli", "injection", "union", "or 1=1"],
    "BFLA - Unprotected Internal Endpoint": ["bfla", "internal", "authorization", "privilege"],
    "Sensitive Data Exposure (Card Numbers)": ["card", "sensitive", "pci", "data exposure"],
    "BOLA - Unauthorized User List Access": ["bola", "idor", "object level authorization", "unauthorized"],
}


def _normalize_alert_text(alert: dict) -> str:
    signature = str(alert.get("signature", ""))
    category = str(alert.get("category", ""))
    return f"{signature} {category}".lower()


def _count_matches(alerts: Iterable[dict], keywords: list[str]) -> int:
    if not keywords:
        return 0
    count = 0
    for alert in alerts:
        text = _normalize_alert_text(alert)
        if any(k.lower() in text for k in keywords):
            count += 1
    return count


def validate_detection(scan_result: dict, alerts: list[dict]) -> dict:
    """취약점 발견 결과 기준으로 Suricata 탐지 커버리지를 계산한다."""
    results = scan_result.get("results", {})
    findings: list[dict] = []

    for api_name, tests in results.items():
        for test in tests:
            if not test.get("passed"):
                continue

            test_name = str(test.get("test", ""))
            keywords = TEST_ALERT_KEYWORDS.get(test_name, [])
            matched = _count_matches(alerts, keywords)

            findings.append(
                {
                    "api": api_name,
                    "test": test_name,
                    "cve": test.get("cve", "N/A"),
                    "severity": test.get("severity", 3),
                    "detected": matched > 0,
                    "matched_alerts": matched,
                    "match_keywords": keywords,
                }
            )

    total = len(findings)
    detected = len([f for f in findings if f["detected"]])
    undetected = total - detected

    return {
        "summary": {
            "total_vulnerabilities": total,
            "detected": detected,
            "undetected": undetected,
            "coverage_percent": round((detected / total) * 100, 1) if total else 0.0,
            "alerts_analyzed": len(alerts),
        },
        "findings": findings,
    }
