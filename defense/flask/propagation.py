"""
취약점 전파 분석 엔진
API 간 호출 관계를 그래프로 정의하고, BFS로 공격 전파 경로와 영향도를 계산한다.
"""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field


# ── API 노드 정의 ─────────────────────────────────────────────────────────────

@dataclass
class ApiNode:
    id: str
    name: str
    port: int
    tech: str
    vulnerabilities: list[dict] = field(default_factory=list)
    data_sensitivity: int = 1  # 1=낮음, 2=중간, 3=높음 (카드번호/개인정보)


@dataclass
class ApiEdge:
    source: str
    target: str
    call_type: str  # "internal" | "auth" | "payment"
    description: str


# ── 네트워크 정의 ─────────────────────────────────────────────────────────────

NODES: list[ApiNode] = [
    ApiNode(
        id="user-api",
        name="User API",
        port=3001,
        tech="Flask + JWT",
        data_sensitivity=2,
        vulnerabilities=[
            {
                "id": "VULN-001",
                "type": "JWT Weak Secret",
                "severity": 1,
                "cve": "CVE-2021-23440",
                "description": "JWT secret key가 'secret'으로 예측 가능. 토큰 위조 가능.",
                "cvss": 9.1,
            },
            {
                "id": "VULN-002",
                "type": "JWT None Algorithm",
                "severity": 1,
                "cve": "CVE-2022-23529",
                "description": "none 알고리즘 허용으로 서명 없이 토큰 생성 가능.",
                "cvss": 8.8,
            },
            {
                "id": "VULN-003",
                "type": "No Token Expiry",
                "severity": 2,
                "cve": "N/A",
                "description": "JWT 만료시간(exp) 미설정. 탈취된 토큰 영구 사용 가능.",
                "cvss": 6.5,
            },
        ],
    ),
    ApiNode(
        id="product-api",
        name="Product API",
        port=3002,
        tech="Flask + SQLite",
        data_sensitivity=2,
        vulnerabilities=[
            {
                "id": "VULN-004",
                "type": "SQL Injection",
                "severity": 1,
                "cve": "CVE-2021-23639",
                "description": "검색 쿼리에 사용자 입력이 raw SQL로 삽입됨.",
                "cvss": 9.8,
            },
            {
                "id": "VULN-005",
                "type": "Error Info Disclosure",
                "severity": 2,
                "cve": "N/A",
                "description": "SQL 에러 메시지와 쿼리 내용을 응답에 그대로 노출.",
                "cvss": 5.3,
            },
        ],
    ),
    ApiNode(
        id="payment-api",
        name="Payment API",
        port=3003,
        tech="Flask + SQLite",
        data_sensitivity=3,
        vulnerabilities=[
            {
                "id": "VULN-006",
                "type": "Broken Function Level Authorization",
                "severity": 1,
                "cve": "OWASP API5",
                "description": "/internal/ 엔드포인트에 인증 없이 외부 접근 가능.",
                "cvss": 9.0,
            },
            {
                "id": "VULN-007",
                "type": "Sensitive Data Exposure",
                "severity": 1,
                "cve": "OWASP API3",
                "description": "카드번호 평문 저장 및 인증 없이 결제 내역 전체 노출.",
                "cvss": 8.6,
            },
            {
                "id": "VULN-008",
                "type": "Missing Authentication",
                "severity": 1,
                "cve": "OWASP API2",
                "description": "/internal/charge 결제 API에 인증 없이 결제 실행 가능.",
                "cvss": 9.5,
            },
        ],
    ),
]

EDGES: list[ApiEdge] = [
    ApiEdge(
        source="user-api",
        target="product-api",
        call_type="auth",
        description="JWT 토큰을 발급하면 product-api가 해당 토큰으로 사용자 인증",
    ),
    ApiEdge(
        source="product-api",
        target="payment-api",
        call_type="internal",
        description="주문 처리 시 payment-api /internal/charge 호출",
    ),
    ApiEdge(
        source="product-api",
        target="payment-api",
        call_type="payment",
        description="상품 조회 시 payment-api /internal/pricing 호출로 할인 정보 취득",
    ),
]

# ── 그래프 인덱스 ──────────────────────────────────────────────────────────────

_NODE_MAP: dict[str, ApiNode] = {n.id: n for n in NODES}
_ADJ: dict[str, list[str]] = {n.id: [] for n in NODES}
for e in EDGES:
    _ADJ[e.source].append(e.target)


# ── BFS 전파 분석 ─────────────────────────────────────────────────────────────

def get_network_data() -> dict:
    """D3.js force graph용 nodes/links 데이터 반환."""
    nodes = []
    for n in NODES:
        max_severity = min(v["severity"] for v in n.vulnerabilities) if n.vulnerabilities else 3
        nodes.append({
            "id": n.id,
            "name": n.name,
            "port": n.port,
            "tech": n.tech,
            "vuln_count": len(n.vulnerabilities),
            "max_severity": max_severity,
            "data_sensitivity": n.data_sensitivity,
            "risk_score": _node_risk(n),
        })

    links = [
        {"source": e.source, "target": e.target, "call_type": e.call_type, "description": e.description}
        for e in EDGES
    ]
    return {"nodes": nodes, "links": links}


def _node_risk(node: ApiNode) -> int:
    score = 0
    for v in node.vulnerabilities:
        score += (4 - v["severity"]) * 3  # severity 1→9점, 2→6점, 3→3점
    score += node.data_sensitivity * 5
    return score


def simulate_propagation(entry_api_id: str) -> dict:
    """
    entry_api_id 에서 공격을 시작했을 때 BFS로 전파 경로와 영향도를 계산.
    Returns:
        {
          "entry": str,
          "path": [{"api": id, "depth": int, "impact": str}],
          "affected_apis": [id, ...],
          "impact_percent": float,
          "attack_chain": [...],
          "recommendations": [...]
        }
    """
    if entry_api_id not in _NODE_MAP:
        return {"error": f"Unknown API: {entry_api_id}"}

    visited: dict[str, int] = {}  # api_id → depth
    queue: deque[tuple[str, int, list[str]]] = deque()
    queue.append((entry_api_id, 0, [entry_api_id]))
    all_paths: list[list[str]] = []

    while queue:
        current, depth, path = queue.popleft()
        if current in visited:
            continue
        visited[current] = depth

        for neighbor in _ADJ.get(current, []):
            if neighbor not in visited:
                new_path = path + [neighbor]
                all_paths.append(new_path)
                queue.append((neighbor, depth + 1, new_path))

    affected_ids = list(visited.keys())
    impact_pct = round(len(affected_ids) / len(NODES) * 100, 1)

    # 공격 체인 상세
    entry_node = _NODE_MAP[entry_api_id]
    chain = []
    for api_id, depth in sorted(visited.items(), key=lambda x: x[1]):
        node = _NODE_MAP[api_id]
        vulns = node.vulnerabilities
        chain.append({
            "step": depth + 1,
            "api": api_id,
            "name": node.name,
            "depth": depth,
            "vulnerabilities": vulns,
            "data_exposed": _data_label(node.data_sensitivity),
            "edge_type": _get_edge_type(entry_api_id, api_id) if api_id != entry_api_id else "entry_point",
        })

    # 보안 권고
    recs = _recommendations(affected_ids)

    return {
        "entry": entry_api_id,
        "entry_name": entry_node.name,
        "affected_apis": affected_ids,
        "affected_count": len(affected_ids),
        "total_apis": len(NODES),
        "impact_percent": impact_pct,
        "attack_chain": chain,
        "recommendations": recs,
        "scenario": _scenario_text(entry_api_id, affected_ids),
    }


def _data_label(sensitivity: int) -> str:
    return {1: "일반 데이터", 2: "개인정보", 3: "카드번호/금융정보"}.get(sensitivity, "미분류")


def _get_edge_type(source: str, target: str) -> str:
    for e in EDGES:
        if e.source == source and e.target == target:
            return e.call_type
        # 간접 경로도 찾기
    return "indirect"


def _scenario_text(entry: str, affected: list[str]) -> str:
    scenarios = {
        "user-api": (
            "공격자가 JWT weak secret을 이용해 user-api 토큰을 위조합니다. "
            "위조된 토큰으로 product-api 인증을 우회하고, "
            "product-api의 내부 API 호출을 통해 payment-api의 카드 정보에 접근합니다. "
            f"영향 범위: 전체 시스템 {round(len(affected)/len(NODES)*100)}%"
        ),
        "product-api": (
            "공격자가 product-api의 SQL 인젝션을 통해 DB를 덤프합니다. "
            "획득한 내부 호출 정보를 이용해 payment-api의 /internal/ 엔드포인트에 직접 접근, "
            "결제 내역과 카드번호를 탈취합니다. "
            f"영향 범위: {round(len(affected)/len(NODES)*100)}%"
        ),
        "payment-api": (
            "공격자가 payment-api의 인증 없는 /admin/ 엔드포인트에 직접 접근합니다. "
            "카드번호 평문과 전체 결제 내역을 획득합니다. "
            f"영향 범위: payment-api 직접 {round(len(affected)/len(NODES)*100)}%"
        ),
    }
    return scenarios.get(entry, "알 수 없는 공격 경로")


def _recommendations(affected_apis: list[str]) -> list[dict]:
    recs = []
    if "user-api" in affected_apis:
        recs.append({
            "priority": "🔴 긴급",
            "api": "user-api",
            "action": "JWT secret을 256비트 랜덤값으로 교체, none 알고리즘 비허용, exp 클레임 필수화",
            "roi": f"수정 시 {len(affected_apis)}/{len(NODES)} API 보호 (ROI {len(affected_apis)*100//len(NODES)}%)",
        })
    if "product-api" in affected_apis:
        recs.append({
            "priority": "🔴 긴급",
            "api": "product-api",
            "action": "Parameterized query 사용, 에러 메시지에서 SQL 정보 제거, 입력값 화이트리스트 검증",
            "roi": "payment-api 간접 보호 포함",
        })
    if "payment-api" in affected_apis:
        recs.append({
            "priority": "🟠 높음",
            "api": "payment-api",
            "action": "/internal/ 경로에 IP 화이트리스트 적용, 카드번호 암호화 저장, /admin/ 역할 검증 추가",
            "roi": "금융 데이터 직접 보호",
        })
    return recs


def get_all_propagations() -> list[dict]:
    """모든 API를 시작점으로 전파 분석 결과를 반환."""
    return [simulate_propagation(n.id) for n in NODES]
