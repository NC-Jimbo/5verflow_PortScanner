import json
import os
from datetime import datetime
from collections import defaultdict

EVE_JSON_PATH = os.environ.get(
    "EVE_JSON_PATH",
    os.path.join(os.path.dirname(__file__), "..", "suricata", "eve.json"),
)


class LogParser:
    """eve.json (JSON Lines) 파서 – Suricata 알럿 로그를 읽어 파이썬 객체로 반환."""

    def __init__(self, path: str = EVE_JSON_PATH):
        self.path = os.path.abspath(path)

    def parse(self) -> list[dict]:
        """eve.json 전체를 파싱해서 alert 이벤트만 반환."""
        alerts = []
        if not os.path.exists(self.path):
            return alerts

        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if entry.get("event_type") != "alert":
                    continue

                alert_info = entry.get("alert", {})
                alerts.append(
                    {
                        "timestamp": entry.get("timestamp", ""),
                        "src_ip": entry.get("src_ip", ""),
                        "src_port": entry.get("src_port", 0),
                        "dest_ip": entry.get("dest_ip", ""),
                        "dest_port": entry.get("dest_port", 0),
                        "signature": alert_info.get("signature", ""),
                        "category": alert_info.get("category", "Unknown"),
                        "severity": alert_info.get("severity", 3),
                    }
                )

        # 최신 순 정렬
        alerts.sort(key=lambda x: x["timestamp"], reverse=True)
        return alerts

    def get_stats(self) -> dict:
        """파싱된 알럿에서 통계 데이터를 계산해 반환."""
        alerts = self.parse()

        category_count: dict[str, int] = defaultdict(int)
        severity_count: dict[int, int] = defaultdict(int)
        ip_count: dict[str, int] = defaultdict(int)
        timeline: dict[str, int] = defaultdict(int)

        for a in alerts:
            category_count[a["category"]] += 1
            severity_count[a["severity"]] += 1
            ip_count[a["src_ip"]] += 1

            # 시간대별 집계 (HH:MM 단위)
            try:
                ts = datetime.fromisoformat(a["timestamp"])
                time_key = ts.strftime("%H:%M")
            except ValueError:
                time_key = a["timestamp"][:16]
            timeline[time_key] += 1

        # 위험도 점수: severity 1(긴급)=3점, 2(높음)=2점, 3(낮음)=1점
        risk_score = (
            severity_count.get(1, 0) * 3
            + severity_count.get(2, 0) * 2
            + severity_count.get(3, 0) * 1
        )

        return {
            "total": len(alerts),
            "risk_score": risk_score,
            "category": dict(category_count),
            "severity": {str(k): v for k, v in severity_count.items()},
            "top_ips": sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:10],
            "timeline": dict(sorted(timeline.items())),
        }
