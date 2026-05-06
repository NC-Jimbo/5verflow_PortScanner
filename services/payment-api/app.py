"""
취약한 Payment API (Python Flask)
CVE 시나리오:
  - 권한 검증 없는 내부 API 엔드포인트 (BFLA)
  - 민감한 결제 정보 과도 노출
  - 인증 헤더 무시
"""
from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

DB_PATH = "/tmp/payments.db"


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            amount REAL,
            card_number TEXT,
            status TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    conn.execute(
        "INSERT OR IGNORE INTO payments (id,product_id,amount,card_number,status) VALUES (?,?,?,?,?)",
        (1, 1, 50000.0, "4111-1111-1111-1111", "completed"),
    )
    conn.execute(
        "INSERT OR IGNORE INTO payments (id,product_id,amount,card_number,status) VALUES (?,?,?,?,?)",
        (2, 2, 15000.0, "5500-0000-0000-0004", "completed"),
    )
    conn.commit()
    conn.close()


_init_db()


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "payment-api"})


@app.route("/internal/pricing/<int:product_id>")
def internal_pricing(product_id: int):
    """
    ⚠️  취약점: /internal/ 경로임에도 인증 없이 외부 접근 가능 (BFLA)
    원래는 product-api 내부 호출 전용이어야 함
    """
    discounts = {1: 0.10, 2: 0.05, 3: 0.08, 4: 0.15}
    discount = discounts.get(product_id, 0.0)
    return jsonify({
        "product_id": product_id,
        "discount_rate": discount,
        "promo_code": "INTERNAL_PROMO_2026",  # ⚠️  내부 프로모코드 노출
    })


@app.route("/internal/charge", methods=["POST"])
def internal_charge():
    """
    ⚠️  취약점: 인증 없이 결제 처리 가능 (인증 헤더 무시)
    """
    data = request.get_json() or {}
    product_id = data.get("product_id")
    amount = data.get("amount", 0)

    # ⚠️  취약점: Authorization 헤더 검증 전혀 안 함
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO payments (product_id,amount,card_number,status) VALUES (?,?,?,?)",
        (product_id, amount, "0000-0000-0000-TEST", "completed"),
    )
    conn.commit()
    conn.close()

    return jsonify({"status": "completed", "amount": amount, "transaction_id": "TXN-BYPASS-001"})


@app.route("/api/v1/payments")
def list_payments():
    """⚠️  취약점: 인증 없이 모든 결제 내역(카드번호 포함) 노출"""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id,product_id,amount,card_number,status,created_at FROM payments"
    ).fetchall()
    conn.close()
    return jsonify([
        {
            "id": r[0], "product_id": r[1], "amount": r[2],
            "card_number": r[3],  # ⚠️  취약점: 카드번호 평문 노출
            "status": r[4], "created_at": r[5],
        }
        for r in rows
    ])


@app.route("/api/v1/admin/payments")
def admin_payments():
    """
    ⚠️  취약점: /admin/ 경로임에도 role 검증 없음 (BFLA)
    """
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id,product_id,amount,card_number,status,created_at FROM payments"
    ).fetchall()
    conn.close()
    return jsonify({
        "admin_view": True,
        "total_revenue": sum(r[2] for r in rows),
        "payments": [
            {"id": r[0], "card_number": r[3], "amount": r[2], "status": r[4]}
            for r in rows
        ],
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3003, debug=False)
