"""
취약한 Product API (Python Flask)
CVE 시나리오:
  - Raw SQL 인젝션 (SQLite)
  - 에러 메시지에 DB 정보 노출
  - 사용자 입력 미검증
"""
from flask import Flask, request, jsonify
import sqlite3
import os
import requests

app = Flask(__name__)

DB_PATH = "/tmp/products.db"
PAYMENT_API_URL = os.environ.get("PAYMENT_API_URL", "http://payment-api:3003")
USER_API_URL = os.environ.get("USER_API_URL", "http://user-api:3001")


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            stock INTEGER,
            description TEXT
        )"""
    )
    products = [
        (1, "Premium Car", 50000.0, 5, "Luxury vehicle with full options"),
        (2, "Economy Car", 15000.0, 20, "Budget-friendly sedan"),
        (3, "SUV", 35000.0, 8, "4WD Sport Utility Vehicle"),
        (4, "Electric Car", 45000.0, 3, "Zero emission electric vehicle"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO products VALUES (?,?,?,?,?)", products
    )
    conn.commit()
    conn.close()


_init_db()


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "product-api"})


@app.route("/api/v1/products")
def list_products():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id,name,price,stock,description FROM products").fetchall()
    conn.close()
    return jsonify([
        {"id": r[0], "name": r[1], "price": r[2], "stock": r[3], "description": r[4]}
        for r in rows
    ])


@app.route("/api/v1/products/search")
def search_products():
    """
    ⚠️  취약점: SQL 인젝션
    공격 예시: ?q=' OR '1'='1
              ?q=' UNION SELECT username,password,role,1,1 FROM users--
    """
    q = request.args.get("q", "")

    conn = sqlite3.connect(DB_PATH)
    try:
        # ⚠️  취약점: f-string으로 직접 쿼리 삽입
        query = f"SELECT id,name,price,stock,description FROM products WHERE name LIKE '%{q}%'"
        rows = conn.execute(query).fetchall()
    except Exception as e:
        # ⚠️  취약점: 에러 메시지에 쿼리 정보 노출
        return jsonify({"error": str(e), "query": query}), 500
    finally:
        conn.close()

    return jsonify([
        {"id": r[0], "name": r[1], "price": r[2], "stock": r[3], "description": r[4]}
        for r in rows
    ])


@app.route("/api/v1/products/<int:product_id>")
def get_product(product_id: int):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id,name,price,stock,description FROM products WHERE id=?", (product_id,)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Product not found"}), 404

    product = {"id": row[0], "name": row[1], "price": row[2], "stock": row[3], "description": row[4]}

    # 내부 API 호출: payment-api 에서 할인 정보 가져오기 (API 체인)
    try:
        resp = requests.get(f"{PAYMENT_API_URL}/internal/pricing/{product_id}", timeout=2)
        if resp.status_code == 200:
            product["pricing"] = resp.json()
    except Exception:
        pass

    return jsonify(product)


@app.route("/api/v1/order", methods=["POST"])
def create_order():
    """product-api → payment-api 결제 API 체인 데모"""
    data = request.get_json() or {}
    token = request.headers.get("Authorization", "")

    product_id = data.get("product_id")
    quantity = data.get("quantity", 1)

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id,name,price FROM products WHERE id=?", (product_id,)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Product not found"}), 404

    total = row[2] * quantity

    # 내부 API 호출: payment-api 결제 처리
    try:
        pay_resp = requests.post(
            f"{PAYMENT_API_URL}/internal/charge",
            json={"product_id": product_id, "amount": total},
            headers={"Authorization": token},
            timeout=3,
        )
        payment_result = pay_resp.json()
    except Exception as e:
        payment_result = {"error": str(e)}

    return jsonify({
        "order": {"product": row[1], "quantity": quantity, "total": total},
        "payment": payment_result,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3002, debug=False)
