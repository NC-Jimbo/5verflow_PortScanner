"""
취약한 User API (Python Flask)
CVE 시나리오:
  - JWT weak secret (HS256, secret="secret")
  - JWT none 알고리즘 우회
  - 토큰 만료시간 검증 누락
"""
from flask import Flask, request, jsonify
import jwt  # PyJWT
import sqlite3
import os

app = Flask(__name__)

# ⚠️  취약점: 예측 가능한 weak secret
JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"

DB_PATH = "/tmp/users.db"

PRODUCT_API_URL = os.environ.get("PRODUCT_API_URL", "http://product-api:3002")


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            balance REAL DEFAULT 1000.0
        )"""
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username,password,role,balance) VALUES (?,?,?,?)",
        ("admin", "admin123", "admin", 99999.0),
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username,password,role,balance) VALUES (?,?,?,?)",
        ("alice", "alice123", "user", 500.0),
    )
    conn.commit()
    conn.close()


_init_db()


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "user-api"})


@app.route("/api/v1/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, username, role FROM users WHERE username=? AND password=?",
        (username, password),
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Invalid credentials"}), 401

    # ⚠️  취약점: exp 없음 (만료시간 미설정)
    token = jwt.encode(
        {"user_id": row[0], "username": row[1], "role": row[2]},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )
    return jsonify({"token": token, "user": {"id": row[0], "username": row[1], "role": row[2]}})


@app.route("/api/v1/profile/<int:user_id>")
def profile(user_id: int):
    """
    ⚠️  취약점: none 알고리즘 우회 허용 (algorithms 리스트에 'none' 포함)
    공격 예시: header.alg=none, signature 없이 전송
    """
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    if not token:
        return jsonify({"error": "No token"}), 401

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM, "none"],  # ⚠️  취약점: none 허용
            options={"verify_exp": False},        # ⚠️  취약점: exp 검증 안 함
        )
    except jwt.InvalidTokenError as e:
        return jsonify({"error": str(e)}), 401

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, username, role, balance FROM users WHERE id=?", (user_id,)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    return jsonify({"id": row[0], "username": row[1], "role": row[2], "balance": row[3]})


@app.route("/api/v1/users")
def list_users():
    """⚠️  취약점: 인증 없이 모든 사용자 목록 노출 (BOLA)"""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, username, role, balance FROM users").fetchall()
    conn.close()
    return jsonify([{"id": r[0], "username": r[1], "role": r[2], "balance": r[3]} for r in rows])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3001, debug=False)
