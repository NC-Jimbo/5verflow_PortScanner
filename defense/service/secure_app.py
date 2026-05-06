import os
from contextlib import closing
from functools import wraps
from urllib.parse import urlparse

import pyodbc
from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = os.getenv("SERVICE_SECRET_KEY", "dev-only-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"

ROLE_LABELS = {
    "admin": "관리자",
    "viewer": "조회 전용",
}

_identity_schema_ready = False


def get_connection() -> pyodbc.Connection:
    server = os.getenv("MSSQL_SERVER", "localhost")
    port = os.getenv("MSSQL_PORT", "1433")
    database = os.getenv("MSSQL_DATABASE", "CompanyConfidential")
    username = os.getenv("MSSQL_USER", "sa")
    password = os.getenv("MSSQL_PASSWORD", "Password123!")
    driver = os.getenv("MSSQL_DRIVER", "ODBC Driver 18 for SQL Server")
    encrypt = os.getenv("MSSQL_ENCRYPT", "no")
    trust_cert = os.getenv("MSSQL_TRUST_SERVER_CERTIFICATE", "yes")

    conn_str = (
        f"DRIVER={{{driver}}};"
        f"SERVER={server},{port};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={password};"
        f"Encrypt={encrypt};"
        f"TrustServerCertificate={trust_cert};"
    )
    return pyodbc.connect(conn_str, timeout=5)


def get_default_users() -> list[dict]:
    return [
        {
            "username": os.getenv("SERVICE_ADMIN_USERNAME", "admin"),
            "password": os.getenv("SERVICE_ADMIN_PASSWORD", "Admin123!"),
            "display_name": os.getenv("SERVICE_ADMIN_DISPLAY_NAME", "인사팀 관리자"),
            "role": "admin",
        },
        {
            "username": os.getenv("SERVICE_VIEWER_USERNAME", "viewer"),
            "password": os.getenv("SERVICE_VIEWER_PASSWORD", "Viewer123!"),
            "display_name": os.getenv("SERVICE_VIEWER_DISPLAY_NAME", "부서 조회 사용자"),
            "role": "viewer",
        },
    ]


def ensure_identity_schema() -> None:
    global _identity_schema_ready

    if _identity_schema_ready:
        return

    create_users_table = """
        IF OBJECT_ID('dbo.AppUsers', 'U') IS NULL
        BEGIN
            CREATE TABLE AppUsers (
                UserID INT IDENTITY(1,1) PRIMARY KEY,
                Username NVARCHAR(50) NOT NULL UNIQUE,
                PasswordHash NVARCHAR(255) NOT NULL,
                DisplayName NVARCHAR(100) NOT NULL,
                RoleName NVARCHAR(30) NOT NULL,
                IsActive BIT NOT NULL DEFAULT 1,
                CreatedAt DATETIME2 NOT NULL DEFAULT SYSDATETIME()
            )
        END
    """

    insert_user = """
        IF NOT EXISTS (SELECT 1 FROM AppUsers WHERE Username = ?)
        BEGIN
            INSERT INTO AppUsers (Username, PasswordHash, DisplayName, RoleName, IsActive)
            VALUES (?, ?, ?, ?, 1)
        END
    """

    with closing(get_connection()) as connection:
        cursor = connection.cursor()
        cursor.execute(create_users_table)
        for user in get_default_users():
            cursor.execute(
                insert_user,
                user["username"],
                user["username"],
                generate_password_hash(user["password"]),
                user["display_name"],
                user["role"],
            )
        connection.commit()

    _identity_schema_ready = True


def fetch_user(username: str) -> dict | None:
    query = """
        SELECT
            Username,
            PasswordHash,
            DisplayName,
            RoleName,
            IsActive
        FROM AppUsers
        WHERE Username = ?
    """

    with closing(get_connection()) as connection:
        cursor = connection.cursor()
        row = cursor.execute(query, username).fetchone()
        if not row:
            return None

        return {
            "username": row.Username,
            "password_hash": row.PasswordHash,
            "display_name": row.DisplayName,
            "role": row.RoleName,
            "is_active": bool(row.IsActive),
        }


def get_current_user() -> dict | None:
    username = session.get("username")
    if not username:
        return None

    ensure_identity_schema()
    user = fetch_user(username)
    if user is None or not user["is_active"]:
        session.clear()
        return None
    return user


def is_safe_next_url(target: str | None) -> bool:
    if not target:
        return False
    parsed = urlparse(target)
    return parsed.scheme == "" and parsed.netloc == "" and target.startswith("/")


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if get_current_user() is None:
            next_url = request.full_path if request.query_string else request.path
            return redirect(url_for("login", next=next_url))
        return view(*args, **kwargs)

    return wrapped_view


def role_required(*allowed_roles: str):
    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            user = get_current_user()
            if user is None:
                next_url = request.full_path if request.query_string else request.path
                return redirect(url_for("login", next=next_url))
            if user["role"] not in allowed_roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped_view

    return decorator


def fetch_employees(search: str) -> list[dict]:
    query = """
        SELECT TOP 100
            EmployeeID,
            Name,
            Phone,
            Email,
            Address,
            Salary
        FROM Employees
    """
    params: list[str] = []

    if search:
        query += " WHERE Name LIKE ? OR Email LIKE ? OR Phone LIKE ?"
        like_value = f"%{search}%"
        params.extend([like_value, like_value, like_value])

    query += " ORDER BY EmployeeID ASC"

    with closing(get_connection()) as connection:
        cursor = connection.cursor()
        rows = cursor.execute(query, params).fetchall()
        return [
            {
                "employee_id": row.EmployeeID,
                "name": row.Name,
                "phone": row.Phone,
                "email": row.Email,
                "address": row.Address,
                "salary": row.Salary,
            }
            for row in rows
        ]


def fetch_employee(employee_id: int) -> dict | None:
    query = """
        SELECT
            EmployeeID,
            Name,
            ResidentNumber,
            Phone,
            Email,
            Salary,
            CreditCard,
            Address
        FROM Employees
        WHERE EmployeeID = ?
    """

    with closing(get_connection()) as connection:
        cursor = connection.cursor()
        row = cursor.execute(query, employee_id).fetchone()
        if not row:
            return None

        return {
            "employee_id": row.EmployeeID,
            "name": row.Name,
            "resident_number": row.ResidentNumber,
            "phone": row.Phone,
            "email": row.Email,
            "salary": row.Salary,
            "credit_card": row.CreditCard,
            "address": row.Address,
        }


def update_employee(employee_id: int, phone: str, email: str, address: str) -> None:
    query = """
        UPDATE Employees
        SET Phone = ?, Email = ?, Address = ?
        WHERE EmployeeID = ?
    """

    with closing(get_connection()) as connection:
        cursor = connection.cursor()
        cursor.execute(query, phone, email, address, employee_id)
        connection.commit()


def mask_resident_number(value: str) -> str:
    if not value or len(value) < 8:
        return value
    return f"{value[:8]}******"


def mask_credit_card(value: str) -> str:
    if not value or len(value) < 4:
        return value
    return f"****-****-****-{value[-4:]}"


def build_selected_employee(employee_id: int, user: dict) -> dict:
    selected_employee = fetch_employee(employee_id)
    if selected_employee is None:
        abort(404)

    selected_employee["resident_number_masked"] = mask_resident_number(selected_employee["resident_number"])
    selected_employee["credit_card_masked"] = mask_credit_card(selected_employee["credit_card"])
    selected_employee["salary_display"] = (
        f"₩ {selected_employee['salary']:,}" if user["role"] == "admin" else "권한 필요"
    )
    return selected_employee


LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CompanyConfidential 로그인</title>
  <style>
    :root {
      --bg: #f2ede3;
      --panel: rgba(255, 252, 246, 0.95);
      --text: #1d1a16;
      --muted: #6f665b;
      --accent: #0b6e4f;
      --accent-strong: #084c38;
      --danger: #9f2a2a;
      --border: #d8cbba;
      --shadow: 0 20px 80px rgba(66, 48, 24, 0.14);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 20% 20%, rgba(11, 110, 79, 0.12), transparent 26%),
        radial-gradient(circle at 80% 10%, rgba(204, 133, 53, 0.1), transparent 22%),
        linear-gradient(180deg, #f8f4ec 0%, #ebe2d5 100%);
      padding: 24px;
    }
    .frame {
      width: min(100%, 980px);
      display: grid;
      grid-template-columns: 1.1fr 0.9fr;
      gap: 20px;
      align-items: stretch;
    }
    .brand,
    .login-card {
      border-radius: 28px;
      border: 1px solid var(--border);
      background: var(--panel);
      box-shadow: var(--shadow);
    }
    .brand {
      padding: 34px;
      background:
        linear-gradient(160deg, rgba(255, 252, 246, 0.94), rgba(241, 232, 219, 0.92)),
        linear-gradient(45deg, rgba(11, 110, 79, 0.04), transparent);
    }
    .tag {
      display: inline-flex;
      border-radius: 999px;
      padding: 7px 11px;
      background: rgba(11, 110, 79, 0.12);
      color: var(--accent-strong);
      font-weight: 700;
      font-size: 0.82rem;
    }
    h1 {
      margin: 18px 0 10px;
      font-size: 2.3rem;
      line-height: 1.05;
      letter-spacing: -0.04em;
    }
    .brand p,
    .login-card p,
    .role p {
      color: var(--muted);
      line-height: 1.6;
    }
    .roles {
      display: grid;
      gap: 12px;
      margin-top: 24px;
    }
    .role {
      padding: 16px;
      border-radius: 18px;
      border: 1px solid var(--border);
      background: rgba(255, 253, 248, 0.82);
    }
    .role strong {
      display: block;
      margin-bottom: 6px;
    }
    .login-card {
      padding: 32px;
    }
    .login-card h2 {
      margin: 0;
      font-size: 1.5rem;
    }
    .field {
      display: grid;
      gap: 7px;
      margin-top: 18px;
    }
    label {
      color: var(--muted);
      font-size: 0.9rem;
    }
    input {
      width: 100%;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: #fffdf8;
      padding: 13px 14px;
      font-size: 0.96rem;
    }
    button {
      width: 100%;
      border: 0;
      border-radius: 14px;
      padding: 14px 16px;
      margin-top: 22px;
      background: var(--accent);
      color: white;
      font-size: 1rem;
      font-weight: 700;
      cursor: pointer;
    }
    button:hover { background: var(--accent-strong); }
    .error {
      margin-top: 18px;
      padding: 12px 14px;
      border-radius: 14px;
      color: var(--danger);
      background: rgba(159, 42, 42, 0.08);
      border: 1px solid rgba(159, 42, 42, 0.18);
    }
    .hint {
      margin-top: 18px;
      font-size: 0.9rem;
      color: var(--muted);
    }
    .hint code {
      font-family: monospace;
      background: rgba(11, 110, 79, 0.08);
      padding: 2px 6px;
      border-radius: 6px;
    }
    @media (max-width: 900px) {
      .frame { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="frame">
    <section class="brand">
      <span class="tag">CompanyConfidential HR Portal</span>
      <h1>실제 업무 서비스에 가까운<br>사내 인사 포털</h1>
      <p>IDS 화면과 분리된 별도 서비스입니다. 로그인 세션을 만들고, 사용자 역할에 따라 조회와 수정 권한을 구분합니다.</p>
      <div class="roles">
        <div class="role">
          <strong>관리자</strong>
          <p>직원 목록 조회, 상세 조회, 연락처 정보 수정 권한을 가집니다.</p>
        </div>
        <div class="role">
          <strong>조회 전용 사용자</strong>
          <p>직원 목록과 마스킹된 상세 정보는 볼 수 있지만, 수정은 할 수 없습니다.</p>
        </div>
      </div>
    </section>

    <section class="login-card">
      <h2>로그인</h2>
      <p>업무 서비스에 접근하려면 사내 계정으로 로그인하세요.</p>
      <form method="post" action="{{ url_for('login') }}">
        <input type="hidden" name="next" value="{{ next_url }}">
        <div class="field">
          <label for="username">아이디</label>
          <input id="username" type="text" name="username" autocomplete="username" required>
        </div>
        <div class="field">
          <label for="password">비밀번호</label>
          <input id="password" type="password" name="password" autocomplete="current-password" required>
        </div>
        <button type="submit">서비스 들어가기</button>
      </form>
      {% if error %}
      <div class="error">{{ error }}</div>
      {% endif %}
      <div class="hint">
        기본 계정은 환경변수로 바꿀 수 있습니다. 기본값은 <code>admin / Admin123!</code>, <code>viewer / Viewer123!</code> 입니다.
      </div>
    </section>
  </div>
</body>
</html>
"""


PAGE = """
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CompanyConfidential 직원 서비스</title>
  <style>
    :root {
      --bg: #f5f1e8;
      --panel: rgba(255, 252, 245, 0.92);
      --text: #1d1a16;
      --muted: #6b6258;
      --border: #d8cbba;
      --accent: #0b6e4f;
      --accent-strong: #084c38;
      --warn: #9f2a2a;
      --soft: rgba(11, 110, 79, 0.08);
      --shadow: 0 20px 60px rgba(72, 49, 20, 0.12);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(11, 110, 79, 0.08), transparent 30%),
        radial-gradient(circle at top right, rgba(180, 95, 34, 0.08), transparent 26%),
        linear-gradient(180deg, #f7f3eb 0%, #efe5d8 100%);
      min-height: 100vh;
    }
    .shell {
      width: min(1180px, calc(100% - 32px));
      margin: 26px auto 32px;
    }
    .topbar {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      margin-bottom: 18px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-badge,
    .user-role {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 7px 10px;
      border-radius: 999px;
      background: rgba(11, 110, 79, 0.1);
      color: var(--accent-strong);
      font-size: 0.82rem;
      font-weight: 700;
    }
    .userbox {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px 12px;
      border-radius: 18px;
      background: rgba(255, 252, 245, 0.82);
      border: 1px solid var(--border);
    }
    .userbox form { margin: 0; }
    .user-meta {
      display: grid;
      gap: 2px;
    }
    .user-name { font-weight: 700; }
    .user-caption { color: var(--muted); font-size: 0.83rem; }
    .topbar button {
      border: 0;
      border-radius: 12px;
      background: var(--accent);
      color: white;
      padding: 10px 14px;
      cursor: pointer;
    }
    .topbar button:hover { background: var(--accent-strong); }
    .hero {
      background: linear-gradient(135deg, rgba(255, 252, 245, 0.94), rgba(239, 229, 216, 0.92));
      border: 1px solid var(--border);
      border-radius: 24px;
      padding: 28px;
      box-shadow: var(--shadow);
      margin-bottom: 20px;
    }
    .hero h1 {
      margin: 0;
      font-size: 2rem;
      letter-spacing: -0.03em;
    }
    .hero p {
      margin: 10px 0 0;
      color: var(--muted);
      max-width: 780px;
      line-height: 1.6;
    }
    .toolbar {
      display: flex;
      gap: 12px;
      margin-top: 20px;
      flex-wrap: wrap;
      align-items: center;
    }
    .toolbar input {
      flex: 1 1 320px;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: #fffdf8;
      font-size: 0.95rem;
    }
    .toolbar button,
    .action {
      background: var(--accent);
      color: white;
      border: 0;
      border-radius: 12px;
      padding: 12px 16px;
      font-size: 0.95rem;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    .toolbar button:hover,
    .action:hover {
      background: var(--accent-strong);
    }
    .layout {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 20px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 24px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .panel-header {
      padding: 22px 24px 0;
    }
    .panel-header h2,
    .panel-header h3 {
      margin: 0;
    }
    .panel-header p {
      color: var(--muted);
      margin: 8px 0 0;
      font-size: 0.92rem;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 18px;
    }
    th, td {
      padding: 14px 24px;
      text-align: left;
      border-top: 1px solid rgba(216, 203, 186, 0.7);
      vertical-align: middle;
    }
    th {
      color: var(--muted);
      font-weight: 600;
      font-size: 0.82rem;
      background: rgba(239, 229, 216, 0.5);
    }
    tbody tr:hover {
      background: rgba(11, 110, 79, 0.05);
    }
    .empty {
      padding: 24px;
      color: var(--muted);
    }
    .stats {
      display: grid;
      gap: 14px;
      padding: 24px;
    }
    .stat {
      padding: 16px;
      border-radius: 18px;
      background: rgba(255, 253, 248, 0.85);
      border: 1px solid var(--border);
    }
    .stat-label {
      color: var(--muted);
      font-size: 0.82rem;
    }
    .stat-value {
      font-size: 1.6rem;
      font-weight: 700;
      margin-top: 8px;
    }
    .detail {
      padding: 24px;
      display: grid;
      gap: 12px;
    }
    .detail-row {
      display: grid;
      gap: 4px;
    }
    .detail-label {
      color: var(--muted);
      font-size: 0.82rem;
    }
    .detail-value {
      font-size: 1rem;
      word-break: break-word;
    }
    .form {
      padding: 24px;
      border-top: 1px solid rgba(216, 203, 186, 0.7);
      display: grid;
      gap: 12px;
    }
    .form input {
      width: 100%;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: #fffdf8;
    }
    .note,
    .permission-note {
      padding: 0 24px 24px;
      color: var(--warn);
      font-size: 0.84rem;
      line-height: 1.6;
    }
    .permission-note {
      color: var(--muted);
      background: var(--soft);
      margin: 0 24px 24px;
      padding: 14px 16px;
      border-radius: 16px;
      border: 1px solid rgba(11, 110, 79, 0.1);
    }
    @media (max-width: 900px) {
      .layout { grid-template-columns: 1fr; }
      .topbar { flex-direction: column; align-items: flex-start; }
      .userbox { width: 100%; justify-content: space-between; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="topbar">
      <div class="brand">
        <span class="brand-badge">CompanyConfidential HR Portal</span>
        <span class="user-role">{{ role_label }}</span>
      </div>
      <div class="userbox">
        <div class="user-meta">
          <span class="user-name">{{ current_user.display_name }}</span>
          <span class="user-caption">{{ current_user.username }} 계정으로 로그인됨</span>
        </div>
        <form method="post" action="{{ url_for('logout') }}">
          <button type="submit">로그아웃</button>
        </form>
      </div>
    </div>

    <section class="hero">
      <h1>직원 정보 서비스</h1>
      <p>로그인 기반 세션과 역할 권한을 적용한 사내 업무 웹입니다. 조회 전용 사용자는 직원 검색과 상세 확인만 가능하고, 관리자는 연락처 수정까지 수행할 수 있습니다.</p>
      <form class="toolbar" method="get" action="{{ url_for('employees') }}">
        <input type="text" name="q" value="{{ search }}" placeholder="이름, 이메일, 전화번호로 검색">
        <button type="submit">검색</button>
        <a class="action" href="{{ url_for('employees') }}">초기화</a>
      </form>
    </section>

    <div class="layout">
      <section class="panel">
        <div class="panel-header">
          <h2>직원 목록</h2>
          <p>최대 100명까지 표시합니다. 상세 보기에서 역할별로 허용된 데이터와 동작만 노출합니다.</p>
        </div>
        {% if employees %}
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>이름</th>
              <th>이메일</th>
              <th>연락처</th>
              <th>근무지</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {% for employee in employees %}
            <tr>
              <td>{{ employee.employee_id }}</td>
              <td>{{ employee.name }}</td>
              <td>{{ employee.email }}</td>
              <td>{{ employee.phone }}</td>
              <td>{{ employee.address }}</td>
              <td><a class="action" href="{{ url_for('employee_detail', employee_id=employee.employee_id, q=search) }}">상세 보기</a></td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
        {% else %}
        <div class="empty">검색 결과가 없습니다.</div>
        {% endif %}
      </section>

      <aside class="panel">
        <div class="panel-header">
          <h3>서비스 상태</h3>
          <p>현재 로그인한 사용자 기준으로 권한 범위를 표시합니다.</p>
        </div>
        <div class="stats">
          <div class="stat">
            <div class="stat-label">검색 결과</div>
            <div class="stat-value">{{ employees|length }}</div>
          </div>
          <div class="stat">
            <div class="stat-label">사용자 역할</div>
            <div class="stat-value">{{ role_label }}</div>
          </div>
          <div class="stat">
            <div class="stat-label">수정 권한</div>
            <div class="stat-value">{{ '허용' if can_edit else '없음' }}</div>
          </div>
        </div>
        {% if selected_employee %}
        <div class="detail">
          <div class="detail-row">
            <span class="detail-label">이름</span>
            <span class="detail-value">{{ selected_employee.name }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">주민번호</span>
            <span class="detail-value">{{ selected_employee.resident_number_masked }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">카드번호</span>
            <span class="detail-value">{{ selected_employee.credit_card_masked }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">연봉</span>
            <span class="detail-value">{{ selected_employee.salary_display }}</span>
          </div>
        </div>
        {% if can_edit %}
        <form class="form" method="post" action="{{ url_for('employee_update', employee_id=selected_employee.employee_id) }}">
          <input type="hidden" name="q" value="{{ search }}">
          <input type="text" name="phone" value="{{ selected_employee.phone }}" placeholder="연락처" required>
          <input type="email" name="email" value="{{ selected_employee.email }}" placeholder="이메일" required>
          <input type="text" name="address" value="{{ selected_employee.address }}" placeholder="주소" required>
          <button type="submit">연락처 정보 저장</button>
        </form>
        <div class="note">관리자만 직원 연락처를 수정할 수 있습니다. 민감정보는 화면에 마스킹된 상태로 유지됩니다.</div>
        {% else %}
        <div class="permission-note">현재 계정은 조회 전용입니다. 직원 정보 검색과 상세 보기만 허용되며 수정 기능은 관리자 계정으로 로그인해야 사용할 수 있습니다.</div>
        {% endif %}
        {% else %}
        <div class="empty">직원을 선택하면 상세 정보와 권한별 동작이 표시됩니다.</div>
        {% endif %}
      </aside>
    </div>
  </div>
</body>
</html>
"""


def render_employees_page(search: str, selected_employee: dict | None = None):
    current_user = get_current_user()
    if current_user is None:
        return redirect(url_for("login"))

    employee_list = fetch_employees(search)
    can_edit = current_user["role"] == "admin"
    return render_template_string(
        PAGE,
        employees=employee_list,
        search=search,
        selected_employee=selected_employee,
        current_user=current_user,
        can_edit=can_edit,
        role_label=ROLE_LABELS.get(current_user["role"], current_user["role"]),
    )


@app.get("/")
def home():
    if get_current_user() is None:
        return redirect(url_for("login"))
    return redirect(url_for("employees"))


@app.route("/login", methods=["GET", "POST"])
def login():
    ensure_identity_schema()
    if get_current_user() is not None:
        return redirect(url_for("employees"))

    next_url = request.values.get("next", "")
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = fetch_user(username)
        if user is None or not user["is_active"] or not check_password_hash(user["password_hash"], password):
            error = "아이디 또는 비밀번호가 올바르지 않습니다."
        else:
            session.clear()
            session["username"] = user["username"]
            if is_safe_next_url(next_url):
                return redirect(next_url)
            return redirect(url_for("employees"))

    return render_template_string(LOGIN_PAGE, error=error, next_url=next_url)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/health")
def health():
    ensure_identity_schema()
    with closing(get_connection()) as connection:
        connection.cursor().execute("SELECT 1")
    return {"status": "ok"}


@app.get("/employees")
@login_required
def employees():
    search = request.args.get("q", "").strip()
    employee_list = fetch_employees(search)
    if employee_list:
        first_employee_id = employee_list[0]["employee_id"]
        return redirect(url_for("employee_detail", employee_id=first_employee_id, q=search))
    return render_employees_page(search, selected_employee=None)


@app.get("/employees/<int:employee_id>")
@login_required
def employee_detail(employee_id: int):
    search = request.args.get("q", "").strip()
    current_user = get_current_user()
    if current_user is None:
        return redirect(url_for("login"))

    selected_employee = build_selected_employee(employee_id, current_user)
    return render_employees_page(search, selected_employee=selected_employee)


@app.post("/employees/<int:employee_id>")
@role_required("admin")
def employee_update(employee_id: int):
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    address = request.form.get("address", "").strip()
    search = request.form.get("q", "").strip()

    if not phone or not email or not address:
        abort(400)

    update_employee(employee_id, phone, email, address)
    return redirect(url_for("employee_detail", employee_id=employee_id, q=search))


@app.errorhandler(403)
def forbidden(_error):
    return "이 계정에는 해당 작업 권한이 없습니다. 관리자 계정으로 다시 로그인하세요.", 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=False)
