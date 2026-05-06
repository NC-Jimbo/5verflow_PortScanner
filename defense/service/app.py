import os
from contextlib import closing

import pyodbc
from flask import Flask, abort, redirect, render_template_string, request, url_for


app = Flask(__name__)


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
      margin: 32px auto;
    }
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
    .note {
      padding: 0 24px 24px;
      color: var(--warn);
      font-size: 0.84rem;
    }
    .service-tag {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 7px 10px;
      border-radius: 999px;
      background: rgba(11, 110, 79, 0.1);
      color: var(--accent-strong);
      font-size: 0.82rem;
      font-weight: 600;
    }
    @media (max-width: 900px) {
      .layout {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <span class="service-tag">CompanyConfidential HR Portal</span>
      <h1>직원 정보 서비스</h1>
      <p>IDS 대시보드와 분리된 별도 Flask 앱입니다. MSSQL Employees 테이블을 조회하고 기본 연락처 정보를 수정할 수 있습니다.</p>
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
          <p>최대 100명까지 표시합니다. 상세 보기를 눌러 개별 정보를 확인하세요.</p>
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
              <td><a class="action" href="{{ url_for('employee_detail', employee_id=employee.employee_id) }}">상세 보기</a></td>
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
          <p>분리된 업무 웹앱의 기본 운영 지표입니다.</p>
        </div>
        <div class="stats">
          <div class="stat">
            <div class="stat-label">검색 결과</div>
            <div class="stat-value">{{ employees|length }}</div>
          </div>
          <div class="stat">
            <div class="stat-label">DB 대상</div>
            <div class="stat-value">MSSQL</div>
          </div>
          <div class="stat">
            <div class="stat-label">앱 포트</div>
            <div class="stat-value">8000</div>
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
            <span class="detail-value">₩ {{ "{:,}".format(selected_employee.salary) }}</span>
          </div>
        </div>
        <form class="form" method="post" action="{{ url_for('employee_update', employee_id=selected_employee.employee_id) }}">
          <input type="text" name="phone" value="{{ selected_employee.phone }}" placeholder="연락처" required>
          <input type="email" name="email" value="{{ selected_employee.email }}" placeholder="이메일" required>
          <input type="text" name="address" value="{{ selected_employee.address }}" placeholder="주소" required>
          <button type="submit">연락처 정보 저장</button>
        </form>
        <div class="note">민감정보는 화면에서 마스킹합니다. 상세 조회와 수정은 업무 서비스 흐름 검증용입니다.</div>
        {% else %}
        <div class="empty">직원을 선택하면 상세 정보와 수정 폼이 표시됩니다.</div>
        {% endif %}
      </aside>
    </div>
  </div>
</body>
</html>
"""


@app.get("/")
def home():
    return redirect(url_for("employees"))


@app.get("/health")
def health():
    with closing(get_connection()) as connection:
        connection.cursor().execute("SELECT 1")
    return {"status": "ok"}


@app.get("/employees")
def employees():
    search = request.args.get("q", "").strip()
    selected_id = request.args.get("selected", type=int)
    employee_list = fetch_employees(search)

    selected_employee = None
    if selected_id is not None:
        selected_employee = fetch_employee(selected_id)
        if selected_employee is None:
            abort(404)
        selected_employee["resident_number_masked"] = mask_resident_number(selected_employee["resident_number"])
        selected_employee["credit_card_masked"] = mask_credit_card(selected_employee["credit_card"])
    elif employee_list:
        first_employee_id = employee_list[0]["employee_id"]
        return redirect(url_for("employee_detail", employee_id=first_employee_id, q=search))

    return render_template_string(
        PAGE,
        employees=employee_list,
        search=search,
        selected_employee=selected_employee,
    )


@app.get("/employees/<int:employee_id>")
def employee_detail(employee_id: int):
    search = request.args.get("q", "").strip()
    employee_list = fetch_employees(search)
    selected_employee = fetch_employee(employee_id)
    if selected_employee is None:
        abort(404)

    selected_employee["resident_number_masked"] = mask_resident_number(selected_employee["resident_number"])
    selected_employee["credit_card_masked"] = mask_credit_card(selected_employee["credit_card"])

    return render_template_string(
        PAGE,
        employees=employee_list,
        search=search,
        selected_employee=selected_employee,
    )


@app.post("/employees/<int:employee_id>")
def employee_update(employee_id: int):
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    address = request.form.get("address", "").strip()

    if not phone or not email or not address:
        abort(400)

    update_employee(employee_id, phone, email, address)
    return redirect(url_for("employee_detail", employee_id=employee_id))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=False)