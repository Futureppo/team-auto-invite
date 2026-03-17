"""ChatGPT Team 自动邀请"""

import argparse
import functools
import logging
import os
import secrets
import sqlite3
import string
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import jwt
from curl_cffi import requests as cffi_requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, session

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder="static")
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

OAI_CLIENT_VERSION = os.getenv(
    "OAI_CLIENT_VERSION", "prod-eddc2f6ff65fee2d0d6439e379eab94fe3047f72"
)
PORT = int(os.getenv("PORT", "8080"))
BASE_URL = "https://chatgpt.com/backend-api"
DATABASE_PATH = os.getenv("DATABASE_PATH", "data/team_auto_invite.db")
PENDING_TTL_SECONDS = int(os.getenv("REDEEM_PENDING_TTL_SECONDS", "300"))
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat(timespec="seconds")


def ensure_database_directory() -> None:
    directory = os.path.dirname(DATABASE_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_connection():
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def validate_email(email: str) -> bool:
    return "@" in email and "." in email.split("@")[-1]


def normalize_redeem_code(code: str) -> str:
    return code.strip().upper()


def normalize_optional_string(value) -> str | None:
    if not isinstance(value, str):
        return None
    return value.strip()


def init_db() -> None:
    ensure_database_directory()
    with db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS redeem_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'unused',
                max_uses INTEGER NOT NULL DEFAULT 1,
                use_count INTEGER NOT NULL DEFAULT 0,
                reserved_by_email TEXT,
                reserved_at TEXT,
                used_by_email TEXT,
                used_at TEXT,
                disabled_at TEXT,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS invite_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                code TEXT,
                token_id INTEGER,
                client_ip TEXT,
                invite_status TEXT NOT NULL,
                invite_message TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS jwt_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                label TEXT DEFAULT '',
                account_id TEXT DEFAULT '',
                email TEXT DEFAULT '',
                plan_type TEXT DEFAULT '',
                exp INTEGER DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                seat_limit INTEGER NOT NULL DEFAULT 0,
                seat_used INTEGER NOT NULL DEFAULT 0,
                priority INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        _migrate_columns(conn)
        _ensure_default_settings(conn)


def _migrate_columns(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(redeem_codes)").fetchall()}
    if "max_uses" not in cols:
        conn.execute("ALTER TABLE redeem_codes ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 1")
    if "use_count" not in cols:
        conn.execute("ALTER TABLE redeem_codes ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0")
    # 并发处理计数器：跟踪当前正在处理中的请求数
    if "pending_count" not in cols:
        conn.execute("ALTER TABLE redeem_codes ADD COLUMN pending_count INTEGER NOT NULL DEFAULT 0")

    cols2 = {r[1] for r in conn.execute("PRAGMA table_info(invite_records)").fetchall()}
    if "client_ip" not in cols2:
        conn.execute("ALTER TABLE invite_records ADD COLUMN client_ip TEXT")
    if "token_id" not in cols2:
        conn.execute("ALTER TABLE invite_records ADD COLUMN token_id INTEGER")


def _ensure_default_settings(conn: sqlite3.Connection) -> None:
    defaults = {"ip_cooldown": "3600", "default_redeem_limit": "1"}
    for key, val in defaults.items():
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, val))


def get_setting(key: str, default: str = "") -> str:
    with db_connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with db_connection() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))



def decode_token(token: str) -> dict:
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        auth = decoded.get("https://api.openai.com/auth", {})
        profile = decoded.get("https://api.openai.com/profile", {})
        return {
            "account_id": auth.get("chatgpt_account_id", ""),
            "plan_type": auth.get("chatgpt_plan_type", ""),
            "email": profile.get("email", ""),
            "exp": decoded.get("exp", 0),
            "valid": True,
        }
    except Exception as exc:
        logger.error("JWT 解码失败: %s", exc)
        return {"valid": False, "error": str(exc)}


def get_available_token() -> dict | None:
    now_ts = int(utc_now().timestamp())
    with db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM jwt_tokens WHERE status = 'active' AND exp > ? ORDER BY priority ASC, id ASC",
            (now_ts,),
        ).fetchall()
    return dict(rows[0]) if rows else None


def get_all_available_tokens() -> list[dict]:
    now_ts = int(utc_now().timestamp())
    with db_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM jwt_tokens WHERE status = 'active' AND exp > ? ORDER BY priority ASC, id ASC",
            (now_ts,),
        ).fetchall()
    return [dict(r) for r in rows]


def mark_token_full(token_id: int) -> None:
    with db_connection() as conn:
        conn.execute(
            "UPDATE jwt_tokens SET status = 'full', updated_at = ? WHERE id = ?",
            (utc_now_iso(), token_id),
        )
    logger.warning("Token #%d 已标记为团队已满", token_id)


def fetch_team_seats(token_row: dict) -> dict:
    """通过 API 获取当前席位使用情况"""
    url = f"{BASE_URL}/accounts/{token_row['account_id']}/users?limit=1&offset=0&query="
    headers = {
        "Accept": "*/*",
        "Authorization": f"Bearer {token_row['token']}",
        "OAI-Client-Version": OAI_CLIENT_VERSION,
        "OAI-Language": "zh-CN",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/admin/members",
        "chatgpt-account-id": token_row["account_id"],
    }
    try:
        resp = cffi_requests.get(url, headers=headers, impersonate="chrome", timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            total_members = data.get("total", 0)
            return {"ok": True, "total_members": total_members}
        return {"ok": False, "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}



def send_invite_with_token(token_row: dict, email: str) -> dict:
    url = f"{BASE_URL}/accounts/{token_row['account_id']}/invites"
    headers = {
        "Accept": "*/*",
        "Authorization": f"Bearer {token_row['token']}",
        "Content-Type": "application/json",
        "OAI-Client-Version": OAI_CLIENT_VERSION,
        "OAI-Language": "zh-CN",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/admin/members",
        "chatgpt-account-id": token_row["account_id"],
    }
    payload = {"email_addresses": [email], "role": "standard-user", "resend_emails": True}

    try:
        resp = cffi_requests.post(url, json=payload, headers=headers, impersonate="chrome", timeout=30)
        status = resp.status_code
        if status == 200:
            logger.info("邀请成功: %s (Token #%d)", email, token_row["id"])
            return {"success": True, "message": "邀请发送成功，请检查邮箱", "token_id": token_row["id"]}
        if status == 409:
            logger.warning("邀请冲突: %s", email)
            return {"success": False, "message": "该邮箱已被邀请或已是团队成员", "token_id": token_row["id"]}
        if status == 422:
            return {"success": False, "message": "团队已满", "full": True, "token_id": token_row["id"]}
        logger.error("邀请失败 [%s]: %s", status, resp.text)
        return {"success": False, "message": f"邀请失败 (HTTP {status})", "token_id": token_row["id"]}
    except Exception as exc:
        logger.error("请求异常: %s", exc)
        return {"success": False, "message": f"网络请求失败: {str(exc)}", "token_id": token_row["id"]}


def send_invite_with_rotation(email: str) -> dict:
    """尝试所有可用 Token 发送邀请，遇到422自动轮询下一个"""
    tokens = get_all_available_tokens()
    if not tokens:
        return {"success": False, "message": "无可用 Team 母号", "token_id": None}

    for token_row in tokens:
        result = send_invite_with_token(token_row, email)
        if result.get("full"):
            mark_token_full(token_row["id"])
            continue
        return result

    return {"success": False, "message": "所有 Team 母号均已满员", "token_id": None}


def record_invite_attempt(email: str, code: str | None, status: str, message: str,
                          client_ip: str | None = None, token_id: int | None = None) -> None:
    with db_connection() as conn:
        conn.execute(
            "INSERT INTO invite_records (email, code, token_id, client_ip, invite_status, invite_message, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (email, code, token_id, client_ip, status, message, utc_now_iso()),
        )


def check_ip_cooldown(client_ip: str) -> dict:
    cooldown = int(get_setting("ip_cooldown", "3600"))
    if cooldown <= 0:
        return {"ok": True}
    cutoff = (utc_now() - timedelta(seconds=cooldown)).isoformat(timespec="seconds")
    with db_connection() as conn:
        row = conn.execute(
            "SELECT created_at FROM invite_records WHERE client_ip = ? AND invite_status = 'success' AND created_at > ? ORDER BY id DESC LIMIT 1",
            (client_ip, cutoff),
        ).fetchone()
    if row:
        return {"ok": False, "message": f"操作过于频繁，请 {cooldown} 秒后再试"}
    return {"ok": True}


def create_redeem_codes(codes: list[str], max_uses: int = 1) -> dict:
    inserted, skipped = [], []
    now = utc_now_iso()
    with db_connection() as conn:
        for raw_code in codes:
            code = normalize_redeem_code(raw_code)
            if not code:
                continue
            cursor = conn.execute(
                "INSERT OR IGNORE INTO redeem_codes (code, status, max_uses, created_at) VALUES (?, 'unused', ?, ?)",
                (code, max_uses, now),
            )
            if cursor.rowcount:
                inserted.append(code)
            else:
                skipped.append(code)
    return {"inserted": inserted, "skipped": skipped}


def generate_redeem_codes(count: int, prefix: str, length: int, max_uses: int = 1) -> list[str]:
    alphabet = string.ascii_uppercase + string.digits
    normalized_prefix = normalize_redeem_code(prefix) or "TEAM"
    inserted, attempts = [], 0
    max_attempts = max(count * 10, 20)
    while len(inserted) < count and attempts < max_attempts:
        attempts += 1
        body = "".join(secrets.choice(alphabet) for _ in range(max(length, 6)))
        code = f"{normalized_prefix}-{body}"
        result = create_redeem_codes([code], max_uses)
        inserted.extend(result["inserted"])
    return inserted


def claim_redeem_code(code: str, email: str) -> dict:
    """原子地预占一个兑换码名额，支持多线程并发处理"""
    now = utc_now_iso()

    with db_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT status, max_uses, use_count, pending_count FROM redeem_codes WHERE code = ?",
            (code,),
        ).fetchone()

        if row is None:
            return {"ok": False, "status": "invalid_code", "message": "兑换码无效"}
        if row["status"] == "disabled":
            return {"ok": False, "status": "disabled_code", "message": "兑换码已禁用"}

        pending = row["pending_count"] or 0
        used = row["use_count"] or 0

        if used >= row["max_uses"]:
            return {"ok": False, "status": "used_code", "message": "兑换码已达使用上限"}
        # 已用 + 正在处理 >= 上限，说明名额已被占满（包括正在处理的）
        if used + pending >= row["max_uses"]:
            return {"ok": False, "status": "pending_code", "message": "兑换码正在处理中，请稍后重试"}

        # 原子递增 pending_count，预占一个名额
        conn.execute(
            "UPDATE redeem_codes SET pending_count = pending_count + 1, reserved_by_email = ?, reserved_at = ? WHERE code = ?",
            (email, now, code),
        )
    return {"ok": True}


def complete_redeem_code(code: str, email: str) -> None:
    """邀请成功：递减 pending_count，递增 use_count"""
    with db_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT max_uses, use_count FROM redeem_codes WHERE code = ?", (code,)).fetchone()
        new_count = (row["use_count"] if row else 0) + 1
        new_status = "used" if row and new_count >= row["max_uses"] else "unused"
        conn.execute(
            "UPDATE redeem_codes SET status = ?, use_count = ?, pending_count = MAX(pending_count - 1, 0),"
            " used_by_email = ?, used_at = ? WHERE code = ?",
            (new_status, new_count, email, utc_now_iso(), code),
        )


def release_redeem_code(code: str) -> None:
    """邀请失败：递减 pending_count，释放名额"""
    with db_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT max_uses, use_count, pending_count FROM redeem_codes WHERE code = ?", (code,)).fetchone()
        new_pending = max((row["pending_count"] or 0) - 1, 0) if row else 0
        restore_status = "unused" if row and row["use_count"] < row["max_uses"] else "used"
        conn.execute(
            "UPDATE redeem_codes SET status = ?, pending_count = ?,"
            " reserved_by_email = NULL, reserved_at = NULL WHERE code = ?",
            (restore_status, new_pending, code),
        )


def redeem_invite(email: str, code: str, client_ip: str | None = None) -> dict:
    ip_check = check_ip_cooldown(client_ip) if client_ip else {"ok": True}
    if not ip_check["ok"]:
        record_invite_attempt(email, code, "rate_limited", ip_check["message"], client_ip)
        return {"success": False, "message": ip_check["message"], "status_code": 429}

    claim = claim_redeem_code(code, email)
    if not claim["ok"]:
        record_invite_attempt(email, code, claim["status"], claim["message"], client_ip)
        return {"success": False, "message": claim["message"], "status_code": 400}

    result = send_invite_with_rotation(email)
    token_id = result.get("token_id")
    if result["success"]:
        complete_redeem_code(code, email)
        record_invite_attempt(email, code, "success", result["message"], client_ip, token_id)
        return {"success": True, "message": result["message"], "status_code": 200}

    release_redeem_code(code)
    record_invite_attempt(email, code, "invite_failed", result["message"], client_ip, token_id)
    return {"success": False, "message": result["message"], "status_code": 400}


def get_client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/redeem", methods=["POST"])
def api_redeem():
    data = request.get_json(silent=True)
    if not data or not data.get("email") or not data.get("code"):
        return jsonify({"success": False, "message": "请输入邮箱地址和兑换码"}), 400

    email = normalize_optional_string(data["email"])
    code = normalize_optional_string(data["code"])
    if email is None:
        return jsonify({"success": False, "message": "邮箱格式不正确"}), 400
    if code is None:
        return jsonify({"success": False, "message": "兑换码不能为空"}), 400

    email = email.lower()
    code = normalize_redeem_code(code)
    if not validate_email(email):
        return jsonify({"success": False, "message": "邮箱格式不正确"}), 400
    if not code:
        return jsonify({"success": False, "message": "兑换码不能为空"}), 400

    result = redeem_invite(email, code, get_client_ip())
    status_code = result.pop("status_code")
    return jsonify(result), status_code


@app.route("/api/health")
def health():
    token = get_available_token()
    ok = token is not None
    return jsonify({
        "status": "ok" if ok else "error",
        "token_valid": ok,
        "message": "服务正常" if ok else "无可用 Team 母号",
    })



def admin_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"success": False, "message": "未授权"}), 401
        return f(*args, **kwargs)
    return wrapper


@app.route("/admin")
@app.route("/admin/")
def admin_page():
    return send_from_directory("static", "admin.html")


@app.route("/admin/api/login", methods=["POST"])
def admin_login():
    if not ADMIN_PASSWORD:
        return jsonify({"success": False, "message": "未配置管理员密码"}), 503
    data = request.get_json(silent=True)
    password = data.get("password", "") if data else ""
    if not isinstance(password, str) or not password:
        return jsonify({"success": False, "message": "请输入密码"}), 400
    if not secrets.compare_digest(password, ADMIN_PASSWORD):
        logger.warning("后台登录失败，来源: %s", request.remote_addr)
        return jsonify({"success": False, "message": "密码错误"}), 403
    session.clear()
    session["is_admin"] = True
    return jsonify({"success": True})


@app.route("/admin/api/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/admin/api/stats")
@admin_required
def admin_stats():
    with db_connection() as conn:
        cs = conn.execute(
            "SELECT COUNT(*) as total,"
            " COALESCE(SUM(CASE WHEN status='unused' THEN 1 END),0) as unused,"
            " COALESCE(SUM(CASE WHEN status='used' THEN 1 END),0) as used,"
            " COALESCE(SUM(CASE WHEN status='disabled' THEN 1 END),0) as disabled,"
            " COALESCE(SUM(CASE WHEN status='pending' THEN 1 END),0) as pending"
            " FROM redeem_codes"
        ).fetchone()
        rs = conn.execute(
            "SELECT COUNT(*) as total,"
            " COALESCE(SUM(CASE WHEN invite_status='success' THEN 1 END),0) as success,"
            " COALESCE(SUM(CASE WHEN invite_status NOT IN ('success','token_error','rate_limited') THEN 1 END),0) as failed"
            " FROM invite_records"
        ).fetchone()
        ts = conn.execute(
            "SELECT COUNT(*) as total,"
            " COALESCE(SUM(CASE WHEN status='active' THEN 1 END),0) as active,"
            " COALESCE(SUM(CASE WHEN status='full' THEN 1 END),0) as full_count"
            " FROM jwt_tokens"
        ).fetchone()
    return jsonify({"codes": dict(cs), "records": dict(rs), "tokens": dict(ts)})



@app.route("/admin/api/codes")
@admin_required
def admin_list_codes():
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = min(max(request.args.get("per_page", 20, type=int), 1), 100)
    status = request.args.get("status", "").strip()
    search = request.args.get("search", "").strip()
    where_parts, params = [], []
    if status:
        where_parts.append("status = ?")
        params.append(status)
    if search:
        where_parts.append("(code LIKE ? OR used_by_email LIKE ? OR reserved_by_email LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])
    where = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    with db_connection() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM redeem_codes{where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM redeem_codes{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            [*params, per_page, (page - 1) * per_page],
        ).fetchall()
    return jsonify({"total": total, "page": page, "per_page": per_page, "items": [dict(r) for r in rows]})


@app.route("/admin/api/codes", methods=["POST"])
@admin_required
def admin_import_codes():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体无效"}), 400
    codes = data.get("codes", [])
    if not isinstance(codes, list) or not codes:
        return jsonify({"success": False, "message": "请提供兑换码列表"}), 400
    if len(codes) > 1000:
        return jsonify({"success": False, "message": "单次最多导入 1000 个"}), 400
    max_uses = max(int(data.get("max_uses", 1)), 1)
    result = create_redeem_codes(codes, max_uses)
    return jsonify({"success": True, "inserted": len(result["inserted"]), "skipped": len(result["skipped"])})


@app.route("/admin/api/codes/generate", methods=["POST"])
@admin_required
def admin_generate_codes():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体无效"}), 400
    try:
        count = min(max(int(data.get("count", 10)), 1), 500)
        length = min(max(int(data.get("length", 10)), 6), 32)
        max_uses = max(int(data.get("max_uses", 1)), 1)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "参数格式错误"}), 400
    prefix = str(data.get("prefix", "TEAM"))[:16]
    codes = generate_redeem_codes(count, prefix, length, max_uses)
    return jsonify({"success": True, "count": len(codes), "codes": codes})


@app.route("/admin/api/codes/<int:code_id>/disable", methods=["PATCH"])
@admin_required
def admin_disable_code(code_id):
    with db_connection() as conn:
        row = conn.execute("SELECT status FROM redeem_codes WHERE id = ?", (code_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "message": "兑换码不存在"}), 404
        if row["status"] == "disabled":
            return jsonify({"success": False, "message": "兑换码已禁用"}), 400
        if row["status"] == "used":
            r2 = conn.execute("SELECT max_uses, use_count FROM redeem_codes WHERE id = ?", (code_id,)).fetchone()
            if r2 and r2["use_count"] >= r2["max_uses"]:
                return jsonify({"success": False, "message": "已用尽的兑换码无法禁用"}), 400
        conn.execute(
            "UPDATE redeem_codes SET status='disabled', disabled_at=? WHERE id=?",
            (utc_now_iso(), code_id),
        )
    return jsonify({"success": True})


@app.route("/admin/api/codes/<int:code_id>/enable", methods=["PATCH"])
@admin_required
def admin_enable_code(code_id):
    with db_connection() as conn:
        row = conn.execute("SELECT status, max_uses, use_count FROM redeem_codes WHERE id = ?", (code_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "message": "兑换码不存在"}), 404
        if row["status"] != "disabled":
            return jsonify({"success": False, "message": "仅已禁用的兑换码可启用"}), 400
        restore = "unused" if row["use_count"] < row["max_uses"] else "used"
        conn.execute(
            "UPDATE redeem_codes SET status=?, disabled_at=NULL WHERE id=?",
            (restore, code_id),
        )
    return jsonify({"success": True})



@app.route("/admin/api/records")
@admin_required
def admin_list_records():
    page = max(request.args.get("page", 1, type=int), 1)
    per_page = min(max(request.args.get("per_page", 20, type=int), 1), 100)
    status = request.args.get("status", "").strip()
    email = request.args.get("email", "").strip()
    where_parts, params = [], []
    if status:
        where_parts.append("invite_status = ?")
        params.append(status)
    if email:
        where_parts.append("email LIKE ?")
        params.append(f"%{email}%")
    where = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
    with db_connection() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM invite_records{where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM invite_records{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            [*params, per_page, (page - 1) * per_page],
        ).fetchall()
    return jsonify({"total": total, "page": page, "per_page": per_page, "items": [dict(r) for r in rows]})


@app.route("/admin/api/tokens")
@admin_required
def admin_list_tokens():
    with db_connection() as conn:
        rows = conn.execute(
            "SELECT id, label, account_id, email, plan_type, exp, status, seat_limit, seat_used, priority, created_at, updated_at"
            " FROM jwt_tokens ORDER BY priority ASC, id ASC"
        ).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


@app.route("/admin/api/tokens", methods=["POST"])
@admin_required
def admin_add_token():
    data = request.get_json(silent=True)
    if not data or not data.get("token"):
        return jsonify({"success": False, "message": "请提供 JWT Token"}), 400
    raw_token = data["token"].strip()
    if not isinstance(raw_token, str) or len(raw_token) < 20:
        return jsonify({"success": False, "message": "Token 格式无效"}), 400
    info = decode_token(raw_token)
    if not info["valid"]:
        return jsonify({"success": False, "message": f"Token 解码失败: {info.get('error')}"}), 400
    if info["plan_type"] != "team":
        return jsonify({"success": False, "message": f"非 Team 类型 Token（当前: {info['plan_type']})"}), 400
    label = str(data.get("label", ""))[:64]
    seat_limit = max(int(data.get("seat_limit", 0)), 0)
    now = utc_now_iso()
    with db_connection() as conn:
        existing = conn.execute("SELECT id FROM jwt_tokens WHERE account_id = ?", (info["account_id"],)).fetchone()
        if existing:
            conn.execute(
                "UPDATE jwt_tokens SET token=?, label=?, email=?, plan_type=?, exp=?, seat_limit=?, status='active', updated_at=? WHERE id=?",
                (raw_token, label, info["email"], info["plan_type"], info["exp"], seat_limit, now, existing["id"]),
            )
            return jsonify({"success": True, "message": "Token 已更新", "id": existing["id"]})
        cursor = conn.execute(
            "INSERT INTO jwt_tokens (token, label, account_id, email, plan_type, exp, seat_limit, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (raw_token, label, info["account_id"], info["email"], info["plan_type"], info["exp"], seat_limit, now),
        )
        return jsonify({"success": True, "message": "Token 已添加", "id": cursor.lastrowid})


@app.route("/admin/api/tokens/<int:token_id>", methods=["DELETE"])
@admin_required
def admin_delete_token(token_id):
    with db_connection() as conn:
        row = conn.execute("SELECT id FROM jwt_tokens WHERE id = ?", (token_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "message": "Token 不存在"}), 404
        conn.execute("DELETE FROM jwt_tokens WHERE id = ?", (token_id,))
    return jsonify({"success": True})


@app.route("/admin/api/tokens/<int:token_id>/disable", methods=["PATCH"])
@admin_required
def admin_disable_token(token_id):
    with db_connection() as conn:
        row = conn.execute("SELECT status FROM jwt_tokens WHERE id = ?", (token_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "message": "Token 不存在"}), 404
        conn.execute("UPDATE jwt_tokens SET status='disabled', updated_at=? WHERE id=?", (utc_now_iso(), token_id))
    return jsonify({"success": True})


@app.route("/admin/api/tokens/<int:token_id>/enable", methods=["PATCH"])
@admin_required
def admin_enable_token(token_id):
    with db_connection() as conn:
        row = conn.execute("SELECT id FROM jwt_tokens WHERE id = ?", (token_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "message": "Token 不存在"}), 404
        conn.execute("UPDATE jwt_tokens SET status='active', updated_at=? WHERE id=?", (utc_now_iso(), token_id))
    return jsonify({"success": True})


@app.route("/admin/api/tokens/<int:token_id>/seats", methods=["POST"])
@admin_required
def admin_refresh_seats(token_id):
    with db_connection() as conn:
        row = conn.execute("SELECT * FROM jwt_tokens WHERE id = ?", (token_id,)).fetchone()
        if not row:
            return jsonify({"success": False, "message": "Token 不存在"}), 404
        token_row = dict(row)
    result = fetch_team_seats(token_row)
    if not result["ok"]:
        return jsonify({"success": False, "message": result["error"]})
    with db_connection() as conn:
        conn.execute(
            "UPDATE jwt_tokens SET seat_used = ?, updated_at = ? WHERE id = ?",
            (result["total_members"], utc_now_iso(), token_id),
        )
    return jsonify({"success": True, "seat_used": result["total_members"]})


@app.route("/admin/api/settings")
@admin_required
def admin_get_settings():
    with db_connection() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    return jsonify({r["key"]: r["value"] for r in rows})


@app.route("/admin/api/settings", methods=["PUT"])
@admin_required
def admin_update_settings():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "请求体无效"}), 400
    allowed = {"ip_cooldown", "default_redeem_limit"}
    with db_connection() as conn:
        for key, value in data.items():
            if key not in allowed:
                continue
            try:
                int(value)
            except (TypeError, ValueError):
                return jsonify({"success": False, "message": f"{key} 必须为整数"}), 400
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    return jsonify({"success": True})


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ChatGPT Team 自动邀请")
    subparsers = parser.add_subparsers(dest="command")
    gen = subparsers.add_parser("generate-codes", help="生成兑换码")
    gen.add_argument("--count", type=int, default=10, help="生成数量")
    gen.add_argument("--prefix", default="TEAM", help="兑换码前缀")
    gen.add_argument("--length", type=int, default=10, help="随机部分长度")
    gen.add_argument("--max-uses", type=int, default=1, help="每个卡密可用次数")
    add = subparsers.add_parser("add-codes", help="手动添加兑换码")
    add.add_argument("codes", nargs="+", help="兑换码列表")
    add.add_argument("--max-uses", type=int, default=1, help="每个卡密可用次数")
    return parser


def handle_cli() -> bool:
    parser = build_arg_parser()
    args = parser.parse_args()
    if args.command == "generate-codes":
        codes = generate_redeem_codes(args.count, args.prefix, args.length, args.max_uses)
        print(f"已生成 {len(codes)} 个兑换码:")
        for c in codes:
            print(c)
        return True
    if args.command == "add-codes":
        result = create_redeem_codes(args.codes, args.max_uses)
        print(f"新增 {len(result['inserted'])} 个，跳过 {len(result['skipped'])} 个重复项")
        for c in result["inserted"]:
            print(c)
        return True
    return False


def main() -> None:
    init_db()
    if handle_cli():
        return
    token = get_available_token()
    if token:
        logger.info("可用母号: %s (%s)", token["label"] or token["email"], token["account_id"])
    else:
        logger.warning("当前无可用 Team 母号，请在后台添加")
    logger.info("服务启动在端口 %s", PORT)
    app.run(host="0.0.0.0", port=PORT, debug=False)


init_db()

if __name__ == "__main__":
    main()
