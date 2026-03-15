"""ChatGPT Team 自动邀请"""

import argparse
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
from flask import Flask, jsonify, request, send_from_directory

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder="static")

JWT_TOKEN = os.getenv("JWT_TOKEN", "")
OAI_CLIENT_VERSION = os.getenv(
    "OAI_CLIENT_VERSION", "prod-eddc2f6ff65fee2d0d6439e379eab94fe3047f72"
)
PORT = int(os.getenv("PORT", "8080"))
BASE_URL = "https://chatgpt.com/backend-api"
DATABASE_PATH = os.getenv("DATABASE_PATH", "data/team_auto_invite.db")
PENDING_TTL_SECONDS = int(os.getenv("REDEEM_PENDING_TTL_SECONDS", "300"))

_token_cache = None


def utc_now() -> datetime:
    """返回当前的UTC时间"""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """返回一个ISO 8601 UTC时间戳"""
    return utc_now().isoformat(timespec="seconds")


def ensure_database_directory() -> None:
    """必要时创建数据库目录"""
    directory = os.path.dirname(DATABASE_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    """创建一个具有类字典行的SQLite连接"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_connection():
    """生成一个SQLite连接，并确保之后将其关闭"""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """初始化兑换流程所使用的SQLite表"""
    ensure_database_directory()
    with db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS redeem_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'unused',
                reserved_by_email TEXT,
                reserved_at TEXT,
                used_by_email TEXT,
                used_at TEXT,
                disabled_at TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS invite_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                code TEXT,
                invite_status TEXT NOT NULL,
                invite_message TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


def validate_email(email: str) -> bool:
    """验证基本的电子邮件格式"""
    return "@" in email and "." in email.split("@")[-1]


def normalize_redeem_code(code: str) -> str:
    """将用户输入标准化为规范的兑换码格式"""
    return code.strip().upper()


def normalize_optional_string(value) -> str | None:
    """验证输入是否为字符串，并返回去除首尾空白后的结果"""
    if not isinstance(value, str):
        return None
    return value.strip()


def decode_token(token: str) -> dict:
    """解码 JWT，提取 account_id 等信息"""
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


def check_token_status() -> dict:
    """检查 Token 状态"""
    global _token_cache
    if not JWT_TOKEN:
        return {"ok": False, "error": "未配置 JWT_TOKEN，请在 .env 文件中设置"}

    if _token_cache is None:
        _token_cache = decode_token(JWT_TOKEN)

    info = _token_cache
    if not info["valid"]:
        return {"ok": False, "error": f"Token 解码失败: {info.get('error', '未知错误')}"}

    if info["exp"] < int(utc_now().timestamp()):
        return {"ok": False, "error": "Token 已过期，请更新 .env 中的 JWT_TOKEN"}
    if info["plan_type"] != "team":
        return {"ok": False, "error": f"当前 Token 不是 Team 类型（当前: {info['plan_type']}）"}

    return {"ok": True, "account_id": info["account_id"], "email": info["email"]}


def send_invite(account_id: str, email: str) -> dict:
    """发送 Team 邀请"""
    url = f"{BASE_URL}/accounts/{account_id}/invites"
    headers = {
        "Accept": "*/*",
        "Authorization": f"Bearer {JWT_TOKEN}",
        "Content-Type": "application/json",
        "OAI-Client-Version": OAI_CLIENT_VERSION,
        "OAI-Language": "zh-CN",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/admin/members",
        "chatgpt-account-id": account_id,
    }
    payload = {"email_addresses": [email], "role": "standard-user", "resend_emails": True}

    try:
        resp = cffi_requests.post(
            url,
            json=payload,
            headers=headers,
            impersonate="chrome",
            timeout=30,
        )
        status = resp.status_code

        if status == 200:
            logger.info("邀请发送成功: %s", email)
            return {"success": True, "message": "邀请发送成功，请检查邮箱"}
        if status == 409:
            logger.warning("邀请冲突: %s (已邀请或已是成员)", email)
            return {"success": False, "message": "该邮箱已被邀请或已是团队成员"}
        if status == 422:
            logger.warning("团队已满，无法邀请: %s", email)
            return {"success": False, "message": "团队已满，无法继续邀请"}

        logger.error("邀请失败 [%s]: %s", status, resp.text)
        return {"success": False, "message": f"邀请失败 (HTTP {status})"}
    except Exception as exc:
        logger.error("请求异常: %s", exc)
        return {"success": False, "message": f"网络请求失败: {str(exc)}"}


def record_invite_attempt(email: str, code: str | None, status: str, message: str) -> None:
    """保留邀请记录，用于后续审计追溯"""
    with db_connection() as conn:
        conn.execute(
            """
            INSERT INTO invite_records (email, code, invite_status, invite_message, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (email, code, status, message, utc_now_iso()),
        )


def create_redeem_codes(codes: list[str]) -> dict:
    """输入兑换码并跳过重复项"""
    inserted: list[str] = []
    skipped: list[str] = []
    now = utc_now_iso()

    with db_connection() as conn:
        for raw_code in codes:
            code = normalize_redeem_code(raw_code)
            if not code:
                continue

            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO redeem_codes (code, status, created_at)
                VALUES (?, 'unused', ?)
                """,
                (code, now),
            )
            if cursor.rowcount:
                inserted.append(code)
            else:
                skipped.append(code)

    return {"inserted": inserted, "skipped": skipped}


def generate_redeem_codes(count: int, prefix: str, length: int) -> list[str]:
    """生成唯一的兑换码并将其存储在SQLite中"""
    alphabet = string.ascii_uppercase + string.digits
    normalized_prefix = normalize_redeem_code(prefix) or "TEAM"
    inserted: list[str] = []
    attempts = 0
    max_attempts = max(count * 10, 20)

    while len(inserted) < count and attempts < max_attempts:
        attempts += 1
        body = "".join(secrets.choice(alphabet) for _ in range(max(length, 6)))
        code = f"{normalized_prefix}-{body}"
        result = create_redeem_codes([code])
        inserted.extend(result["inserted"])

    return inserted


def claim_redeem_code(code: str, email: str) -> dict:
    """发送邀请前请预留一个兑换码"""
    now = utc_now_iso()
    stale_before = (utc_now() - timedelta(seconds=PENDING_TTL_SECONDS)).isoformat(
        timespec="seconds"
    )

    with db_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT status, reserved_at
            FROM redeem_codes
            WHERE code = ?
            """,
            (code,),
        ).fetchone()

        if row is None:
            return {"ok": False, "status": "invalid_code", "message": "兑换码无效"}
        if row["status"] == "disabled":
            return {"ok": False, "status": "disabled_code", "message": "兑换码已禁用"}
        if row["status"] == "used":
            return {"ok": False, "status": "used_code", "message": "兑换码已被使用"}
        if row["status"] == "pending" and row["reserved_at"] and row["reserved_at"] > stale_before:
            return {"ok": False, "status": "pending_code", "message": "兑换码正在处理中，请稍后重试"}

        conn.execute(
            """
            UPDATE redeem_codes
            SET status = 'pending',
                reserved_by_email = ?,
                reserved_at = ?
            WHERE code = ?
            """,
            (email, now, code),
        )

    return {"ok": True}


def complete_redeem_code(code: str, email: str) -> None:
    """将兑换码标记为永久已使用"""
    with db_connection() as conn:
        conn.execute(
            """
            UPDATE redeem_codes
            SET status = 'used',
                used_by_email = ?,
                used_at = ?,
                reserved_by_email = NULL,
                reserved_at = NULL
            WHERE code = ?
            """,
            (email, utc_now_iso(), code),
        )


def release_redeem_code(code: str) -> None:
    """邀请失败后释放一个待处理的兑换码"""
    with db_connection() as conn:
        conn.execute(
            """
            UPDATE redeem_codes
            SET status = 'unused',
                reserved_by_email = NULL,
                reserved_at = NULL
            WHERE code = ? AND status = 'pending'
            """,
            (code,),
        )


def redeem_invite(email: str, code: str) -> dict:
    """兑换代码，若有效则发送团队邀请"""
    token_status = check_token_status()
    if not token_status["ok"]:
        record_invite_attempt(email, code, "token_error", token_status["error"])
        return {
            "success": False,
            "message": token_status["error"],
            "status_code": 503,
        }

    claim = claim_redeem_code(code, email)
    if not claim["ok"]:
        record_invite_attempt(email, code, claim["status"], claim["message"])
        return {
            "success": False,
            "message": claim["message"],
            "status_code": 400,
        }

    result = send_invite(token_status["account_id"], email)
    if result["success"]:
        complete_redeem_code(code, email)
        record_invite_attempt(email, code, "success", result["message"])
        return {"success": True, "message": result["message"], "status_code": 200}

    release_redeem_code(code)
    record_invite_attempt(email, code, "invite_failed", result["message"])
    return {"success": False, "message": result["message"], "status_code": 400}


@app.route("/")
def index():
    """首页"""
    return send_from_directory("static", "index.html")


@app.route("/api/invite", methods=["POST"])
def api_invite():
    """发送邀请"""
    data = request.get_json(silent=True)
    if not data or not data.get("email"):
        return jsonify({"success": False, "message": "请输入邮箱地址"}), 400

    email = normalize_optional_string(data["email"])
    if email is None:
        return jsonify({"success": False, "message": "邮箱格式不正确"}), 400

    email = email.lower()
    if not validate_email(email):
        return jsonify({"success": False, "message": "邮箱格式不正确"}), 400

    token_status = check_token_status()
    if not token_status["ok"]:
        return jsonify({"success": False, "message": token_status["error"]}), 503

    result = send_invite(token_status["account_id"], email)
    return jsonify(result), 200 if result["success"] else 400


@app.route("/api/redeem", methods=["POST"])
def api_redeem():
    """兑换卡密并发送邀请"""
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

    result = redeem_invite(email, code)
    status_code = result.pop("status_code")
    return jsonify(result), status_code


@app.route("/api/health")
def health():
    """健康检查"""
    token_status = check_token_status()
    return jsonify(
        {
            "status": "ok" if token_status["ok"] else "error",
            "token_valid": token_status["ok"],
            "message": token_status.get("error", "服务正常"),
        }
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Create a small CLI for seeding redeem codes."""
    parser = argparse.ArgumentParser(description="ChatGPT Team 自动邀请")
    subparsers = parser.add_subparsers(dest="command")

    generate_parser = subparsers.add_parser("generate-codes", help="生成兑换码")
    generate_parser.add_argument("--count", type=int, default=10, help="生成数量")
    generate_parser.add_argument("--prefix", default="TEAM", help="兑换码前缀")
    generate_parser.add_argument(
        "--length",
        type=int,
        default=10,
        help="兑换码随机部分长度",
    )

    add_parser = subparsers.add_parser("add-codes", help="手动添加兑换码")
    add_parser.add_argument("codes", nargs="+", help="兑换码列表")
    return parser


def handle_cli() -> bool:
    """Handle CLI commands and return whether a command was executed."""
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command == "generate-codes":
        codes = generate_redeem_codes(args.count, args.prefix, args.length)
        print(f"已生成 {len(codes)} 个兑换码:")
        for code in codes:
            print(code)
        return True

    if args.command == "add-codes":
        result = create_redeem_codes(args.codes)
        print(f"新增 {len(result['inserted'])} 个兑换码，跳过 {len(result['skipped'])} 个重复项")
        for code in result["inserted"]:
            print(code)
        return True

    return False


def main() -> None:
    """运行命令行界面或启动Flask应用程序"""
    init_db()
    if handle_cli():
        return

    status = check_token_status()
    if status["ok"]:
        logger.info("Token 有效 | 管理员邮箱: %s", status["email"])
    else:
        logger.warning("Token 问题: %s", status.get("error", "未知"))
    logger.info("服务启动在端口 %s", PORT)
    app.run(host="0.0.0.0", port=PORT, debug=False)


init_db()


if __name__ == "__main__":
    main()
