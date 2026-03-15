"""
ChatGPT Team 自动邀请服务
一个轻量级的 Flask 应用，提供 ChatGPT Team 邀请功能
"""

import fcntl
import hmac
import json
import logging
import os
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

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


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
STATE_FILE = DATA_DIR / "state.json"

JWT_TOKEN = os.getenv("JWT_TOKEN", "").strip()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()
OAI_CLIENT_VERSION = os.getenv(
    "OAI_CLIENT_VERSION", "prod-eddc2f6ff65fee2d0d6439e379eab94fe3047f72"
)
IMPERSONATE_BROWSER = os.getenv("IMPERSONATE_BROWSER", "chrome")
PORT = int(os.getenv("PORT", "8080"))
RATE_LIMIT_SECONDS = max(0, int(os.getenv("RATE_LIMIT_SECONDS", "180")))


BASE_URL = "https://chatgpt.com/backend-api"
PUBLIC_ACCEPTED_MESSAGE = "请求已提交，请留意邮箱"
PUBLIC_RETRY_LATER_MESSAGE = "服务暂不可用，请稍后再试"
UNAUTHORIZED_MESSAGE = "未授权"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def build_initial_state() -> dict:
    state = {
        "meta": {"env_seed_done": True},
        "tokens": [],
        "ip_cooldowns": {},
    }
    if JWT_TOKEN:
        state["tokens"].append(
            {
                "id": uuid.uuid4().hex,
                "token": JWT_TOKEN,
                "created_at": utc_now_iso(),
            }
        )
    return state


def normalize_state(payload: dict | None) -> dict:
    payload = payload or {}
    meta = payload.get("meta")
    tokens = payload.get("tokens")
    ip_cooldowns = payload.get("ip_cooldowns")

    if not isinstance(meta, dict):
        meta = {"env_seed_done": True}
    if not isinstance(tokens, list):
        tokens = []
    if not isinstance(ip_cooldowns, dict):
        ip_cooldowns = {}

    normalized_tokens = []
    for record in tokens:
        if not isinstance(record, dict):
            continue
        token_id = str(record.get("id", "")).strip()
        token = str(record.get("token", "")).strip()
        created_at = str(record.get("created_at", "")).strip() or utc_now_iso()
        if token_id and token:
            normalized_tokens.append(
                {
                    "id": token_id,
                    "token": token,
                    "created_at": created_at,
                }
            )

    normalized_cooldowns = {}
    for ip, last_success in ip_cooldowns.items():
        try:
            normalized_cooldowns[str(ip)] = int(last_success)
        except (TypeError, ValueError):
            continue

    return {
        "meta": meta,
        "tokens": normalized_tokens,
        "ip_cooldowns": normalized_cooldowns,
    }


def ensure_state_file() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if STATE_FILE.exists():
        return

    try:
        with STATE_FILE.open("x", encoding="utf-8") as file:
            json.dump(build_initial_state(), file, ensure_ascii=False, indent=2)
    except FileExistsError:
        return


@contextmanager
def locked_state():
    ensure_state_file()
    with STATE_FILE.open("r+", encoding="utf-8") as file:
        fcntl.flock(file.fileno(), fcntl.LOCK_EX)
        try:
            raw = file.read().strip()
            if raw:
                try:
                    state = normalize_state(json.loads(raw))
                except json.JSONDecodeError:
                    logger.error("state.json 解析失败，已回退为空状态")
                    state = normalize_state({})
            else:
                state = normalize_state({})
            yield state, file
        finally:
            fcntl.flock(file.fileno(), fcntl.LOCK_UN)


def save_state(file, state: dict) -> None:
    file.seek(0)
    json.dump(state, file, ensure_ascii=False, indent=2)
    file.truncate()
    file.flush()
    os.fsync(file.fileno())


def decode_token(token: str) -> dict:
    """
    解码 JWT Token，提取 account_id 等关键信息
    不验证签名，仅提取 payload
    """
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        auth = decoded.get("https://api.openai.com/auth", {})
        profile = decoded.get("https://api.openai.com/profile", {})
        account_id = auth.get("chatgpt_account_id", "")
        plan_type = auth.get("chatgpt_plan_type", "")
        email = profile.get("email", "")
        exp = decoded.get("exp", 0)
        return {
            "account_id": account_id,
            "plan_type": plan_type,
            "email": email,
            "exp": exp,
            "valid": True,
        }
    except Exception as exc:
        logger.error(f"JWT 解码失败: {exc}")
        return {"valid": False, "error": str(exc)}


def get_headers(account_id: str, token: str) -> dict:
    """构建请求头"""
    return {
        "Accept": "*/*",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "OAI-Client-Version": OAI_CLIENT_VERSION,
        "OAI-Language": "zh-CN",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/admin/members",
        "chatgpt-account-id": account_id,
    }


def get_token_status(token: str) -> dict:
    """
    检查单个 Token 状态：是否存在、是否过期、是否为 Team 类型
    """
    if not token:
        return {"ok": False, "status": "missing", "error": "暂无可用 Token，请先添加"}

    info = decode_token(token)
    if not info["valid"]:
        return {
            "ok": False,
            "status": "invalid",
            "error": f"Token 解码失败: {info.get('error', '未知错误')}",
        }

    now_ts = int(utc_now().timestamp())
    if info["exp"] < now_ts:
        return {
            "ok": False,
            "status": "expired",
            "error": "Token 已过期，请删除后重新添加",
            **info,
        }

    if info["plan_type"] != "team":
        return {
            "ok": False,
            "status": "not_team",
            "error": f"当前 Token 不是 Team 类型（当前: {info['plan_type']}）",
            **info,
        }

    return {"ok": True, "status": "valid", **info}


def mask_token(token: str) -> str:
    if len(token) <= 24:
        return f"{token[:8]}...{token[-4:]}"
    return f"{token[:12]}...{token[-8:]}"


def format_timestamp(timestamp: int) -> str:
    if not timestamp:
        return ""
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def token_status_label(status: str) -> str:
    labels = {
        "valid": "可用",
        "expired": "已过期",
        "not_team": "非 Team",
        "invalid": "无效",
        "missing": "缺失",
    }
    return labels.get(status, "未知")


def list_token_records() -> list[dict]:
    with locked_state() as (state, _):
        return list(state["tokens"])


def build_token_summary(record: dict) -> dict:
    status = get_token_status(record["token"])
    return {
        "id": record["id"],
        "token_preview": mask_token(record["token"]),
        "created_at": record["created_at"],
        "email": status.get("email", ""),
        "account_id": status.get("account_id", ""),
        "plan_type": status.get("plan_type", ""),
        "expires_at": format_timestamp(status.get("exp", 0)),
        "is_valid": status["ok"],
        "status": status["status"],
        "status_label": token_status_label(status["status"]),
        "message": status.get("error", "Token 可用"),
    }


def get_token_summaries() -> list[dict]:
    return [build_token_summary(record) for record in list_token_records()]


def add_token_record(token: str) -> tuple[dict | None, str | None, int]:
    cleaned = token.strip()
    if not cleaned:
        return None, "Token 不能为空", 400

    status = get_token_status(cleaned)
    if not status["ok"]:
        return None, status["error"], 400

    record = {
        "id": uuid.uuid4().hex,
        "token": cleaned,
        "created_at": utc_now_iso(),
    }

    with locked_state() as (state, file):
        exists = any(item["token"] == cleaned for item in state["tokens"])
        if exists:
            return None, "该 Token 已存在", 409
        state["tokens"].insert(0, record)
        save_state(file, state)

    return record, None, 201


def delete_token_record(token_id: str) -> bool:
    with locked_state() as (state, file):
        original_size = len(state["tokens"])
        state["tokens"] = [item for item in state["tokens"] if item["id"] != token_id]
        deleted = len(state["tokens"]) != original_size
        if deleted:
            save_state(file, state)
        return deleted


def get_pool_status() -> dict:
    summaries = get_token_summaries()
    valid_count = sum(1 for item in summaries if item["is_valid"])

    if valid_count > 0:
        return {
            "ok": True,
            "message": "服务正常",
            "token_count": len(summaries),
            "valid_token_count": valid_count,
            "tokens": summaries,
        }

    if summaries:
        return {
            "ok": False,
            "message": summaries[0]["message"],
            "token_count": len(summaries),
            "valid_token_count": 0,
            "tokens": summaries,
        }

    return {
        "ok": False,
        "message": "暂无可用 Token，请先在后台添加",
        "token_count": 0,
        "valid_token_count": 0,
        "tokens": [],
    }


def get_client_ip() -> str:
    client_ip = request.headers.get("X-Forwarded-For") or request.remote_addr or ""
    if client_ip and "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    return client_ip or "unknown"


def get_remaining_cooldown(client_ip: str) -> int:
    if RATE_LIMIT_SECONDS <= 0:
        return 0

    now_ts = int(time.time())
    with locked_state() as (state, file):
        last_success = state["ip_cooldowns"].get(client_ip, 0)
        elapsed = now_ts - int(last_success)
        if elapsed >= RATE_LIMIT_SECONDS:
            if client_ip in state["ip_cooldowns"]:
                state["ip_cooldowns"].pop(client_ip, None)
                save_state(file, state)
            return 0
        return RATE_LIMIT_SECONDS - elapsed


def record_invite_success(client_ip: str) -> None:
    if RATE_LIMIT_SECONDS <= 0:
        return

    now_ts = int(time.time())
    expiry_cutoff = now_ts - RATE_LIMIT_SECONDS
    with locked_state() as (state, file):
        state["ip_cooldowns"][client_ip] = now_ts
        expired = [
            ip
            for ip, last_success in state["ip_cooldowns"].items()
            if int(last_success) < expiry_cutoff
        ]
        for ip in expired:
            state["ip_cooldowns"].pop(ip, None)
        save_state(file, state)


def verify_admin_password(password: str) -> bool:
    if not ADMIN_PASSWORD:
        return False
    return hmac.compare_digest(password or "", ADMIN_PASSWORD)


def require_admin_access() -> tuple[bool, tuple | None]:
    if not ADMIN_PASSWORD:
        return False, (
            jsonify({"success": False, "message": UNAUTHORIZED_MESSAGE}),
            401,
        )

    provided = request.headers.get("X-Admin-Password", "")
    if verify_admin_password(provided):
        return True, None

    return False, (
        jsonify({"success": False, "message": UNAUTHORIZED_MESSAGE}),
        401,
    )


def send_invite(token: str, account_id: str, email: str) -> dict:
    """
    调用 ChatGPT API 发送 Team 邀请
    """
    url = f"{BASE_URL}/accounts/{account_id}/invites"
    headers = get_headers(account_id, token)
    payload = {
        "email_addresses": [email],
        "role": "standard-user",
        "resend_emails": True,
    }

    try:
        resp = cffi_requests.post(
            url,
            json=payload,
            headers=headers,
            impersonate=IMPERSONATE_BROWSER,
            timeout=30,
        )

        if resp.status_code == 200:
            logger.info(f"邀请发送成功: {email}")
            return {"success": True, "message": PUBLIC_ACCEPTED_MESSAGE}

        if resp.status_code == 409:
            logger.warning(f"邀请冲突: {email} (已邀请或已是成员)")
            return {
                "success": True,
                "message": PUBLIC_ACCEPTED_MESSAGE,
                "retryable": False,
            }

        if resp.status_code == 422:
            logger.warning(f"团队已满，尝试下一个 Token: {email}")
            return {
                "success": False,
                "message": PUBLIC_RETRY_LATER_MESSAGE,
                "retryable": True,
            }

        body = resp.text
        logger.error(f"邀请失败 [{resp.status_code}]: {body}")
        return {
            "success": False,
            "message": PUBLIC_RETRY_LATER_MESSAGE,
            "retryable": True,
        }

    except Exception as exc:
        logger.error(f"请求异常: {exc}")
        return {
            "success": False,
            "message": PUBLIC_RETRY_LATER_MESSAGE,
            "retryable": True,
        }


def invite_with_token_pool(email: str) -> tuple[dict, int]:
    records = list_token_records()
    if not records:
        return {"success": False, "message": PUBLIC_RETRY_LATER_MESSAGE}, 503

    had_valid_token = False
    last_error = PUBLIC_RETRY_LATER_MESSAGE

    for record in records:
        status = get_token_status(record["token"])
        if not status["ok"]:
            last_error = status["error"]
            continue

        had_valid_token = True
        result = send_invite(record["token"], status["account_id"], email)
        if result["success"]:
            return result, 200

        if not result.get("retryable", False):
            return result, 400

        last_error = result["message"]

    if not had_valid_token:
        return {"success": False, "message": PUBLIC_RETRY_LATER_MESSAGE}, 503

    return {"success": False, "message": PUBLIC_RETRY_LATER_MESSAGE}, 400


@app.route("/")
def index():
    """首页 - 返回静态 HTML 页面"""
    return send_from_directory("static", "index.html")


@app.route("/admin")
def admin():
    """管理后台页面"""
    return send_from_directory("static", "admin.html")


@app.route("/api/admin/login", methods=["POST"])
def api_admin_login():
    data = request.get_json(silent=True)
    password = (data or {}).get("password", "")

    if not ADMIN_PASSWORD:
        return jsonify({"success": False, "message": UNAUTHORIZED_MESSAGE}), 401

    if not verify_admin_password(password):
        return jsonify({"success": False, "message": UNAUTHORIZED_MESSAGE}), 401

    return jsonify({"success": True, "message": "登录成功"})


@app.route("/api/invite", methods=["POST"])
def api_invite():
    """
    发送邀请 API
    请求体: { "email": "user@example.com" }
    """
    client_ip = get_client_ip()
    remaining = get_remaining_cooldown(client_ip)
    if remaining > 0:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "请求过于频繁，请稍后再试",
                }
            ),
            429,
        )

    data = request.get_json(silent=True)
    if not data or not data.get("email"):
        return jsonify({"success": False, "message": "请输入邮箱地址"}), 400

    email = data["email"].strip().lower()
    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"success": False, "message": "邮箱格式不正确"}), 400

    result, status_code = invite_with_token_pool(email)
    if result["success"]:
        record_invite_success(client_ip)

    return jsonify(result), status_code


@app.route("/api/tokens", methods=["GET", "POST"])
def api_tokens():
    allowed, error_response = require_admin_access()
    if not allowed:
        return error_response

    if request.method == "GET":
        pool_status = get_pool_status()
        return jsonify(
            {
                "success": True,
                "tokens": pool_status["tokens"],
                "token_count": pool_status["token_count"],
                "valid_token_count": pool_status["valid_token_count"],
                "cooldown_seconds": RATE_LIMIT_SECONDS,
            }
        )

    data = request.get_json(silent=True)
    token = (data or {}).get("token", "")
    record, error, status_code = add_token_record(token)
    if error:
        return jsonify({"success": False, "message": error}), status_code

    return (
        jsonify(
            {
                "success": True,
                "message": "Token 添加成功",
                "token": build_token_summary(record),
            }
        ),
        status_code,
    )


@app.route("/api/tokens/<token_id>", methods=["DELETE"])
def api_delete_token(token_id: str):
    allowed, error_response = require_admin_access()
    if not allowed:
        return error_response

    if not token_id:
        return jsonify({"success": False, "message": "缺少 Token ID"}), 400

    if not delete_token_record(token_id):
        return jsonify({"success": False, "message": "Token 不存在"}), 404

    return jsonify({"success": True, "message": "Token 删除成功"})


@app.route("/api/health")
def health():
    """健康检查接口"""
    return jsonify({"status": "ok"})


ensure_state_file()


if __name__ == "__main__":
    pool_status = get_pool_status()
    if pool_status["ok"]:
        logger.info(
            f" Token 池可用 | 可用数: {pool_status['valid_token_count']} / 总数: {pool_status['token_count']}"
        )
    else:
        logger.warning(f" Token 池异常: {pool_status['message']}")

    if ADMIN_PASSWORD:
        logger.info(" 后台管理密码已启用")
    else:
        logger.warning(" 后台管理密码未配置")

    logger.info(f" 单 IP 邀请冷却: {RATE_LIMIT_SECONDS} 秒")
    logger.info(f" 服务启动在端口 {PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
