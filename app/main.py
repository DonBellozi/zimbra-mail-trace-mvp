from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from threading import Lock

from argon2 import PasswordHasher
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .collector import SSHSource
from .config import store
from .database import db
from .service import search, stats, trace

async def collector_loop() -> None:
    while True:
        config = store.load()
        delay = max(int(config.get("poll_seconds", 10)), 5)
        if config.get("configured") and config.get("database_url"):
            try:
                await asyncio.to_thread(collect_once, config)
            except Exception:
                pass  # The error is exposed in the authenticated status endpoint.
        await asyncio.sleep(delay)


@asynccontextmanager
async def lifespan(_: FastAPI):
    task = asyncio.create_task(collector_loop())
    yield
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task


app = FastAPI(title="Zimbra Mail Trace", version="0.1.0", lifespan=lifespan)
hasher = PasswordHasher()
STATIC = Path(__file__).parent / "static"
collector_lock = Lock()
collector_state = {"status": "idle", "last_run": None, "last_success": None, "last_error": None, "result": None}


def collect_once(config: dict) -> dict:
    if not collector_lock.acquire(blocking=False):
        return {"running": True}
    collector_state.update(status="running", last_run=int(time.time()), last_error=None)
    try:
        with next(db.session(config["database_url"])) as session:
            result = SSHSource(config).sync(session)
        collector_state.update(status="idle", last_success=int(time.time()), result=result)
        return result
    except Exception as exc:
        collector_state.update(status="error", last_error=str(exc))
        raise
    finally:
        collector_lock.release()


class SetupRequest(BaseModel):
    admin_password: str = Field(min_length=10)
    db_mode: str = "bundled"
    database_url: str | None = None
    ssh_host: str
    ssh_port: int = 22
    ssh_user: str
    ssh_auth_method: str = "password"
    ssh_password: str | None = None
    ssh_private_key: str | None = None
    ssh_key_passphrase: str | None = None
    mail_log_path: str = "/var/log/mail.log"
    zimbra_log_path: str = "/var/log/zimbra.log"
    local_domains: list[str] = []
    timezone: str = "Europe/Moscow"
    retention_days: int = 365
    poll_seconds: int = 10


class DatabaseTest(BaseModel):
    database_url: str


class LoginRequest(BaseModel):
    password: str


class SSHSettings(BaseModel):
    ssh_host: str
    ssh_port: int = 22
    ssh_user: str
    ssh_auth_method: str
    ssh_password: str | None = None
    ssh_private_key: str | None = None
    ssh_key_passphrase: str | None = None
    mail_log_path: str = "/var/log/mail.log"


class MigrationRequest(BaseModel):
    target_database_url: str
    copy_data: bool = True
    allow_nonempty: bool = False


def active_config() -> dict:
    return store.load()


def require_ready() -> dict:
    config = active_config()
    if not config.get("configured"):
        raise HTTPException(409, "Требуется первоначальная настройка")
    return config


def make_token(config: dict) -> str:
    expires = str(int(time.time()) + 12 * 60 * 60)
    signature = hmac.new(config["session_secret"].encode(), expires.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{expires}.{signature}".encode()).decode()


def authenticated(request: Request, config: dict) -> bool:
    try:
        raw = base64.urlsafe_b64decode(request.cookies.get("mailtrace_session", "").encode()).decode()
        expires, signature = raw.split(".", 1)
        expected = hmac.new(config["session_secret"].encode(), expires.encode(), hashlib.sha256).hexdigest()
        return int(expires) > time.time() and hmac.compare_digest(signature, expected)
    except (ValueError, TypeError):
        return False


def require_auth(request: Request) -> dict:
    config = require_ready()
    if not authenticated(request, config):
        raise HTTPException(401, "Требуется вход")
    return config


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/state")
def state(request: Request) -> dict:
    config = active_config()
    is_authenticated = bool(config.get("configured")) and authenticated(request, config)
    response = {"configured": bool(config.get("configured")), "authenticated": is_authenticated}
    if not config.get("configured"):
        response["config"] = {}
    if is_authenticated and config.get("database_url"):
        response["config"] = store.public(config)
        response["collector"] = collector_state
        try:
            with next(db.session(config["database_url"])) as session:
                response["stats"] = stats(session)
        except Exception as exc:
            response["database_error"] = str(exc)
    return response


@app.post("/api/setup")
def setup(payload: SetupRequest) -> dict:
    if active_config().get("configured"):
        raise HTTPException(409, "Первоначальная настройка уже завершена")
    if payload.db_mode not in {"bundled", "external"}:
        raise HTTPException(400, "Неизвестный режим базы данных")
    database_url = os.getenv("BUNDLED_DATABASE_URL") if payload.db_mode == "bundled" else payload.database_url
    if not database_url:
        raise HTTPException(400, "Не указан адрес PostgreSQL")
    if payload.ssh_auth_method not in {"password", "key"}:
        raise HTTPException(400, "Неизвестный способ SSH-аутентификации")
    if payload.ssh_auth_method == "password" and not payload.ssh_password:
        raise HTTPException(400, "Введите SSH-пароль")
    if payload.ssh_auth_method == "key" and not payload.ssh_private_key:
        raise HTTPException(400, "Вставьте приватный SSH-ключ")
    try:
        db.test(database_url)
    except Exception as exc:
        raise HTTPException(400, f"PostgreSQL недоступен: {exc}") from exc
    config = payload.model_dump(exclude={"admin_password"})
    if payload.ssh_auth_method == "password":
        config.update(ssh_private_key=None, ssh_key_passphrase=None)
    else:
        config["ssh_password"] = None
    config.update(configured=True, database_url=database_url, admin_password_hash=hasher.hash(payload.admin_password), host_key_policy="accept-new")
    try:
        SSHSource(config).test()
    except Exception as exc:
        raise HTTPException(400, f"SSH к Zimbra недоступен: {exc}") from exc
    store.save(config)
    db.connect(database_url)
    return {"ok": True}


@app.post("/api/login")
def login(payload: LoginRequest, response: Response) -> dict:
    config = require_ready()
    try:
        hasher.verify(config["admin_password_hash"], payload.password)
    except Exception as exc:
        raise HTTPException(401, "Неверный пароль") from exc
    response.set_cookie("mailtrace_session", make_token(config), httponly=True, samesite="strict", secure=False, max_age=12 * 60 * 60)
    return {"ok": True}


@app.post("/api/logout")
def logout(response: Response) -> dict:
    response.delete_cookie("mailtrace_session")
    return {"ok": True}


@app.post("/api/test/database")
def test_database(payload: DatabaseTest, request: Request) -> dict:
    require_auth(request)
    try:
        return db.test(payload.database_url)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/test/ssh")
def test_ssh(request: Request) -> dict:
    try:
        return SSHSource(require_auth(request)).test()
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.put("/api/settings/ssh")
def update_ssh(payload: SSHSettings, request: Request) -> dict:
    current = require_auth(request)
    if payload.ssh_auth_method not in {"password", "key"}:
        raise HTTPException(400, "Неизвестный способ SSH-аутентификации")
    candidate = {**current, **payload.model_dump(exclude_none=True), "host_key_policy": "accept-new"}
    if payload.ssh_auth_method == "password":
        if not payload.ssh_password and current.get("ssh_auth_method") != "password":
            raise HTTPException(400, "Введите SSH-пароль")
        candidate.update(ssh_private_key=None, ssh_key_passphrase=None)
    else:
        if not payload.ssh_private_key and current.get("ssh_auth_method") != "key":
            raise HTTPException(400, "Вставьте приватный SSH-ключ")
        candidate["ssh_password"] = None
    try:
        result = SSHSource(candidate).test()
    except Exception as exc:
        raise HTTPException(400, f"Настройки не сохранены: {exc}") from exc
    store.save(candidate)
    return result


@app.post("/api/collector/run")
def run_collector(request: Request) -> dict:
    config = require_auth(request)
    try:
        return collect_once(config)
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/search")
def api_search(request: Request, q: str, limit: int = 100) -> list[dict]:
    config = require_auth(request)
    with next(db.session(config["database_url"])) as session:
        return search(session, q, limit)


@app.get("/api/trace/{queue_id}")
def api_trace(queue_id: str, request: Request) -> dict:
    config = require_auth(request)
    with next(db.session(config["database_url"])) as session:
        return trace(session, queue_id.upper())


@app.post("/api/database/migrate")
def migrate_database(payload: MigrationRequest, request: Request) -> dict:
    config = require_auth(request)
    try:
        db.test(payload.target_database_url)
        result = db.migrate(config["database_url"], payload.target_database_url, payload.allow_nonempty) if payload.copy_data else {"ok": True, "copied": {}}
        db.connect(payload.target_database_url)
        store.save({"database_url": payload.target_database_url, "db_mode": "external"})
        return result
    except Exception as exc:
        raise HTTPException(400, f"Перенос отменён, старая база остаётся активной: {exc}") from exc
