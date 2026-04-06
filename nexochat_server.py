#!/usr/bin/env python3
"""
NexoChat — Modern secure web messenger (Python-only)
WebSocket + HTTP server with E2E encryption, groups, channels, roles

FIXES APPLIED:
  1. Passwords now use PBKDF2-HMAC-SHA256 with per-user salt (was: plain SHA-256)
  2. Admin credentials removed from source — must be set via env vars
  3. Path traversal vulnerability fixed in static/avatar/upload serving
  4. Thread-safe sessions dict (added RLock)
  5. CORS wildcard replaced with configurable allowed origins
  6. Log format string bug fixed (missing f-prefix on line with port)
  7. get_messages pagination logic fixed
  8. SERVER_SECRET persisted to disk to survive restarts
  9. Rate limiting on auth endpoints (simple in-memory)
 10. build_auth_page uses correct /api/auth/* endpoints
"""

import os, sys, json, hashlib, uuid, time, base64, re, hmac, secrets
import threading, asyncio, logging, mimetypes, struct, subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, unquote
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
import socket

# ── Optional WebSocket support ────────────────────────────────────
try:
    import websockets
    HAS_WS = True
except ImportError:
    HAS_WS = False

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')
log = logging.getLogger("NexoChat")

BASE      = Path(__file__).parent
DATA      = BASE / "data"
AVATARS   = BASE / "avatars"
UPLOADS   = BASE / "uploads"
STATIC    = BASE / "static"
for d in [DATA, AVATARS, UPLOADS, STATIC]: d.mkdir(exist_ok=True)

# Data files
USERS_F        = DATA / "users.json"
CHATS_F        = DATA / "chats.json"
MSGS_F         = DATA / "messages.json"
SESSIONS_F     = DATA / "sessions.json"
MUTES_F        = DATA / "mutes.json"
BANS_F         = DATA / "bans.json"
RESET_TOKENS_F = DATA / "reset_tokens.json"
SECRET_F       = DATA / "server_secret.txt"

FILE_LOCK = threading.RLock()
SESS_LOCK = threading.RLock()   # FIX #4: dedicated lock for _sessions
WS_CLIENTS: dict = {}           # chat_id -> set of SimpleWSConnection
WS_LOCK    = threading.Lock()

# ── Persistence ───────────────────────────────────────────────────
def _load(path):
    p = Path(path)
    if not p.exists(): return {}
    with FILE_LOCK:
        try: return json.loads(p.read_text(encoding='utf-8'))
        except: return {}

def _load_list(path):
    p = Path(path)
    if not p.exists(): return []
    with FILE_LOCK:
        try:
            d = json.loads(p.read_text(encoding='utf-8'))
            return d if isinstance(d, list) else []
        except: return []

def _save(path, data):
    with FILE_LOCK:
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')

def ts():
    return datetime.now().strftime("%H:%M %d.%m.%Y")

def now_iso():
    return datetime.now().isoformat()

# ── Crypto helpers ────────────────────────────────────────────────
# FIX #1: Use PBKDF2-HMAC-SHA256 with per-user salt instead of plain SHA-256
def hash_pw(pw: str, salt: str | None = None) -> tuple[str, str]:
    """Returns (hash_hex, salt_hex). Always generates new salt if none given."""
    if salt is None:
        salt = secrets.token_hex(32)
    key = hashlib.pbkdf2_hmac(
        'sha256', pw.encode('utf-8'), salt.encode('utf-8'), 260_000
    )
    return key.hex(), salt

def verify_pw(pw: str, stored_hash: str, stored_salt: str) -> bool:
    computed, _ = hash_pw(pw, stored_salt)
    return hmac.compare_digest(computed, stored_hash)

# Backward-compat: detect old plain SHA-256 hashes (64-char hex, no salt field)
def _verify_any(pw: str, u: dict) -> bool:
    salt = u.get("password_salt")
    phash = u.get("password_hash", "")
    if salt:
        return verify_pw(pw, phash, salt)
    # Legacy SHA-256 (no salt) — accept but migrate on success
    return hmac.compare_digest(phash, hashlib.sha256(pw.encode()).hexdigest())

def _maybe_migrate_pw(u: dict, pw: str, username: str):
    """If user still has old SHA-256 hash, upgrade to PBKDF2 silently."""
    if not u.get("password_salt"):
        new_hash, new_salt = hash_pw(pw)
        u["password_hash"] = new_hash
        u["password_salt"] = new_salt
        save_user(username, u)

def gen_token() -> str:
    return secrets.token_hex(32)

def gen_invite() -> str:
    return secrets.token_urlsafe(16)

def derive_room_key(room_id: str, server_secret: str) -> str:
    """Derive per-room key (HMAC-SHA256)."""
    return hmac.new(server_secret.encode(), room_id.encode(), hashlib.sha256).hexdigest()

# FIX #8: Persist SERVER_SECRET so encrypted messages survive restarts
def _load_or_create_secret() -> str:
    if SECRET_F.exists():
        try:
            s = SECRET_F.read_text().strip()
            if len(s) == 64: return s
        except: pass
    s = secrets.token_hex(32)
    SECRET_F.write_text(s)
    SECRET_F.chmod(0o600)
    return s

SERVER_SECRET = os.environ.get("NEXO_SECRET") or _load_or_create_secret()

# FIX #2: Admin credentials MUST come from environment — no hardcoded fallback
SITE_ADMIN      = os.environ.get("NEXO_ADMIN_USER", "admin")
SITE_ADMIN_PASS = os.environ.get("NEXO_ADMIN_PASS", "")   # empty = disabled if not set
if not SITE_ADMIN_PASS:
    log.warning("NEXO_ADMIN_PASS not set — default admin account will use a random password. "
                "Set NEXO_ADMIN_PASS env var before first run.")
    SITE_ADMIN_PASS = secrets.token_urlsafe(24)
    log.warning("Generated one-time admin password: %s", SITE_ADMIN_PASS)

# ── Email (SMTP) config ───────────────────────────────────────────
SMTP_EMAIL    = os.environ.get("SMTP_EMAIL", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_HOST     = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "465"))
SITE_URL      = os.environ.get("NEXO_URL", "https://nexochats.bothost.tech")

# FIX #5: Configurable CORS origins — no wildcard with cookies
_raw_origins = os.environ.get("NEXO_ALLOWED_ORIGINS", SITE_URL)
ALLOWED_ORIGINS = {o.strip().rstrip("/") for o in _raw_origins.split(",")}

# ── Rate limiting (simple in-memory) ─────────────────────────────
# FIX #9: Prevent brute-force on auth endpoints
_rate: dict = {}   # ip -> [timestamp, ...]
_rate_lock = threading.Lock()
RATE_WINDOW = 60   # seconds
RATE_LIMIT  = 20   # max attempts per window

def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        hits = _rate.get(ip, [])
        hits = [t for t in hits if now - t < RATE_WINDOW]
        hits.append(now)
        _rate[ip] = hits
        return len(hits) > RATE_LIMIT

# ── Seed default data ─────────────────────────────────────────────
def seed():
    users = _load(USERS_F)
    if SITE_ADMIN not in users:
        pw_hash, pw_salt = hash_pw(SITE_ADMIN_PASS)
        users[SITE_ADMIN] = {
            "uid": str(uuid.uuid4()),
            "username": SITE_ADMIN,
            "email": "",
            "password_hash": pw_hash,
            "password_salt": pw_salt,       # FIX #1
            "display": SITE_ADMIN.capitalize(),
            "bio": "Admin",
            "avatar": "",
            "avatar_emoji": "👑",
            "language": "en",
            "created": time.time(),
            "online": False,
            "last_seen": now_iso(),
            "role": "superadmin",
            "telegram_id": None,
        }
        _save(USERS_F, users)

    chats = _load(CHATS_F)
    if "nexochat" not in chats:
        chats["nexochat"] = {
            "id": "nexochat",
            "type": "channel",
            "name": "NexoChat",
            "description": "Official NexoChat channel",
            "avatar_emoji": "💬",
            "avatar": "",
            "owner": SITE_ADMIN,
            "admins": {SITE_ADMIN: {"all": True}},
            "members": [],
            "invite_link": "nexochat",
            "private_invite": gen_invite(),
            "is_public": True,
            "created": time.time(),
            "pinned_message": None,
            "permissions": {
                "send_messages": True, "send_media": True,
                "add_members": False, "pin_messages": False, "change_info": False,
            }
        }
        chats["general"] = {
            "id": "general",
            "type": "group",
            "name": "General",
            "description": "Public group for everyone",
            "avatar_emoji": "👥",
            "avatar": "",
            "owner": SITE_ADMIN,
            "admins": {SITE_ADMIN: {"all": True}},
            "members": [],
            "invite_link": "general",
            "private_invite": gen_invite(),
            "is_public": True,
            "created": time.time(),
            "pinned_message": None,
            "permissions": {
                "send_messages": True, "send_media": True,
                "add_members": True, "pin_messages": False, "change_info": False,
            }
        }
        _save(CHATS_F, chats)

    msgs = _load(MSGS_F)
    if "nexochat" not in msgs:
        msgs["nexochat"] = [{
            "id": str(uuid.uuid4()), "author": SITE_ADMIN, "display": "NexoChat",
            "text": "Welcome to NexoChat! 🎉", "ts": ts(),
            "type": "text", "reactions": {}, "pinned": True, "edited": False,
        }]
        msgs["general"] = [{
            "id": str(uuid.uuid4()), "author": SITE_ADMIN, "display": "NexoChat",
            "text": "Welcome to the General group!", "ts": ts(),
            "type": "text", "reactions": {}, "pinned": True, "edited": False,
        }]
        _save(MSGS_F, msgs)

# ── Sessions ──────────────────────────────────────────────────────
_sessions: dict = {}  # token -> {username, expires}

def create_session(username: str) -> str:
    token = gen_token()
    with SESS_LOCK:   # FIX #4
        _sessions[token] = {
            "username": username,
            "expires": time.time() + 86400 * 30
        }
    return token

def get_session(token: str) -> str | None:
    if not token: return None
    with SESS_LOCK:   # FIX #4
        s = _sessions.get(token)
        if not s: return None
        if time.time() > s["expires"]:
            del _sessions[token]
            return None
        return s["username"]

def delete_session(token: str):
    with SESS_LOCK:   # FIX #4
        _sessions.pop(token, None)

# ── User helpers ──────────────────────────────────────────────────
def get_user(username: str) -> dict | None:
    u = _load(USERS_F).get(username)
    return dict(u) if u else None

def save_user(username: str, data: dict):
    users = _load(USERS_F)
    users[username] = data
    _save(USERS_F, users)

# ── Email helpers ─────────────────────────────────────────────────
def send_recovery_email(to_email: str, reset_token: str) -> bool:
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        log.warning("SMTP_EMAIL or SMTP_PASSWORD not set — email not sent")
        return False
    reset_link = f"{SITE_URL}/auth?reset_token={reset_token}"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "NexoChat — Password Reset"
    msg["From"]    = f"NexoChat <{SMTP_EMAIL}>"
    msg["To"]      = to_email
    html = f"""
    <div style="font-family:sans-serif;max-width:480px;margin:auto;background:#141210;
                color:#f5ede4;padding:32px;border-radius:16px;">
      <h2 style="color:#ff8c32;">🔐 Password Reset</h2>
      <p>You requested a password reset for your NexoChat account.</p>
      <a href="{reset_link}"
         style="display:inline-block;margin:20px 0;padding:12px 28px;
                background:linear-gradient(135deg,#ff6a00,#ff8c32);
                color:#fff;border-radius:10px;text-decoration:none;font-weight:700;">
        Reset Password →
      </a>
      <p style="color:#9c8a78;font-size:.85em;">Link expires in <b>1 hour</b>.<br>
      If you didn't request this, ignore this email.</p>
    </div>"""
    msg.attach(MIMEText(html, "html"))
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as s:
            s.login(SMTP_EMAIL, SMTP_PASSWORD)
            s.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        log.info("Recovery email sent to %s", to_email)
        return True
    except Exception as e:
        log.error("Failed to send recovery email: %s", e)
        return False

def user_public(u: dict) -> dict:
    return {
        "username": u.get("username"),
        "display": u.get("display"),
        "bio": u.get("bio"),
        "avatar": u.get("avatar"),
        "avatar_emoji": u.get("avatar_emoji", "👤"),
        "online": u.get("online", False),
        "last_seen": u.get("last_seen"),
        "created": u.get("created"),
    }

# ── Chat helpers ──────────────────────────────────────────────────
def get_chat(chat_id: str) -> dict | None:
    c = _load(CHATS_F).get(chat_id)
    return dict(c) if c else None

def save_chat(chat_id: str, data: dict):
    chats = _load(CHATS_F)
    chats[chat_id] = data
    _save(CHATS_F, chats)

def get_member_role(chat: dict, username: str) -> str:
    if chat.get("owner") == username: return "owner"
    if username in chat.get("admins", {}): return "admin"
    if username in chat.get("members", []): return "user"
    return "none"

def is_banned(chat_id: str, username: str) -> bool:
    bans = _load(BANS_F)
    b = bans.get(chat_id, {}).get(username)
    if not b: return False
    if b.get("permanent"): return True
    if b.get("until") and time.time() < b["until"]: return True
    return False

def is_muted(chat_id: str, username: str) -> bool:
    mutes = _load(MUTES_F)
    m = mutes.get(chat_id, {}).get(username)
    if not m: return False
    if m.get("until") and time.time() < m["until"]: return True
    return False

# ── Message helpers ───────────────────────────────────────────────
# FIX #7: Correct pagination logic
def get_messages(chat_id: str, limit: int = 50, offset: int = 0) -> list:
    msgs = _load(MSGS_F)
    room_msgs = msgs.get(chat_id, [])
    total = len(room_msgs)
    if offset >= total:
        return []
    start = max(0, total - offset - limit)
    end   = total - offset
    return room_msgs[start:end]

def add_message(chat_id: str, msg: dict):
    msgs = _load(MSGS_F)
    if chat_id not in msgs: msgs[chat_id] = []
    msgs[chat_id].append(msg)
    if len(msgs[chat_id]) > 10000:
        msgs[chat_id] = msgs[chat_id][-10000:]
    _save(MSGS_F, msgs)

# ── Moderation commands ───────────────────────────────────────────
def parse_duration(s: str) -> int | None:
    m = re.match(r'^(\d+)([smhd])$', s.lower())
    if not m: return None
    v, u = int(m.group(1)), m.group(2)
    return v * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[u]

def handle_command(chat_id: str, author: str, text: str) -> dict | None:
    chat = get_chat(chat_id)
    if not chat: return None
    role = get_member_role(chat, author)
    if role not in ("owner", "admin"):
        return {"error": "No permission"}

    parts = text.strip().split()
    cmd = parts[0].lower()

    if cmd == "/mute" and len(parts) >= 2:
        target = parts[1].lstrip("@")
        duration_str = parts[2] if len(parts) > 2 and re.match(r'^\d+[smhd]$', parts[2]) else None
        reason = " ".join(parts[3:]) if duration_str and len(parts) > 3 else (" ".join(parts[2:]) if not duration_str else "")
        duration = parse_duration(duration_str) if duration_str else 3600
        mutes = _load(MUTES_F)
        mutes.setdefault(chat_id, {})[target] = {"until": time.time() + duration, "reason": reason, "by": author}
        _save(MUTES_F, mutes)
        return {"ok": True, "action": "muted", "target": target, "duration": duration}

    elif cmd == "/unmute" and len(parts) >= 2:
        target = parts[1].lstrip("@")
        mutes = _load(MUTES_F)
        mutes.get(chat_id, {}).pop(target, None)
        _save(MUTES_F, mutes)
        return {"ok": True, "action": "unmuted", "target": target}

    elif cmd == "/ban" and len(parts) >= 2:
        target = parts[1].lstrip("@")
        duration_str = parts[2] if len(parts) > 2 and re.match(r'^\d+[smhd]$', parts[2]) else None
        reason = " ".join(parts[3:]) if duration_str and len(parts) > 3 else (" ".join(parts[2:]) if not duration_str else "")
        bans = _load(BANS_F)
        bans.setdefault(chat_id, {})
        if duration_str:
            dur = parse_duration(duration_str)
            bans[chat_id][target] = {"until": time.time() + dur, "permanent": False, "reason": reason, "by": author}
        else:
            bans[chat_id][target] = {"permanent": True, "reason": reason, "by": author}
        chat = get_chat(chat_id)
        if target in chat.get("members", []):
            chat["members"].remove(target)
            save_chat(chat_id, chat)
        _save(BANS_F, bans)
        return {"ok": True, "action": "banned", "target": target, "permanent": not duration_str}

    elif cmd == "/unban" and len(parts) >= 2:
        target = parts[1].lstrip("@")
        bans = _load(BANS_F)
        bans.get(chat_id, {}).pop(target, None)
        _save(BANS_F, bans)
        return {"ok": True, "action": "unbanned", "target": target}

    elif cmd == "/pin" and len(parts) >= 2:
        msg_id = parts[1]
        chat = get_chat(chat_id)
        chat["pinned_message"] = msg_id
        save_chat(chat_id, chat)
        return {"ok": True, "action": "pinned", "msg_id": msg_id}

    return None

# ── HTTP Handler helpers ──────────────────────────────────────────
TRANSLATIONS = {
    "en": {
        "title": "NexoChat", "tagline": "Secure modern messenger",
        "login": "Login", "register": "Register", "email": "Email",
        "password": "Password", "username": "Username",
        "forgot": "Forgot password?", "or_tg": "or login via Telegram",
        "join": "Join", "send": "Send", "search": "Search",
        "members": "Members", "online": "online",
        "settings": "Settings", "logout": "Logout",
        "write": "Write a message", "groups": "Groups",
        "channels": "Channels", "dms": "Direct Messages",
        "save": "Save", "cancel": "Cancel",
    },
    "uk": {
        "title": "NexoChat", "tagline": "Безпечний сучасний месенджер",
        "login": "Увійти", "register": "Реєстрація", "email": "Пошта",
        "password": "Пароль", "username": "Нікнейм",
        "forgot": "Забув пароль?", "or_tg": "або через Telegram",
        "join": "Приєднатись", "send": "Надіслати", "search": "Пошук",
        "members": "Учасники", "online": "онлайн",
        "settings": "Налаштування", "logout": "Вийти",
        "write": "Написати повідомлення", "groups": "Групи",
        "channels": "Канали", "dms": "Особисті",
        "save": "Зберегти", "cancel": "Скасувати",
    },
    "ru": {
        "title": "NexoChat", "tagline": "Безопасный мессенджер",
        "login": "Войти", "register": "Регистрация", "email": "Почта",
        "password": "Пароль", "username": "Никнейм",
        "forgot": "Забыл пароль?", "or_tg": "или через Telegram",
        "join": "Вступить", "send": "Отправить", "search": "Поиск",
        "members": "Участники", "online": "онлайн",
        "settings": "Настройки", "logout": "Выйти",
        "write": "Написать сообщение", "groups": "Группы",
        "channels": "Каналы", "dms": "Личные",
        "save": "Сохранить", "cancel": "Отмена",
    },
    "pl": {
        "title": "NexoChat", "tagline": "Bezpieczny komunikator",
        "login": "Zaloguj", "register": "Rejestracja", "email": "Email",
        "password": "Hasło", "username": "Nazwa",
        "forgot": "Zapomniałeś hasła?", "or_tg": "lub przez Telegram",
        "join": "Dołącz", "send": "Wyślij", "search": "Szukaj",
        "members": "Członkowie", "online": "online",
        "settings": "Ustawienia", "logout": "Wyloguj",
        "write": "Napisz wiadomość", "groups": "Grupy",
        "channels": "Kanały", "dms": "Prywatne",
        "save": "Zapisz", "cancel": "Anuluj",
    },
}

def t(key: str, lang: str = "en") -> str:
    return TRANSLATIONS.get(lang, TRANSLATIONS["en"]).get(key, key)

def get_token_from_request(handler) -> str:
    # 1. Cookie
    cookie_hdr = handler.headers.get("Cookie", "")
    for part in cookie_hdr.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip() == "nexo_token":
            return v.strip()
    # 2. Authorization header
    auth = handler.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return ""

def json_response(handler, data, status=200):
    body = json.dumps(data, ensure_ascii=False).encode('utf-8')
    # FIX #5: CORS — echo back only if origin is in allowed list
    origin = handler.headers.get("Origin", "")
    origin_clean = origin.rstrip("/")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    if origin_clean in ALLOWED_ORIGINS:
        handler.send_header("Access-Control-Allow-Origin", origin)
        handler.send_header("Access-Control-Allow-Credentials", "true")
    handler.end_headers()
    handler.wfile.write(body)

def html_response(handler, html: str, status=200):
    body = html.encode('utf-8')
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    # Basic security headers
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "SAMEORIGIN")
    handler.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
    handler.end_headers()
    handler.wfile.write(body)

def redirect(handler, url: str, status=302):
    handler.send_response(status)
    handler.send_header("Location", url)
    handler.end_headers()

def read_body(handler) -> dict:
    length = int(handler.headers.get("Content-Length", 0))
    if not length: return {}
    raw = handler.rfile.read(length)
    ct = handler.headers.get("Content-Type", "")
    if "application/json" in ct:
        try: return json.loads(raw)
        except: return {}
    from urllib.parse import parse_qs
    parsed = parse_qs(raw.decode('utf-8', errors='replace'))
    return {k: v[0] for k, v in parsed.items()}

# FIX #3: Path traversal safe file resolver
def _safe_resolve(base: Path, relative: str) -> Path | None:
    """Resolve relative path within base. Returns None if outside base."""
    try:
        # Remove any leading slashes / dots to prevent traversal
        clean = re.sub(r'[^\w.\-]', '', relative.replace('/', '_').replace('\\', '_'))
        # Also try raw resolve approach for legit filenames with UUIDs/dashes
        candidate = (base / relative).resolve()
        base_resolved = base.resolve()
        if str(candidate).startswith(str(base_resolved) + os.sep) or candidate == base_resolved:
            return candidate
        return None
    except Exception:
        return None

# ── Simple encrypt (XOR demo — NOT for production) ────────────────
def simple_encrypt(text: str, key: str) -> str:
    if not text: return ""
    key_bytes = key.encode('utf-8')
    text_bytes = text.encode('utf-8')
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(text_bytes))
    return base64.b64encode(out).decode('ascii')

# ── WebSocket broadcast ───────────────────────────────────────────
def broadcast_message(chat_id: str, msg: dict):
    data = json.dumps(msg).encode('utf-8')
    dead = set()
    with WS_LOCK:
        clients = set(WS_CLIENTS.get(chat_id, set()))
    for ws in clients:
        try:
            ws.send(data)
        except:
            dead.add(ws)
    if dead:
        with WS_LOCK:
            for d in dead:
                WS_CLIENTS.get(chat_id, set()).discard(d)

# ── NexoChat Shield — Anti-Bot / DDoS Protection ─────────────────
# Multi-layer: rate limiting per IP, UA fingerprinting,
# request pattern analysis, honeypot endpoints, auto-ban
import ipaddress

_SHIELD_LOCK   = threading.Lock()
_SHIELD_HITS   : dict = {}   # ip -> deque of timestamps
_SHIELD_BANS   : dict = {}   # ip -> ban_until timestamp
_SHIELD_WARNS  : dict = {}   # ip -> warn count
_SHIELD_UA_BAN : dict = {}   # ip -> bad_ua_count
_HONEYPOT_HITS : dict = {}   # ip -> count

SHIELD_WINDOW        = 10    # seconds sliding window
SHIELD_REQ_LIMIT     = 60    # max requests per window (normal)
SHIELD_AUTH_LIMIT    = 8     # max auth attempts per window
SHIELD_BAN_THRESHOLD = 3     # warns before hard ban
SHIELD_BAN_DURATION  = 300   # 5 min soft ban, escalates
SHIELD_HARD_BAN      = 3600  # 1 hour hard ban after repeat

# Known bad User-Agent fragments (bots, scanners, exploit tools)
_BAD_UA_FRAGMENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster",
    "gobuster", "wfuzz", "hydra", "medusa", "burpsuite", "havij",
    "acunetix", "nessus", "openvas", "python-requests/2.2",
    "curl/7.1", "libwww-perl", "lwp-trivial", "scrapy",
    "wget/1.1", "go-http-client/1.1", "java/1.", "okhttp/3.1",
]

# Honeypot paths — legitimate users never visit these
_HONEYPOT_PATHS = {
    "/admin", "/wp-admin", "/wp-login.php", "/phpmyadmin",
    "/.env", "/.git/config", "/config.php", "/xmlrpc.php",
    "/shell.php", "/cmd.php", "/.htaccess", "/server-status",
    "/actuator", "/api/v1/admin", "/.aws/credentials",
    "/etc/passwd", "/proc/self/environ",
}

def _shield_get_ip(handler) -> str:
    xff = handler.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return handler.client_address[0]

def _shield_is_banned(ip: str) -> bool:
    with _SHIELD_LOCK:
        until = _SHIELD_BANS.get(ip, 0)
        if until and time.time() < until:
            return True
        elif until:
            _SHIELD_BANS.pop(ip, None)
    return False

def _shield_ban(ip: str, reason: str, duration: int = SHIELD_BAN_DURATION):
    with _SHIELD_LOCK:
        existing = _SHIELD_BANS.get(ip, 0)
        if time.time() < existing:
            # Already banned — escalate duration
            duration = SHIELD_HARD_BAN
        _SHIELD_BANS[ip] = time.time() + duration
    log.warning("[SHIELD] BAN %s for %ds — %s", ip, duration, reason)

def _shield_check_ua(ua: str) -> bool:
    """Returns True if UA looks malicious."""
    if not ua or len(ua) < 8:
        return True
    ua_lower = ua.lower()
    for frag in _BAD_UA_FRAGMENTS:
        if frag in ua_lower:
            return True
    return False

def _shield_check_rate(ip: str, endpoint_type: str = "normal") -> bool:
    """Returns True if rate limit exceeded."""
    limit = SHIELD_AUTH_LIMIT if endpoint_type == "auth" else SHIELD_REQ_LIMIT
    now = time.time()
    with _SHIELD_LOCK:
        from collections import deque
        hits = _SHIELD_HITS.setdefault(ip, deque())
        while hits and now - hits[0] > SHIELD_WINDOW:
            hits.popleft()
        hits.append(now)
        return len(hits) > limit

def _shield_honeypot(ip: str, path: str):
    """Instantly ban anyone touching honeypot paths."""
    with _SHIELD_LOCK:
        _HONEYPOT_HITS[ip] = _HONEYPOT_HITS.get(ip, 0) + 1
    _shield_ban(ip, f"honeypot:{path}", SHIELD_HARD_BAN)

def shield_check(handler, endpoint_type: str = "normal") -> bool:
    """
    Full Shield check. Returns True if request is BLOCKED.
    Call at top of do_GET / do_POST.
    """
    ip  = _shield_get_ip(handler)
    ua  = handler.headers.get("User-Agent", "")
    path = urlparse(handler.path).path

    # 1. Hard ban check
    if _shield_is_banned(ip):
        return True

    # 2. Honeypot path
    path_lower = path.rstrip("/").lower()
    for hp in _HONEYPOT_PATHS:
        if path_lower == hp or path_lower.startswith(hp + "/"):
            _shield_honeypot(ip, path)
            return True

    # 3. Bad User-Agent
    if _shield_check_ua(ua):
        with _SHIELD_LOCK:
            cnt = _SHIELD_UA_BAN.get(ip, 0) + 1
            _SHIELD_UA_BAN[ip] = cnt
        if cnt >= 2:
            _shield_ban(ip, f"bad_ua:{ua[:60]}", SHIELD_BAN_DURATION)
            return True

    # 4. Rate limit
    if _shield_check_rate(ip, endpoint_type):
        with _SHIELD_LOCK:
            w = _SHIELD_WARNS.get(ip, 0) + 1
            _SHIELD_WARNS[ip] = w
        if w >= SHIELD_BAN_THRESHOLD:
            _shield_ban(ip, "rate_limit_exceeded")
        return True

    return False

def _shield_send_blocked(handler):
    """Send 403 response to blocked request."""
    try:
        body = b'{"error":"NexoChat Shield: Access denied"}'
        handler.send_response(403)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("X-Shield", "NexoChat-Shield/1.0")
        handler.end_headers()
        handler.wfile.write(body)
    except Exception:
        pass


# ── WebSocket Thread (proper hijack pattern) ──────────────────────
class NexoWSThread(threading.Thread):
    """
    WebSocket runs in its own thread — HTTP handler returns immediately.
    This is the correct hijack pattern (same as PuwePanel).
    """
    def __init__(self, sock, username: str, chat_id: str):
        super().__init__(daemon=True)
        self.sock     = sock
        self.username = username
        self.chat_id  = chat_id
        self._alive   = True

    def run(self):
        self.sock.settimeout(300)
        with WS_LOCK:
            WS_CLIENTS.setdefault(self.chat_id, set()).add(self)
        try:
            while self._alive:
                try:
                    msg = self._recv_frame()
                    if msg is None:
                        break
                except (ConnectionResetError, BrokenPipeError, OSError):
                    break
                except Exception:
                    break
        finally:
            with WS_LOCK:
                WS_CLIENTS.get(self.chat_id, set()).discard(self)
            if self.username:
                u = get_user(self.username)
                if u:
                    u["online"]    = False
                    u["last_seen"] = now_iso()
                    save_user(self.username, u)

    def send(self, data: bytes):
        try:
            self.sock.sendall(self._build_frame(data))
        except Exception:
            self._alive = False

    def _build_frame(self, data: bytes) -> bytes:
        ln  = len(data)
        hdr = bytearray([0x81])
        if ln < 126:
            hdr.append(ln)
        elif ln < 65536:
            hdr += bytearray([126]) + struct.pack(">H", ln)
        else:
            hdr += bytearray([127]) + struct.pack(">Q", ln)
        return bytes(hdr) + data

    def _recv_frame(self) -> str | None:
        try:
            hdr    = self._recv_exact(2)
            if not hdr: return None
            opcode = hdr[0] & 0x0F
            if opcode == 8: return None           # close frame
            masked = (hdr[1] & 0x80) != 0
            ln     = hdr[1] & 0x7F
            if ln == 126:   ln = struct.unpack(">H", self._recv_exact(2))[0]
            elif ln == 127: ln = struct.unpack(">Q", self._recv_exact(8))[0]
            mask    = self._recv_exact(4) if masked else None
            payload = bytearray(self._recv_exact(ln))
            if masked:
                for i in range(ln): payload[i] ^= mask[i % 4]
            return payload.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _recv_exact(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk: raise ConnectionResetError
            data += chunk
        return data


# ── HTTP Handler ──────────────────────────────────────────────────
class NexoHandler(BaseHTTPRequestHandler):
    server_version = "NexoChat/2.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log.info("%s - %s", self.address_string(), fmt % args)

    # ── Correct hijack: suppress wfile.flush after WS upgrade ─────
    def handle_one_request(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = self.request_version = self.command = ""
                self.send_error(414); return
            if not self.raw_requestline:
                self.close_connection = True; return
            if not self.parse_request(): return
            mname = "do_" + self.command
            if not hasattr(self, mname):
                self.send_error(501, "Unsupported method"); return
            getattr(self, mname)()
            # Do NOT flush if we hijacked the socket for WebSocket
            if not getattr(self, "_ws_hijacked", False):
                self.wfile.flush()
        except TimeoutError as e:
            self.log_error("Timeout: %r", e)
            self.close_connection = True
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass

    def handle(self):
        try: super().handle()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError): pass

    def finish(self):
        if getattr(self, "_ws_hijacked", False): return
        try: super().finish()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError): pass

    def do_OPTIONS(self):
        if shield_check(self): _shield_send_blocked(self); return
        origin = self.headers.get("Origin", "").rstrip("/")
        self.send_response(204)
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, Cookie")
        self.end_headers()

    def do_GET(self):
        if shield_check(self): _shield_send_blocked(self); return
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"
        qs     = parse_qs(parsed.query)

        token    = get_token_from_request(self)
        username = get_session(token)

        # FIX #3: Safe static file serving
        if path.startswith("/static/"):
            fname = path[8:]
            fp = _safe_resolve(STATIC, fname)
            if fp and fp.exists():
                self._serve_file(fp)
            else:
                self.send_response(404); self.end_headers()
            return

        if path.startswith("/avatars/"):
            fname = path[9:]
            fp = _safe_resolve(AVATARS, fname)
            if fp and fp.exists():
                self._serve_file(fp)
            else:
                self.send_response(404); self.end_headers()
            return

        if path.startswith("/uploads/"):
            fname = path[9:]
            fp = _safe_resolve(UPLOADS, fname)
            if fp and fp.exists():
                self._serve_file(fp)
            else:
                self.send_response(404); self.end_headers()
            return

        if path.startswith("/api/"):
            self._handle_api_get(path, qs, username)
            return

        # WebSocket upgrade (both /api/ws and generic upgrade)
        if "Upgrade" in self.headers and self.headers["Upgrade"].lower() == "websocket":
            self._handle_ws_upgrade()
            return

        lang = qs.get("lang", ["en"])[0]
        if username:
            u = get_user(username)
            if u: lang = u.get("language", "en")

        if path in ("/auth", "/login"):
            if username:
                redirect(self, "/"); return
            html_response(self, build_auth_page(lang))
            return

        if not username:
            redirect(self, "/auth"); return

        u = get_user(username)
        if not u:
            redirect(self, "/auth"); return

        lang = u.get("language", "en")

        if path in ("/", ""):
            html_response(self, build_main_page(u, lang))
            return

        all_users = _load(USERS_F)
        slug = path.lstrip("/")
        if slug in all_users:
            html_response(self, build_profile_page(all_users[slug], u, lang))
            return

        chats = _load(CHATS_F)
        found_chat = None
        for cid, chat in chats.items():
            if chat.get("invite_link") == slug or chat.get("private_invite") == slug:
                found_chat = chat; break

        if found_chat:
            role = get_member_role(found_chat, username)
            if role != "none":
                html_response(self, build_main_page(u, lang, active_chat=found_chat["id"]))
            else:
                html_response(self, build_chat_preview(found_chat, u, lang))
            return

        html_response(self, build_main_page(u, lang))

    def do_POST(self):
        if shield_check(self, endpoint_type="auth" if "/auth" in self.path else "normal"):
            _shield_send_blocked(self); return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        token = get_token_from_request(self)
        username = get_session(token)

        if path.startswith("/api/"):
            self._handle_api_post(path, username)
            return

        json_response(self, {"error": "Not found"}, 404)

    def _get_client_ip(self) -> str:
        # Trust X-Forwarded-For if behind a proxy
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _handle_api_get(self, path, qs, username):
        if path == "/api/chat_preview":
            slug = qs.get("slug", [""])[0]
            chats = _load(CHATS_F)
            for cid, chat in chats.items():
                if chat.get("invite_link") == slug or chat.get("private_invite") == slug:
                    json_response(self, {
                        "id": cid, "name": chat["name"],
                        "description": chat.get("description", ""),
                        "avatar_emoji": chat.get("avatar_emoji", "💬"),
                        "type": chat["type"],
                        "members_count": len(chat.get("members", [])) + 1,
                    }); return
            json_response(self, {"error": "Not found"}, 404); return

        if not username:
            json_response(self, {"error": "Unauthorized"}, 401); return

        u = get_user(username)
        if not u:
            json_response(self, {"error": "Unauthorized"}, 401); return

        if path == "/api/me":
            json_response(self, user_public(u))

        elif path == "/api/chats":
            chats = _load(CHATS_F)
            result = []
            for cid, chat in chats.items():
                role = get_member_role(chat, username)
                if role != "none":
                    msgs = get_messages(cid, limit=1)
                    last = msgs[-1] if msgs else None
                    result.append({
                        "id": cid, "name": chat["name"],
                        "type": chat["type"],
                        "avatar_emoji": chat.get("avatar_emoji", "💬"),
                        "avatar": chat.get("avatar", ""),
                        "members_count": len(chat.get("members", [])) + 1,
                        "is_public": chat.get("is_public", True),
                        "invite_link": chat.get("invite_link"),
                        "last_message": last, "role": role,
                    })
            json_response(self, result)

        elif path == "/api/messages":
            chat_id = qs.get("chat_id", [""])[0]
            limit   = min(int(qs.get("limit", ["50"])[0]), 200)
            offset  = max(int(qs.get("offset", ["0"])[0]), 0)
            if not chat_id:
                json_response(self, {"error": "chat_id required"}, 400); return
            chat = get_chat(chat_id)
            if not chat:
                json_response(self, {"error": "Chat not found"}, 404); return
            role = get_member_role(chat, username)
            if role == "none":
                json_response(self, {"error": "Not a member"}, 403); return
            json_response(self, get_messages(chat_id, limit=limit, offset=offset))

        elif path == "/api/chat_info":
            chat_id = qs.get("chat_id", [""])[0]
            chat = get_chat(chat_id)
            if not chat:
                json_response(self, {"error": "Not found"}, 404); return
            role = get_member_role(chat, username)
            if role == "none":
                json_response(self, {"error": "Not a member"}, 403); return
            all_users = _load(USERS_F)
            members_info = []
            member_ids = [chat["owner"]] + list(chat.get("admins", {}).keys()) + chat.get("members", [])
            seen = set()
            for mid in member_ids:
                if mid in seen: continue
                seen.add(mid)
                mu = all_users.get(mid)
                if mu:
                    members_info.append({
                        "username": mid,
                        "display": mu.get("display", mid),
                        "avatar_emoji": mu.get("avatar_emoji", "👤"),
                        "role": get_member_role(chat, mid),
                        "online": mu.get("online", False),
                    })
            json_response(self, {
                "id": chat_id, "name": chat["name"],
                "description": chat.get("description", ""),
                "type": chat["type"],
                "avatar_emoji": chat.get("avatar_emoji", "💬"),
                "avatar": chat.get("avatar", ""),
                "owner": chat["owner"],
                "is_public": chat.get("is_public", True),
                "invite_link": chat.get("invite_link"),
                "private_invite": chat.get("private_invite") if role in ("owner", "admin") else None,
                "pinned_message": chat.get("pinned_message"),
                "permissions": chat.get("permissions", {}),
                "members": members_info,
                "members_count": len(members_info),
                "my_role": role,
            })

        elif path == "/api/profile":
            target = qs.get("username", [username])[0]
            tu = get_user(target)
            if not tu:
                json_response(self, {"error": "Not found"}, 404); return
            json_response(self, user_public(tu))

        elif path == "/api/search_chats":
            q = qs.get("q", [""])[0].lower()
            chats = _load(CHATS_F)
            result = [
                {
                    "id": cid, "name": chat["name"],
                    "type": chat["type"],
                    "avatar_emoji": chat.get("avatar_emoji", "💬"),
                    "members_count": len(chat.get("members", [])) + 1,
                    "description": chat.get("description", ""),
                }
                for cid, chat in chats.items()
                if chat.get("is_public")
                and (q in chat["name"].lower() or q in chat.get("description", "").lower())
            ]
            json_response(self, result)


        elif path == "/api/users":
            all_users = _load(USERS_F)
            result = [user_public(v) for v in all_users.values() if v.get("username") != username]
            json_response(self, result)

        elif path == "/api/dm_chats":
            chats = _load(CHATS_F)
            dms = []
            for cid, chat in chats.items():
                if chat.get("type") != "dm": continue
                if username not in chat.get("members", []) and chat.get("owner") != username: continue
                other = [m for m in (chat.get("members", []) + [chat.get("owner")]) if m != username]
                other_u = get_user(other[0]) if other else None
                msgs = get_messages(cid, limit=1)
                dms.append({
                    "id": cid,
                    "other_user": user_public(other_u) if other_u else {},
                    "last_message": msgs[-1] if msgs else None,
                })
            json_response(self, dms)

        else:
            json_response(self, {"error": "Not found"}, 404)

    def _handle_api_post(self, path, username):
        body = read_body(self)
        client_ip = self._get_client_ip()

        # ── Auth: Login ──────────────────────────────────────────
        if path == "/api/auth/login":
            if _is_rate_limited(client_ip):   # FIX #9
                json_response(self, {"error": "Too many attempts, slow down"}, 429); return
            uname = body.get("username", "").strip().lower()
            pw    = body.get("password", "")
            u = get_user(uname)
            # FIX #1: use _verify_any (handles both PBKDF2 and legacy SHA-256)
            if not u or not _verify_any(pw, u):
                json_response(self, {"error": "Invalid credentials"}, 401); return
            _maybe_migrate_pw(u, pw, uname)   # FIX #1: upgrade legacy hashes
            token = create_session(uname)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie",
                f"nexo_token={token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax")
            resp = json.dumps({"ok": True, "username": uname}).encode()
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        # ── Auth: Register ───────────────────────────────────────
        if path == "/api/auth/register":
            if _is_rate_limited(client_ip):   # FIX #9
                json_response(self, {"error": "Too many attempts"}, 429); return
            uname   = re.sub(r'[^a-z0-9_]', '', body.get("username", "").strip().lower())
            pw      = body.get("password", "")
            email   = body.get("email", "").strip().lower()
            display = body.get("display", uname).strip()
            if not uname or len(uname) < 3:
                json_response(self, {"error": "Username too short (min 3)"}, 400); return
            if len(uname) > 32:
                json_response(self, {"error": "Username too long (max 32)"}, 400); return
            if not pw or len(pw) < 6:
                json_response(self, {"error": "Password too short (min 6)"}, 400); return
            users = _load(USERS_F)
            if uname in users:
                json_response(self, {"error": "Username taken"}, 409); return
            pw_hash, pw_salt = hash_pw(pw)   # FIX #1
            users[uname] = {
                "uid": str(uuid.uuid4()),
                "username": uname,
                "email": email,
                "password_hash": pw_hash,
                "password_salt": pw_salt,     # FIX #1
                "display": display or uname,
                "bio": "",
                "avatar": "",
                "avatar_emoji": "👤",
                "language": body.get("language", "en"),
                "created": time.time(),
                "online": False,
                "last_seen": now_iso(),
                "role": "user",
                "telegram_id": None,
            }
            _save(USERS_F, users)
            token = create_session(uname)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie",
                f"nexo_token={token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax")
            resp = json.dumps({"ok": True, "username": uname}).encode()
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        # ── Auth: Logout ─────────────────────────────────────────
        if path == "/api/auth/logout":
            token = get_token_from_request(self)
            if token:
                delete_session(token)
                if username:
                    u = get_user(username)
                    if u:
                        u["online"] = False
                        save_user(username, u)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "nexo_token=; Path=/; Max-Age=0; HttpOnly")
            resp = json.dumps({"ok": True}).encode()
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        # ── Password recovery: request email ─────────────────────
        if path == "/api/auth/recovery/email":
            email = body.get("email", "").strip().lower()
            if not email:
                json_response(self, {"error": "Email required"}, 400); return
            users = _load(USERS_F)
            found_user = next(
                (uname for uname, udata in users.items()
                 if udata.get("email", "").lower() == email), None
            )
            if found_user:
                reset_token = secrets.token_urlsafe(32)
                tokens = _load(RESET_TOKENS_F)
                tokens[reset_token] = {"username": found_user, "expires": time.time() + 3600}
                _save(RESET_TOKENS_F, tokens)
                send_recovery_email(email, reset_token)
            # Always return ok to prevent email enumeration
            json_response(self, {"ok": True}); return

        # ── Password recovery: set new password ──────────────────
        if path == "/api/auth/reset/password":
            reset_token = body.get("token", "").strip()
            new_password = body.get("password", "")
            if not reset_token or not new_password:
                json_response(self, {"error": "Token and password required"}, 400); return
            if len(new_password) < 6:
                json_response(self, {"error": "Password too short (min 6)"}, 400); return
            tokens = _load(RESET_TOKENS_F)
            entry = tokens.get(reset_token)
            if not entry or time.time() > entry.get("expires", 0):
                json_response(self, {"error": "Invalid or expired token"}, 400); return
            uname = entry["username"]
            u = get_user(uname)
            if not u:
                json_response(self, {"error": "User not found"}, 404); return
            new_hash, new_salt = hash_pw(new_password)   # FIX #1
            u["password_hash"] = new_hash
            u["password_salt"] = new_salt
            save_user(uname, u)
            del tokens[reset_token]
            _save(RESET_TOKENS_F, tokens)
            json_response(self, {"ok": True}); return

        # ── All other endpoints require authentication ─────────────
        if not username:
            json_response(self, {"error": "Unauthorized"}, 401); return

        u = get_user(username)
        if not u:
            json_response(self, {"error": "Unauthorized"}, 401); return

        # ── Messages: send ───────────────────────────────────────
        if path == "/api/messages/send":
            chat_id  = body.get("chat_id", "")
            text     = body.get("text", "").strip()
            msg_type = body.get("type", "text")
            file_id  = body.get("file_id", "")

            if not chat_id:
                json_response(self, {"error": "chat_id required"}, 400); return
            chat = get_chat(chat_id)
            if not chat:
                json_response(self, {"error": "Chat not found"}, 404); return
            role = get_member_role(chat, username)
            if role == "none":
                json_response(self, {"error": "Not a member"}, 403); return
            if is_banned(chat_id, username):
                json_response(self, {"error": "You are banned"}, 403); return
            if is_muted(chat_id, username):
                json_response(self, {"error": "You are muted"}, 403); return
            if role == "user":
                perms = chat.get("permissions", {})
                if not perms.get("send_messages", True):
                    json_response(self, {"error": "Sending messages disabled"}, 403); return

            if text.startswith("/") and role in ("owner", "admin"):
                result = handle_command(chat_id, username, text)
                if result:
                    sys_msg = {
                        "id": str(uuid.uuid4()), "author": "system", "display": "System",
                        "text": f"[MOD] {result.get('action', '?')} → {result.get('target', '')}",
                        "ts": ts(), "type": "system",
                        "reactions": {}, "pinned": False, "edited": False,
                    }
                    add_message(chat_id, sys_msg)
                    broadcast_message(chat_id, sys_msg)
                    json_response(self, {"ok": True, "mod": result, "message": sys_msg})
                    return

            if not text and not file_id:
                json_response(self, {"error": "Empty message"}, 400); return

            msg = {
                "id": str(uuid.uuid4()),
                "author": username,
                "display": u.get("display", username),
                "avatar_emoji": u.get("avatar_emoji", "👤"),
                "text": text,
                "ts": ts(),
                "type": msg_type,
                "file_id": file_id,
                "reactions": {},
                "pinned": False,
                "edited": False,
                "reply_to": body.get("reply_to", None),
            }
            add_message(chat_id, msg)
            broadcast_message(chat_id, msg)
            json_response(self, {"ok": True, "message": msg})

        elif path == "/api/messages/react":
            chat_id = body.get("chat_id", "")
            msg_id  = body.get("msg_id", "")
            emoji   = body.get("emoji", "")
            if not all([chat_id, msg_id, emoji]):
                json_response(self, {"error": "Missing params"}, 400); return
            msgs = _load(MSGS_F)
            for m in msgs.get(chat_id, []):
                if m["id"] == msg_id:
                    m["reactions"].setdefault(emoji, [])
                    if username in m["reactions"][emoji]:
                        m["reactions"][emoji].remove(username)
                    else:
                        m["reactions"][emoji].append(username)
                    _save(MSGS_F, msgs)
                    broadcast_message(chat_id, {
                        "type": "reaction_update",
                        "msg_id": msg_id,
                        "reactions": m["reactions"]
                    })
                    json_response(self, {"ok": True, "reactions": m["reactions"]}); return
            json_response(self, {"error": "Message not found"}, 404)
        elif path == "/api/messages/pin":
            chat_id = body.get("chat_id", "")
            msg_id  = body.get("msg_id", "")
            chat = get_chat(chat_id)
            if not chat:
                json_response(self, {"error": "Not found"}, 404); return
            role = get_member_role(chat, username)
            if role not in ("owner", "admin"):
                json_response(self, {"error": "No permission"}, 403); return
            chat["pinned_message"] = msg_id
            save_chat(chat_id, chat)
            broadcast_message(chat_id, {"type": "pin", "msg_id": msg_id})
            json_response(self, {"ok": True})

        elif path == "/api/messages/unpin":
            chat_id = body.get("chat_id", "")
            chat = get_chat(chat_id)
            if not chat:
                json_response(self, {"error": "Not found"}, 404); return
            role = get_member_role(chat, username)
            if role not in ("owner", "admin"):
                json_response(self, {"error": "No permission"}, 403); return
            chat["pinned_message"] = None
            save_chat(chat_id, chat)
            broadcast_message(chat_id, {"type": "pin", "msg_id": None})
            json_response(self, {"ok": True})

        elif path == "/api/messages/delete":
            chat_id = body.get("chat_id", "")
            msg_id  = body.get("msg_id", "")
            msgs = _load(MSGS_F)
            room_msgs = msgs.get(chat_id, [])
            chat = get_chat(chat_id)
            role = get_member_role(chat, username) if chat else "none"
            new_msgs = []
            deleted = False
            for m in room_msgs:
                if m["id"] == msg_id:
                    if m["author"] != username and role not in ("owner", "admin"):
                        json_response(self, {"error": "No permission"}, 403); return
                    deleted = True
                    broadcast_message(chat_id, {"type": "delete", "id": msg_id})
                else:
                    new_msgs.append(m)
            if deleted:
                msgs[chat_id] = new_msgs
                _save(MSGS_F, msgs)
                json_response(self, {"ok": True})
            else:
                json_response(self, {"error": "Not found"}, 404)

        elif path.startswith("/api/mod/"):
            action = path[9:]  # mute/unmute/ban/unban/kick/promote/demote
            chat_id  = body.get("chat_id", "")
            target   = body.get("username", "")
            duration = body.get("duration", None)
            reason   = body.get("reason", "")
            chat = get_chat(chat_id)
            if not chat:
                json_response(self, {"error": "Not found"}, 404); return
            role = get_member_role(chat, username)
            if role not in ("owner", "admin"):
                json_response(self, {"error": "No permission"}, 403); return

            if action in ("mute", "unmute"):
                mutes = _load(MUTES_F)
                if action == "mute":
                    dur_sec = 3600
                    if duration:
                        m2 = re.match(r"^(\d+)([mhd])$", str(duration))
                        if m2:
                            v, u2 = int(m2.group(1)), m2.group(2)
                            dur_sec = v * {"m": 60, "h": 3600, "d": 86400}[u2]
                    mutes.setdefault(chat_id, {})[target] = {"until": time.time() + dur_sec, "reason": reason, "by": username}
                else:
                    mutes.get(chat_id, {}).pop(target, None)
                _save(MUTES_F, mutes)
                json_response(self, {"ok": True})

            elif action in ("ban", "unban"):
                bans = _load(BANS_F)
                if action == "ban":
                    dur_sec = None
                    if duration:
                        m2 = re.match(r"^(\d+)([mhd])$", str(duration))
                        if m2:
                            v, u2 = int(m2.group(1)), m2.group(2)
                            dur_sec = v * {"m": 60, "h": 3600, "d": 86400}[u2]
                    bans.setdefault(chat_id, {})[target] = {
                        "until": time.time() + dur_sec if dur_sec else None,
                        "permanent": dur_sec is None,
                        "reason": reason, "by": username
                    }
                    ch = get_chat(chat_id)
                    if target in ch.get("members", []):
                        ch["members"].remove(target)
                        save_chat(chat_id, ch)
                else:
                    bans.get(chat_id, {}).pop(target, None)
                _save(BANS_F, bans)
                json_response(self, {"ok": True})

            elif action == "kick":
                ch = get_chat(chat_id)
                if target in ch.get("members", []):
                    ch["members"].remove(target)
                    save_chat(chat_id, ch)
                broadcast_message(chat_id, {"type": "system", "text": f"{target} був вигнаний"})
                json_response(self, {"ok": True})

            elif action in ("promote", "demote"):
                ch = get_chat(chat_id)
                if ch.get("owner") != username:
                    json_response(self, {"error": "Only owner"}, 403); return
                if action == "promote":
                    ch.setdefault("admins", {})[target] = {"all": False}
                else:
                    ch.get("admins", {}).pop(target, None)
                save_chat(chat_id, ch)
                json_response(self, {"ok": True})

            else:
                json_response(self, {"error": "Unknown action"}, 404)


        elif path == "/api/chats/create":
            name        = body.get("name", "").strip()
            chat_type   = body.get("type", "group")
            description = body.get("description", "").strip()
            is_public   = body.get("is_public", True)
            avatar_emoji = body.get("avatar_emoji", "💬")

            if not name or len(name) < 2:
                json_response(self, {"error": "Name too short"}, 400); return
            if chat_type not in ("group", "channel"):
                json_response(self, {"error": "Invalid type"}, 400); return

            chat_id = re.sub(r'[^a-z0-9_]', '', name.lower().replace(' ', '_'))
            chats = _load(CHATS_F)
            if chat_id in chats:
                chat_id = chat_id + "_" + str(uuid.uuid4())[:6]

            invite = gen_invite()
            chats[chat_id] = {
                "id": chat_id, "type": chat_type, "name": name,
                "description": description, "avatar_emoji": avatar_emoji,
                "avatar": "", "owner": username, "admins": {}, "members": [],
                "invite_link": chat_id if is_public else None,
                "private_invite": invite,
                "is_public": bool(is_public),
                "created": time.time(), "pinned_message": None,
                "permissions": {
                    "send_messages": True, "send_media": True,
                    "add_members": True, "pin_messages": False, "change_info": False,
                }
            }
            _save(CHATS_F, chats)
            json_response(self, {"ok": True, "chat_id": chat_id, "invite": invite})

        elif path == "/api/chats/join":
            chat_id = body.get("chat_id", "")
            invite  = body.get("invite", "")
            chat = get_chat(chat_id)
            if not chat:
                chats = _load(CHATS_F)
                for cid, c in chats.items():
                    if c.get("invite_link") == invite or c.get("private_invite") == invite:
                        chat = c; chat_id = cid; break
            if not chat:
                json_response(self, {"error": "Chat not found"}, 404); return
            if is_banned(chat_id, username):
                json_response(self, {"error": "You are banned"}, 403); return
            role = get_member_role(chat, username)
            if role != "none":
                json_response(self, {"ok": True, "chat_id": chat_id, "already": True}); return
            chat.setdefault("members", []).append(username)
            save_chat(chat_id, chat)
            json_response(self, {"ok": True, "chat_id": chat_id})

        elif path == "/api/chats/leave":
            chat_id = body.get("chat_id", "")
            chat = get_chat(chat_id)
            if not chat:
                json_response(self, {"error": "Chat not found"}, 404); return
            if chat.get("owner") == username:
                json_response(self, {"error": "Owner cannot leave"}, 400); return
            if username in chat.get("members", []):
                chat["members"].remove(username)
            chat.get("admins", {}).pop(username, None)
            save_chat(chat_id, chat)
            json_response(self, {"ok": True})

        elif path == "/api/chats/update":
            chat_id = body.get("chat_id", "")
            chat = get_chat(chat_id)
            if not chat:
                json_response(self, {"error": "Not found"}, 404); return
            role = get_member_role(chat, username)
            if role not in ("owner", "admin"):
                json_response(self, {"error": "No permission"}, 403); return
            for field in ["name", "description", "avatar_emoji", "is_public"]:
                if field in body: chat[field] = body[field]
            if "permissions" in body:
                chat["permissions"].update(body["permissions"])
            save_chat(chat_id, chat)
            json_response(self, {"ok": True})

        elif path == "/api/profile/update":
            display      = body.get("display", "").strip()
            bio          = body.get("bio", "").strip()
            avatar_emoji = body.get("avatar_emoji", "")
            language     = body.get("language", "")
            if display: u["display"] = display[:64]
            if bio is not None: u["bio"] = bio[:256]
            if avatar_emoji: u["avatar_emoji"] = avatar_emoji
            if language in TRANSLATIONS: u["language"] = language
            save_user(username, u)
            json_response(self, {"ok": True})

        elif path == "/api/dm/start":
            target = body.get("username", "")
            if not target or target == username:
                json_response(self, {"error": "Invalid target"}, 400); return
            tu = get_user(target)
            if not tu:
                json_response(self, {"error": "User not found"}, 404); return
            chats = _load(CHATS_F)
            for cid, chat in chats.items():
                if chat.get("type") == "dm":
                    members = set(chat.get("members", []) + [chat.get("owner")])
                    if username in members and target in members:
                        json_response(self, {"ok": True, "chat_id": cid}); return
            dm_id = "dm_" + "_".join(sorted([username, target]))
            chats[dm_id] = {
                "id": dm_id, "type": "dm",
                "name": f"{u.get('display', username)} ↔ {tu.get('display', target)}",
                "description": "", "avatar_emoji": "💬",
                "owner": username, "admins": {}, "members": [target],
                "invite_link": None, "private_invite": None,
                "is_public": False, "created": time.time(), "pinned_message": None,
                "permissions": {"send_messages": True, "send_media": True},
            }
            _save(CHATS_F, chats)
            json_response(self, {"ok": True, "chat_id": dm_id})

        elif path == "/api/upload":
            content_type = self.headers.get("Content-Type", "")
            length = int(self.headers.get("Content-Length", 0))
            if not length:
                json_response(self, {"error": "No file"}, 400); return
            # FIX: limit upload size to 50 MB
            if length > 50 * 1024 * 1024:
                json_response(self, {"error": "File too large (max 50 MB)"}, 413); return
            raw = self.rfile.read(length)
            ext = ".bin"
            if "image/jpeg" in content_type: ext = ".jpg"
            elif "image/png" in content_type: ext = ".png"
            elif "image/gif" in content_type: ext = ".gif"
            elif "video/mp4" in content_type: ext = ".mp4"
            elif "audio/mpeg" in content_type: ext = ".mp3"
            fid = str(uuid.uuid4()) + ext
            (UPLOADS / fid).write_bytes(raw)
            json_response(self, {"ok": True, "file_id": fid, "url": f"/uploads/{fid}"})

        elif path == "/api/typing":
            chat_id = body.get("chat_id", "")
            broadcast_message(chat_id, {
                "type": "typing",
                "username": username,
                "display": u.get("display", username),
            })
            json_response(self, {"ok": True})

        else:
            json_response(self, {"error": "Not found"}, 404)

    def _serve_file(self, fp: Path):
        mime, _ = mimetypes.guess_type(str(fp))
        mime = mime or "application/octet-stream"
        data = fp.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        self.wfile.write(data)

    def _handle_ws_upgrade(self):
        """
        Proper WebSocket hijack:
        1. Send 101 handshake
        2. Set _ws_hijacked = True  ← suppresses wfile.flush() in handle_one_request
        3. Start NexoWSThread        ← runs loop in own thread, HTTP handler returns immediately
        """
        key = self.headers.get("Sec-WebSocket-Key", "").strip()
        if not key:
            self.send_response(400); self.end_headers(); return

        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()

        # Write raw bytes — bypass send_response/send_header to avoid buffering issues
        resp = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode("ascii")
        try:
            self.wfile.write(resp)
            self.wfile.flush()
        except Exception:
            return

        # Hijack: prevent finish() / flush() from closing the socket
        self._ws_hijacked = True

        token    = get_token_from_request(self)
        username = get_session(token)
        parsed   = urlparse(self.path)
        qs       = parse_qs(parsed.query)
        chat_id  = qs.get("chat_id", [""])[0]

        if username and chat_id:
            u = get_user(username)
            if u:
                u["online"] = True
                save_user(username, u)

        # Hand off socket to dedicated thread — HTTP handler returns immediately
        NexoWSThread(self.connection, username, chat_id).start()


# ── Page builders ─────────────────────────────────────────────────
def build_auth_page(lang="en") -> str:
    """Serve auth.html from disk if present, else inline fallback."""
    f = BASE / "auth.html"
    if f.exists():
        try: return f.read_text(encoding="utf-8")
        except: pass
    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexoChat — {t('login', lang)}</title>
<style>
*,*::before,*::after{{margin:0;padding:0;box-sizing:border-box;}}
:root{{
  --bg:#0d0d0d;--card:#141414;--orange:#ff6b00;--orange2:#ff8c00;--orange3:#ffaa44;
  --border:rgba(255,107,0,.2);--border2:rgba(255,107,0,.4);
  --text:#f0f0f0;--muted:#888;--red:#ff4444;
  --font:'Segoe UI',system-ui,sans-serif;
}}
body{{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;
  display:flex;align-items:center;justify-content:center;padding:16px;}}
body::before{{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background:radial-gradient(ellipse 60% 50% at 20% 20%,rgba(255,107,0,.08),transparent 60%),
             radial-gradient(ellipse 50% 60% at 80% 80%,rgba(255,140,0,.06),transparent 60%);}}
.wrap{{position:relative;z-index:1;width:100%;max-width:400px;}}
.logo{{text-align:center;margin-bottom:32px;}}
.logo-icon{{font-size:56px;display:block;margin-bottom:8px;}}
.logo-name{{font-size:2em;font-weight:900;
  background:linear-gradient(135deg,var(--orange),var(--orange3));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}}
.logo-sub{{color:var(--muted);font-size:.82em;margin-top:4px;}}
.card{{background:var(--card);border:1.5px solid var(--border2);border-radius:18px;
  padding:32px 28px;box-shadow:0 0 40px rgba(255,107,0,.08);}}
.tabs{{display:flex;gap:2px;margin-bottom:24px;background:rgba(255,255,255,.04);
  border-radius:10px;padding:3px;}}
.tab{{flex:1;padding:10px;border:none;background:none;color:var(--muted);
  font-size:.88em;font-weight:700;cursor:pointer;border-radius:8px;transition:all .2s;}}
.tab.active{{background:var(--orange);color:#fff;}}
.field{{margin-bottom:14px;}}
.field label{{display:block;font-size:.72em;color:var(--muted);text-transform:uppercase;
  letter-spacing:.08em;margin-bottom:6px;font-weight:600;}}
.field input,.field select{{width:100%;padding:11px 14px;background:rgba(255,255,255,.05);
  border:1.5px solid rgba(255,255,255,.08);border-radius:10px;color:var(--text);
  font-size:.9em;outline:none;transition:border .2s;}}
.field input:focus,.field select:focus{{border-color:var(--orange);}}
.field select option{{background:#1a1a1a;}}
.btn{{width:100%;padding:13px;margin-top:8px;
  background:linear-gradient(135deg,var(--orange),var(--orange2));
  border:none;border-radius:10px;color:#fff;font-size:.95em;font-weight:800;
  cursor:pointer;transition:all .2s;box-shadow:0 4px 20px rgba(255,107,0,.3);}}
.btn:hover{{transform:translateY(-1px);box-shadow:0 6px 28px rgba(255,107,0,.45);}}
.err{{color:var(--red);font-size:.8em;margin-top:10px;padding:8px 12px;
  background:rgba(255,68,68,.1);border:1px solid rgba(255,68,68,.2);
  border-radius:8px;display:none;}}
.err.show{{display:block;}}
.lang-row{{display:flex;justify-content:center;gap:8px;margin-bottom:20px;}}
.lang-btn{{padding:5px 12px;border:1px solid var(--border);border-radius:20px;
  background:none;color:var(--muted);font-size:.78em;cursor:pointer;transition:all .2s;}}
.lang-btn.active,.lang-btn:hover{{border-color:var(--orange);color:var(--orange);}}
#tab-login,#tab-register{{display:none;}}
#tab-login.active,#tab-register.active{{display:block;}}
.spin{{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.3);
  border-top-color:#fff;border-radius:50%;animation:sp .6s linear infinite;vertical-align:middle;}}
@keyframes sp{{to{{transform:rotate(360deg)}}}}
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">
    <span class="logo-icon">💬</span>
    <div class="logo-name">NexoChat</div>
    <div class="logo-sub">{t('tagline', lang)}</div>
  </div>
  <div class="lang-row">
    <button class="lang-btn{' active' if lang=='en' else ''}" onclick="setLang('en')">EN</button>
    <button class="lang-btn{' active' if lang=='uk' else ''}" onclick="setLang('uk')">UA</button>
    <button class="lang-btn{' active' if lang=='ru' else ''}" onclick="setLang('ru')">RU</button>
    <button class="lang-btn{' active' if lang=='pl' else ''}" onclick="setLang('pl')">PL</button>
  </div>
  <div class="card">
    <div class="tabs">
      <button class="tab active" id="btn-login" onclick="switchTab('login')">{t('login', lang)}</button>
      <button class="tab" id="btn-register" onclick="switchTab('register')">{t('register', lang)}</button>
    </div>

    <div id="tab-login" class="active">
      <div class="field">
        <label>{t('username', lang)}</label>
        <input type="text" id="l-user" placeholder="username" autocomplete="username">
      </div>
      <div class="field">
        <label>{t('password', lang)}</label>
        <input type="password" id="l-pass" placeholder="••••••••" autocomplete="current-password">
      </div>
      <button class="btn" id="l-btn" onclick="doLogin()">{t('login', lang)}</button>
      <div class="err" id="l-err"></div>
    </div>

    <div id="tab-register">
      <div class="field">
        <label>{t('username', lang)}</label>
        <input type="text" id="r-user" placeholder="my_username" autocomplete="username">
      </div>
      <div class="field">
        <label>{t('email', lang)}</label>
        <input type="email" id="r-email" placeholder="you@email.com">
      </div>
      <div class="field">
        <label>{t('password', lang)}</label>
        <input type="password" id="r-pass" placeholder="••••••••" autocomplete="new-password">
      </div>
      <div class="field">
        <label>Display name</label>
        <input type="text" id="r-display" placeholder="Your Name">
      </div>
      <div class="field">
        <label>Language</label>
        <select id="r-lang">
          <option value="en"{' selected' if lang=='en' else ''}>English</option>
          <option value="uk"{' selected' if lang=='uk' else ''}>Українська</option>
          <option value="ru"{' selected' if lang=='ru' else ''}>Русский</option>
          <option value="pl"{' selected' if lang=='pl' else ''}>Polski</option>
        </select>
      </div>
      <button class="btn" id="r-btn" onclick="doRegister()">{t('register', lang)}</button>
      <div class="err" id="r-err"></div>
    </div>
  </div>

  <!-- Reset password modal (for ?reset_token= links) -->
  <div id="reset-overlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);
    z-index:100;display:flex;align-items:center;justify-content:center;">
    <div style="background:#141414;border:1.5px solid rgba(255,107,0,.4);border-radius:18px;
      padding:32px 28px;width:100%;max-width:380px;">
      <div style="font-size:1.1em;font-weight:800;margin-bottom:16px;">🔐 New password</div>
      <input type="hidden" id="reset-token-val">
      <div class="field"><label>New password</label>
        <input id="reset-pw" type="password" placeholder="Min 6 characters"></div>
      <div class="field"><label>Confirm password</label>
        <input id="reset-pw2" type="password" placeholder="Repeat password"></div>
      <button class="btn" onclick="doResetPassword()">Change password</button>
      <div class="err" id="reset-err"></div>
    </div>
  </div>
</div>

<script>
// ── Language ──────────────────────────────────────────────────────
function setLang(l) {{
  const u = new URL(location.href);
  u.searchParams.set('lang', l);
  location.href = u.toString();
}}

// ── Tabs ──────────────────────────────────────────────────────────
function switchTab(tab) {{
  document.getElementById('tab-login').classList.toggle('active', tab === 'login');
  document.getElementById('tab-register').classList.toggle('active', tab === 'register');
  document.getElementById('btn-login').classList.toggle('active', tab === 'login');
  document.getElementById('btn-register').classList.toggle('active', tab === 'register');
}}

function showErr(id, msg) {{
  const e = document.getElementById(id);
  e.textContent = msg;
  e.classList.add('show');
  e.style.display = 'block';
}}
function clearErr(id) {{
  const e = document.getElementById(id);
  e.classList.remove('show');
  e.style.display = 'none';
}}

// FIX: Login calls /api/auth/login (not /web/api/login)
// FIX: No localStorage token — server sets HttpOnly cookie automatically
async function doLogin() {{
  const u = document.getElementById('l-user').value.trim();
  const p = document.getElementById('l-pass').value;
  clearErr('l-err');
  if (!u || !p) {{ showErr('l-err', 'Fill all fields'); return; }}
  const btn = document.getElementById('l-btn');
  btn.innerHTML = '<span class="spin"></span>';
  btn.disabled = true;
  try {{
    const r = await fetch('/api/auth/login', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{username: u, password: p}})
    }});
    const d = await r.json();
    if (d.ok) {{
      window.location.href = '/';
    }} else {{
      showErr('l-err', d.error || 'Wrong username or password');
    }}
  }} catch(e) {{
    showErr('l-err', 'Network error — check your connection');
  }}
  btn.textContent = 'Login';
  btn.disabled = false;
}}

// FIX: Register calls /api/auth/register (not /web/api/register)
async function doRegister() {{
  const u  = document.getElementById('r-user').value.trim();
  const e  = document.getElementById('r-email').value.trim();
  const p  = document.getElementById('r-pass').value;
  const dn = document.getElementById('r-display').value.trim();
  const l  = document.getElementById('r-lang').value;
  clearErr('r-err');
  if (!u || !p) {{ showErr('r-err', 'Username and password required'); return; }}
  if (p.length < 6) {{ showErr('r-err', 'Password must be at least 6 characters'); return; }}
  const btn = document.getElementById('r-btn');
  btn.innerHTML = '<span class="spin"></span>';
  btn.disabled = true;
  try {{
    const r = await fetch('/api/auth/register', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{username: u, email: e, password: p, display: dn, language: l}})
    }});
    const d = await r.json();
    if (d.ok) {{
      window.location.href = '/';
    }} else {{
      showErr('r-err', d.error || 'Registration error');
    }}
  }} catch(e) {{
    showErr('r-err', 'Network error — check your connection');
  }}
  btn.textContent = 'Create account';
  btn.disabled = false;
}}

// ── Enter key support ─────────────────────────────────────────────
document.addEventListener('keydown', ev => {{
  if (ev.key === 'Enter') {{
    if (document.getElementById('tab-login').classList.contains('active')) doLogin();
    else doRegister();
  }}
}});

// ── Auto-open reset modal if ?reset_token= in URL ─────────────────
// FIX: removed localStorage check (server uses cookies, no localStorage token needed)
const _params = new URLSearchParams(location.search);
const _rt = _params.get('reset_token');
if (_rt) {{
  document.getElementById('reset-token-val').value = _rt;
  document.getElementById('reset-overlay').style.display = 'flex';
}}

async function doResetPassword() {{
  const token = document.getElementById('reset-token-val').value;
  const pw    = document.getElementById('reset-pw').value;
  const pw2   = document.getElementById('reset-pw2').value;
  if (pw !== pw2) {{ showErr('reset-err', 'Passwords do not match'); return; }}
  if (pw.length < 6) {{ showErr('reset-err', 'Min 6 characters'); return; }}
  try {{
    const r = await fetch('/api/auth/reset/password', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{token, password: pw}})
    }});
    const d = await r.json();
    if (d.ok) {{
      document.getElementById('reset-overlay').style.display = 'none';
      alert('✅ Password changed! You can now log in.');
      history.replaceState({{}},'', '/auth');
    }} else {{
      showErr('reset-err', d.error || 'Error');
    }}
  }} catch(e) {{ showErr('reset-err', 'Network error'); }}
}}
</script>
</body>
</html>"""


def build_profile_page(profile_user: dict, viewer: dict, lang="en") -> str:
    uname   = profile_user.get("username", "")
    display = profile_user.get("display", uname)
    bio     = profile_user.get("bio", "")
    emoji   = profile_user.get("avatar_emoji", "👤")
    is_self = viewer.get("username") == uname

    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{display} — NexoChat</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
:root{{--bg:#0d0d0d;--card:#141414;--orange:#ff6b00;--orange2:#ff8c00;
  --border:rgba(255,107,0,.25);--text:#f0f0f0;--muted:#777;--font:'Segoe UI',system-ui,sans-serif;}}
body{{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;
  display:flex;align-items:center;justify-content:center;padding:16px;}}
.card{{background:var(--card);border:1.5px solid var(--border);border-radius:24px;
  padding:40px 32px;width:100%;max-width:400px;text-align:center;
  box-shadow:0 0 60px rgba(255,107,0,.08);}}
.avatar{{font-size:5em;margin-bottom:16px;}}
.name{{font-size:1.6em;font-weight:900;margin-bottom:4px;}}
.user{{color:var(--muted);font-size:.9em;margin-bottom:16px;}}
.bio{{color:var(--muted);font-size:.92em;line-height:1.6;margin-bottom:24px;padding:0 8px;}}
.btn{{padding:11px 22px;border:none;border-radius:10px;font-size:.92em;font-weight:700;
  cursor:pointer;text-decoration:none;transition:all .2s;display:inline-block;}}
.btn-primary{{background:linear-gradient(135deg,var(--orange),var(--orange2));color:#fff;}}
.btn-secondary{{background:rgba(255,255,255,.07);color:var(--text);}}
.actions{{display:flex;justify-content:center;gap:10px;flex-wrap:wrap;}}
.back{{margin-top:20px;font-size:.82em;color:var(--muted);}}
.back a{{color:var(--orange);text-decoration:none;font-weight:600;}}
</style>
</head>
<body>
<div class="card">
  <div class="avatar">{emoji}</div>
  <div class="name">{display}</div>
  <div class="user">@{uname}</div>
  {f'<div class="bio">{bio}</div>' if bio else ''}
  <div class="actions">
    {'<button class="btn btn-primary" onclick="location.href=&#39;/?profile=edit&#39;">✏️ Edit profile</button>' if is_self else ''}
    {'<button class="btn btn-primary" onclick="sendMessage()">💬 Message</button>' if not is_self else ''}
    <a class="btn btn-secondary" href="/">← Back</a>
  </div>
  <div class="back"><a href="/">Open NexoChat</a></div>
</div>
<script>
async function sendMessage() {{
  const r = await fetch('/api/dm/start', {{
    method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{username:'{uname}'}})
  }});
  const data = await r.json();
  if (data.ok) location.href = '/';
}}
</script>
</body>
</html>"""


def build_chat_preview(chat: dict, viewer: dict, lang="en") -> str:
    name    = chat.get("name", "Chat")
    desc    = chat.get("description", "")
    emoji   = chat.get("avatar_emoji", "💬")
    ctype   = chat.get("type", "group")
    members = len(chat.get("members", [])) + 1
    chat_id = chat.get("id", "")
    invite  = chat.get("invite_link") or chat.get("private_invite") or chat_id

    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{name} — NexoChat</title>
<meta property="og:title" content="{name}">
<meta property="og:description" content="{desc}">
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
:root{{--bg:#0d0d0d;--card:#141414;--orange:#ff6b00;--orange2:#ff8c00;
  --border:rgba(255,107,0,.25);--text:#f0f0f0;--muted:#777;
  --green:#4caf50;--font:'Segoe UI',system-ui,sans-serif;}}
body{{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;
  display:flex;align-items:center;justify-content:center;padding:16px;}}
.card{{background:var(--card);border:1.5px solid var(--border);border-radius:24px;
  padding:40px 32px;width:100%;max-width:420px;text-align:center;
  box-shadow:0 0 60px rgba(255,107,0,.1);}}
.avatar{{font-size:5em;margin-bottom:16px;}}
.type-badge{{display:inline-block;padding:4px 12px;border-radius:12px;font-size:.72em;
  font-weight:700;margin-bottom:12px;background:rgba(255,107,0,.12);
  color:var(--orange);border:1px solid rgba(255,107,0,.2);}}
.name{{font-size:1.7em;font-weight:900;margin-bottom:8px;}}
.desc{{color:var(--muted);font-size:.9em;line-height:1.6;margin-bottom:20px;}}
.stats{{display:flex;justify-content:center;gap:24px;margin-bottom:28px;}}
.stat-val{{font-size:1.3em;font-weight:800;color:var(--orange);}}
.stat-label{{font-size:.72em;color:var(--muted);margin-top:2px;}}
.join-btn{{width:100%;padding:14px;background:linear-gradient(135deg,var(--orange),var(--orange2));
  border:none;border-radius:12px;color:#fff;font-size:1em;font-weight:800;
  cursor:pointer;transition:all .2s;}}
.join-btn:hover{{transform:translateY(-2px);}}
.msg{{margin-top:12px;font-size:.8em;padding:8px;border-radius:8px;display:none;}}
.msg.err{{background:rgba(255,68,68,.1);color:#ff4444;display:block;}}
.msg.ok{{background:rgba(76,175,80,.1);color:var(--green);display:block;}}
.back{{margin-top:16px;font-size:.82em;color:var(--muted);}}
.back a{{color:var(--orange);text-decoration:none;font-weight:600;}}
</style>
</head>
<body>
<div class="card">
  <div class="avatar">{emoji}</div>
  <div class="type-badge">{'📡 Channel' if ctype == 'channel' else '👥 Group'}</div>
  <div class="name">{name}</div>
  {f'<div class="desc">{desc}</div>' if desc else ''}
  <div class="stats">
    <div class="stat">
      <div class="stat-val">{members}</div>
      <div class="stat-label">{t('members', lang)}</div>
    </div>
    <div class="stat">
      <div class="stat-val">{'🔓' if chat.get('is_public') else '🔒'}</div>
      <div class="stat-label">{'Public' if chat.get('is_public') else 'Private'}</div>
    </div>
  </div>
  <button class="join-btn" onclick="joinChat()">{t('join', lang)}</button>
  <div class="msg" id="msg"></div>
  <div class="back"><a href="/">← NexoChat</a></div>
</div>
<script>
async function joinChat() {{
  const r = await fetch('/api/chats/join', {{
    method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{chat_id:'{chat_id}', invite:'{invite}'}})
  }});
  const data = await r.json();
  const el = document.getElementById('msg');
  if (data.ok) {{
    el.textContent = 'Joined! Redirecting...';
    el.className = 'msg ok';
    setTimeout(() => location.href = '/', 1200);
  }} else {{
    el.textContent = data.error || 'Error';
    el.className = 'msg err';
  }}
}}
</script>
</body>
</html>"""


def build_main_page(user: dict, lang="en", active_chat=None) -> str:
    """Serve chat.html from disk if present, else fallback."""
    f = BASE / "chat.html"
    if f.exists():
        try: return f.read_text(encoding="utf-8")
        except: pass
    uname   = user.get("username", "")
    display = user.get("display", uname)
    emoji   = user.get("avatar_emoji", "👤")

    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexoChat</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d0d0d;color:#f0f0f0;
  height:100vh;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:16px;}}
.logo{{font-size:3em;}}
h1{{font-size:1.5em;font-weight:900;background:linear-gradient(135deg,#ff6b00,#ffaa44);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}}
p{{color:#888;font-size:.9em;}}
.btn{{padding:12px 24px;background:linear-gradient(135deg,#ff6b00,#ff8c00);border:none;
  border-radius:10px;color:#fff;font-size:.95em;font-weight:700;cursor:pointer;
  text-decoration:none;display:inline-block;margin-top:8px;}}
.user-info{{color:#666;font-size:.85em;}}
</style>
</head>
<body>
  <div class="logo">💬</div>
  <h1>NexoChat</h1>
  <p class="user-info">Logged in as {emoji} <strong>{display}</strong> (@{uname})</p>
  <p>Main chat interface (SPA) should be served as a static file.</p>
  <a class="btn" href="/api/auth/logout" onclick="event.preventDefault();logout()">Logout</a>
<script>
async function logout() {{
  await fetch('/api/auth/logout', {{method:'POST'}});
  location.href = '/auth';
}}
</script>
</body>
</html>"""


# ── Main ──────────────────────────────────────────────────────────
def main():
    seed()

    # Start Telegram bot in subprocess (only if not already a subprocess)
    if not os.environ.get("NEXO_BOT_SUBPROCESS"):
        def _run_bot():
            bot_file = BASE / "nexochat_bot.py"
            if not bot_file.exists():
                log.warning("nexochat_bot.py not found — bot not started")
                return
            env = os.environ.copy()
            env["NEXO_BOT_SUBPROCESS"] = "1"
            log.info("Starting Telegram bot...")
            while True:
                try:
                    proc = subprocess.Popen(
                        [sys.executable, "-u", str(bot_file)],
                        cwd=str(BASE), env=env
                    )
                    proc.wait()
                    log.warning("Bot stopped (code %d), restarting in 5s...", proc.returncode)
                    time.sleep(5)
                except Exception as e:
                    log.warning("Bot launch error: %s", e)
                    time.sleep(5)
        threading.Thread(target=_run_bot, daemon=True).start()

    port = int(os.environ.get("PORT", 80))
    host = os.environ.get("HOST", "0.0.0.0")

    server = ThreadingHTTPServer((host, port), NexoHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    log.info("=" * 55)
    log.info("  NexoChat running at http://%s:%d", host, port)   # FIX #6: was missing f-prefix
    log.info("  Auth page: http://localhost:%d/auth", port)       # FIX #6
    log.info("  Admin user: %s", SITE_ADMIN)
    log.info("=" * 55)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutdown")
        server.server_close()


if __name__ == "__main__":
    main()
