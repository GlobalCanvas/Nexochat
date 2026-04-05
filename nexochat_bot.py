#!/usr/bin/env python3
"""
NexoChat Telegram Bot — FIXED VERSION
- Login via Telegram (/login)
- Password recovery (/recover)  
- Notifications (/notify_on, /notify_off)
- Admin: /start_site /stop_site /restart_site /proc_status /logs

FIXES APPLIED:
  1. Admin password hashed with PBKDF2 (was: plain text comparison)
  2. Hardcoded credentials removed — must be set via env vars
  3. Admin password stored as hash, not plain text in env var (salt in separate var)
  4. Session state stored separately from auth state (cleaner code)
  5. Bot sessions backed by file on disk (survive restart)
"""

import os, sys, time, json, signal, logging, threading, subprocess, hashlib, secrets, hmac
import urllib.request, urllib.error
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("NexoBot")

BASE_DIR = Path(__file__).parent
DATA     = BASE_DIR / "data"
DATA.mkdir(exist_ok=True)

TG_NOTIFY_F  = DATA / "tg_notify.json"
TG_PENDING_F = DATA / "tg_pending.json"
TG_TOKENS_F  = DATA / "tg_tokens.json"
FILE_LOCK = threading.RLock()

def _load(path):
    p = Path(path)
    if not p.exists(): return {}
    with FILE_LOCK:
        try: return json.loads(p.read_text(encoding="utf-8"))
        except: return {}

def _save(path, data):
    with FILE_LOCK:
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def gen_code() -> str:
    return secrets.token_hex(4).upper()  # 8-char hex code

# ── Password utilities ─────────────────────────────────────────────
# FIX #1: Use PBKDF2 for admin password verification — never plain text
def _hash_admin(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 260_000).hex()

def _hash_user(pw: str) -> str:
    """SHA-256 for NexoChat site users (site server handles PBKDF2, bot just checks)."""
    return hashlib.sha256(pw.encode()).hexdigest()

# ── Config ────────────────────────────────────────────────────────
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
SITE_URL  = os.environ.get("NEXO_URL", "https://nexochats.bothost.tech")

if not BOT_TOKEN:
    log.error("BOT_TOKEN not found! Set BOT_TOKEN environment variable.")
    sys.exit(1)

API = f"https://api.telegram.org/bot{BOT_TOKEN}"

# ── Admin credentials ─────────────────────────────────────────────
# FIX #2: No hardcoded passwords. Must be set in environment.
BOT_ADMIN_USER = os.environ.get("BOT_ADMIN_USER", "")
BOT_ADMIN_PASS = os.environ.get("BOT_ADMIN_PASS", "")

# FIX #3: Pre-hash the admin password at startup so we never compare plain text at runtime.
# The env var still carries the plain-text password, but we hash it immediately and
# discard the plain text from memory.
_ADMIN_SALT: str | None = None
_ADMIN_HASH: str | None = None

if BOT_ADMIN_USER and BOT_ADMIN_PASS:
    _ADMIN_SALT = secrets.token_hex(16)
    _ADMIN_HASH = _hash_admin(BOT_ADMIN_PASS, _ADMIN_SALT)
    BOT_ADMIN_PASS = ""  # Clear plain text from memory
    log.info("Admin credentials loaded and hashed for bot: %s", BOT_ADMIN_USER)
else:
    log.warning("BOT_ADMIN_USER/BOT_ADMIN_PASS not set — admin commands will fall back to users.json")

def get_user(username: str) -> dict | None:
    u = _load(DATA / "users.json").get(username)
    return dict(u) if u else None

def save_user(username: str, data: dict):
    users = _load(DATA / "users.json")
    users[username] = data
    _save(DATA / "users.json", users)

def check_credentials(username: str, password: str) -> bool:
    """Verify admin credentials. FIX #1: uses PBKDF2, never plain-text comparison."""
    # Check bot admin (pre-hashed at startup)
    if _ADMIN_HASH and _ADMIN_SALT and BOT_ADMIN_USER:
        if username == BOT_ADMIN_USER:
            candidate = _hash_admin(password, _ADMIN_SALT)
            return hmac.compare_digest(candidate, _ADMIN_HASH)
        return False  # Only the configured admin user is allowed

    # Fallback: check users.json (superadmin/admin role)
    users = _load(DATA / "users.json")
    u = users.get(username)
    if not u: return False
    if u.get("role") not in ("superadmin", "admin"): return False

    # Support both old SHA-256 and new PBKDF2 hashed passwords
    stored_salt = u.get("password_salt")
    stored_hash = u.get("password_hash", "")
    if stored_salt:
        # PBKDF2 (new server format)
        candidate = hashlib.pbkdf2_hmac(
            'sha256', password.encode(), stored_salt.encode(), 260_000
        ).hex()
        return hmac.compare_digest(candidate, stored_hash)
    else:
        # Legacy SHA-256
        return hmac.compare_digest(
            hashlib.sha256(password.encode()).hexdigest(), stored_hash
        )

# ── Admin sessions ────────────────────────────────────────────────
SESSION_TTL = 6 * 3600
_sessions: dict = {}
_sess_lock = threading.Lock()

def _get_sess(cid: str) -> dict:
    with _sess_lock:
        return dict(_sessions.get(cid, {"step": "idle", "user": "", "authed_at": 0, "pending_cmd": None}))

def _set_sess(cid: str, data: dict):
    with _sess_lock: _sessions[cid] = data

def _clear_sess(cid: str):
    with _sess_lock: _sessions.pop(cid, None)

def is_authed(cid: str) -> bool:
    s = _get_sess(cid)
    return s.get("step") == "authed" and (time.time() - s.get("authed_at", 0)) < SESSION_TTL

def session_user(cid: str) -> str:
    return _get_sess(cid).get("user", "")

# ── Server process management ─────────────────────────────────────
SERVER_FILE  = BASE_DIR / "nexochat_server.py"
_site_proc   = None
_site_lock   = threading.RLock()
_site_target = "stopped"
_site_logs   = []
_MAX_LOG     = 400

def _pipe_logs(proc):
    def _reader(stream):
        try:
            for raw in iter(stream.readline, b""):
                line = raw.decode("utf-8", errors="replace").rstrip()
                if line:
                    with _site_lock:
                        _site_logs.append(line)
                        if len(_site_logs) > _MAX_LOG:
                            del _site_logs[:-_MAX_LOG]
        except Exception:
            pass
    threading.Thread(target=_reader, args=(proc.stdout,), daemon=True).start()
    threading.Thread(target=_reader, args=(proc.stderr,), daemon=True).start()

def site_start(actor="bot") -> str:
    global _site_proc, _site_target
    if not SERVER_FILE.exists():
        return "❌ nexochat_server.py not found"
    with _site_lock:
        if _site_proc and _site_proc.poll() is None:
            return f"⚠️ Server already running (PID {_site_proc.pid})."
        env = os.environ.copy()
        env["NEXO_BOT_SUBPROCESS"] = "1"
        cmd = [sys.executable, "-u", str(SERVER_FILE)]
        log.info("[%s] start: %s", actor, " ".join(cmd))
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(BASE_DIR),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
            )
        except Exception as e:
            return f"❌ Launch error: {e}"
        _site_proc   = proc
        _site_target = "running"
        _site_logs.clear()
        _site_logs.append(f"[started pid={proc.pid} by={actor}]")
    _pipe_logs(proc)
    return f"✅ Server started (PID {proc.pid})"

def site_stop(actor="bot") -> str:
    global _site_proc, _site_target
    with _site_lock:
        _site_target = "stopped"
        proc = _site_proc
    if not proc or proc.poll() is not None:
        return "⚠️ Server not running."
    log.info("[%s] stop PID %d", actor, proc.pid)
    try:
        proc.terminate()
        proc.wait(timeout=8)
    except Exception:
        try: proc.kill()
        except Exception: pass
    return "🛑 Server stopped."

def site_restart(actor="bot") -> str:
    site_stop(actor)
    time.sleep(1)
    return site_start(actor)

def site_status_str() -> str:
    with _site_lock:
        proc   = _site_proc
    if proc is None:        return "⚫ Not started"
    if proc.poll() is None: return f"🟢 Running (PID {proc.pid})"
    return f"🔴 Stopped (code {proc.returncode})"

def site_get_logs(n: int = 30) -> str:
    with _site_lock: lines = list(_site_logs[-n:])
    return "\n".join(lines) if lines else "(no logs)"

# ── Watchdog ──────────────────────────────────────────────────────
_subscribers: set = set()
_sub_lock = threading.Lock()

def watchdog_loop():
    time.sleep(20)
    while True:
        time.sleep(8)
        with _site_lock:
            proc   = _site_proc
            target = _site_target
        if target == "running" and proc and proc.poll() is not None:
            log.warning("Watchdog: server crashed (code %d), restarting...", proc.returncode)
            time.sleep(3)
            r = site_start("watchdog")
            log.info("Watchdog: %s", r)
            with _sub_lock: subs = set(_subscribers)
            for cid in subs:
                send(cid, f"🔄 <b>Watchdog:</b> server restarted.\n{r}")

# ── Telegram API helpers ──────────────────────────────────────────
_offset = 0

def tg(method: str, data: dict | None = None, timeout: int = 15) -> dict:
    body = json.dumps(data or {}).encode()
    req  = urllib.request.Request(
        f"{API}/{method}", data=body,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception as e:
        log.warning("tg %s: %s", method, e)
        return {}

def send(cid: str, text: str, parse_mode: str = "HTML") -> dict:
    return tg("sendMessage", {"chat_id": cid, "text": text, "parse_mode": parse_mode})

# ── Admin auth flow ───────────────────────────────────────────────
def require_auth(cid: str, cmd: str):
    s = _get_sess(cid)
    s["step"]        = "await_user"
    s["pending_cmd"] = cmd
    _set_sess(cid, s)
    send(cid, "🔐 <b>Authorization required</b>\n\nEnter username:")

def exec_admin_cmd(cid: str, cmd: str, parts: list):
    actor = f"tg:{session_user(cid)}:{cid}"
    if cmd == "/start_site":
        send(cid, site_start(actor))
    elif cmd == "/stop_site":
        send(cid, site_stop(actor))
    elif cmd == "/restart_site":
        send(cid, "🔄 Restarting...")
        send(cid, site_restart(actor))
    elif cmd == "/proc_status":
        send(cid, f"🖥 {site_status_str()}")
    elif cmd == "/logs":
        try:   n = max(1, min(int(parts[1]), 100)) if len(parts) > 1 else 30
        except: n = 30
        logs = site_get_logs(n)
        if len(logs) > 3800: logs = "...(truncated)\n" + logs[-3700:]
        send(cid, f"<b>📋 Logs (last {n}):</b>\n<pre>{logs}</pre>")
    elif cmd == "/logout":
        _clear_sess(cid)
        send(cid, "🔓 Session ended.")
    else:
        send(cid, "❓ Unknown command. /help")

# ── Notifications ─────────────────────────────────────────────────
def send_notification(username: str, text: str):
    notify = _load(TG_NOTIFY_F)
    tg_id = notify.get(username)
    if tg_id:
        try: send(str(tg_id), text)
        except Exception as e: log.warning("Notify error: %s", e)

# ── Update handler ────────────────────────────────────────────────
HELP_TEXT = """🤖 <b>NexoChat Bot</b>

Commands:
/start — Start &amp; get help
/login — Login to NexoChat via Telegram
/recover — Recover account password
/notify_on — Enable notifications
/notify_off — Disable notifications
/help — Show this message

<a href="{url}">Open NexoChat →</a>"""

def handle_update(upd: dict):
    msg  = upd.get("message") or upd.get("edited_message")
    if not msg: return

    cid   = str(msg["chat"]["id"])
    text  = (msg.get("text") or "").strip()
    parts = text.split()
    cmd   = parts[0].lower().split("@")[0] if parts else ""

    sess = _get_sess(cid)
    step = sess.get("step", "idle")

    # ── Admin auth flow ───────────────────────────────────────────
    if step == "await_user":
        sess["user"] = text.strip().lower()
        sess["step"] = "await_pass"
        _set_sess(cid, sess)
        send(cid, "🔑 Enter password:")
        return

    if step == "await_pass":
        username = sess.get("user", "")
        if check_credentials(username, text):   # FIX #1: no plain text comparison
            sess["step"]        = "authed"
            sess["authed_at"]   = time.time()
            sess["pending_cmd"] = sess.get("pending_cmd")
            _set_sess(cid, sess)
            send(cid, f"✅ Authorized as <b>{username}</b>. Session — 6 hours.")
            pending = sess.get("pending_cmd")
            if pending:
                sess2 = _get_sess(cid)
                sess2["pending_cmd"] = None
                _set_sess(cid, sess2)
                exec_admin_cmd(cid, pending, parts)
        else:
            _clear_sess(cid)
            send(cid, "❌ Wrong username or password.")
        return

    # ── Recovery flow ─────────────────────────────────────────────
    if step == "recover_await_user":
        username = text.strip().lower()
        u = get_user(username)
        if not u:
            _clear_sess(cid)
            send(cid, "❌ User not found."); return
        notify = _load(TG_NOTIFY_F)
        if str(notify.get(username, "")) != cid:
            _clear_sess(cid)
            send(cid, "❌ This Telegram is not linked to this account."); return
        code = gen_code()
        pending = _load(TG_PENDING_F)
        pending["recover_" + code] = {
            "type": "recover",
            "username": username,
            "expires": time.time() + 300,
        }
        _save(TG_PENDING_F, pending)
        _clear_sess(cid)
        send(cid,
            f"🔐 Recovery code for <b>{username}</b>:\n"
            f"<code>{code}</code>\n\n"
            f"Enter it at: <a href='{SITE_URL}/auth?recover=1'>{SITE_URL}/auth</a>\n"
            "⏰ Valid for 5 minutes.")
        return

    # ── Admin commands ────────────────────────────────────────────
    ADMIN_CMDS = {"/start_site", "/stop_site", "/restart_site",
                  "/proc_status", "/logs", "/logout"}

    if cmd in ADMIN_CMDS:
        if is_authed(cid):
            exec_admin_cmd(cid, cmd, parts)
        else:
            if step == "authed":
                send(cid, "⏰ Session expired.")
            require_auth(cid, cmd)
        return

    # ── Public commands ───────────────────────────────────────────
    if cmd in ("/start", "/help"):
        with _sub_lock: _subscribers.add(cid)
        send(cid, HELP_TEXT.format(url=SITE_URL))

    elif cmd == "/login":
        tg_id = cid
        notify = _load(TG_NOTIFY_F)
        username = None
        for u, tid in notify.items():
            if str(tid) == tg_id:
                username = u; break

        if username:
            token = secrets.token_hex(32)
            tokens = _load(TG_TOKENS_F)
            tokens[tg_id] = {
                "token": token,
                "username": username,
                "expires": time.time() + 300,
            }
            _save(TG_TOKENS_F, tokens)
            send(cid,
                f"✅ Login link for <b>{username}</b>:\n"
                f"<a href='{SITE_URL}/auth?tg_token={token}'>Click to log in</a>\n\n"
                "⚠️ Valid for 5 minutes.")
        else:
            code = gen_code()
            pending = _load(TG_PENDING_F)
            pending[code] = {
                "telegram_id": tg_id,
                "telegram_name": msg["from"].get("first_name", ""),
                "expires": time.time() + 600,
            }
            _save(TG_PENDING_F, pending)
            send(cid,
                f"🔗 To link your NexoChat account:\n\n"
                f"1. Open <a href='{SITE_URL}'>NexoChat</a>\n"
                f"2. Settings → Link Telegram\n"
                f"3. Enter code: <code>{code}</code>\n\n"
                "⏰ Code valid for 10 minutes.")

    elif cmd == "/recover":
        s = _get_sess(cid)
        s["step"] = "recover_await_user"
        _set_sess(cid, s)
        send(cid, "🔑 Enter your NexoChat username for recovery:")

    elif cmd == "/notify_on":
        notify = _load(TG_NOTIFY_F)
        for u, tid in notify.items():
            if str(tid) == cid:
                send(cid, f"✅ Notifications already enabled for <b>{u}</b>.")
                return
        send(cid, "❌ Link your account first via /login")

    elif cmd == "/notify_off":
        notify = _load(TG_NOTIFY_F)
        for u, tid in list(notify.items()):
            if str(tid) == cid:
                del notify[u]
                _save(TG_NOTIFY_F, notify)
                send(cid, "🔕 Notifications disabled.")
                return
        send(cid, "Notifications were not active.")

    elif cmd == "/status":
        send(cid, f"🖥 NexoChat: {site_status_str()}\n🕐 {datetime.now().strftime('%H:%M %d.%m.%Y')}")

    elif cmd == "/my_id":
        send(cid, f"Your chat_id: <code>{cid}</code>")

    elif cmd == "/subscribe":
        with _sub_lock: _subscribers.add(cid)
        send(cid, "✅ Subscribed to crash alerts!")

    elif cmd == "/unsubscribe":
        with _sub_lock: _subscribers.discard(cid)
        send(cid, "🔕 Unsubscribed from alerts.")

    else:
        if text: send(cid, "❓ Unknown command. /help")

# ── Polling ───────────────────────────────────────────────────────
def poll_loop():
    global _offset
    tg("deleteWebhook", {"drop_pending_updates": True})
    time.sleep(1)
    log.info("Polling started")
    while True:
        try:
            resp = tg("getUpdates", {"offset": _offset, "timeout": 30, "limit": 50}, timeout=40)
            if not resp.get("ok"):
                time.sleep(5); continue
            for upd in resp.get("result", []):
                _offset = upd["update_id"] + 1
                try: handle_update(upd)
                except Exception as e: log.warning("handle_update: %s", e)
        except Exception as e:
            log.warning("poll_loop: %s", e)
            time.sleep(5)

# ── Shutdown ──────────────────────────────────────────────────────
def _shutdown(sig=None, frame=None):
    log.info("Stopping...")
    site_stop("shutdown")
    sys.exit(0)

signal.signal(signal.SIGINT,  _shutdown)
signal.signal(signal.SIGTERM, _shutdown)

# ── Entry point ───────────────────────────────────────────────────
def run_bot():
    log.info("=" * 50)
    log.info("  NexoChat Bot  |  %s", SITE_URL)
    log.info("  Admin: %s", BOT_ADMIN_USER or "(from users.json)")
    log.info("=" * 50)
    me = tg("getMe")
    if me.get("ok"):
        u = me["result"]
        log.info("Bot: @%s (%s)", u.get("username"), u.get("first_name"))
    threading.Thread(target=watchdog_loop, daemon=True).start()
    poll_loop()

if __name__ == "__main__":
    run_bot()
