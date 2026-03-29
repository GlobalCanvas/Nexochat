#!/usr/bin/env python3
"""
NexoChat Telegram Bot
- Login via Telegram (/login)
- Password recovery (/recover)  
- Notifications (/notify_on, /notify_off)
- Admin: /start_site /stop_site /restart_site /proc_status /logs
"""

import os, sys, time, json, signal, logging, threading, subprocess, hashlib, secrets
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

def gen_code():
    return secrets.token_hex(4).upper()

def _hash(pw): return hashlib.sha256(pw.encode()).hexdigest()

def get_user(username):
    u = _load(DATA / "users.json").get(username)
    return dict(u) if u else None

def save_user(username, data):
    users = _load(DATA / "users.json")
    users[username] = data
    _save(DATA / "users.json", users)

# ── Config ────────────────────────────────────────────────────────
BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
SITE_URL  = os.environ.get("NEXO_URL", "https://nexochat.bothost.tech/")

if not BOT_TOKEN:
    log.error("BOT_TOKEN не знайдено!")
    sys.exit(1)

API = f"https://api.telegram.org/bot{BOT_TOKEN}"

# ── Admin credentials ─────────────────────────────────────────────
BOT_ADMIN_USER = os.environ.get("BOT_ADMIN_USER", "puwe")
BOT_ADMIN_PASS = os.environ.get("BOT_ADMIN_PASS", "93059306")

def check_credentials(username, password):
    if BOT_ADMIN_USER and BOT_ADMIN_PASS:
        return username == BOT_ADMIN_USER and password == BOT_ADMIN_PASS
    users = _load(DATA / "users.json")
    u = users.get(username)
    if not u: return False
    if u.get("role") not in ("superadmin", "admin"): return False
    return u.get("password_hash") == _hash(password)

# ── Сесії адміна ──────────────────────────────────────────────────
SESSION_TTL = 6 * 3600
_sessions = {}
_sess_lock = threading.Lock()

def _get_sess(cid):
    with _sess_lock:
        return dict(_sessions.get(cid, {"step": "idle", "user": "", "authed_at": 0, "pending_cmd": None}))

def _set_sess(cid, data):
    with _sess_lock: _sessions[cid] = data

def _clear_sess(cid):
    with _sess_lock: _sessions.pop(cid, None)

def is_authed(cid):
    s = _get_sess(cid)
    return s.get("step") == "authed" and (time.time() - s.get("authed_at", 0)) < SESSION_TTL

def session_user(cid):
    return _get_sess(cid).get("user", "")

# ── Процес сервера ────────────────────────────────────────────────
SERVER_FILE  = BASE_DIR / "nexochat_server.py"
_site_proc   = None
_site_lock   = threading.RLock()
_site_target = "stopped"
_site_logs   = []
_MAX_LOG     = 400

def _pipe_logs(proc):
    def _r(s):
        try:
            for raw in iter(s.readline, b""):
                line = raw.decode("utf-8", errors="replace").rstrip()
                if line:
                    with _site_lock:
                        _site_logs.append(line)
                        if len(_site_logs) > _MAX_LOG:
                            del _site_logs[:-_MAX_LOG]
        except Exception: pass
    threading.Thread(target=_r, args=(proc.stdout,), daemon=True).start()
    threading.Thread(target=_r, args=(proc.stderr,), daemon=True).start()

def site_start(actor="bot"):
    global _site_proc, _site_target
    if not SERVER_FILE.exists():
        return "❌ nexochat_server.py не знайдено"
    with _site_lock:
        if _site_proc and _site_proc.poll() is None:
            return f"⚠️ Сервер вже запущено (PID {_site_proc.pid})."
        env = os.environ.copy()
        env["NEXO_BOT_SUBPROCESS"] = "1"  # щоб сервер не запускав бота
        cmd = [sys.executable, "-u", str(SERVER_FILE)]
        log.info("[%s] start: %s", actor, " ".join(cmd))
        try:
            proc = subprocess.Popen(cmd, cwd=str(BASE_DIR),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        except Exception as e:
            return f"❌ Помилка запуску: {e}"
        _site_proc   = proc
        _site_target = "running"
        _site_logs.clear()
        _site_logs.append(f"[started pid={proc.pid} by={actor}]")
    _pipe_logs(proc)
    return f"✅ Сервер запущено (PID {proc.pid})"

def site_stop(actor="bot"):
    global _site_proc, _site_target
    with _site_lock:
        _site_target = "stopped"
        proc = _site_proc
    if not proc or proc.poll() is not None:
        return "⚠️ Сервер не запущено."
    log.info("[%s] stop PID %d", actor, proc.pid)
    try:
        proc.terminate(); proc.wait(timeout=8)
    except Exception:
        try: proc.kill()
        except Exception: pass
    return "🛑 Сервер зупинено."

def site_restart(actor="bot"):
    site_stop(actor); time.sleep(1); return site_start(actor)

def site_status_str():
    with _site_lock:
        proc   = _site_proc
        target = _site_target
    if proc is None:        return "⚫ Не запущено"
    if proc.poll() is None: return f"🟢 Запущено (PID {proc.pid})"
    return f"🔴 Зупинено (код {proc.returncode})"

def site_get_logs(n=30):
    with _site_lock: lines = list(_site_logs[-n:])
    return "\n".join(lines) if lines else "(логів немає)"

# ── Watchdog ──────────────────────────────────────────────────────
_subscribers = set()
_sub_lock = threading.Lock()

def watchdog_loop():
    time.sleep(20)
    while True:
        time.sleep(8)
        with _site_lock:
            proc   = _site_proc
            target = _site_target
        if target == "running" and proc and proc.poll() is not None:
            log.warning("Watchdog: сервер впав (код %d), рестарт...", proc.returncode)
            time.sleep(3)
            r = site_start("watchdog")
            log.info("Watchdog: %s", r)
            with _sub_lock: subs = set(_subscribers)
            for cid in subs:
                send(cid, f"🔄 <b>Watchdog:</b> сервер перезапущено.\n{r}")

# ── Telegram helpers ──────────────────────────────────────────────
_offset = 0

def tg(method, data=None, timeout=15):
    body = json.dumps(data or {}).encode()
    req  = urllib.request.Request(f"{API}/{method}", data=body,
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception as e:
        log.warning("tg %s: %s", method, e); return {}

def send(cid, text, parse_mode="HTML"):
    return tg("sendMessage", {"chat_id": cid, "text": text, "parse_mode": parse_mode})

# ── Admin auth flow ───────────────────────────────────────────────
def require_auth(cid, cmd):
    s = _get_sess(cid)
    s["step"]        = "await_user"
    s["pending_cmd"] = cmd
    _set_sess(cid, s)
    send(cid, "🔐 <b>Потрібна авторизація</b>\n\nВведи логін:")

def exec_admin_cmd(cid, cmd, parts):
    actor = f"tg:{session_user(cid)}:{cid}"
    if cmd == "/start_site":
        send(cid, site_start(actor))
    elif cmd == "/stop_site":
        send(cid, site_stop(actor))
    elif cmd == "/restart_site":
        send(cid, "🔄 Рестарт...")
        send(cid, site_restart(actor))
    elif cmd == "/proc_status":
        send(cid, f"🖥 {site_status_str()}")
    elif cmd == "/logs":
        try:   n = max(1, min(int(parts[1]), 100)) if len(parts) > 1 else 30
        except: n = 30
        logs = site_get_logs(n)
        if len(logs) > 3800: logs = "...(обрізано)\n" + logs[-3700:]
        send(cid, f"<b>📋 Логи (останні {n}):</b>\n<pre>{logs}</pre>")
    elif cmd == "/logout":
        _clear_sess(cid)
        send(cid, "🔓 Сесію завершено.")
    else:
        send(cid, "❓ Невідома команда. /help")

# ── Notifications ─────────────────────────────────────────────────
def send_notification(username, text):
    notify = _load(TG_NOTIFY_F)
    tg_id = notify.get(username)
    if tg_id:
        try: send(str(tg_id), text)
        except Exception as e: log.warning("Notify error: %s", e)

# ── Handle updates ────────────────────────────────────────────────
HELP_TEXT = """🤖 <b>NexoChat Bot</b>

Commands:
/start — Start & get help
/login — Login to NexoChat via Telegram
/recover — Recover your account password
/notify_on — Enable notifications
/notify_off — Disable notifications
/help — Show this message

<a href="{url}">Open NexoChat →</a>"""

def handle_update(upd):
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
        sess["user"] = text
        sess["step"] = "await_pass"
        _set_sess(cid, sess)
        send(cid, "🔑 Введи пароль:")
        return

    if step == "await_pass":
        username = sess.get("user", "")
        if check_credentials(username, text):
            sess["step"]      = "authed"
            sess["authed_at"] = time.time()
            _set_sess(cid, sess)
            pending = sess.get("pending_cmd")
            send(cid, f"✅ Авторизовано як <b>{username}</b>. Сесія — 6 годин.")
            if pending:
                sess["pending_cmd"] = None
                _set_sess(cid, sess)
                exec_admin_cmd(cid, pending, parts)
        else:
            _clear_sess(cid)
            send(cid, "❌ Невірний логін або пароль.")
        return

    # ── Recovery flow (step: recover_await_user) ──────────────────
    if step == "recover_await_user":
        username = text.strip().lower()
        u = get_user(username)
        if not u:
            _clear_sess(cid)
            send(cid, "❌ Користувача не знайдено."); return
        notify = _load(TG_NOTIFY_F)
        if str(notify.get(username, "")) != cid:
            _clear_sess(cid)
            send(cid, "❌ Цей Telegram не прив'язаний до цього акаунту."); return
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
            f"🔐 Код відновлення для <b>{username}</b>:\n"
            f"<code>{code}</code>\n\n"
            f"Введи його на: <a href='{SITE_URL}/auth?recover=1'>{SITE_URL}/auth</a>\n"
            "⏰ Діє 5 хвилин.")
        return

    # ── Admin commands ────────────────────────────────────────────
    ADMIN_CMDS = {"/start_site", "/stop_site", "/restart_site",
                  "/proc_status", "/logs", "/logout"}

    if cmd in ADMIN_CMDS:
        if is_authed(cid):
            exec_admin_cmd(cid, cmd, parts)
        else:
            if step == "authed":
                send(cid, "⏰ Сесія закінчилась.")
            require_auth(cid, cmd)
        return

    # ── Public commands ───────────────────────────────────────────
    if cmd in ("/start", "/help"):
        with _sub_lock: _subscribers.add(cid)
        send(cid, HELP_TEXT.format(url=SITE_URL))

    elif cmd == "/login":
        tg_id = cid
        notify = _load(TG_NOTIFY_F)
        # Шукаємо чи прив'язаний цей tg_id до акаунту
        username = None
        for u, tid in notify.items():
            if str(tid) == tg_id:
                username = u; break

        if username:
            # Вже прив'язаний — генеруємо токен входу
            token = secrets.token_hex(32)
            tokens = _load(TG_TOKENS_F)
            tokens[tg_id] = {
                "token": token,
                "username": username,
                "expires": time.time() + 300,
            }
            _save(TG_TOKENS_F, tokens)
            send(cid,
                f"✅ Посилання для входу як <b>{username}</b>:\n"
                f"<a href='{SITE_URL}/auth?tg_token={token}'>Натисни щоб увійти</a>\n\n"
                "⚠️ Діє 5 хвилин.")
        else:
            # Не прив'язаний — генеруємо код прив'язки
            code = gen_code()
            pending = _load(TG_PENDING_F)
            pending[code] = {
                "telegram_id": tg_id,
                "telegram_name": msg["from"].get("first_name", ""),
                "expires": time.time() + 600,
            }
            _save(TG_PENDING_F, pending)
            send(cid,
                f"🔗 Щоб прив'язати акаунт NexoChat:\n\n"
                f"1. Відкрий <a href='{SITE_URL}'>NexoChat</a>\n"
                f"2. Налаштування → Прив'язати Telegram\n"
                f"3. Введи код: <code>{code}</code>\n\n"
                "⏰ Код дійсний 10 хвилин.")

    elif cmd == "/recover":
        s = _get_sess(cid)
        s["step"] = "recover_await_user"
        _set_sess(cid, s)
        send(cid, "🔑 Введи свій нікнейм NexoChat для відновлення:")

    elif cmd == "/notify_on":
        notify = _load(TG_NOTIFY_F)
        for u, tid in notify.items():
            if str(tid) == cid:
                send(cid, f"✅ Сповіщення вже увімкнені для <b>{u}</b>.")
                return
        send(cid, "❌ Спочатку прив'яжи акаунт через /login")

    elif cmd == "/notify_off":
        notify = _load(TG_NOTIFY_F)
        for u, tid in list(notify.items()):
            if str(tid) == cid:
                del notify[u]
                _save(TG_NOTIFY_F, notify)
                send(cid, "🔕 Сповіщення вимкнено.")
                return
        send(cid, "Сповіщення не були активні.")

    elif cmd == "/status":
        send(cid, f"🖥 NexoChat: {site_status_str()}\n🕐 {datetime.now().strftime('%H:%M %d.%m.%Y')}")

    elif cmd == "/my_id":
        send(cid, f"Твій chat_id: <code>{cid}</code>")

    elif cmd == "/subscribe":
        with _sub_lock: _subscribers.add(cid)
        send(cid, "✅ Підписаний на алерти про падіння!")

    elif cmd == "/unsubscribe":
        with _sub_lock: _subscribers.discard(cid)
        send(cid, "🔕 Відписаний від алертів.")

    else:
        if text: send(cid, "❓ Не розумію. /help")

# ── Polling ───────────────────────────────────────────────────────
def poll_loop():
    global _offset
    tg("deleteWebhook", {"drop_pending_updates": True})
    time.sleep(1)
    log.info("Polling запущено")
    while True:
        try:
            resp = tg("getUpdates", {"offset": _offset, "timeout": 30, "limit": 50}, timeout=40)
            if not resp.get("ok"): time.sleep(5); continue
            for upd in resp.get("result", []):
                _offset = upd["update_id"] + 1
                try: handle_update(upd)
                except Exception as e: log.warning("handle_update: %s", e)
        except Exception as e:
            log.warning("poll_loop: %s", e); time.sleep(5)

# ── Shutdown ──────────────────────────────────────────────────────
def _shutdown(sig=None, frame=None):
    log.info("Зупинка...")
    site_stop("shutdown")
    sys.exit(0)

signal.signal(signal.SIGINT,  _shutdown)
signal.signal(signal.SIGTERM, _shutdown)

# ── Entry point ───────────────────────────────────────────────────
def run_bot():
    log.info("=" * 50)
    log.info("  NexoChat Bot  |  %s", SITE_URL)
    log.info("  Admin: %s", BOT_ADMIN_USER)
    log.info("=" * 50)
    me = tg("getMe")
    if me.get("ok"):
        u = me["result"]
        log.info("Бот: @%s (%s)", u.get("username"), u.get("first_name"))
    threading.Thread(target=watchdog_loop, daemon=True).start()
    poll_loop()

if __name__ == "__main__":
    # Запускаємо сервер як subprocess, потім бот
    log.info("Запускаю nexochat_server.py...")
    log.info(site_start("autostart"))
    run_bot()
