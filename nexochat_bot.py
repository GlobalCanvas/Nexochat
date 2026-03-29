#!/usr/bin/env python3
"""
NexoChat Telegram Bot
- Login via Telegram
- Notifications
- Password recovery
"""

import os, sys, json, time, hashlib, secrets, threading
from pathlib import Path

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    import telebot
    HAS_TELEBOT = True
except ImportError:
    print("[NexoBot] python-telegram-bot not installed. Run: pip install pyTelegramBotAPI")
    HAS_TELEBOT = False

BASE = Path(__file__).parent
DATA = BASE / "data"
DATA.mkdir(exist_ok=True)

TG_TOKENS_F = DATA / "tg_tokens.json"  # {telegram_id: {token, expires, username}}
TG_PENDING_F = DATA / "tg_pending.json"  # {code: {telegram_id, expires}}
TG_NOTIFY_F  = DATA / "tg_notify.json"  # {username: telegram_id}

FILE_LOCK = threading.RLock()

def _load(path):
    p = Path(path)
    if not p.exists(): return {}
    with FILE_LOCK:
        try: return json.loads(p.read_text())
        except: return {}

def _save(path, data):
    with FILE_LOCK:
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2))

def gen_code():
    return secrets.token_hex(4).upper()

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def get_user(username):
    users_f = DATA / "users.json"
    u = _load(users_f).get(username)
    return dict(u) if u else None

def save_user(username, data):
    users_f = DATA / "users.json"
    users = _load(users_f)
    users[username] = data
    _save(users_f, users)

def create_session(username):
    from nexochat_server import create_session as cs
    return cs(username)

BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
SITE_URL = os.environ.get("NEXO_URL", "http://localhost:8080")

HELP_TEXT = """
🤖 <b>NexoChat Bot</b>

Commands:
/start — Start & get help
/login — Login to NexoChat via Telegram
/recover — Recover your account password
/notify_on — Enable notifications
/notify_off — Disable notifications
/help — Show this message

<a href="{url}">Open NexoChat →</a>
""".format(url=SITE_URL)

if HAS_TELEBOT and BOT_TOKEN:
    bot = telebot.TeleBot(BOT_TOKEN, parse_mode='HTML')

    @bot.message_handler(commands=['start', 'help'])
    def cmd_start(msg):
        bot.reply_to(msg, HELP_TEXT)

    @bot.message_handler(commands=['login'])
    def cmd_login(msg):
        tg_id = str(msg.from_user.id)
        # Check if this tg_id is linked to any account
        notify = _load(TG_NOTIFY_F)
        # Reverse lookup
        username = None
        for u, tid in notify.items():
            if str(tid) == tg_id:
                username = u; break

        if username:
            # Already linked — generate session token
            token = secrets.token_hex(32)
            tokens = _load(TG_TOKENS_F)
            tokens[tg_id] = {
                "token": token,
                "username": username,
                "expires": time.time() + 300,  # 5 min
            }
            _save(TG_TOKENS_F, tokens)
            bot.reply_to(msg,
                f"✅ Login link for <b>{username}</b>:\n"
                f"<a href='{SITE_URL}/auth?tg_token={token}'>Click to login</a>\n\n"
                "⚠️ Link expires in 5 minutes."
            )
        else:
            # Generate linking code
            code = gen_code()
            pending = _load(TG_PENDING_F)
            pending[code] = {
                "telegram_id": tg_id,
                "telegram_name": msg.from_user.first_name,
                "expires": time.time() + 600,
            }
            _save(TG_PENDING_F, pending)
            bot.reply_to(msg,
                f"🔗 To link your NexoChat account:\n\n"
                f"1. Open <a href='{SITE_URL}'>NexoChat</a>\n"
                f"2. Go to Settings → Link Telegram\n"
                f"3. Enter code: <code>{code}</code>\n\n"
                f"⏰ Code expires in 10 minutes."
            )

    @bot.message_handler(commands=['recover'])
    def cmd_recover(msg):
        bot.reply_to(msg, "Enter your NexoChat username to recover:")
        bot.register_next_step_handler(msg, recover_step2)

    def recover_step2(msg):
        username = msg.text.strip().lower()
        u = get_user(username)
        if not u:
            bot.reply_to(msg, "❌ User not found."); return
        tg_id = str(msg.from_user.id)
        notify = _load(TG_NOTIFY_F)
        if str(notify.get(username, "")) != tg_id:
            bot.reply_to(msg, "❌ This Telegram is not linked to that account."); return
        # Generate recovery code
        code = gen_code()
        pending = _load(TG_PENDING_F)
        pending["recover_" + code] = {
            "type": "recover",
            "username": username,
            "expires": time.time() + 300,
        }
        _save(TG_PENDING_F, pending)
        bot.reply_to(msg,
            f"🔐 Recovery code for <b>{username}</b>:\n"
            f"<code>{code}</code>\n\n"
            f"Enter this at: <a href='{SITE_URL}/auth?recover=1'>{SITE_URL}/auth</a>\n"
            "⏰ Expires in 5 minutes."
        )

    @bot.message_handler(commands=['notify_on'])
    def cmd_notify_on(msg):
        tg_id = str(msg.from_user.id)
        notify = _load(TG_NOTIFY_F)
        # Check if linked
        for u, tid in notify.items():
            if str(tid) == tg_id:
                bot.reply_to(msg, f"✅ Notifications already enabled for {u}.")
                return
        bot.reply_to(msg, "❌ Link your account first with /login")

    @bot.message_handler(commands=['notify_off'])
    def cmd_notify_off(msg):
        tg_id = str(msg.from_user.id)
        notify = _load(TG_NOTIFY_F)
        for u, tid in list(notify.items()):
            if str(tid) == tg_id:
                del notify[u]
                _save(TG_NOTIFY_F, notify)
                bot.reply_to(msg, "🔕 Notifications disabled.")
                return
        bot.reply_to(msg, "No notifications were active.")

    def send_notification(username: str, text: str):
        """Call this from the main server to send TG notifications"""
        notify = _load(TG_NOTIFY_F)
        tg_id = notify.get(username)
        if tg_id and bot:
            try:
                bot.send_message(tg_id, text)
            except Exception as e:
                print(f"[NexoBot] Notify error: {e}")

    def run_bot():
        print(f"[NexoBot] Starting bot polling...")
        bot.infinity_polling(skip_pending=True)

    if __name__ == "__main__":
        run_bot()

else:
    def send_notification(username: str, text: str):
        pass

    if __name__ == "__main__":
        if not BOT_TOKEN:
            print("Set TG_BOT_TOKEN environment variable to use the Telegram bot.")
        elif not HAS_TELEBOT:
            print("Install pyTelegramBotAPI: pip install pyTelegramBotAPI")
