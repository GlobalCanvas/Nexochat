#!/usr/bin/env python3
"""
NexoChat — Modern secure web messenger (Python-only)
WebSocket + HTTP server with E2E encryption, groups, channels, roles
"""

import os, sys, json, hashlib, uuid, time, base64, re, hmac, secrets
import threading, asyncio, logging, mimetypes, struct
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, unquote
from http.server import HTTPServer, BaseHTTPRequestHandler
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
USERS_F   = DATA / "users.json"
CHATS_F   = DATA / "chats.json"
MSGS_F    = DATA / "messages.json"
SESSIONS_F= DATA / "sessions.json"
MUTES_F   = DATA / "mutes.json"
BANS_F    = DATA / "bans.json"

FILE_LOCK = threading.RLock()
WS_CLIENTS: dict = {}   # chat_id -> set of (ws, username)
WS_LOCK = threading.Lock()

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
def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def gen_token() -> str:
    return secrets.token_hex(32)

def gen_invite() -> str:
    return secrets.token_urlsafe(16)

def derive_room_key(room_id: str, server_secret: str) -> str:
    """Derive per-room key (simplified HKDF-like)"""
    return hmac.new(server_secret.encode(), room_id.encode(), hashlib.sha256).hexdigest()

SERVER_SECRET = os.environ.get("NEXO_SECRET", secrets.token_hex(32))

# ── Seed default data ─────────────────────────────────────────────
def seed():
    users = _load(USERS_F)
    if "admin" not in users:
        users["admin"] = {
            "uid": str(uuid.uuid4()),
            "username": "admin",
            "email": "admin@nexochat.local",
            "password_hash": hash_pw("admin123"),
            "display": "NexoChat",
            "bio": "System administrator",
            "avatar": "",
            "avatar_emoji": "🔑",
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
            "owner": "admin",
            "admins": {"admin": {"all": True}},
            "members": [],
            "invite_link": "nexochat",
            "private_invite": gen_invite(),
            "is_public": True,
            "created": time.time(),
            "pinned_message": None,
            "permissions": {
                "send_messages": True,
                "send_media": True,
                "add_members": False,
                "pin_messages": False,
                "change_info": False,
            }
        }
        chats["general"] = {
            "id": "general",
            "type": "group",
            "name": "General",
            "description": "Public group for everyone",
            "avatar_emoji": "👥",
            "avatar": "",
            "owner": "admin",
            "admins": {"admin": {"all": True}},
            "members": [],
            "invite_link": "general",
            "private_invite": gen_invite(),
            "is_public": True,
            "created": time.time(),
            "pinned_message": None,
            "permissions": {
                "send_messages": True,
                "send_media": True,
                "add_members": True,
                "pin_messages": False,
                "change_info": False,
            }
        }
        _save(CHATS_F, chats)

    msgs = _load(MSGS_F)
    if "nexochat" not in msgs:
        msgs["nexochat"] = [{
            "id": str(uuid.uuid4()),
            "author": "admin",
            "display": "NexoChat",
            "text": "Welcome to NexoChat! 🎉",
            "ts": ts(),
            "type": "text",
            "reactions": {},
            "pinned": True,
            "edited": False,
        }]
        msgs["general"] = [{
            "id": str(uuid.uuid4()),
            "author": "admin",
            "display": "NexoChat",
            "text": "Welcome to the General group! Feel free to chat here.",
            "ts": ts(),
            "type": "text",
            "reactions": {},
            "pinned": True,
            "edited": False,
        }]
        _save(MSGS_F, msgs)

# ── Sessions ──────────────────────────────────────────────────────
_sessions: dict = {}  # token -> {username, expires}

def create_session(username: str) -> str:
    token = gen_token()
    _sessions[token] = {
        "username": username,
        "expires": time.time() + 86400 * 30  # 30 days
    }
    return token

def get_session(token: str) -> str | None:
    if not token: return None
    s = _sessions.get(token)
    if not s: return None
    if time.time() > s["expires"]:
        del _sessions[token]
        return None
    return s["username"]

def delete_session(token: str):
    _sessions.pop(token, None)

# ── User helpers ──────────────────────────────────────────────────
def get_user(username: str) -> dict | None:
    u = _load(USERS_F).get(username)
    return dict(u) if u else None

def save_user(username: str, data: dict):
    users = _load(USERS_F)
    users[username] = data
    _save(USERS_F, users)

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
def get_messages(chat_id: str, limit=50, offset=0) -> list:
    msgs = _load(MSGS_F)
    room_msgs = msgs.get(chat_id, [])
    return room_msgs[-(limit + offset):][:limit] if offset == 0 else room_msgs[-(limit + offset):-offset]

def add_message(chat_id: str, msg: dict):
    msgs = _load(MSGS_F)
    if chat_id not in msgs: msgs[chat_id] = []
    msgs[chat_id].append(msg)
    # Keep last 10000 messages
    if len(msgs[chat_id]) > 10000:
        msgs[chat_id] = msgs[chat_id][-10000:]
    _save(MSGS_F, msgs)

# ── Moderation commands ───────────────────────────────────────────
def parse_duration(s: str) -> int | None:
    """Parse '10m', '2h', '1d' → seconds"""
    m = re.match(r'^(\d+)([smhd])$', s.lower())
    if not m: return None
    v, u = int(m.group(1)), m.group(2)
    return v * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[u]

def handle_command(chat_id: str, author: str, text: str) -> dict | None:
    """Process /mute /unmute /ban /unban /pin commands"""
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
        reason = " ".join(parts[3:]) if duration_str and len(parts) > 3 else " ".join(parts[2:]) if not duration_str else ""
        duration = parse_duration(duration_str) if duration_str else 3600
        mutes = _load(MUTES_F)
        if chat_id not in mutes: mutes[chat_id] = {}
        mutes[chat_id][target] = {"until": time.time() + duration, "reason": reason, "by": author}
        _save(MUTES_F, mutes)
        return {"ok": True, "action": "muted", "target": target, "duration": duration, "reason": reason}

    elif cmd == "/unmute" and len(parts) >= 2:
        target = parts[1].lstrip("@")
        mutes = _load(MUTES_F)
        mutes.get(chat_id, {}).pop(target, None)
        _save(MUTES_F, mutes)
        return {"ok": True, "action": "unmuted", "target": target}

    elif cmd == "/ban" and len(parts) >= 2:
        target = parts[1].lstrip("@")
        duration_str = parts[2] if len(parts) > 2 and re.match(r'^\d+[smhd]$', parts[2]) else None
        reason = " ".join(parts[3:]) if duration_str and len(parts) > 3 else " ".join(parts[2:]) if not duration_str else ""
        bans = _load(BANS_F)
        if chat_id not in bans: bans[chat_id] = {}
        if duration_str:
            dur = parse_duration(duration_str)
            bans[chat_id][target] = {"until": time.time() + dur, "permanent": False, "reason": reason, "by": author}
        else:
            bans[chat_id][target] = {"permanent": True, "reason": reason, "by": author}
        # Remove from members
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

# ── HTTP Handler ──────────────────────────────────────────────────
TRANSLATIONS = {
    "en": {
        "title": "NexoChat", "tagline": "Secure modern messenger",
        "login": "Login", "register": "Register", "email": "Email",
        "password": "Password", "username": "Username",
        "forgot": "Forgot password?", "or_tg": "or login via Telegram",
        "join": "Join", "send": "Send", "search": "Search",
        "members": "Members", "online": "online", "typing": "typing...",
        "pin": "Pinned", "mute": "Mute", "ban": "Ban", "kick": "Kick",
        "settings": "Settings", "logout": "Logout", "profile": "Profile",
        "write": "Write a message", "groups": "Groups", "channels": "Channels",
        "dms": "Direct Messages", "create_group": "Create Group",
        "create_channel": "Create Channel", "name": "Name",
        "description": "Description", "public": "Public", "private": "Private",
        "invite": "Invite Link", "save": "Save", "cancel": "Cancel",
        "reactions": "Reactions", "files": "Files", "voice": "Voice",
        "video": "Video", "photo": "Photo",
    },
    "uk": {
        "title": "NexoChat", "tagline": "Безпечний сучасний месенджер",
        "login": "Увійти", "register": "Реєстрація", "email": "Email",
        "password": "Пароль", "username": "Нікнейм",
        "forgot": "Забули пароль?", "or_tg": "або увійти через Telegram",
        "join": "Приєднатися", "send": "Надіслати", "search": "Пошук",
        "members": "Учасники", "online": "онлайн", "typing": "друкує...",
        "pin": "Закріпити", "mute": "Мут", "ban": "Бан", "kick": "Кік",
        "settings": "Налаштування", "logout": "Вийти", "profile": "Профіль",
        "write": "Написати повідомлення", "groups": "Групи", "channels": "Канали",
        "dms": "Особисті", "create_group": "Створити групу",
        "create_channel": "Створити канал", "name": "Назва",
        "description": "Опис", "public": "Публічна", "private": "Приватна",
        "invite": "Запрошення", "save": "Зберегти", "cancel": "Скасувати",
        "reactions": "Реакції", "files": "Файли", "voice": "Голос",
        "video": "Відео", "photo": "Фото",
    },
    "ru": {
        "title": "NexoChat", "tagline": "Безопасный современный мессенджер",
        "login": "Войти", "register": "Регистрация", "email": "Email",
        "password": "Пароль", "username": "Никнейм",
        "forgot": "Забыли пароль?", "or_tg": "или войти через Telegram",
        "join": "Вступить", "send": "Отправить", "search": "Поиск",
        "members": "Участники", "online": "онлайн", "typing": "печатает...",
        "pin": "Закрепить", "mute": "Мут", "ban": "Бан", "kick": "Кик",
        "settings": "Настройки", "logout": "Выйти", "profile": "Профиль",
        "write": "Написать сообщение", "groups": "Группы", "channels": "Каналы",
        "dms": "Личные", "create_group": "Создать группу",
        "create_channel": "Создать канал", "name": "Название",
        "description": "Описание", "public": "Публичная", "private": "Приватная",
        "invite": "Приглашение", "save": "Сохранить", "cancel": "Отмена",
        "reactions": "Реакции", "files": "Файлы", "voice": "Голос",
        "video": "Видео", "photo": "Фото",
    },
    "pl": {
        "title": "NexoChat", "tagline": "Bezpieczny nowoczesny komunikator",
        "login": "Zaloguj", "register": "Rejestracja", "email": "Email",
        "password": "Hasło", "username": "Nazwa użytkownika",
        "forgot": "Zapomniałeś hasła?", "or_tg": "lub zaloguj przez Telegram",
        "join": "Dołącz", "send": "Wyślij", "search": "Szukaj",
        "members": "Członkowie", "online": "online", "typing": "pisze...",
        "pin": "Przypnij", "mute": "Wycisz", "ban": "Zbanuj", "kick": "Wyrzuć",
        "settings": "Ustawienia", "logout": "Wyloguj", "profile": "Profil",
        "write": "Napisz wiadomość", "groups": "Grupy", "channels": "Kanały",
        "dms": "Wiadomości", "create_group": "Utwórz grupę",
        "create_channel": "Utwórz kanał", "name": "Nazwa",
        "description": "Opis", "public": "Publiczna", "private": "Prywatna",
        "invite": "Link zaproszenia", "save": "Zapisz", "cancel": "Anuluj",
        "reactions": "Reakcje", "files": "Pliki", "voice": "Głos",
        "video": "Wideo", "photo": "Zdjęcie",
    },
}

def t(key: str, lang: str = "en") -> str:
    return TRANSLATIONS.get(lang, TRANSLATIONS["en"]).get(key, key)

def get_token_from_request(handler) -> str:
    cookie = handler.headers.get("Cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("nexo_token="):
            return part[11:]
    return ""

def json_response(handler, data: dict | list, status=200):
    body = json.dumps(data, ensure_ascii=False).encode('utf-8')
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.end_headers()
    handler.wfile.write(body)

def html_response(handler, html: str, status=200):
    body = html.encode('utf-8')
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
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
    # form-urlencoded
    from urllib.parse import parse_qs
    parsed = parse_qs(raw.decode('utf-8', errors='replace'))
    return {k: v[0] for k, v in parsed.items()}

class NexoHandler(BaseHTTPRequestHandler):
    server_version = "NexoChat/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log.info(f"{self.address_string()} - {fmt % args}")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, Cookie")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        token = get_token_from_request(self)
        username = get_session(token)

        # Static files
        if path.startswith("/static/"):
            self._serve_static(path[8:])
            return

        # Avatar files
        if path.startswith("/avatars/"):
            fname = path[9:]
            fp = AVATARS / fname
            if fp.exists():
                self._serve_file(fp)
            else:
                self.send_response(404); self.end_headers()
            return

        # Upload files
        if path.startswith("/uploads/"):
            fname = path[9:]
            fp = UPLOADS / fname
            if fp.exists():
                self._serve_file(fp)
            else:
                self.send_response(404); self.end_headers()
            return

        # API routes
        if path.startswith("/api/"):
            self._handle_api_get(path, qs, username)
            return

        # WebSocket upgrade handled elsewhere
        if "Upgrade" in self.headers and self.headers["Upgrade"].lower() == "websocket":
            self._handle_ws_upgrade()
            return

        # Pages
        lang = qs.get("lang", ["en"])[0]
        if username:
            u = get_user(username)
            if u:
                lang = u.get("language", "en")

        if path == "/auth" or path == "/login":
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

        if path == "/" or path == "":
            html_response(self, build_main_page(u, lang))
            return

        # Profile page
        # Check if it's a username profile
        all_users = _load(USERS_F)
        slug = path.lstrip("/")
        if slug in all_users:
            html_response(self, build_profile_page(all_users[slug], u, lang))
            return

        # Chat preview / join
        chats = _load(CHATS_F)
        # Find by invite_link or private_invite
        found_chat = None
        for cid, chat in chats.items():
            if chat.get("invite_link") == slug or chat.get("private_invite") == slug:
                found_chat = chat
                break

        if found_chat:
            role = get_member_role(found_chat, username)
            if role != "none":
                html_response(self, build_main_page(u, lang, active_chat=found_chat["id"]))
            else:
                html_response(self, build_chat_preview(found_chat, u, lang))
            return

        html_response(self, build_main_page(u, lang))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        token = get_token_from_request(self)
        username = get_session(token)

        if path.startswith("/api/"):
            self._handle_api_post(path, username)
            return

        json_response(self, {"error": "Not found"}, 404)

    def _handle_api_get(self, path, qs, username):
        # Public endpoints
        if path == "/api/chat_preview":
            slug = qs.get("slug", [""])[0]
            chats = _load(CHATS_F)
            for cid, chat in chats.items():
                if chat.get("invite_link") == slug or chat.get("private_invite") == slug:
                    members_count = len(chat.get("members", [])) + 1  # +1 for owner
                    json_response(self, {
                        "id": cid,
                        "name": chat["name"],
                        "description": chat.get("description", ""),
                        "avatar_emoji": chat.get("avatar_emoji", "💬"),
                        "type": chat["type"],
                        "members_count": members_count,
                    })
                    return
            json_response(self, {"error": "Not found"}, 404)
            return

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
                    # Last message
                    msgs = get_messages(cid, limit=1)
                    last = msgs[-1] if msgs else None
                    result.append({
                        "id": cid,
                        "name": chat["name"],
                        "type": chat["type"],
                        "avatar_emoji": chat.get("avatar_emoji", "💬"),
                        "avatar": chat.get("avatar", ""),
                        "members_count": len(chat.get("members", [])) + 1,
                        "is_public": chat.get("is_public", True),
                        "invite_link": chat.get("invite_link"),
                        "last_message": last,
                        "role": role,
                    })
            # Sort by last message time
            json_response(self, result)

        elif path == "/api/messages":
            chat_id = qs.get("chat_id", [""])[0]
            limit = int(qs.get("limit", ["50"])[0])
            if not chat_id:
                json_response(self, {"error": "chat_id required"}, 400); return
            chat = get_chat(chat_id)
            if not chat:
                json_response(self, {"error": "Chat not found"}, 404); return
            role = get_member_role(chat, username)
            if role == "none":
                json_response(self, {"error": "Not a member"}, 403); return
            msgs = get_messages(chat_id, limit=limit)
            json_response(self, msgs)

        elif path == "/api/chat_info":
            chat_id = qs.get("chat_id", [""])[0]
            chat = get_chat(chat_id)
            if not chat:
                json_response(self, {"error": "Not found"}, 404); return
            role = get_member_role(chat, username)
            if role == "none":
                json_response(self, {"error": "Not a member"}, 403); return
            # Build members list with online status
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
            bans_count = len(_load(BANS_F).get(chat_id, {}))
            json_response(self, {
                "id": chat_id,
                "name": chat["name"],
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
                "bans_count": bans_count,
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
            result = []
            for cid, chat in chats.items():
                if not chat.get("is_public"): continue
                if q in chat["name"].lower() or q in chat.get("description", "").lower():
                    result.append({
                        "id": cid,
                        "name": chat["name"],
                        "type": chat["type"],
                        "avatar_emoji": chat.get("avatar_emoji", "💬"),
                        "members_count": len(chat.get("members", [])) + 1,
                        "description": chat.get("description", ""),
                    })
            json_response(self, result)

        elif path == "/api/dm_chats":
            chats = _load(CHATS_F)
            dms = []
            for cid, chat in chats.items():
                if chat.get("type") != "dm": continue
                if username not in chat.get("members", []) and chat.get("owner") != username: continue
                other = [m for m in chat.get("members", []) + [chat.get("owner")] if m != username]
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

        if path == "/api/auth/login":
            uname = body.get("username", "").strip().lower()
            pw = body.get("password", "")
            u = get_user(uname)
            if not u or u.get("password_hash") != hash_pw(pw):
                json_response(self, {"error": "Invalid credentials"}, 401); return
            token = create_session(uname)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"nexo_token={token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax")
            resp = json.dumps({"ok": True, "username": uname}).encode()
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        if path == "/api/auth/register":
            uname = re.sub(r'[^a-z0-9_]', '', body.get("username", "").strip().lower())
            pw = body.get("password", "")
            email = body.get("email", "").strip().lower()
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
            users[uname] = {
                "uid": str(uuid.uuid4()),
                "username": uname,
                "email": email,
                "password_hash": hash_pw(pw),
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
            self.send_header("Set-Cookie", f"nexo_token={token}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax")
            resp = json.dumps({"ok": True, "username": uname}).encode()
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

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
            self.send_header("Set-Cookie", "nexo_token=; Path=/; Max-Age=0")
            resp = json.dumps({"ok": True}).encode()
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        if not username:
            json_response(self, {"error": "Unauthorized"}, 401); return

        u = get_user(username)
        if not u:
            json_response(self, {"error": "Unauthorized"}, 401); return

        if path == "/api/messages/send":
            chat_id = body.get("chat_id", "")
            text = body.get("text", "").strip()
            msg_type = body.get("type", "text")
            file_id = body.get("file_id", "")

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

            # Check permissions for non-owners/admins
            if role == "user":
                perms = chat.get("permissions", {})
                if not perms.get("send_messages", True):
                    json_response(self, {"error": "Sending messages disabled"}, 403); return

            # Handle commands
            if text.startswith("/") and role in ("owner", "admin"):
                result = handle_command(chat_id, username, text)
                if result:
                    # Send system message
                    sys_msg = {
                        "id": str(uuid.uuid4()),
                        "author": "system",
                        "display": "System",
                        "text": f"[MOD] {result.get('action', '?')} → {result.get('target', '')}",
                        "ts": ts(),
                        "type": "system",
                        "reactions": {},
                        "pinned": False,
                        "edited": False,
                    }
                    add_message(chat_id, sys_msg)
                    # Broadcast
                    broadcast_message(chat_id, sys_msg)
                    json_response(self, {"ok": True, "mod": result, "message": sys_msg})
                    return

            if not text and not file_id:
                json_response(self, {"error": "Empty message"}, 400); return

            # E2E: encrypt message text with room key (base64 XOR for demo)
            # In production: use Signal Protocol / libsodium
            room_key = derive_room_key(chat_id, SERVER_SECRET)
            encrypted = simple_encrypt(text, room_key)

            msg = {
                "id": str(uuid.uuid4()),
                "author": username,
                "display": u.get("display", username),
                "avatar_emoji": u.get("avatar_emoji", "👤"),
                "text": text,  # plaintext for now (E2E done client-side in real app)
                "encrypted": encrypted,
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
            msg_id = body.get("msg_id", "")
            emoji = body.get("emoji", "")
            if not all([chat_id, msg_id, emoji]):
                json_response(self, {"error": "Missing params"}, 400); return
            msgs = _load(MSGS_F)
            for m in msgs.get(chat_id, []):
                if m["id"] == msg_id:
                    if emoji not in m["reactions"]:
                        m["reactions"][emoji] = []
                    if username in m["reactions"][emoji]:
                        m["reactions"][emoji].remove(username)
                    else:
                        m["reactions"][emoji].append(username)
                    _save(MSGS_F, msgs)
                    broadcast_message(chat_id, {"type": "reaction_update", "msg_id": msg_id, "reactions": m["reactions"]})
                    json_response(self, {"ok": True, "reactions": m["reactions"]})
                    return
            json_response(self, {"error": "Message not found"}, 404)

        elif path == "/api/chats/create":
            name = body.get("name", "").strip()
            chat_type = body.get("type", "group")
            description = body.get("description", "").strip()
            is_public = body.get("is_public", True)
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
                "id": chat_id,
                "type": chat_type,
                "name": name,
                "description": description,
                "avatar_emoji": avatar_emoji,
                "avatar": "",
                "owner": username,
                "admins": {},
                "members": [],
                "invite_link": chat_id if is_public else None,
                "private_invite": invite,
                "is_public": bool(is_public),
                "created": time.time(),
                "pinned_message": None,
                "permissions": {
                    "send_messages": True,
                    "send_media": True,
                    "add_members": True,
                    "pin_messages": False,
                    "change_info": False,
                }
            }
            _save(CHATS_F, chats)
            json_response(self, {"ok": True, "chat_id": chat_id, "invite": invite})

        elif path == "/api/chats/join":
            chat_id = body.get("chat_id", "")
            invite = body.get("invite", "")
            chat = get_chat(chat_id)
            if not chat:
                # Try by invite
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
            chat.setdefault("members", [])
            chat["members"].append(username)
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
            perms = chat.get("permissions", {})
            if not perms.get("change_info", True) and role == "user":
                json_response(self, {"error": "No permission"}, 403); return
            for field in ["name", "description", "avatar_emoji", "is_public"]:
                if field in body:
                    chat[field] = body[field]
            if "permissions" in body:
                chat["permissions"].update(body["permissions"])
            save_chat(chat_id, chat)
            json_response(self, {"ok": True})

        elif path == "/api/chats/add_admin":
            chat_id = body.get("chat_id", "")
            target = body.get("username", "")
            chat = get_chat(chat_id)
            if not chat:
                json_response(self, {"error": "Not found"}, 404); return
            if chat.get("owner") != username:
                json_response(self, {"error": "Only owner can add admins"}, 403); return
            chat.setdefault("admins", {})[target] = body.get("rights", {"all": False})
            save_chat(chat_id, chat)
            json_response(self, {"ok": True})

        elif path == "/api/profile/update":
            display = body.get("display", "").strip()
            bio = body.get("bio", "").strip()
            avatar_emoji = body.get("avatar_emoji", "")
            language = body.get("language", "")
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
            # Check if DM exists
            chats = _load(CHATS_F)
            for cid, chat in chats.items():
                if chat.get("type") == "dm":
                    members = set(chat.get("members", []) + [chat.get("owner")])
                    if username in members and target in members:
                        json_response(self, {"ok": True, "chat_id": cid}); return
            # Create DM
            dm_id = "dm_" + "_".join(sorted([username, target]))
            chats[dm_id] = {
                "id": dm_id,
                "type": "dm",
                "name": f"{u.get('display', username)} ↔ {tu.get('display', target)}",
                "description": "",
                "avatar_emoji": "💬",
                "owner": username,
                "admins": {},
                "members": [target],
                "invite_link": None,
                "private_invite": None,
                "is_public": False,
                "created": time.time(),
                "pinned_message": None,
                "permissions": {"send_messages": True, "send_media": True},
            }
            _save(CHATS_F, chats)
            json_response(self, {"ok": True, "chat_id": dm_id})

        elif path == "/api/upload":
            # Simple file upload handler
            content_type = self.headers.get("Content-Type", "")
            length = int(self.headers.get("Content-Length", 0))
            if not length:
                json_response(self, {"error": "No file"}, 400); return
            raw = self.rfile.read(length)
            ext = ".bin"
            if "image" in content_type:
                ext = ".jpg" if "jpeg" in content_type else ".png"
            elif "video" in content_type:
                ext = ".mp4"
            elif "audio" in content_type:
                ext = ".mp3"
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

    def _serve_static(self, filename):
        fp = STATIC / filename
        if fp.exists():
            self._serve_file(fp)
        else:
            self.send_response(404); self.end_headers()

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
        """Simple WebSocket upgrade"""
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

        token = get_token_from_request(self)
        username = get_session(token)
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        chat_id = qs.get("chat_id", [""])[0]

        if username and chat_id:
            u = get_user(username)
            if u:
                u["online"] = True
                save_user(username, u)

        ws_conn = SimpleWSConnection(self.connection, username, chat_id)
        with WS_LOCK:
            if chat_id not in WS_CLIENTS:
                WS_CLIENTS[chat_id] = set()
            WS_CLIENTS[chat_id].add(ws_conn)

        try:
            ws_conn.run()
        finally:
            with WS_LOCK:
                WS_CLIENTS.get(chat_id, set()).discard(ws_conn)
            if username:
                u = get_user(username)
                if u:
                    u["online"] = False
                    u["last_seen"] = now_iso()
                    save_user(username, u)


def broadcast_message(chat_id: str, msg: dict):
    """Send message to all WebSocket clients in a chat"""
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


def simple_encrypt(text: str, key: str) -> str:
    """Simple XOR encryption for demo (use libsodium/Signal in production)"""
    if not text: return ""
    key_bytes = key.encode('utf-8')
    text_bytes = text.encode('utf-8')
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(text_bytes))
    return base64.b64encode(out).decode('ascii')


class SimpleWSConnection:
    """Minimal RFC 6455 WebSocket connection"""
    def __init__(self, sock, username, chat_id):
        self.sock = sock
        self.username = username
        self.chat_id = chat_id
        self._alive = True

    def run(self):
        self.sock.settimeout(300)
        while self._alive:
            try:
                msg = self._recv_frame()
                if msg is None: break
                if msg:
                    try:
                        data = json.loads(msg)
                        self._handle(data)
                    except: pass
            except (ConnectionResetError, BrokenPipeError, OSError):
                break
            except Exception:
                break

    def _handle(self, data: dict):
        pass  # Client-sent WS messages handled via HTTP API

    def send(self, data: bytes):
        try:
            frame = self._build_frame(data)
            self.sock.sendall(frame)
        except: self._alive = False

    def _build_frame(self, data: bytes) -> bytes:
        length = len(data)
        header = bytearray()
        header.append(0x81)  # FIN + text frame
        if length < 126:
            header.append(length)
        elif length < 65536:
            header.append(126)
            header += struct.pack(">H", length)
        else:
            header.append(127)
            header += struct.pack(">Q", length)
        return bytes(header) + data

    def _recv_frame(self) -> str | None:
        try:
            header = self._recv_exact(2)
            if not header: return None
            opcode = header[0] & 0x0F
            if opcode == 8: return None  # close
            masked = (header[1] & 0x80) != 0
            length = header[1] & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._recv_exact(8))[0]
            mask = self._recv_exact(4) if masked else None
            payload = bytearray(self._recv_exact(length))
            if masked:
                for i in range(length):
                    payload[i] ^= mask[i % 4]
            return payload.decode('utf-8', errors='replace')
        except: return None

    def _recv_exact(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk: raise ConnectionResetError
            data += chunk
        return data


# ── HTML Page Builders ────────────────────────────────────────────
def build_auth_page(lang="en") -> str:
    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexoChat — {t('login', lang)}</title>
<style>
*,*::before,*::after{{margin:0;padding:0;box-sizing:border-box;}}
:root{{
  --bg:#0d0d0d;--card:#141414;--card2:#1a1a1a;
  --orange:#ff6b00;--orange2:#ff8c00;--orange3:#ffaa44;
  --border:rgba(255,107,0,.2);--border2:rgba(255,107,0,.4);
  --text:#f0f0f0;--muted:#888;--red:#ff4444;
  --font:'Segoe UI',system-ui,sans-serif;
}}
body{{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;}}
body::before{{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background:radial-gradient(ellipse 60% 50% at 20% 20%,rgba(255,107,0,.08) 0%,transparent 60%),
             radial-gradient(ellipse 50% 60% at 80% 80%,rgba(255,140,0,.06) 0%,transparent 60%);}}
.wrap{{position:relative;z-index:1;width:100%;max-width:400px;}}
.logo{{text-align:center;margin-bottom:32px;}}
.logo-icon{{font-size:56px;display:block;margin-bottom:8px;}}
.logo-name{{font-size:2em;font-weight:900;background:linear-gradient(135deg,var(--orange),var(--orange3));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-.02em;}}
.logo-sub{{color:var(--muted);font-size:.82em;margin-top:4px;}}
.card{{background:var(--card);border:1.5px solid var(--border2);border-radius:18px;padding:32px 28px;box-shadow:0 0 40px rgba(255,107,0,.08);}}
.tabs{{display:flex;gap:2px;margin-bottom:24px;background:rgba(255,255,255,.04);border-radius:10px;padding:3px;}}
.tab{{flex:1;padding:10px;border:none;background:none;color:var(--muted);font-size:.88em;font-weight:700;cursor:pointer;border-radius:8px;transition:all .2s;}}
.tab.active{{background:var(--orange);color:#fff;}}
.field{{margin-bottom:14px;}}
.field label{{display:block;font-size:.72em;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;font-weight:600;}}
.field input,.field select{{width:100%;padding:11px 14px;background:rgba(255,255,255,.05);border:1.5px solid rgba(255,255,255,.08);border-radius:10px;color:var(--text);font-size:.9em;outline:none;transition:border .2s;}}
.field input:focus,.field select:focus{{border-color:var(--orange);}}
.field select option{{background:#1a1a1a;}}
.btn{{width:100%;padding:13px;margin-top:8px;background:linear-gradient(135deg,var(--orange),var(--orange2));border:none;border-radius:10px;color:#fff;font-size:.95em;font-weight:800;cursor:pointer;transition:all .2s;box-shadow:0 4px 20px rgba(255,107,0,.3);}}
.btn:hover{{transform:translateY(-1px);box-shadow:0 6px 28px rgba(255,107,0,.45);}}
.btn:active{{transform:translateY(0);}}
.btn-tg{{width:100%;padding:11px;margin-top:10px;background:rgba(41,182,246,.15);border:1.5px solid rgba(41,182,246,.3);border-radius:10px;color:#29b6f6;font-size:.88em;font-weight:700;cursor:pointer;transition:all .2s;}}
.btn-tg:hover{{background:rgba(41,182,246,.25);}}
.divider{{text-align:center;color:var(--muted);font-size:.78em;margin:14px 0;position:relative;}}
.divider::before,.divider::after{{content:'';position:absolute;top:50%;width:40%;height:1px;background:rgba(255,255,255,.08);}}
.divider::before{{left:0;}} .divider::after{{right:0;}}
.err{{color:var(--red);font-size:.8em;margin-top:10px;padding:8px 12px;background:rgba(255,68,68,.1);border:1px solid rgba(255,68,68,.2);border-radius:8px;display:none;}}
.err.show{{display:block;}}
.lang-row{{display:flex;justify-content:center;gap:8px;margin-bottom:20px;}}
.lang-btn{{padding:5px 12px;border:1px solid var(--border);border-radius:20px;background:none;color:var(--muted);font-size:.78em;cursor:pointer;transition:all .2s;}}
.lang-btn.active,.lang-btn:hover{{border-color:var(--orange);color:var(--orange);}}
#tab-login,#tab-register{{display:none;}}
#tab-login.active,#tab-register.active{{display:block;}}
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
    <button class="lang-btn{' active' if lang=='uk' else ''}" onclick="setLang('uk')">UK</button>
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
      <button class="btn" onclick="doLogin()">{t('login', lang)}</button>
      <div class="divider">{t('or_tg', lang)}</div>
      <button class="btn-tg" onclick="loginTg()">📱 Telegram</button>
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
      <button class="btn" onclick="doRegister()">{t('register', lang)}</button>
      <div class="err" id="r-err"></div>
    </div>
  </div>
</div>
<script>
const LANG = '{lang}';
function setLang(l) {{
  const u = new URL(location.href); u.searchParams.set('lang', l);
  location.href = u.toString();
}}
function switchTab(tab) {{
  document.getElementById('tab-login').classList.toggle('active', tab==='login');
  document.getElementById('tab-register').classList.toggle('active', tab==='register');
  document.getElementById('btn-login').classList.toggle('active', tab==='login');
  document.getElementById('btn-register').classList.toggle('active', tab==='register');
}}
async function doLogin() {{
  const u = document.getElementById('l-user').value.trim();
  const p = document.getElementById('l-pass').value;
  const err = document.getElementById('l-err');
  err.className = 'err';
  if (!u || !p) {{ err.textContent = 'Fill all fields'; err.className='err show'; return; }}
  const r = await fetch('/api/auth/login', {{
    method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{username: u, password: p}})
  }});
  const data = await r.json();
  if (data.ok) {{ location.href = '/'; }}
  else {{ err.textContent = data.error || 'Error'; err.className='err show'; }}
}}
async function doRegister() {{
  const u = document.getElementById('r-user').value.trim();
  const e = document.getElementById('r-email').value.trim();
  const p = document.getElementById('r-pass').value;
  const d = document.getElementById('r-display').value.trim();
  const l = document.getElementById('r-lang').value;
  const err = document.getElementById('r-err');
  err.className = 'err';
  if (!u || !p) {{ err.textContent = 'Fill required fields'; err.className='err show'; return; }}
  const r = await fetch('/api/auth/register', {{
    method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{username: u, email: e, password: p, display: d, language: l}})
  }});
  const data = await r.json();
  if (data.ok) {{ location.href = '/'; }}
  else {{ err.textContent = data.error || 'Error'; err.className='err show'; }}
}}
function loginTg() {{
  alert('Connect your Telegram bot (configure TG_BOT_TOKEN in .env)');
}}
document.addEventListener('keydown', e => {{
  if (e.key === 'Enter') {{
    const tab = document.getElementById('tab-login').classList.contains('active');
    if (tab) doLogin(); else doRegister();
  }}
}});
</script>
</body>
</html>"""


def build_main_page(user: dict, lang="en", active_chat=None) -> str:
    uname = user.get("username", "")
    display = user.get("display", uname)
    emoji = user.get("avatar_emoji", "👤")
    active_js = f'"{active_chat}"' if active_chat else 'null'

    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexoChat</title>
<style>
*,*::before,*::after{{margin:0;padding:0;box-sizing:border-box;}}
:root{{
  --bg:#0d0d0d;--sidebar:#111;--card:#141414;--card2:#1a1a1a;--panel:#161616;
  --orange:#ff6b00;--orange2:#ff8c00;--orange3:#ffaa44;--orange-dim:rgba(255,107,0,.12);
  --border:rgba(255,255,255,.07);--border-o:rgba(255,107,0,.25);
  --text:#f0f0f0;--muted:#777;--muted2:#555;--blue:#29b6f6;--green:#4caf50;
  --red:#ff4444;--system:#888;
  --font:'Segoe UI',system-ui,sans-serif;
  --sidebar-w:320px;
}}
html,body{{height:100%;overflow:hidden;font-family:var(--font);background:var(--bg);color:var(--text);}}
.app{{display:flex;height:100vh;}}

/* Sidebar */
.sidebar{{width:var(--sidebar-w);min-width:240px;max-width:360px;background:var(--sidebar);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;}}
.sidebar-header{{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;}}
.app-logo{{font-size:1.3em;font-weight:900;background:linear-gradient(135deg,var(--orange),var(--orange3));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}}
.sidebar-header-actions{{margin-left:auto;display:flex;gap:6px;}}
.icon-btn{{background:none;border:none;color:var(--muted);font-size:1.1em;cursor:pointer;padding:6px;border-radius:8px;transition:all .15s;}}
.icon-btn:hover{{background:var(--orange-dim);color:var(--orange);}}
.sidebar-search{{padding:10px 14px;}}
.search-input{{width:100%;padding:8px 14px;background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:20px;color:var(--text);font-size:.85em;outline:none;transition:border .2s;}}
.search-input:focus{{border-color:var(--border-o);}}
.sidebar-tabs{{display:flex;border-bottom:1px solid var(--border);}}
.s-tab{{flex:1;padding:9px;border:none;background:none;color:var(--muted);font-size:.78em;cursor:pointer;border-bottom:2px solid transparent;transition:all .2s;}}
.s-tab.active{{color:var(--orange);border-bottom-color:var(--orange);}}
.chat-list{{flex:1;overflow-y:auto;padding:4px 0;}}
.chat-list::-webkit-scrollbar{{width:4px;}}
.chat-list::-webkit-scrollbar-thumb{{background:rgba(255,255,255,.1);border-radius:2px;}}
.chat-item{{display:flex;align-items:center;gap:11px;padding:10px 14px;cursor:pointer;transition:background .15s;border-radius:0;}}
.chat-item:hover{{background:rgba(255,255,255,.04);}}
.chat-item.active{{background:var(--orange-dim);}}
.chat-avatar{{width:44px;height:44px;border-radius:50%;background:rgba(255,107,0,.2);border:2px solid rgba(255,107,0,.3);display:flex;align-items:center;justify-content:center;font-size:1.4em;flex-shrink:0;overflow:hidden;}}
.chat-avatar img{{width:100%;height:100%;object-fit:cover;}}
.chat-info{{flex:1;min-width:0;}}
.chat-name{{font-weight:600;font-size:.9em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}}
.chat-last{{font-size:.78em;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px;}}
.chat-meta{{display:flex;flex-direction:column;align-items:flex-end;gap:4px;}}
.chat-time{{font-size:.7em;color:var(--muted2);}}
.chat-type-badge{{font-size:.6em;padding:2px 6px;border-radius:8px;font-weight:700;}}
.badge-channel{{background:rgba(41,182,246,.15);color:var(--blue);}}
.badge-group{{background:rgba(76,175,80,.15);color:var(--green);}}
.badge-dm{{background:var(--orange-dim);color:var(--orange);}}

/* Main chat area */
.chat-area{{flex:1;display:flex;flex-direction:column;min-width:0;}}
.chat-header{{padding:12px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;cursor:pointer;transition:background .15s;user-select:none;}}
.chat-header:hover{{background:rgba(255,255,255,.02);}}
.chat-header-info{{flex:1;min-width:0;}}
.chat-header-name{{font-weight:700;font-size:1em;}}
.chat-header-sub{{font-size:.75em;color:var(--muted);margin-top:1px;}}
.chat-header-actions{{display:flex;gap:6px;}}
.messages{{flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;gap:2px;}}
.messages::-webkit-scrollbar{{width:4px;}}
.messages::-webkit-scrollbar-thumb{{background:rgba(255,255,255,.08);border-radius:2px;}}
.pinned-bar{{background:rgba(255,107,0,.08);border-left:3px solid var(--orange);padding:8px 14px;font-size:.8em;color:var(--orange);cursor:pointer;}}
.msg{{display:flex;gap:9px;padding:3px 0;max-width:100%;position:relative;}}
.msg:hover .msg-actions{{opacity:1;}}
.msg.own{{flex-direction:row-reverse;}}
.msg-av{{width:34px;height:34px;border-radius:50%;background:rgba(255,107,0,.2);display:flex;align-items:center;justify-content:center;font-size:1em;flex-shrink:0;align-self:flex-end;}}
.msg-body{{max-width:68%;}}
.msg.own .msg-body{{align-items:flex-end;}}
.msg-bubble{{background:var(--card2);border-radius:16px 16px 16px 4px;padding:8px 12px;position:relative;word-wrap:break-word;}}
.msg.own .msg-bubble{{background:rgba(255,107,0,.18);border-radius:16px 16px 4px 16px;border:1px solid rgba(255,107,0,.2);}}
.msg-author{{font-size:.72em;font-weight:700;color:var(--orange);margin-bottom:3px;}}
.msg.own .msg-author{{display:none;}}
.msg-text{{font-size:.9em;line-height:1.45;}}
.msg-text a{{color:var(--orange);}}
.msg-footer{{display:flex;align-items:center;gap:6px;margin-top:4px;}}
.msg-time{{font-size:.68em;color:var(--muted2);}}
.msg-reactions{{display:flex;flex-wrap:wrap;gap:4px;margin-top:4px;}}
.reaction-badge{{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);border-radius:12px;padding:2px 8px;font-size:.78em;cursor:pointer;transition:all .15s;display:flex;align-items:center;gap:3px;}}
.reaction-badge:hover{{background:rgba(255,107,0,.15);border-color:var(--border-o);}}
.reaction-badge.mine{{background:rgba(255,107,0,.18);border-color:var(--border-o);}}
.msg-actions{{position:absolute;top:-28px;right:0;background:var(--card);border:1px solid var(--border);border-radius:8px;display:flex;gap:2px;padding:3px;opacity:0;transition:opacity .15s;z-index:10;}}
.msg.own .msg-actions{{right:auto;left:0;}}
.msg-act-btn{{background:none;border:none;cursor:pointer;font-size:.85em;padding:3px 5px;border-radius:5px;transition:background .15s;color:var(--muted);}}
.msg-act-btn:hover{{background:rgba(255,107,0,.15);color:var(--orange);}}
.msg-system{{text-align:center;color:var(--system);font-size:.78em;padding:6px 0;}}
.msg-image{{max-width:300px;border-radius:10px;cursor:pointer;margin-top:4px;}}
.msg-video{{max-width:300px;border-radius:10px;margin-top:4px;}}
.msg-audio{{width:220px;margin-top:4px;}}
.typing-indicator{{padding:8px 16px;color:var(--muted);font-size:.8em;font-style:italic;height:28px;}}

/* Input area */
.input-area{{padding:12px 16px;border-top:1px solid var(--border);background:var(--panel);}}
.reply-preview{{background:rgba(255,107,0,.08);border-left:3px solid var(--orange);padding:6px 10px;border-radius:6px;margin-bottom:8px;display:flex;align-items:center;justify-content:space-between;font-size:.8em;color:var(--muted);}}
.input-row{{display:flex;align-items:flex-end;gap:8px;}}
.input-attach{{background:none;border:none;color:var(--muted);font-size:1.2em;cursor:pointer;padding:8px;border-radius:8px;transition:all .15s;flex-shrink:0;}}
.input-attach:hover{{color:var(--orange);background:var(--orange-dim);}}
.msg-input{{flex:1;padding:10px 14px;background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:20px;color:var(--text);font-size:.9em;outline:none;resize:none;max-height:120px;overflow-y:auto;transition:border .2s;font-family:var(--font);line-height:1.45;}}
.msg-input:focus{{border-color:var(--border-o);}}
.send-btn{{background:var(--orange);border:none;border-radius:50%;width:40px;height:40px;color:#fff;font-size:1.1em;cursor:pointer;transition:all .2s;flex-shrink:0;display:flex;align-items:center;justify-content:center;}}
.send-btn:hover{{background:var(--orange2);transform:scale(1.05);}}

/* Right panel - chat info */
.right-panel{{width:300px;min-width:280px;background:var(--sidebar);border-left:1px solid var(--border);display:flex;flex-direction:column;transform:translateX(100%);transition:transform .3s;position:relative;}}
.right-panel.open{{transform:translateX(0);}}
.rp-header{{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;}}
.rp-title{{font-weight:700;flex:1;}}
.rp-body{{flex:1;overflow-y:auto;padding:12px 14px;}}
.rp-section{{margin-bottom:18px;}}
.rp-section-title{{font-size:.72em;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;font-weight:700;margin-bottom:8px;}}
.rp-name{{font-size:1.1em;font-weight:700;margin-bottom:4px;}}
.rp-desc{{font-size:.83em;color:var(--muted);margin-bottom:12px;line-height:1.5;}}
.rp-stat{{display:flex;gap:8px;font-size:.82em;color:var(--muted);margin-bottom:10px;}}
.member-item{{display:flex;align-items:center;gap:8px;padding:6px 0;}}
.member-av{{width:32px;height:32px;border-radius:50%;background:rgba(255,107,0,.15);display:flex;align-items:center;justify-content:center;font-size:.95em;}}
.member-info{{flex:1;min-width:0;}}
.member-name{{font-size:.85em;font-weight:600;}}
.member-role{{font-size:.7em;color:var(--muted);}}
.member-online{{width:8px;height:8px;border-radius:50%;background:var(--green);flex-shrink:0;}}
.member-offline{{width:8px;height:8px;border-radius:50%;background:var(--muted2);flex-shrink:0;}}
.rp-input{{width:100%;padding:9px 12px;background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:.88em;outline:none;margin-bottom:8px;transition:border .2s;}}
.rp-input:focus{{border-color:var(--border-o);}}
.rp-btn{{width:100%;padding:9px;background:var(--orange);border:none;border-radius:8px;color:#fff;font-size:.85em;font-weight:700;cursor:pointer;margin-bottom:6px;transition:all .2s;}}
.rp-btn:hover{{background:var(--orange2);}}
.rp-btn.danger{{background:rgba(255,68,68,.15);color:var(--red);border:1px solid rgba(255,68,68,.2);}}
.rp-btn.danger:hover{{background:rgba(255,68,68,.25);}}
.rp-btn.secondary{{background:rgba(255,255,255,.06);color:var(--text);}}
.rp-btn.secondary:hover{{background:rgba(255,255,255,.1);}}
.link-box{{background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-size:.8em;color:var(--muted);word-break:break-all;margin-bottom:8px;cursor:pointer;transition:border .15s;}}
.link-box:hover{{border-color:var(--border-o);color:var(--orange);}}

/* No chat selected */
.no-chat{{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--muted);gap:12px;}}
.no-chat-icon{{font-size:4em;opacity:.3;}}
.no-chat-text{{font-size:1em;opacity:.5;}}

/* Modal */
.modal-overlay{{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;display:flex;align-items:center;justify-content:center;padding:16px;display:none;}}
.modal-overlay.open{{display:flex;}}
.modal{{background:var(--card);border:1px solid var(--border-o);border-radius:16px;padding:24px;width:100%;max-width:420px;max-height:90vh;overflow-y:auto;}}
.modal-title{{font-size:1.1em;font-weight:700;margin-bottom:20px;}}
.modal-field{{margin-bottom:14px;}}
.modal-label{{font-size:.72em;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;font-weight:600;display:block;margin-bottom:6px;}}
.modal-input{{width:100%;padding:10px 13px;background:rgba(255,255,255,.05);border:1.5px solid var(--border);border-radius:10px;color:var(--text);font-size:.9em;outline:none;transition:border .2s;}}
.modal-input:focus{{border-color:var(--orange);}}
.modal-select{{width:100%;padding:10px 13px;background:rgba(255,255,255,.05);border:1.5px solid var(--border);border-radius:10px;color:var(--text);font-size:.9em;outline:none;}}
.modal-select option{{background:#1a1a1a;}}
.modal-row{{display:flex;gap:8px;}}
.modal-btn{{flex:1;padding:11px;border:none;border-radius:10px;font-size:.9em;font-weight:700;cursor:pointer;transition:all .2s;}}
.modal-btn.primary{{background:var(--orange);color:#fff;}}
.modal-btn.primary:hover{{background:var(--orange2);}}
.modal-btn.cancel{{background:rgba(255,255,255,.06);color:var(--muted);}}
.emoji-picker{{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;}}
.emoji-opt{{font-size:1.4em;cursor:pointer;padding:4px;border-radius:6px;transition:background .15s;border:2px solid transparent;}}
.emoji-opt.selected,.emoji-opt:hover{{background:var(--orange-dim);border-color:var(--border-o);}}
.toast{{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:var(--card);border:1px solid var(--border-o);border-radius:12px;padding:10px 20px;font-size:.88em;z-index:9999;animation:toastin .3s ease;pointer-events:none;}}
@keyframes toastin{{from{{opacity:0;transform:translateX(-50%) translateY(10px)}}to{{opacity:1;transform:translateX(-50%) translateY(0)}}}}
.reaction-picker{{position:fixed;background:var(--card);border:1px solid var(--border-o);border-radius:12px;padding:8px 10px;z-index:500;display:flex;gap:6px;box-shadow:0 8px 32px rgba(0,0,0,.4);}}
.r-emoji{{font-size:1.3em;cursor:pointer;padding:4px;border-radius:6px;transition:background .15s;}}
.r-emoji:hover{{background:var(--orange-dim);}}
.search-results{{background:var(--card);border:1px solid var(--border-o);border-radius:12px;position:absolute;top:100%;left:0;right:0;z-index:200;max-height:300px;overflow-y:auto;box-shadow:0 8px 32px rgba(0,0,0,.4);}}
.search-result-item{{padding:10px 14px;cursor:pointer;display:flex;align-items:center;gap:10px;transition:background .15s;}}
.search-result-item:hover{{background:rgba(255,107,0,.08);}}

/* Profile page overlay */
.profile-overlay{{position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:800;display:none;align-items:center;justify-content:center;}}
.profile-overlay.open{{display:flex;}}
.profile-card{{background:var(--card);border:1px solid var(--border-o);border-radius:20px;padding:32px 28px;width:100%;max-width:380px;text-align:center;}}
.profile-avatar{{font-size:3.5em;margin-bottom:12px;}}
.profile-name{{font-size:1.4em;font-weight:800;}}
.profile-user{{color:var(--muted);font-size:.88em;margin-top:4px;}}
.profile-bio{{color:var(--muted);font-size:.9em;margin:12px 0;line-height:1.5;}}
.profile-btn{{padding:10px 20px;background:var(--orange);border:none;border-radius:10px;color:#fff;font-weight:700;cursor:pointer;margin:4px;transition:all .2s;}}
.profile-btn:hover{{background:var(--orange2);}}

/* Responsive */
@media(max-width:768px){{
  .sidebar{{width:100%;position:fixed;z-index:100;height:100%;transform:translateX(-100%);transition:transform .3s;}}
  .sidebar.mobile-open{{transform:none;}}
  .right-panel{{width:100%;position:fixed;z-index:100;height:100%;}}
  .app-logo{{display:none;}}
}}
</style>
</head>
<body>
<div class="app" id="app">
  <!-- Sidebar -->
  <div class="sidebar" id="sidebar">
    <div class="sidebar-header">
      <span class="app-logo">💬 NexoChat</span>
      <div class="sidebar-header-actions">
        <button class="icon-btn" onclick="openModal('create-chat-modal')" title="New chat">✏️</button>
        <button class="icon-btn" onclick="openProfileSelf()" title="{t('profile', lang)}">{emoji}</button>
        <button class="icon-btn" onclick="doLogout()" title="{t('logout', lang)}">🚪</button>
      </div>
    </div>
    <div class="sidebar-search" style="position:relative">
      <input class="search-input" id="search-input" placeholder="🔍 {t('search', lang)}..." oninput="onSearch(this.value)" onblur="setTimeout(()=>closeSearch(),200)">
      <div class="search-results" id="search-results" style="display:none"></div>
    </div>
    <div class="sidebar-tabs">
      <button class="s-tab active" onclick="filterChats('all')" id="tab-all">All</button>
      <button class="s-tab" onclick="filterChats('group')" id="tab-groups">{t('groups', lang)}</button>
      <button class="s-tab" onclick="filterChats('channel')" id="tab-channels">{t('channels', lang)}</button>
      <button class="s-tab" onclick="filterChats('dm')" id="tab-dms">{t('dms', lang)}</button>
    </div>
    <div class="chat-list" id="chat-list"></div>
  </div>

  <!-- Main area -->
  <div class="chat-area" id="chat-area">
    <div class="no-chat" id="no-chat">
      <div class="no-chat-icon">💬</div>
      <div class="no-chat-text">Select a chat to start messaging</div>
    </div>

    <div id="active-chat" style="display:none;flex-direction:column;flex:1;min-height:0;">
      <div class="chat-header" id="chat-header" onclick="toggleRightPanel()">
        <div class="chat-avatar" id="hdr-avatar" style="font-size:1.6em">💬</div>
        <div class="chat-header-info">
          <div class="chat-header-name" id="hdr-name">Chat</div>
          <div class="chat-header-sub" id="hdr-sub">0 members</div>
        </div>
        <div class="chat-header-actions">
          <button class="icon-btn" onclick="event.stopPropagation();openSearch()" title="Search">🔍</button>
          <button class="icon-btn" onclick="event.stopPropagation();toggleRightPanel()" title="Info">ℹ️</button>
        </div>
      </div>
      <div class="pinned-bar" id="pinned-bar" style="display:none" onclick="scrollToPinned()">📌 Pinned message</div>
      <div class="messages" id="messages"></div>
      <div class="typing-indicator" id="typing-indicator"></div>
      <div class="input-area" id="input-area">
        <div class="reply-preview" id="reply-preview" style="display:none">
          <span id="reply-text"></span>
          <button onclick="clearReply()" style="background:none;border:none;cursor:pointer;color:var(--muted);">✕</button>
        </div>
        <div class="input-row">
          <button class="input-attach" onclick="triggerFileUpload()" title="Attach file">📎</button>
          <textarea class="msg-input" id="msg-input" placeholder="{t('write', lang)}..." rows="1"
            onkeydown="onInputKeydown(event)" oninput="onInputChange()" onpaste="onPaste(event)"></textarea>
          <button class="send-btn" onclick="sendMessage()">➤</button>
        </div>
        <input type="file" id="file-input" style="display:none" accept="image/*,video/*,audio/*" onchange="uploadFile(this)">
      </div>
    </div>
  </div>

  <!-- Right panel -->
  <div class="right-panel" id="right-panel">
    <div class="rp-header">
      <button class="icon-btn" onclick="toggleRightPanel()">✕</button>
      <span class="rp-title">Info</span>
    </div>
    <div class="rp-body" id="rp-body"></div>
  </div>
</div>

<!-- Modals -->
<div class="modal-overlay" id="create-chat-modal">
  <div class="modal">
    <div class="modal-title">Create chat</div>
    <div class="modal-field">
      <label class="modal-label">Type</label>
      <select class="modal-select" id="new-chat-type">
        <option value="group">{t('groups', lang)}</option>
        <option value="channel">{t('channels', lang)}</option>
      </select>
    </div>
    <div class="modal-field">
      <label class="modal-label">{t('name', lang)}</label>
      <input class="modal-input" id="new-chat-name" placeholder="My Chat">
    </div>
    <div class="modal-field">
      <label class="modal-label">{t('description', lang)}</label>
      <input class="modal-input" id="new-chat-desc" placeholder="Optional description">
    </div>
    <div class="modal-field">
      <label class="modal-label">Emoji</label>
      <div class="emoji-picker" id="emoji-picker">
        {"".join(f'<span class="emoji-opt" onclick="selectEmoji(this,\\"{e}\\")">{e}</span>' for e in ['💬','👥','🔥','🌍','🎮','🎵','📸','🚀','⚡','🌙','💡','🎯','🏆','🦄','🌈'])}
      </div>
    </div>
    <div class="modal-field">
      <label class="modal-label">Visibility</label>
      <select class="modal-select" id="new-chat-public">
        <option value="1">{t('public', lang)}</option>
        <option value="0">{t('private', lang)}</option>
      </select>
    </div>
    <div class="modal-row">
      <button class="modal-btn cancel" onclick="closeModal('create-chat-modal')">Cancel</button>
      <button class="modal-btn primary" onclick="createChat()">Create</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="profile-edit-modal">
  <div class="modal">
    <div class="modal-title">{t('profile', lang)}</div>
    <div class="modal-field">
      <label class="modal-label">Display name</label>
      <input class="modal-input" id="pe-display" placeholder="Your Name">
    </div>
    <div class="modal-field">
      <label class="modal-label">Bio</label>
      <input class="modal-input" id="pe-bio" placeholder="Tell about yourself">
    </div>
    <div class="modal-field">
      <label class="modal-label">Avatar emoji</label>
      <div class="emoji-picker" id="profile-emoji-picker">
        {"".join(f'<span class="emoji-opt" onclick="selectProfileEmoji(this,\\"{e}\\")">{e}</span>' for e in ['👤','😎','🦁','🐉','🌟','🔥','❄️','🎭','🎨','🚀','👑','🦅','🌙','⚡','🎯'])}
      </div>
    </div>
    <div class="modal-field">
      <label class="modal-label">Language</label>
      <select class="modal-select" id="pe-lang">
        <option value="en">English</option>
        <option value="uk">Українська</option>
        <option value="ru">Русский</option>
        <option value="pl">Polski</option>
      </select>
    </div>
    <div class="modal-row">
      <button class="modal-btn cancel" onclick="closeModal('profile-edit-modal')">Cancel</button>
      <button class="modal-btn primary" onclick="saveProfile()">{t('save', lang)}</button>
    </div>
  </div>
</div>

<!-- Reaction picker -->
<div class="reaction-picker" id="reaction-picker" style="display:none">
  {"".join(f'<span class="r-emoji" onclick="addReaction(\\"{e}\\")">{e}</span>' for e in ['👍','❤️','😂','😮','😢','🔥','👏','🎉','😡','💯'])}
</div>

<!-- Profile overlay -->
<div class="profile-overlay" id="profile-overlay">
  <div class="profile-card">
    <div class="profile-avatar" id="po-avatar">👤</div>
    <div class="profile-name" id="po-name">User</div>
    <div class="profile-user" id="po-user">@user</div>
    <div class="profile-bio" id="po-bio"></div>
    <div style="display:flex;justify-content:center;flex-wrap:wrap;gap:8px;margin-top:12px">
      <button class="profile-btn" id="po-dm-btn" onclick="startDM()">💬 Message</button>
      <button class="profile-btn" onclick="closeProfileOverlay()" style="background:rgba(255,255,255,.07);color:var(--text);">Close</button>
    </div>
  </div>
</div>

<script>
const ME = '{uname}';
const LANG = '{lang}';
let activeChat = {active_js};
let chats = [];
let chatFilter = 'all';
let ws = null;
let typingTimer = null;
let replyTo = null;
let reactionMsgId = null;
let selectedEmoji = '💬';
let selectedProfileEmoji = '👤';
let lastTypingNotif = 0;
let profileTarget = null;
let chatInfoCache = {{}};

// ── Init ──────────────────────────────────────────────────────────
async function init() {{
  await loadChats();
  if (activeChat) selectChat(activeChat);
  setInterval(pollTyping, 3000);
  setInterval(loadChats, 15000);
}}

// ── Chat list ─────────────────────────────────────────────────────
async function loadChats() {{
  const r = await api('/api/chats');
  chats = r;
  renderChatList();
}}

function renderChatList() {{
  const list = document.getElementById('chat-list');
  const filtered = chats.filter(c => chatFilter === 'all' || c.type === chatFilter);
  if (!filtered.length) {{
    list.innerHTML = '<div style="text-align:center;color:var(--muted);padding:24px;font-size:.85em;">No chats yet</div>';
    return;
  }}
  list.innerHTML = filtered.map(c => {{
    const last = c.last_message;
    const lastText = last ? (last.text || '[media]').substring(0, 40) : 'No messages';
    const lastTime = last ? last.ts : '';
    const badge = c.type === 'channel' ? 'badge-channel' : c.type === 'dm' ? 'badge-dm' : 'badge-group';
    const typeLabel = c.type === 'channel' ? '📡' : c.type === 'dm' ? '💌' : '👥';
    return `<div class="chat-item${{activeChat===c.id?' active':''}}" onclick="selectChat('${{c.id}}')">
      <div class="chat-avatar">${{c.avatar ? `<img src="/avatars/${{c.avatar}}">` : c.avatar_emoji}}</div>
      <div class="chat-info">
        <div class="chat-name">${{typeLabel}} ${{esc(c.name)}}</div>
        <div class="chat-last">${{esc(lastText)}}</div>
      </div>
      <div class="chat-meta">
        <div class="chat-time">${{lastTime}}</div>
        <div class="chat-type-badge ${{badge}}">${{c.type}}</div>
      </div>
    </div>`;
  }}).join('');
}}

function filterChats(type) {{
  chatFilter = type;
  ['all','groups','channels','dms'].forEach(t => {{
    document.getElementById('tab-'+t)?.classList.toggle('active', t===type || (type==='all'&&t==='all'));
  }});
  document.getElementById('tab-all').classList.toggle('active', type==='all');
  document.getElementById('tab-groups').classList.toggle('active', type==='group');
  document.getElementById('tab-channels').classList.toggle('active', type==='channel');
  document.getElementById('tab-dms').classList.toggle('active', type==='dm');
  renderChatList();
}}

// ── Select chat ───────────────────────────────────────────────────
async function selectChat(chatId) {{
  activeChat = chatId;
  document.getElementById('no-chat').style.display = 'none';
  const ac = document.getElementById('active-chat');
  ac.style.display = 'flex';
  renderChatList();
  await loadMessages(chatId);
  await loadChatInfo(chatId);
  connectWS(chatId);
  // Mobile: close sidebar
  document.getElementById('sidebar').classList.remove('mobile-open');
}}

async function loadMessages(chatId) {{
  const msgs = await api('/api/messages?chat_id='+chatId+'&limit=80');
  renderMessages(msgs, chatId);
}}

async function loadChatInfo(chatId) {{
  const info = await api('/api/chat_info?chat_id='+chatId);
  chatInfoCache[chatId] = info;
  document.getElementById('hdr-name').textContent = info.name;
  document.getElementById('hdr-sub').textContent = info.members_count + ' members · ' + info.type;
  document.getElementById('hdr-avatar').textContent = info.avatar_emoji || '💬';
  if (info.pinned_message) {{
    document.getElementById('pinned-bar').style.display = 'block';
  }} else {{
    document.getElementById('pinned-bar').style.display = 'none';
  }}
}}

// ── Render messages ───────────────────────────────────────────────
function renderMessages(msgs, chatId) {{
  const el = document.getElementById('messages');
  el.innerHTML = msgs.map(m => renderMsg(m)).join('');
  el.scrollTop = el.scrollHeight;
}}

function renderMsg(m) {{
  if (m.type === 'system') {{
    return `<div class="msg-system">${{esc(m.text)}}</div>`;
  }}
  const own = m.author === ME;
  const cls = 'msg' + (own ? ' own' : '');
  const reactions = Object.entries(m.reactions || {{}}).filter(([,u])=>u.length>0).map(([e,users]) => {{
    const mine = users.includes(ME);
    return `<span class="reaction-badge${{mine?' mine':''}}" onclick="reactMsg('${{m.id}}','${{e}}')">${{e}} ${{users.length}}</span>`;
  }}).join('');

  let content = '';
  if (m.file_id && m.type === 'image') {{
    content = `<img class="msg-image" src="/uploads/${{m.file_id}}" onclick="openMedia('/uploads/${{m.file_id}}','image')">`;
  }} else if (m.file_id && m.type === 'video') {{
    content = `<video class="msg-video" controls src="/uploads/${{m.file_id}}"></video>`;
  }} else if (m.file_id && m.type === 'audio') {{
    content = `<audio class="msg-audio" controls src="/uploads/${{m.file_id}}"></audio>`;
  }} else {{
    content = `<div class="msg-text">${{linkify(esc(m.text))}}</div>`;
  }}

  const reply = m.reply_to ? `<div style="border-left:3px solid var(--orange);padding-left:8px;color:var(--muted);font-size:.78em;margin-bottom:4px">↩ Reply</div>` : '';
  
  return `<div class="msg ${{cls}}" id="msg-${{m.id}}">
    ${{!own ? `<div class="msg-av" onclick="openProfile('${{m.author}}')" style="cursor:pointer">${{m.avatar_emoji||'👤'}}</div>` : ''}}
    <div class="msg-body">
      ${{!own ? `<div class="msg-author">${{esc(m.display||m.author)}}</div>` : ''}}
      ${{reply}}
      <div class="msg-bubble">
        ${{content}}
        <div class="msg-footer">
          <span class="msg-time">${{m.ts}}${{m.edited?' ✏️':''}}</span>
        </div>
      </div>
      ${{reactions ? `<div class="msg-reactions">${{reactions}}</div>` : ''}}
      <div class="msg-actions">
        <button class="msg-act-btn" onclick="showReactionPicker(event,'${{m.id}}')" title="React">😊</button>
        <button class="msg-act-btn" onclick="setReply('${{m.id}}','${{esc(m.text).substring(0,40)}}',event)" title="Reply">↩</button>
        ${{own ? `<button class="msg-act-btn" onclick="deleteMsg('${{m.id}}')" title="Delete">🗑️</button>` : ''}}
      </div>
    </div>
    ${{own ? `<div class="msg-av">${{m.avatar_emoji||'👤'}}</div>` : ''}}
  </div>`;
}}

// ── Send message ──────────────────────────────────────────────────
async function sendMessage() {{
  const input = document.getElementById('msg-input');
  const text = input.value.trim();
  if (!text || !activeChat) return;
  input.value = '';
  input.style.height = '';
  const payload = {{chat_id: activeChat, text, type: 'text'}};
  if (replyTo) {{ payload.reply_to = replyTo; clearReply(); }}
  const r = await api('/api/messages/send', 'POST', payload);
  if (r.ok) {{
    appendMessage(r.message);
  }} else {{
    showToast(r.error || 'Failed to send');
  }}
}}

function appendMessage(m) {{
  const el = document.getElementById('messages');
  const div = document.createElement('div');
  div.innerHTML = renderMsg(m);
  el.appendChild(div.firstChild);
  el.scrollTop = el.scrollHeight;
}}

function onInputKeydown(e) {{
  if (e.key === 'Enter' && !e.shiftKey) {{
    e.preventDefault(); sendMessage();
  }}
}}

function onInputChange() {{
  const ta = document.getElementById('msg-input');
  ta.style.height = 'auto';
  ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
  // Typing indicator
  const now = Date.now();
  if (now - lastTypingNotif > 2000 && activeChat) {{
    lastTypingNotif = now;
    api('/api/typing', 'POST', {{chat_id: activeChat}});
  }}
}}

// ── WebSocket ─────────────────────────────────────────────────────
function connectWS(chatId) {{
  if (ws) {{ ws.close(); ws = null; }}
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const token = getCookie('nexo_token');
  ws = new WebSocket(`${{proto}}://${{location.host}}/?chat_id=${{chatId}}`);
  ws.onmessage = (e) => {{
    try {{
      const msg = JSON.parse(e.data);
      if (msg.type === 'typing') {{
        if (msg.username !== ME) showTyping(msg.display);
        return;
      }}
      if (msg.type === 'reaction_update') {{
        updateReactions(msg.msg_id, msg.reactions); return;
      }}
      if (msg.author !== ME) appendMessage(msg);
    }} catch(e) {{}}
  }};
  ws.onclose = () => {{ setTimeout(()=>{{ if(activeChat===chatId) connectWS(chatId); }}, 3000); }};
}}

let typingTimeout = null;
function showTyping(display) {{
  const el = document.getElementById('typing-indicator');
  el.textContent = display + ' is typing...';
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(()=>{{el.textContent=''}}, 3000);
}}

// ── File upload ───────────────────────────────────────────────────
function triggerFileUpload() {{ document.getElementById('file-input').click(); }}

async function uploadFile(input) {{
  const file = input.files[0];
  if (!file || !activeChat) return;
  const type = file.type.split('/')[0]; // image, video, audio
  const r = await fetch('/api/upload', {{
    method: 'POST',
    headers: {{'Content-Type': file.type}},
    body: file
  }});
  const data = await r.json();
  if (data.ok) {{
    await api('/api/messages/send', 'POST', {{
      chat_id: activeChat, text: file.name, type, file_id: data.file_id
    }});
    await loadMessages(activeChat);
  }}
  input.value = '';
}}

async function onPaste(e) {{
  const items = e.clipboardData?.items;
  if (!items) return;
  for (const item of items) {{
    if (item.type.startsWith('image/')) {{
      e.preventDefault();
      const blob = item.getAsFile();
      const r = await fetch('/api/upload', {{
        method:'POST', headers:{{'Content-Type':blob.type}}, body: blob
      }});
      const data = await r.json();
      if (data.ok) {{
        await api('/api/messages/send','POST',{{chat_id:activeChat,text:'Image',type:'image',file_id:data.file_id}});
        await loadMessages(activeChat);
      }}
    }}
  }}
}}

// ── Right panel ───────────────────────────────────────────────────
function toggleRightPanel() {{
  document.getElementById('right-panel').classList.toggle('open');
  if (document.getElementById('right-panel').classList.contains('open')) {{
    renderRightPanel();
  }}
}}

function renderRightPanel() {{
  if (!activeChat) return;
  const info = chatInfoCache[activeChat];
  if (!info) return;
  const rp = document.getElementById('rp-body');
  const myRole = info.my_role;
  const isAdmin = myRole === 'owner' || myRole === 'admin';
  const pubLink = info.invite_link ? `<div class="link-box" onclick="copyLink('${{location.origin}}/${{info.invite_link}}')">${{location.origin}}/${{info.invite_link}}</div>` : '';
  const privLink = info.private_invite ? `<div class="link-box" onclick="copyLink('${{location.origin}}/${{info.private_invite}}')">${{location.origin}}/${{info.private_invite}} (private)</div>` : '';
  const membersHtml = info.members.map(m => `
    <div class="member-item">
      <div class="member-av" onclick="openProfile('${{m.username}}')" style="cursor:pointer">${{m.avatar_emoji||'👤'}}</div>
      <div class="member-info">
        <div class="member-name">${{esc(m.display||m.username)}}</div>
        <div class="member-role">${{m.role}} · @${{m.username}}</div>
      </div>
      <div class="${{m.online?'member-online':'member-offline'}}"></div>
    </div>`).join('');

  rp.innerHTML = `
    <div class="rp-section">
      <div style="text-align:center;font-size:2.5em;margin-bottom:10px">${{info.avatar_emoji||'💬'}}</div>
      <div class="rp-name">${{esc(info.name)}}</div>
      <div class="rp-desc">${{esc(info.description||'No description')}}</div>
      <div class="rp-stat"><span>👥 ${{info.members_count}} members</span><span>📋 ${{info.type}}</span></div>
    </div>
    ${{isAdmin ? `<div class="rp-section">
      <div class="rp-section-title">Links</div>
      ${{pubLink}}${{privLink}}
    </div>` : pubLink ? `<div class="rp-section"><div class="rp-section-title">Link</div>${{pubLink}}</div>` : ''}}
    ${{isAdmin ? `<div class="rp-section">
      <div class="rp-section-title">Settings</div>
      <input class="rp-input" id="edit-name" value="${{esc(info.name)}}" placeholder="Name">
      <input class="rp-input" id="edit-desc" value="${{esc(info.description||'')}}" placeholder="Description">
      <button class="rp-btn" onclick="saveSettings()">${{LANG==='uk'?'Зберегти':'Save'}}</button>
    </div>` : ''}}
    <div class="rp-section">
      <div class="rp-section-title">Members (${{info.members_count}})</div>
      ${{membersHtml}}
    </div>
    <div class="rp-section">
      <button class="rp-btn danger" onclick="leaveChat()">${{myRole==='owner'?'Delete & Leave':'Leave chat'}}</button>
    </div>
  `;
}}

async function saveSettings() {{
  const name = document.getElementById('edit-name').value.trim();
  const desc = document.getElementById('edit-desc').value.trim();
  await api('/api/chats/update','POST',{{chat_id:activeChat,name,description:desc}});
  await loadChatInfo(activeChat);
  renderRightPanel();
  showToast('Saved!');
}}

async function leaveChat() {{
  if (!confirm('Leave this chat?')) return;
  const r = await api('/api/chats/leave','POST',{{chat_id:activeChat}});
  if (r.ok) {{ activeChat=null; location.reload(); }}
  else showToast(r.error||'Error');
}}

// ── Search ────────────────────────────────────────────────────────
let searchTimeout = null;
async function onSearch(q) {{
  clearTimeout(searchTimeout);
  if (!q.trim()) {{ document.getElementById('search-results').style.display='none'; return; }}
  searchTimeout = setTimeout(async ()=>{{
    const r = await api('/api/search_chats?q='+encodeURIComponent(q));
    const el = document.getElementById('search-results');
    if (!r.length) {{ el.style.display='none'; return; }}
    el.innerHTML = r.map(c=>`<div class="search-result-item" onclick="joinAndOpen('${{c.id}}')">
      <div style="font-size:1.4em">${{c.avatar_emoji}}</div>
      <div><div style="font-size:.88em;font-weight:600">${{esc(c.name)}}</div>
      <div style="font-size:.75em;color:var(--muted)">${{c.members_count}} members · ${{c.type}}</div></div>
    </div>`).join('');
    el.style.display = 'block';
  }}, 300);
}}

function closeSearch() {{ document.getElementById('search-results').style.display='none'; }}

async function joinAndOpen(chatId) {{
  document.getElementById('search-results').style.display='none';
  document.getElementById('search-input').value='';
  const r = await api('/api/chats/join','POST',{{chat_id:chatId}});
  await loadChats();
  selectChat(chatId);
}}

// ── Create chat ───────────────────────────────────────────────────
async function createChat() {{
  const name = document.getElementById('new-chat-name').value.trim();
  const type = document.getElementById('new-chat-type').value;
  const desc = document.getElementById('new-chat-desc').value.trim();
  const is_public = document.getElementById('new-chat-public').value === '1';
  if (!name) {{ showToast('Enter a name'); return; }}
  const r = await api('/api/chats/create','POST',{{name,type,description:desc,is_public,avatar_emoji:selectedEmoji}});
  if (r.ok) {{
    closeModal('create-chat-modal');
    await loadChats();
    selectChat(r.chat_id);
    showToast('Chat created!');
  }} else showToast(r.error||'Error');
}}

// ── Reactions ─────────────────────────────────────────────────────
function showReactionPicker(e, msgId) {{
  e.stopPropagation();
  reactionMsgId = msgId;
  const picker = document.getElementById('reaction-picker');
  picker.style.display = 'flex';
  picker.style.left = Math.min(e.clientX - 80, window.innerWidth - 280) + 'px';
  picker.style.top = e.clientY - 60 + 'px';
  setTimeout(()=>document.addEventListener('click',closeReactionPicker,{{once:true}}),10);
}}

function closeReactionPicker() {{
  document.getElementById('reaction-picker').style.display = 'none';
}}

async function addReaction(emoji) {{
  if (!reactionMsgId || !activeChat) return;
  closeReactionPicker();
  await reactMsg(reactionMsgId, emoji);
}}

async function reactMsg(msgId, emoji) {{
  await api('/api/messages/react','POST',{{chat_id:activeChat,msg_id:msgId,emoji}});
  await loadMessages(activeChat);
}}

function updateReactions(msgId, reactions) {{
  // Update in-place
  const msgEl = document.getElementById('msg-'+msgId);
  if (!msgEl) return;
  const container = msgEl.querySelector('.msg-reactions');
  if (container) {{
    const html = Object.entries(reactions||{{}}).filter(([,u])=>u.length>0).map(([e,users])=>{{
      const mine = users.includes(ME);
      return `<span class="reaction-badge${{mine?' mine':''}}" onclick="reactMsg('${{msgId}}','${{e}}')">${{e}} ${{users.length}}</span>`;
    }}).join('');
    container.innerHTML = html;
  }}
}}

// ── Profile ───────────────────────────────────────────────────────
async function openProfile(username) {{
  const info = await api('/api/profile?username='+username);
  profileTarget = username;
  document.getElementById('po-avatar').textContent = info.avatar_emoji || '👤';
  document.getElementById('po-name').textContent = info.display || username;
  document.getElementById('po-user').textContent = '@' + username;
  document.getElementById('po-bio').textContent = info.bio || '';
  document.getElementById('po-dm-btn').style.display = username === ME ? 'none' : '';
  document.getElementById('profile-overlay').classList.add('open');
}}

async function startDM() {{
  if (!profileTarget || profileTarget === ME) return;
  const r = await api('/api/dm/start','POST',{{username:profileTarget}});
  closeProfileOverlay();
  if (r.ok) {{ await loadChats(); selectChat(r.chat_id); }}
  else showToast(r.error||'Error');
}}

function closeProfileOverlay() {{
  document.getElementById('profile-overlay').classList.remove('open');
  profileTarget = null;
}}

async function openProfileSelf() {{
  const me = await api('/api/me');
  document.getElementById('pe-display').value = me.display || '';
  document.getElementById('pe-bio').value = me.bio || '';
  document.getElementById('pe-lang').value = LANG;
  openModal('profile-edit-modal');
}}

async function saveProfile() {{
  const r = await api('/api/profile/update','POST',{{
    display: document.getElementById('pe-display').value.trim(),
    bio: document.getElementById('pe-bio').value.trim(),
    avatar_emoji: selectedProfileEmoji,
    language: document.getElementById('pe-lang').value,
  }});
  if (r.ok) {{
    closeModal('profile-edit-modal');
    showToast('Saved!');
    setTimeout(()=>location.reload(), 1000);
  }}
}}

// ── Reply ─────────────────────────────────────────────────────────
function setReply(msgId, text, e) {{
  e?.stopPropagation();
  replyTo = msgId;
  document.getElementById('reply-preview').style.display = 'flex';
  document.getElementById('reply-text').textContent = '↩ ' + text;
  document.getElementById('msg-input').focus();
}}

function clearReply() {{
  replyTo = null;
  document.getElementById('reply-preview').style.display = 'none';
}}

// ── Media viewer ──────────────────────────────────────────────────
function openMedia(url, type) {{
  const overlay = document.createElement('div');
  overlay.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.95);z-index:9000;display:flex;align-items:center;justify-content:center;cursor:zoom-out';
  const el = type==='image' ? document.createElement('img') : document.createElement('video');
  el.src = url;
  el.style.maxWidth = '95vw'; el.style.maxHeight = '95vh'; el.style.borderRadius = '8px';
  if (type==='video') {{ el.controls=true; el.autoplay=true; }}
  overlay.appendChild(el);
  overlay.onclick = () => document.body.removeChild(overlay);
  document.body.appendChild(overlay);
}}

// ── Chat settings search in messages ─────────────────────────────
function openSearch() {{
  const q = prompt('Search in chat:');
  if (!q) return;
  const msgs = document.querySelectorAll('.msg-text');
  let found = 0;
  msgs.forEach(m => {{
    const orig = m.textContent;
    if (orig.toLowerCase().includes(q.toLowerCase())) {{
      m.innerHTML = orig.replace(new RegExp(q,'gi'), s=>`<mark style="background:var(--orange);color:#000;border-radius:2px">${{s}}</mark>`);
      found++;
    }}
  }});
  showToast(found ? `Found ${{found}} matches` : 'Not found');
}}

// ── Utils ─────────────────────────────────────────────────────────
async function doLogout() {{
  await api('/api/auth/logout','POST',{{}});
  location.href = '/auth';
}}

function getCookie(name) {{
  return document.cookie.split(';').map(c=>c.trim()).find(c=>c.startsWith(name+'='))?.split('=')[1]||'';
}}

async function api(url, method='GET', body=null) {{
  const opts = {{method, headers:{{'Content-Type':'application/json'}}}};
  if (body) opts.body = JSON.stringify(body);
  try {{
    const r = await fetch(url, opts);
    return await r.json();
  }} catch(e) {{ return {{error:'Network error'}}; }}
}}

function esc(s) {{
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

function linkify(text) {{
  return text.replace(/(https?:\\/\\/[^\\s]+)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>');
}}

function openModal(id) {{ document.getElementById(id).classList.add('open'); }}
function closeModal(id) {{ document.getElementById(id).classList.remove('open'); }}

function selectEmoji(el, e) {{
  selectedEmoji = e;
  document.querySelectorAll('#emoji-picker .emoji-opt').forEach(x=>x.classList.remove('selected'));
  el.classList.add('selected');
}}

function selectProfileEmoji(el, e) {{
  selectedProfileEmoji = e;
  document.querySelectorAll('#profile-emoji-picker .emoji-opt').forEach(x=>x.classList.remove('selected'));
  el.classList.add('selected');
}}

function copyLink(link) {{
  navigator.clipboard.writeText(link).then(()=>showToast('Link copied!'));
}}

let toastTimer = null;
function showToast(msg) {{
  let t = document.getElementById('global-toast');
  if (!t) {{ t=document.createElement('div'); t.id='global-toast'; t.className='toast'; document.body.appendChild(t); }}
  t.textContent = msg; t.style.display='block';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>{{t.style.display='none';}}, 2500);
}}

function pollTyping() {{}} // handled by WS

function scrollToPinned() {{
  const info = chatInfoCache[activeChat];
  if (!info?.pinned_message) return;
  const el = document.getElementById('msg-'+info.pinned_message);
  el?.scrollIntoView({{behavior:'smooth',block:'center'}});
}}

// Close modals on overlay click
document.addEventListener('click', e=>{{
  if (e.target.classList.contains('modal-overlay')) e.target.classList.remove('open');
}});

document.addEventListener('keydown', e=>{{
  if (e.key==='Escape') {{
    document.querySelectorAll('.modal-overlay.open').forEach(m=>m.classList.remove('open'));
    document.getElementById('profile-overlay').classList.remove('open');
  }}
}});

init();
</script>
</body>
</html>"""


def build_profile_page(profile_user: dict, viewer: dict, lang="en") -> str:
    uname = profile_user.get("username", "")
    display = profile_user.get("display", uname)
    bio = profile_user.get("bio", "")
    emoji = profile_user.get("avatar_emoji", "👤")
    is_self = viewer.get("username") == uname

    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{display} — NexoChat</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
:root{{--bg:#0d0d0d;--card:#141414;--orange:#ff6b00;--orange2:#ff8c00;--border:rgba(255,107,0,.25);--text:#f0f0f0;--muted:#777;--font:'Segoe UI',system-ui,sans-serif;}}
body{{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;}}
.card{{background:var(--card);border:1.5px solid var(--border);border-radius:24px;padding:40px 32px;width:100%;max-width:400px;text-align:center;box-shadow:0 0 60px rgba(255,107,0,.08);}}
.avatar{{font-size:5em;margin-bottom:16px;}}
.name{{font-size:1.6em;font-weight:900;margin-bottom:4px;}}
.user{{color:var(--muted);font-size:.9em;margin-bottom:16px;}}
.bio{{color:var(--muted);font-size:.92em;line-height:1.6;margin-bottom:24px;padding:0 8px;}}
.actions{{display:flex;justify-content:center;gap:10px;flex-wrap:wrap;}}
.btn{{padding:11px 22px;border:none;border-radius:10px;font-size:.92em;font-weight:700;cursor:pointer;text-decoration:none;transition:all .2s;display:inline-block;}}
.btn-primary{{background:linear-gradient(135deg,var(--orange),var(--orange2));color:#fff;box-shadow:0 4px 16px rgba(255,107,0,.25);}}
.btn-primary:hover{{transform:translateY(-1px);box-shadow:0 6px 24px rgba(255,107,0,.4);}}
.btn-secondary{{background:rgba(255,255,255,.07);color:var(--text);}}
.btn-secondary:hover{{background:rgba(255,255,255,.12);}}
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
    {'<button class="btn btn-primary" onclick="editProfile()">✏️ Edit profile</button>' if is_self else ''}
    {'<button class="btn btn-primary" onclick="sendMessage()">💬 Message</button>' if not is_self else ''}
    <a class="btn btn-secondary" href="/">← Back</a>
  </div>
  <div class="back"><a href="/">Open NexoChat</a></div>
</div>
<script>
function editProfile() {{ location.href = '/?profile=edit'; }}
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
    name = chat.get("name", "Chat")
    desc = chat.get("description", "")
    emoji = chat.get("avatar_emoji", "💬")
    ctype = chat.get("type", "group")
    members = len(chat.get("members", [])) + 1
    chat_id = chat.get("id", "")
    invite = chat.get("invite_link") or chat.get("private_invite") or chat_id

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
:root{{--bg:#0d0d0d;--card:#141414;--orange:#ff6b00;--orange2:#ff8c00;--border:rgba(255,107,0,.25);--text:#f0f0f0;--muted:#777;--blue:#29b6f6;--green:#4caf50;--font:'Segoe UI',system-ui,sans-serif;}}
body{{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;}}
body::before{{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 60% 50% at 50% 50%,rgba(255,107,0,.06) 0%,transparent 70%);pointer-events:none;}}
.card{{position:relative;background:var(--card);border:1.5px solid var(--border);border-radius:24px;padding:40px 32px;width:100%;max-width:420px;text-align:center;box-shadow:0 0 60px rgba(255,107,0,.1);}}
.avatar{{font-size:5em;margin-bottom:16px;}}
.type-badge{{display:inline-block;padding:4px 12px;border-radius:12px;font-size:.72em;font-weight:700;margin-bottom:12px;background:rgba(255,107,0,.12);color:var(--orange);border:1px solid rgba(255,107,0,.2);}}
.name{{font-size:1.7em;font-weight:900;margin-bottom:8px;}}
.desc{{color:var(--muted);font-size:.9em;line-height:1.6;margin-bottom:20px;}}
.stats{{display:flex;justify-content:center;gap:24px;margin-bottom:28px;}}
.stat{{text-align:center;}}
.stat-val{{font-size:1.3em;font-weight:800;color:var(--orange);}}
.stat-label{{font-size:.72em;color:var(--muted);margin-top:2px;}}
.join-btn{{width:100%;padding:14px;background:linear-gradient(135deg,var(--orange),var(--orange2));border:none;border-radius:12px;color:#fff;font-size:1em;font-weight:800;cursor:pointer;transition:all .2s;box-shadow:0 4px 20px rgba(255,107,0,.3);}}
.join-btn:hover{{transform:translateY(-2px);box-shadow:0 6px 28px rgba(255,107,0,.45);}}
.back{{margin-top:16px;font-size:.82em;color:var(--muted);}}
.back a{{color:var(--orange);text-decoration:none;font-weight:600;}}
.msg{{margin-top:12px;font-size:.8em;padding:8px;border-radius:8px;display:none;}}
.msg.err{{background:rgba(255,68,68,.1);color:#ff4444;display:block;}}
.msg.ok{{background:rgba(76,175,80,.1);color:var(--green);display:block;}}
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
  const msg = document.getElementById('msg');
  if (data.ok) {{
    msg.textContent = 'Joined! Redirecting...';
    msg.className = 'msg ok';
    setTimeout(()=>location.href='/', 1200);
  }} else {{
    msg.textContent = data.error || 'Error';
    msg.className = 'msg err';
  }}
}}
</script>
</body>
</html>"""


# ── Main ──────────────────────────────────────────────────────────
def main():
    seed()
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "0.0.0.0")

    server = HTTPServer((host, port), NexoHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    log.info(f"NexoChat running at http://{host}:{port}")
    log.info("Default admin: admin / admin123")
    log.info("Auth: http://localhost:{port}/auth")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutdown")
        server.server_close()


if __name__ == "__main__":
    main()
