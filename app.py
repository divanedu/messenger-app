import streamlit as st
import sqlite3
import hmac
import hashlib
import secrets
import re
import time
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

DB_PATH = "messenger.db"

# -------------------------
# Security helpers (PBKDF2)
# -------------------------
PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16

def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Empty password")
    salt = secrets.token_bytes(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters_str, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

# -------------------------
# Validation
# -------------------------
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")

def valid_username(username: str) -> bool:
    return bool(USERNAME_RE.match((username or "").strip()))

# -------------------------
# DB helpers
# -------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_pair_time ON messages(sender_id, receiver_id, created_at);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_receiver_time ON messages(receiver_id, created_at);")

    conn.commit()
    conn.close()

def create_user(username: str, password: str) -> tuple[bool, str]:
    username = (username or "").strip()

    if not valid_username(username):
        return False, "Логин: 3–32 символа, только буквы/цифры и _. -"
    if not password or len(password) < 6:
        return False, "Пароль должен быть минимум 6 символов."
    if len(password) > 128:
        return False, "Пароль слишком длинный."

    pw_hash = hash_password(password)
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, pw_hash, datetime.utcnow().isoformat())
        )
        conn.commit()
        return True, "Пользователь создан. Теперь войдите."
    except sqlite3.IntegrityError:
        return False, "Такой логин уже существует."
    finally:
        conn.close()

def authenticate(username: str, password: str):
    username = (username or "").strip()
    if not valid_username(username):
        return None

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    user_id, uname, pw_hash = row
    if verify_password(password or "", pw_hash):
        return {"id": user_id, "username": uname}
    return None

def get_user_by_id(user_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {"id": row[0], "username": row[1]}

def search_users(query: str, exclude_user_id: int, limit: int = 50):
    q = (query or "").strip()
    conn = get_conn()
    cur = conn.cursor()

    if q == "":
        cur.execute(
            "SELECT id, username FROM users WHERE id != ? ORDER BY username LIMIT ?",
            (exclude_user_id, limit)
        )
    else:
        cur.execute(
            "SELECT id, username FROM users WHERE id != ? AND username LIKE ? ORDER BY username LIMIT ?",
            (exclude_user_id, f"%{q}%", limit)
        )
    rows = cur.fetchall()
    conn.close()
    return [{"id": r[0], "username": r[1]} for r in rows]

def send_message(sender_id: int, receiver_id: int, body: str) -> tuple[bool, str]:
    text = (body or "").strip()
    if not text:
        return False, "Сообщение пустое."
    if len(text) > 2000:
        return False, "Сообщение слишком длинное (макс 2000)."

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO messages(sender_id, receiver_id, body, created_at) VALUES (?, ?, ?, ?)",
        (sender_id, receiver_id, text, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    return True, "Отправлено."

def get_conversation(user_a: int, user_b: int, limit: int = 200):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, sender_id, receiver_id, body, created_at
        FROM messages
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY datetime(created_at) ASC, id ASC
        LIMIT ?
    """, (user_a, user_b, user_b, user_a, limit))
    rows = cur.fetchall()
    conn.close()
    return [{
        "id": r[0],
        "sender_id": r[1],
        "receiver_id": r[2],
        "body": r[3],
        "created_at": r[4],
    } for r in rows]

def inbox_preview(user_id: int, limit: int = 20):
    """
    Последние входящие сообщения. Возвращаем msg_id, чтобы делать 100% уникальные ключи в UI.
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT m.id, m.sender_id, u.username, m.body, m.created_at
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.receiver_id = ?
        ORDER BY datetime(m.created_at) DESC, m.id DESC
        LIMIT ?
    """, (user_id, limit))
    rows = cur.fetchall()
    conn.close()
    return [{
        "msg_id": r[0],
        "from_id": r[1],
        "from_username": r[2],
        "body": r[3],
        "created_at": r[4],
    } for r in rows]

# -------------------------
# UI / State
# -------------------------
def ensure_state():
    st.session_state.setdefault("user", None)
    st.session_state.setdefault("chat_with_id", None)
    st.session_state.setdefault("user_search", "")
    st.session_state.setdefault("compose_text", "")

    st.session_state.setdefault("autorefresh_enabled", True)
    st.session_state.setdefault("autorefresh_ms", 1200)
    st.session_state.setdefault("pause_refresh_while_typing", True)

def logout():
    st.session_state.user = None
    st.session_state.chat_with_id = None
    st.session_state.compose_text = ""
    st.session_state.user_search = ""
    st.rerun()

def apply_styles():
    st.markdown(
        """
        <style>
        /* Wider content, cleaner spacing */
        .block-container { padding-top: 1.2rem; padding-bottom: 2rem; max-width: 1200px; }

        /* Hide Streamlit default menu/footer */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}

        /* Titles */
        .app-title { font-size: 26px; font-weight: 800; margin-bottom: 0.2rem; }
        .app-sub { opacity: 0.75; margin-bottom: 1rem; }

        /* Sidebar card */
        .card {
            border: 1px solid rgba(255,255,255,0.10);
            border-radius: 16px;
            padding: 14px 14px;
            background: rgba(255,255,255,0.03);
            margin-bottom: 12px;
        }

        /* Chat area */
        .chat-wrap {
            border: 1px solid rgba(255,255,255,0.10);
            border-radius: 18px;
            padding: 14px 14px;
            background: rgba(255,255,255,0.02);
        }

        .msg-row { margin: 10px 0; display:flex; }
        .msg-left { justify-content:flex-start; }
        .msg-right { justify-content:flex-end; }

        .bubble {
            max-width: 78%;
            padding: 10px 12px;
            border-radius: 14px;
            line-height: 1.35;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .bubble-me {
            background: #1f2937;
            color: #fff;
            border-top-right-radius: 6px;
        }
        .bubble-other {
            background: #f3f4f6;
            color: #111827;
            border-top-left-radius: 6px;
        }
        .meta {
            font-size: 12px;
            opacity: 0.75;
            margin-bottom: 4px;
        }

        /* Compact buttons */
        div.stButton > button {
            border-radius: 12px;
            padding: 0.55rem 0.85rem;
        }

        /* Inputs */
        .stTextInput input, .stTextArea textarea {
            border-radius: 12px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

def header():
    st.markdown('<div class="app-title">💬 Messenger</div>', unsafe_allow_html=True)
    st.markdown('<div class="app-sub">Регистрация • Вход • Поиск пользователей • Личные сообщения</div>', unsafe_allow_html=True)

def auth_screen():
    st.subheader("Вход / Регистрация")
    tab_login, tab_register = st.tabs(["Вход", "Регистрация"])

    with tab_login:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        username = st.text_input("Логин", key="login_username", placeholder="username")
        password = st.text_input("Пароль", type="password", key="login_password", placeholder="••••••••")
        if st.button("Войти", type="primary", key="btn_login"):
            if not valid_username(username):
                st.error("Некорректный логин.")
            else:
                user = authenticate(username, password)
                if user:
                    st.session_state.user = user
                    st.success("Вход выполнен.")
                    st.rerun()
                else:
                    time.sleep(0.6)  # small anti-bruteforce delay
                    st.error("Неверный логин или пароль.")
        st.markdown('</div>', unsafe_allow_html=True)

    with tab_register:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        new_username = st.text_input("Новый логин", key="reg_username", placeholder="username")
        new_password = st.text_input("Новый пароль", type="password", key="reg_password", placeholder="••••••••")
        new_password2 = st.text_input("Повтор пароля", type="password", key="reg_password2", placeholder="••••••••")

        if st.button("Создать аккаунт", type="primary", key="btn_register"):
            if new_password != new_password2:
                st.error("Пароли не совпадают.")
            else:
                ok, msg = create_user(new_username, new_password)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)
        st.markdown('</div>', unsafe_allow_html=True)

def maybe_autorefresh():
    if not st.session_state.autorefresh_enabled:
        return
    if st.session_state.pause_refresh_while_typing and st.session_state.compose_text.strip():
        return
    st_autorefresh(interval=st.session_state.autorefresh_ms, key="chat_autorefresh")

def messenger_screen():
    user = st.session_state.user
    assert user is not None

    maybe_autorefresh()

    col_left, col_right = st.columns([1.05, 2.25], gap="large")

    with col_left:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown(f"### 👤 {user['username']}")
        c1, c2 = st.columns([1, 1])
        with c1:
            if st.button("Выйти", key="btn_logout"):
                logout()
        with c2:
            st.session_state.autorefresh_enabled = st.toggle(
                "Auto",
                value=st.session_state.autorefresh_enabled,
                key="toggle_autorefresh"
            )
        st.caption("Auto = автообновление чатов")
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown("#### ⚙️ Настройки")
        st.session_state.pause_refresh_while_typing = st.toggle(
            "Пауза при вводе",
            value=st.session_state.pause_refresh_while_typing,
            key="toggle_pause_typing"
        )
        st.session_state.autorefresh_ms = st.slider(
            "Частота (мс)",
            min_value=800,
            max_value=5000,
            value=st.session_state.autorefresh_ms,
            step=100,
            key="slider_refresh_ms"
        )
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown("#### 🔎 Пользователи")
        st.session_state.user_search = st.text_input(
            "Поиск",
            value=st.session_state.user_search,
            placeholder="введите логин",
            label_visibility="collapsed",
            key="input_user_search"
        )

        users = search_users(st.session_state.user_search, exclude_user_id=user["id"], limit=50)

        if not users:
            st.info("Никого не найдено.")
        else:
            for u in users:
                is_selected = (st.session_state.chat_with_id == u["id"])
                label = f"✅ {u['username']}" if is_selected else f"{u['username']}"
                if st.button(label, key=f"user_pick_{u['id']}"):
                    st.session_state.chat_with_id = u["id"]
                    st.session_state.compose_text = ""
                    st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown("#### 📥 Входящие")
        previews = inbox_preview(user["id"], limit=10)
        if not previews:
            st.caption("Пока нет входящих сообщений.")
        else:
            for p in previews:
                ts = p["created_at"].replace("T", " ")[:16]
                st.write(f"**{p['from_username']}** · {ts}")
                st.caption(p["body"][:120] + ("…" if len(p["body"]) > 120 else ""))

                # 100% unique key uses message id
                if st.button(
                    "Открыть чат",
                    key=f"open_from_msg_{p['msg_id']}"
                ):
                    st.session_state.chat_with_id = p["from_id"]
                    st.session_state.compose_text = ""
                    st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    with col_right:
        chat_with_id = st.session_state.chat_with_id
        if not chat_with_id:
            st.info("Выбери пользователя слева, чтобы начать переписку.")
            return

        other = get_user_by_id(chat_with_id)
        if not other:
            st.error("Пользователь не найден (возможно удалён).")
            st.session_state.chat_with_id = None
            return

        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown(f"### 💬 Чат с **{other['username']}**")
        st.caption("Сообщения обновляются автоматически (если включён Auto).")
        st.markdown('</div>', unsafe_allow_html=True)

        msgs = get_conversation(user["id"], other["id"], limit=250)

        st.markdown('<div class="chat-wrap">', unsafe_allow_html=True)
        if not msgs:
            st.caption("Сообщений пока нет. Напиши первым(ой).")
        else:
            for m in msgs:
                sender_is_me = (m["sender_id"] == user["id"])
                ts = m["created_at"].replace("T", " ")[:16]
                who = "Вы" if sender_is_me else other["username"]

                if sender_is_me:
                    st.markdown(
                        f"""
                        <div class="msg-row msg-right">
                          <div class="bubble bubble-me">
                            <div class="meta">{who} · {ts}</div>
                            {m['body']}
                          </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                else:
                    st.markdown(
                        f"""
                        <div class="msg-row msg-left">
                          <div class="bubble bubble-other">
                            <div class="meta">{who} · {ts}</div>
                            {m['body']}
                          </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.session_state.compose_text = st.text_area(
            "Сообщение",
            value=st.session_state.compose_text,
            placeholder="Напиши сообщение…",
            height=120,
            label_visibility="collapsed",
            key="textarea_compose"
        )

        c1, c2 = st.columns([1, 1])
        with c1:
            if st.button("Отправить", type="primary", key="btn_send"):
                ok, msg = send_message(user["id"], other["id"], st.session_state.compose_text)
                if ok:
                    st.session_state.compose_text = ""
                    st.rerun()
                else:
                    st.error(msg)
        with c2:
            if st.button("Очистить", key="btn_clear"):
                st.session_state.compose_text = ""
                st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)

# -------------------------
# App
# -------------------------
def main():
    st.set_page_config(page_title="Messenger", page_icon="💬", layout="wide")
    init_db()
    ensure_state()
    apply_styles()
    header()

    if st.session_state.user is None:
        auth_screen()
    else:
        messenger_screen()

if __name__ == "__main__":
    main()
