import streamlit as st
import sqlite3
import hmac
import hashlib
import secrets
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

DB_PATH = "messenger.db"

# -------------------------
# Security helpers (PBKDF2)
# -------------------------
PBKDF2_ITERATIONS = 200_000
SALT_BYTES = 16

def hash_password(password: str) -> str:
    """
    Returns a string: pbkdf2_sha256$iterations$salt_hex$hash_hex
    """
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
    username = username.strip()
    if not username or len(username) < 3:
        return False, "Логин должен быть минимум 3 символа."
    if len(username) > 32:
        return False, "Логин слишком длинный (макс 32)."
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
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username.strip(),))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    user_id, uname, pw_hash = row
    if verify_password(password, pw_hash):
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
        SELECT sender_id, receiver_id, body, created_at
        FROM messages
        WHERE (sender_id = ? AND receiver_id = ?)
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY datetime(created_at) ASC
        LIMIT ?
    """, (user_a, user_b, user_b, user_a, limit))
    rows = cur.fetchall()
    conn.close()
    return [{
        "sender_id": r[0],
        "receiver_id": r[1],
        "body": r[2],
        "created_at": r[3],
    } for r in rows]

def inbox_preview(user_id: int, limit: int = 20):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT m.sender_id, u.username, m.body, m.created_at
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.receiver_id = ?
        ORDER BY datetime(m.created_at) DESC
        LIMIT ?
    """, (user_id, limit))
    rows = cur.fetchall()
    conn.close()
    return [{"from_id": r[0], "from_username": r[1], "body": r[2], "created_at": r[3]} for r in rows]

# -------------------------
# State + UI helpers
# -------------------------
def ensure_state():
    st.session_state.setdefault("user", None)
    st.session_state.setdefault("chat_with_id", None)
    st.session_state.setdefault("user_search", "")
    st.session_state.setdefault("compose_text", "")

    # Автообновление
    st.session_state.setdefault("autorefresh_enabled", True)
    st.session_state.setdefault("autorefresh_ms", 1500)          # частота обновления
    st.session_state.setdefault("pause_refresh_while_typing", True)

def logout():
    st.session_state.user = None
    st.session_state.chat_with_id = None
    st.session_state.compose_text = ""
    st.session_state.user_search = ""
    st.rerun()

def header():
    st.markdown("## 💬 Streamlit Messenger (MVP)")
    st.caption("Регистрация, логин, поиск пользователей, личные сообщения (только текст).")

def auth_screen():
    st.subheader("Вход / Регистрация")
    tab_login, tab_register = st.tabs(["Вход", "Регистрация"])

    with tab_login:
        username = st.text_input("Логин", key="login_username")
        password = st.text_input("Пароль", type="password", key="login_password")
        if st.button("Войти", type="primary"):
            user = authenticate(username, password)
            if user:
                st.session_state.user = user
                st.success("Вход выполнен.")
                st.rerun()
            else:
                st.error("Неверный логин или пароль.")

    with tab_register:
        new_username = st.text_input("Новый логин", key="reg_username")
        new_password = st.text_input("Новый пароль", type="password", key="reg_password")
        new_password2 = st.text_input("Повтор пароля", type="password", key="reg_password2")

        if st.button("Создать аккаунт", type="primary"):
            if new_password != new_password2:
                st.error("Пароли не совпадают.")
            else:
                ok, msg = create_user(new_username, new_password)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

def maybe_autorefresh():
    """
    Автообновление без кнопки.
    Важно: когда пользователь печатает сообщение, частые rerun могут мешать набору.
    Поэтому по умолчанию: если текст не пустой — пауза.
    """
    if not st.session_state.autorefresh_enabled:
        return

    if st.session_state.pause_refresh_while_typing and st.session_state.compose_text.strip():
        return

    # Это вызывает rerun каждые N мс
    st_autorefresh(interval=st.session_state.autorefresh_ms, key="chat_autorefresh")

def messenger_screen():
    user = st.session_state.user
    assert user is not None

    # Запускаем автообновление на странице мессенджера
    maybe_autorefresh()

    col_left, col_right = st.columns([1.1, 2.2], gap="large")

    with col_left:
        st.markdown(f"### 👤 {user['username']}")
        if st.button("Выйти"):
            logout()

        st.divider()

        # Настройки автообновления (кнопки "обновить" больше нет)
        st.markdown("#### ⚙️ Автообновление")
        st.session_state.autorefresh_enabled = st.toggle(
            "Автообновление включено",
            value=st.session_state.autorefresh_enabled
        )
        st.session_state.pause_refresh_while_typing = st.toggle(
            "Пауза, когда печатаю",
            value=st.session_state.pause_refresh_while_typing
        )
        st.session_state.autorefresh_ms = st.slider(
            "Частота (мс)",
            min_value=800,
            max_value=5000,
            value=st.session_state.autorefresh_ms,
            step=100
        )

        st.divider()

        st.markdown("#### 🔎 Поиск пользователей")
        st.session_state.user_search = st.text_input(
            "Введите логин",
            value=st.session_state.user_search,
            placeholder="например: ivan",
            label_visibility="collapsed"
        )

        users = search_users(st.session_state.user_search, exclude_user_id=user["id"], limit=50)

        if not users:
            st.info("Никого не найдено.")
        else:
            st.caption("Нажми на пользователя, чтобы открыть чат.")
            for u in users:
                is_selected = (st.session_state.chat_with_id == u["id"])
                btn_label = f"➡️ {u['username']}" if not is_selected else f"✅ {u['username']}"
                if st.button(btn_label, key=f"user_pick_{u['id']}"):
                    st.session_state.chat_with_id = u["id"]
                    st.session_state.compose_text = ""
                    st.rerun()

        st.divider()
        st.markdown("#### 📥 Последние входящие")
        previews = inbox_preview(user["id"], limit=10)
        if not previews:
            st.caption("Пока нет входящих сообщений.")
        else:
            for p in previews:
                ts = p["created_at"].replace("T", " ")[:19]
                st.write(f"**{p['from_username']}** · {ts}")
                st.caption(p["body"][:120] + ("…" if len(p["body"]) > 120 else ""))
                if st.button(f"Открыть чат с {p['from_username']}", key=f"open_from_{p['from_id']}"):
                    st.session_state.chat_with_id = p["from_id"]
                    st.session_state.compose_text = ""
                    st.rerun()

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

        st.markdown(f"### 💬 Чат с **{other['username']}**")

        msgs = get_conversation(user["id"], other["id"], limit=200)

        st.markdown("---")
        with st.container():
            if not msgs:
                st.caption("Сообщений пока нет. Напиши первым(ой).")
            else:
                for m in msgs:
                    sender_is_me = (m["sender_id"] == user["id"])
                    ts = m["created_at"].replace("T", " ")[:19]
                    name = "Вы" if sender_is_me else other["username"]

                    if sender_is_me:
                        st.markdown(
                            f"""
                            <div style="text-align:right; margin: 10px 0;">
                              <div style="display:inline-block; padding:10px 12px; border-radius:12px; background:#2b2b2b; color:#fff; max-width:80%;">
                                <div style="font-size:12px; opacity:.75;">{name} · {ts}</div>
                                <div style="white-space:pre-wrap;">{m['body']}</div>
                              </div>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
                    else:
                        st.markdown(
                            f"""
                            <div style="text-align:left; margin: 10px 0;">
                              <div style="display:inline-block; padding:10px 12px; border-radius:12px; background:#f0f2f6; color:#000; max-width:80%;">
                                <div style="font-size:12px; opacity:.75;">{name} · {ts}</div>
                                <div style="white-space:pre-wrap;">{m['body']}</div>
                              </div>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )

        st.markdown("---")

        st.session_state.compose_text = st.text_area(
            "Сообщение",
            value=st.session_state.compose_text,
            placeholder="Напиши сообщение…",
            height=120,
            label_visibility="collapsed"
        )

        c1, c2 = st.columns([1, 4])
        with c1:
            if st.button("Отправить", type="primary"):
                ok, msg = send_message(user["id"], other["id"], st.session_state.compose_text)
                if ok:
                    st.session_state.compose_text = ""
                    st.rerun()
                else:
                    st.error(msg)
        with c2:
            st.caption("Сообщения обновляются автоматически.")

# -------------------------
# App
# -------------------------
def main():
    st.set_page_config(page_title="Streamlit Messenger", page_icon="💬", layout="wide")
    init_db()
    ensure_state()

    header()

    if st.session_state.user is None:
        auth_screen()
    else:
        messenger_screen()

if __name__ == "__main__":
    main()
