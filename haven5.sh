#!/usr/bin/env bash
# ==========================================================================
#  Haven 5.0 - private, encrypted, self-hosted chat for Ubuntu Server
#
#  First time / upgrading (keeps all your data):
#      sudo bash haven5.sh
#  After that you can use the short command  "haven":
#      sudo haven status            health, address, certificate, backups
#      sudo haven backup            save a backup now (also runs nightly)
#      sudo haven restore FILE      restore from a backup file
#      sudo haven regen-cert        refresh the HTTPS certificate (after an IP change)
#      sudo haven uninstall         remove the app, KEEP accounts and messages
#      sudo haven uninstall --purge remove everything including all data
#
#  What it sets up (all from apt, no Docker):
#      Haven app  (Python/Flask/SQLite)  127.0.0.1:6061   - private, local only
#      nginx + your own private certificate authority    - HTTPS on port 6060
#  Folders: /opt/haven (app)  /var/lib/haven (data)  /etc/haven/tls (certificates)
# ==========================================================================
set -euo pipefail

HAVEN_VERSION="5.0.0"
APP_DIR="/opt/haven"
DATA_DIR="/var/lib/haven"
CONF_DIR="/etc/haven"
TLS_DIR="/etc/haven/tls"
UNIT="/etc/systemd/system/haven.service"
BK_SERVICE="/etc/systemd/system/haven-backup.service"
BK_TIMER="/etc/systemd/system/haven-backup.timer"
NGINX_CONF="/etc/nginx/conf.d/haven.conf"
WRAPPER="/usr/local/bin/haven-admin"
CTL="/usr/local/bin/haven"
PORT=6060        # what you type in the browser (HTTPS)
APP_PORT=6061    # internal only
KEEP_BACKUPS=14

if [ -t 1 ]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'; else B=""; G=""; Y=""; R=""; N=""; fi
say()  { printf '%s\n' "${G}==>${N} $*"; }
warn() { printf '%s\n' "${Y}!! ${N}$*"; }
die()  { printf '%s\n' "${R}Error:${N} $*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "Please run with sudo:  sudo bash $0 ${*:-}"; }
lan_ip()     { hostname -I 2>/dev/null | awk '{print $1}'; }
lan_subnet() { ip -o -4 route show scope link 2>/dev/null | awk '{print $1}' | grep '/' | head -1 || true; }
ufw_active() { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; }
port_busy()  { ss -ltn 2>/dev/null | grep -q ":$1 "; }

health() {
python3 - <<'PY' 2>/dev/null
import urllib.request, sys
try:
    body = urllib.request.urlopen("http://127.0.0.1:6061/health", timeout=2).read()
    sys.exit(0 if b'"ok"' in body else 1)
except Exception:
    sys.exit(1)
PY
}

health_https() {
python3 - <<'PY' 2>/dev/null
import urllib.request, ssl, sys
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    body = urllib.request.urlopen("https://127.0.0.1:6060/health", timeout=3, context=ctx).read()
    sys.exit(0 if b'"ok"' in body else 1)
except Exception:
    sys.exit(1)
PY
}

# --------------------------------------------------------------------------
write_app() {
cat > "$APP_DIR/app.py" <<'HAVEN_PY'
#!/usr/bin/env python3
"""Haven 5 - private self-hosted chat. Flask + SQLite + Waitress (behind nginx TLS)."""
import io, os, re, sys, json, time, sqlite3, secrets, threading, getpass
from datetime import timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, g, Response, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageOps, ImageDraw

VERSION = "5.0.0"
DATA = os.environ.get("HAVEN_DATA", "/var/lib/haven")
DB = os.path.join(DATA, "haven.db")
UPLOADS = os.path.join(DATA, "uploads")
AVATARS = os.path.join(DATA, "avatars")
CA_PATH = os.environ.get("HAVEN_CA", "/etc/haven/tls/ca.crt")
PORT = int(os.environ.get("HAVEN_PORT", "6061"))
BIND = os.environ.get("HAVEN_BIND", "127.0.0.1")
TLS = os.environ.get("HAVEN_TLS") == "1"
MAX_UPLOAD = 8 * 1024 * 1024      # photos
MAX_AUDIO = 10 * 1024 * 1024      # voice messages
MAX_FILE = 25 * 1024 * 1024       # any file
MAX_E2E = 14000
E2E = "e2e:1:"
REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🎉", "🔥", "👀", "🙏", "✅"]
IMG_EXT = {"PNG": "png", "JPEG": "jpg", "GIF": "gif", "WEBP": "webp"}
IMG_EXTS = {"png", "jpg", "gif", "webp"}
AUDIO_EXTS = {"webm", "ogg", "m4a"}
IMG_MIME = {"png": "image/png", "jpg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
            "webm": "audio/webm", "ogg": "audio/ogg", "m4a": "audio/mp4",
            "bin": "application/octet-stream", "file": "application/octet-stream"}
UP_RE = re.compile(r"^[a-f0-9]{32}\.(png|jpg|gif|webp|bin|file|webm|ogg|m4a)$")
AV_RE = re.compile(r"^[a-f0-9]{24}\.jpg$")
TTL_OPTIONS = {0, 3600, 86400, 604800, 2592000}
Image.MAX_IMAGE_PIXELS = 40_000_000

os.makedirs(UPLOADS, exist_ok=True)
os.makedirs(AVATARS, exist_ok=True)


def load_secret():
    p = os.path.join(DATA, "secret.key")
    if not os.path.exists(p):
        fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    with open(p) as f:
        return f.read().strip()


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = load_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=TLS,
    SESSION_COOKIE_NAME="haven_session",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    MAX_CONTENT_LENGTH=MAX_FILE + 512 * 1024,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, name TEXT UNIQUE COLLATE NOCASE, pw TEXT,
  admin INTEGER DEFAULT 0, pwv INTEGER DEFAULT 1, created REAL, last_seen REAL DEFAULT 0,
  avatar TEXT, status TEXT, enc_pub TEXT, enc_priv TEXT, receipts INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS rooms(
  id INTEGER PRIMARY KEY, name TEXT UNIQUE COLLATE NOCASE, created REAL,
  kind TEXT NOT NULL DEFAULT 'channel', topic TEXT, ttl INTEGER DEFAULT 0, ttl_since REAL DEFAULT 0,
  created_by INTEGER);
CREATE TABLE IF NOT EXISTS room_members(
  room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY(room_id, user_id));
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY,
  room_id INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  text TEXT, ts REAL, rev INTEGER, edited INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0,
  image TEXT, iw INTEGER, ih INTEGER, reply_to INTEGER,
  fname TEXT, fsize INTEGER, kind TEXT DEFAULT 'text');
CREATE INDEX IF NOT EXISTS m_room ON messages(room_id, rev);
CREATE TABLE IF NOT EXISTS reactions(
  message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  emoji TEXT, PRIMARY KEY(message_id, user_id, emoji));
CREATE TABLE IF NOT EXISTS pins(
  message_id INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
  room_id INTEGER, user_id INTEGER, ts REAL);
CREATE TABLE IF NOT EXISTS bookmarks(
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
  ts REAL, PRIMARY KEY(user_id, message_id));
CREATE TABLE IF NOT EXISTS poll_votes(
  message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  opt INTEGER, PRIMARY KEY(message_id, user_id, opt));
CREATE TABLE IF NOT EXISTS room_prefs(
  user_id INTEGER, room_id INTEGER, muted INTEGER DEFAULT 0, PRIMARY KEY(user_id, room_id));
CREATE TABLE IF NOT EXISTS invites(
  code TEXT PRIMARY KEY, created_by INTEGER, uses_left INTEGER, expires REAL);
CREATE TABLE IF NOT EXISTS uploads(
  name TEXT PRIMARY KEY, user_id INTEGER, iw INTEGER, ih INTEGER, ts REAL, used INTEGER DEFAULT 0,
  fname TEXT, fsize INTEGER);
CREATE TABLE IF NOT EXISTS reads(
  user_id INTEGER, room_id INTEGER, last_id INTEGER DEFAULT 0, PRIMARY KEY(user_id, room_id));
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""

# columns added since earlier versions (used to upgrade existing databases in place)
MIGRATE = {
    "users": [("avatar", "TEXT"), ("status", "TEXT"), ("enc_pub", "TEXT"), ("enc_priv", "TEXT"),
              ("receipts", "INTEGER DEFAULT 1")],
    "rooms": [("kind", "TEXT NOT NULL DEFAULT 'channel'"), ("topic", "TEXT"), ("ttl", "INTEGER DEFAULT 0"),
              ("ttl_since", "REAL DEFAULT 0"), ("created_by", "INTEGER")],
    "messages": [("image", "TEXT"), ("iw", "INTEGER"), ("ih", "INTEGER"), ("reply_to", "INTEGER"),
                 ("fname", "TEXT"), ("fsize", "INTEGER"), ("kind", "TEXT DEFAULT 'text'")],
    "uploads": [("fname", "TEXT"), ("fsize", "INTEGER")],
}


def connect():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c


def columns(c, table):
    return {r["name"] for r in c.execute("PRAGMA table_info(%s)" % table)}


def init():
    c = connect()
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript(SCHEMA)
    for table, cols in MIGRATE.items():
        have = columns(c, table)
        for col, ddl in cols:
            if col not in have:
                c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, ddl))
    c.execute("INSERT OR IGNORE INTO meta VALUES('rev','0')")
    c.execute("INSERT OR IGNORE INTO meta VALUES('registration','open')")
    c.execute("INSERT OR IGNORE INTO meta VALUES('banner','')")
    c.execute("INSERT OR IGNORE INTO rooms(id,name,created,kind) VALUES(1,'general',?, 'channel')", (time.time(),))
    for r in c.execute("SELECT name FROM uploads WHERE used=0 AND ts<?", (time.time() - 86400,)).fetchall():
        try:
            os.remove(os.path.join(UPLOADS, r["name"]))
        except OSError:
            pass
        c.execute("DELETE FROM uploads WHERE name=?", (r["name"],))
    c.commit()
    c.close()


def db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def next_rev(c):
    c.execute("UPDATE meta SET v=CAST(v AS INTEGER)+1 WHERE k='rev'")
    return int(c.execute("SELECT v FROM meta WHERE k='rev'").fetchone()[0])


def cur_rev(c):
    return int(c.execute("SELECT v FROM meta WHERE k='rev'").fetchone()[0])


def reg_open(c):
    return c.execute("SELECT v FROM meta WHERE k='registration'").fetchone()[0] == "open"


def get_meta(c, k, default=""):
    r = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return r[0] if r else default


_hits, _lock = {}, threading.Lock()
_typing = {}


def blocked(key, n, secs):
    now = time.time()
    with _lock:
        l = [t for t in _hits.get(key, []) if now - t < secs]
        _hits[key] = l
        return len(l) >= n


def hit(key):
    with _lock:
        _hits.setdefault(key, []).append(time.time())


def err(msg, code=400):
    return jsonify({"error": msg}), code


def ival(name, default=0):
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default


def body():
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}


def me():
    uid = session.get("uid")
    if not uid:
        return None
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u or u["pwv"] != session.get("pwv"):
        session.clear()
        return None
    return u


def guard(f):
    """Requires login. Non-GET requests must carry X-Haven (blocks cross-site forms)."""
    @wraps(f)
    def w(*a, **k):
        if request.method != "GET" and request.headers.get("X-Haven") != "1":
            return err("Bad request")
        u = me()
        if not u:
            return err("Not signed in", 401)
        g.user = u
        return f(*a, **k)
    return w


def admin_only(f):
    @wraps(f)
    @guard
    def w(*a, **k):
        if not g.user["admin"]:
            return err("Admins only", 403)
        return f(*a, **k)
    return w


def room_for(c, rid, u):
    """The room row if this user may see it (public channels: everyone; DMs and private rooms: members)."""
    r = c.execute("SELECT * FROM rooms WHERE id=?", (rid,)).fetchone()
    if not r:
        return None
    if r["kind"] in ("dm", "private") and not c.execute(
            "SELECT 1 FROM room_members WHERE room_id=? AND user_id=?", (rid, u["id"])).fetchone():
        return None
    return r


def drop_files(c, names):
    for n in names:
        if n and UP_RE.match(n):
            try:
                os.remove(os.path.join(UPLOADS, n))
            except OSError:
                pass
            c.execute("DELETE FROM uploads WHERE name=?", (n,))


def drop_avatar(name):
    if name and AV_RE.match(name):
        try:
            os.remove(os.path.join(AVATARS, name))
        except OSError:
            pass


NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,20}$")
ROOM_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")
MSG_SQL = "SELECT m.*, u.name, u.avatar AS av FROM messages m JOIN users u ON u.id=m.user_id "


def pack(c, rows, uid):
    """Turn message rows into JSON, attaching reactions, pins, saves, polls and reply previews."""
    ids = [r["id"] for r in rows]
    rx, rp, pins, saved, votes = {}, {}, set(), set(), {}
    if ids:
        q = ",".join("?" * len(ids))
        for r in c.execute("SELECT rx.message_id AS mid, rx.emoji AS e, u.name AS n FROM reactions rx "
                           "JOIN users u ON u.id=rx.user_id WHERE rx.message_id IN (%s) ORDER BY rx.rowid" % q, ids):
            rx.setdefault(r["mid"], {}).setdefault(r["e"], []).append(r["n"])
        pins = {x[0] for x in c.execute("SELECT message_id FROM pins WHERE message_id IN (%s)" % q, ids)}
        saved = {x[0] for x in c.execute(
            "SELECT message_id FROM bookmarks WHERE user_id=? AND message_id IN (%s)" % q, [uid] + ids)}
        for r in c.execute("SELECT pv.message_id AS mid, pv.opt AS opt, u.name AS n FROM poll_votes pv "
                           "JOIN users u ON u.id=pv.user_id WHERE pv.message_id IN (%s) ORDER BY pv.rowid" % q, ids):
            votes.setdefault(r["mid"], {}).setdefault(r["opt"], []).append(r["n"])
        rids = list({r["reply_to"] for r in rows if r["reply_to"]})
        if rids:
            q2 = ",".join("?" * len(rids))
            for r in c.execute("SELECT m.id, m.text, m.deleted, m.kind, u.name FROM messages m "
                               "JOIN users u ON u.id=m.user_id WHERE m.id IN (%s)" % q2, rids):
                t = r["text"] or ""
                hide = r["deleted"] or t.startswith(E2E) or r["kind"] == "poll"
                rp[r["id"]] = {"id": r["id"], "name": r["name"], "deleted": bool(r["deleted"]),
                               "text": "" if hide else t[:120]}
    out = []
    for r in rows:
        poll = None
        if r["kind"] == "poll" and not r["deleted"]:
            try:
                p = json.loads(r["text"])
                v = votes.get(r["id"], {})
                poll = {"q": p.get("q", ""), "multi": bool(p.get("m")),
                        "options": [{"t": t, "who": v.get(i, [])} for i, t in enumerate(p.get("o", []))]}
            except (TypeError, ValueError):
                poll = None
        out.append({
            "id": r["id"], "room": r["room_id"], "uid": r["user_id"], "name": r["name"], "av": r["av"],
            "text": "" if (r["deleted"] or poll) else (r["text"] or ""), "ts": r["ts"],
            "edited": bool(r["edited"]), "deleted": bool(r["deleted"]), "rev": r["rev"],
            "kind": r["kind"] or "text", "poll": poll,
            "image": None if r["deleted"] else r["image"], "iw": r["iw"], "ih": r["ih"],
            "fname": r["fname"], "fsize": r["fsize"],
            "pinned": r["id"] in pins, "saved": r["id"] in saved,
            "reactions": [{"e": e, "who": w} for e, w in rx.get(r["id"], {}).items()],
            "reply": rp.get(r["reply_to"]) if r["reply_to"] else None,
        })
    return out


def user_json(u):
    return {"id": u["id"], "name": u["name"], "admin": bool(u["admin"]),
            "avatar": u["avatar"], "status": u["status"] or "", "receipts": bool(u["receipts"] is None or u["receipts"])}


def reap_once():
    """Disappearing messages: tombstone anything older than the room's timer."""
    c = connect()
    now = time.time()
    for r in c.execute("SELECT id, ttl, ttl_since FROM rooms WHERE ttl>0").fetchall():
        rows = c.execute("SELECT id, image FROM messages WHERE room_id=? AND deleted=0 AND ts>=? AND ts<?",
                         (r["id"], r["ttl_since"] or 0, now - r["ttl"])).fetchall()
        if not rows:
            continue
        rev = next_rev(c)
        ids = [x["id"] for x in rows]
        for i in range(0, len(ids), 500):
            part = ids[i:i + 500]
            q = ",".join("?" * len(part))
            c.execute("UPDATE messages SET text='', deleted=1, image=NULL, iw=NULL, ih=NULL, fname=NULL, fsize=NULL, "
                      "kind='expired', rev=? WHERE id IN (%s)" % q, [rev] + part)
            for t in ("reactions", "pins", "poll_votes", "bookmarks"):
                c.execute("DELETE FROM %s WHERE message_id IN (%s)" % (t, q), part)
        drop_files(c, [x["image"] for x in rows])
    c.commit()
    c.close()


def reaper():
    while True:
        time.sleep(60)
        try:
            reap_once()
        except Exception as e:  # keep the loop alive no matter what
            print("reaper error:", e, flush=True)


# ---------- pages & PWA ----------
@app.before_request
def limit_body():
    if request.path not in ("/api/upload", "/api/avatar") and (request.content_length or 0) > 32 * 1024:
        return err("Request too large", 413)


@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Permissions-Policy"] = "camera=(), microphone=(self), geolocation=()"
    if "Content-Security-Policy" not in r.headers:
        r.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "img-src 'self' data: blob:; media-src 'self' blob:")
    if request.path.startswith("/api/") or request.path in ("/", "/trust"):
        r.headers["Cache-Control"] = "no-store"
    return r


@app.get("/")
def index():
    return Response(PAGE, mimetype="text/html")


@app.get("/health")
def health():
    return jsonify(status="ok", version=VERSION)


@app.get("/manifest.webmanifest")
def manifest():
    icons = [{"src": "/icon-%d.png" % s, "sizes": "%dx%d" % (s, s), "type": "image/png", "purpose": "any maskable"}
             for s in (192, 512)]
    return Response(json.dumps({
        "name": "Haven", "short_name": "Haven", "start_url": "/", "scope": "/", "display": "standalone",
        "background_color": "#0f1117", "theme_color": "#0f1117", "icons": icons}),
        mimetype="application/manifest+json")


_icons = {}


def make_icon(size):
    if size not in _icons:
        im = Image.new("RGB", (size, size))
        d = ImageDraw.Draw(im)
        for y in range(size):
            t = y / max(1, size - 1)
            d.line([(0, y), (size, y)], fill=(int(124 - 33 * t), int(108 + 32 * t), 255))
        w = max(2, int(size * 0.11))
        x0, x1, y0, y1 = int(size * .31), int(size * .69), int(size * .26), int(size * .74)
        mid = (y0 + y1) // 2
        d.rectangle([x0, y0, x0 + w, y1], fill="white")
        d.rectangle([x1 - w, y0, x1, y1], fill="white")
        d.rectangle([x0, mid - w // 2, x1, mid + w // 2], fill="white")
        buf = io.BytesIO()
        im.save(buf, "PNG")
        _icons[size] = buf.getvalue()
    return _icons[size]


@app.get("/icon-<int:size>.png")
def icon(size):
    if size not in (180, 192, 512):
        return "", 404
    r = Response(make_icon(size), mimetype="image/png")
    r.headers["Cache-Control"] = "public, max-age=604800"
    return r


@app.get("/apple-touch-icon.png")
def touch_icon():
    return icon(180)


@app.get("/ca.crt")
def ca_cert():
    try:
        with open(CA_PATH, "rb") as f:
            data = f.read()
    except OSError:
        return "Certificate not found on this server.", 404
    r = Response(data, mimetype="application/x-x509-ca-cert")
    r.headers["Content-Disposition"] = 'attachment; filename="haven-ca.crt"'
    return r


@app.get("/trust")
def trust():
    return Response(TRUST_PAGE, mimetype="text/html")


# ---------- auth ----------
@app.get("/api/state")
def state():
    c = db()
    u = me()
    n = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return jsonify(user=user_json(u) if u else None, registration=(n == 0 or reg_open(c)),
                   first=(n == 0), version=VERSION,
                   enc={"pub": u["enc_pub"], "wrapped": u["enc_priv"]} if u else None)


@app.post("/api/register")
def register():
    if request.headers.get("X-Haven") != "1":
        return err("Bad request")
    c, d = db(), body()
    name, pw = str(d.get("name", "")).strip(), str(d.get("password", ""))
    n = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    inv = None
    if n and not reg_open(c):
        inv = c.execute("SELECT * FROM invites WHERE code=? AND uses_left>0 AND (expires IS NULL OR expires>?)",
                        (str(d.get("invite", "")).strip(), time.time())).fetchone()
        if not inv:
            return err("Sign-ups are closed. Ask an admin for an invite link.", 403)
    if blocked("reg:" + request.remote_addr, 5, 600):
        return err("Too many attempts. Try again later.", 429)
    hit("reg:" + request.remote_addr)
    if not NAME_RE.match(name):
        return err("Username: 3-20 letters, numbers, . _ -")
    if len(pw) < 8 or len(pw) > 200:
        return err("Password must be at least 8 characters")
    try:
        cur = c.execute("INSERT INTO users(name,pw,admin,created) VALUES(?,?,?,?)",
                        (name, generate_password_hash(pw), 1 if n == 0 else 0, time.time()))
    except sqlite3.IntegrityError:
        return err("That username is taken")
    uid = cur.lastrowid
    if inv:
        c.execute("UPDATE invites SET uses_left=uses_left-1 WHERE code=?", (inv["code"],))
    for r in c.execute("SELECT id FROM rooms WHERE kind='channel'").fetchall():
        mx = c.execute("SELECT COALESCE(MAX(id),0) FROM messages WHERE room_id=?", (r["id"],)).fetchone()[0]
        c.execute("INSERT OR REPLACE INTO reads VALUES(?,?,?)", (uid, r["id"], mx))
    c.commit()
    session.clear()
    session.permanent = True
    session["uid"], session["pwv"] = uid, 1
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    if request.headers.get("X-Haven") != "1":
        return err("Bad request")
    d = body()
    key = "login:" + request.remote_addr
    if blocked(key, 8, 300):
        return err("Too many failed attempts. Wait a few minutes.", 429)
    u = db().execute("SELECT * FROM users WHERE name=?", (str(d.get("name", "")).strip(),)).fetchone()
    if not u or not check_password_hash(u["pw"], str(d.get("password", ""))):
        hit(key)
        return err("Wrong username or password", 401)
    session.clear()
    session.permanent = True
    session["uid"], session["pwv"] = u["id"], u["pwv"]
    return jsonify(ok=True)


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


def valid_pub(s):
    try:
        j = json.loads(s)
        return (isinstance(j, dict) and j.get("kty") == "EC" and j.get("crv") == "P-256"
                and isinstance(j.get("x"), str) and isinstance(j.get("y"), str) and len(s) < 600)
    except (TypeError, ValueError):
        return False


@app.post("/api/keys")
@guard
def set_keys():
    d, c = body(), db()
    if not check_password_hash(g.user["pw"], str(d.get("password", ""))):
        return err("Wrong password", 403)
    pub, wrapped = d.get("pub"), d.get("wrapped")
    if not isinstance(pub, str) or not isinstance(wrapped, str) or not valid_pub(pub) or len(wrapped) > 4000:
        return err("Invalid key data")
    c.execute("UPDATE users SET enc_pub=?, enc_priv=? WHERE id=?", (pub, wrapped, g.user["id"]))
    c.commit()
    return jsonify(ok=True)


@app.post("/api/password")
@guard
def change_password():
    d, c = body(), db()
    old, new = str(d.get("old", "")), str(d.get("new", ""))
    if not check_password_hash(g.user["pw"], old):
        return err("Current password is wrong", 403)
    if len(new) < 8 or len(new) > 200:
        return err("New password must be at least 8 characters")
    pwv = g.user["pwv"] + 1
    c.execute("UPDATE users SET pw=?, pwv=? WHERE id=?", (generate_password_hash(new), pwv, g.user["id"]))
    wrapped = d.get("wrapped")
    if isinstance(wrapped, str) and g.user["enc_pub"] and len(wrapped) < 4000:
        c.execute("UPDATE users SET enc_priv=? WHERE id=?", (wrapped, g.user["id"]))
    c.commit()
    session["pwv"] = pwv
    return jsonify(ok=True)


# ---------- profile ----------
@app.post("/api/profile")
@guard
def profile():
    c, d = db(), body()
    status = g.user["status"] or ""
    if "status" in d:
        status = re.sub(r"\s+", " ", str(d.get("status", ""))).strip()[:60]
        c.execute("UPDATE users SET status=? WHERE id=?", (status, g.user["id"]))
    if "receipts" in d:
        c.execute("UPDATE users SET receipts=? WHERE id=?", (1 if d["receipts"] else 0, g.user["id"]))
    c.commit()
    return jsonify(ok=True, status=status)


@app.post("/api/avatar")
@guard
def set_avatar():
    f = request.files.get("file")
    if not f:
        return err("No file received")
    if blocked("av:%d" % g.user["id"], 10, 60):
        return err("Too many changes. Wait a minute.", 429)
    hit("av:%d" % g.user["id"])
    data = f.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        return err("Picture is over 4 MB", 413)
    try:
        im = Image.open(io.BytesIO(data))
        if im.format not in IMG_EXT:
            return err("Use a PNG, JPEG, GIF or WebP picture")
        im.load()
        im = ImageOps.exif_transpose(im).convert("RGBA")
        bg = Image.new("RGBA", im.size, (255, 255, 255, 255))
        im = Image.alpha_composite(bg, im).convert("RGB")
        im = ImageOps.fit(im, (256, 256), Image.LANCZOS)
        buf = io.BytesIO()
        im.save(buf, "JPEG", quality=88, optimize=True)
    except Exception:
        return err("That doesn't look like a valid picture")
    name = secrets.token_hex(12) + ".jpg"
    with open(os.path.join(AVATARS, name), "wb") as fh:
        fh.write(buf.getvalue())
    c = db()
    drop_avatar(g.user["avatar"])
    c.execute("UPDATE users SET avatar=? WHERE id=?", (name, g.user["id"]))
    c.commit()
    return jsonify(avatar=name)


@app.post("/api/avatar/remove")
@guard
def remove_avatar():
    c = db()
    drop_avatar(g.user["avatar"])
    c.execute("UPDATE users SET avatar=NULL WHERE id=?", (g.user["id"],))
    c.commit()
    return jsonify(ok=True)


@app.get("/avatars/<name>")
def serve_avatar(name):
    if not me() or not AV_RE.match(name):
        return "", 404
    r = send_from_directory(AVATARS, name, mimetype="image/jpeg", max_age=31536000)
    r.headers["Cache-Control"] = "private, max-age=31536000, immutable"
    return r


# ---------- chat ----------
ROOMS_SQL = """
SELECT r.id, r.kind, r.topic, r.ttl, r.created_by,
  CASE WHEN r.kind='dm'
       THEN (SELECT u.name FROM room_members rm JOIN users u ON u.id=rm.user_id
             WHERE rm.room_id=r.id AND rm.user_id!=:u)
       ELSE r.name END AS name,
  COALESCE((SELECT muted FROM room_prefs WHERE user_id=:u AND room_id=r.id),0) AS muted,
  (SELECT COUNT(*) FROM messages m WHERE m.room_id=r.id AND m.deleted=0 AND m.user_id!=:u
     AND m.id > COALESCE((SELECT last_id FROM reads WHERE user_id=:u AND room_id=r.id),0)) AS unread
FROM rooms r
WHERE r.kind='channel' OR EXISTS(SELECT 1 FROM room_members rm WHERE rm.room_id=r.id AND rm.user_id=:u)
ORDER BY CASE r.kind WHEN 'dm' THEN 1 ELSE 0 END, r.id
"""


@app.get("/api/poll")
@guard
def poll():
    c, u = db(), g.user
    now = time.time()
    c.execute("UPDATE users SET last_seen=? WHERE id=?", (now, u["id"]))
    room, since = ival("room"), ival("since")
    grev = cur_rev(c)
    out, more, rev, typing, last_read = [], False, since, [], 0
    peer_read, room_members = None, []
    rrow = room_for(c, room, u)
    ok = rrow is not None
    if ok:
        lr = c.execute("SELECT last_id FROM reads WHERE user_id=? AND room_id=?", (u["id"], room)).fetchone()
        last_read = lr["last_id"] if lr else 0
        if since == 0:
            rows = c.execute(MSG_SQL + "WHERE m.room_id=? AND m.kind!='expired' ORDER BY m.id DESC LIMIT 101",
                             (room,)).fetchall()
            more = len(rows) > 100
            rows = list(reversed(rows[:100]))
            rev = grev
        else:
            rows = c.execute(MSG_SQL + "WHERE m.room_id=? AND m.rev>? ORDER BY m.rev LIMIT 300",
                             (room, since)).fetchall()
            if rows:
                rev = max(r["rev"] for r in rows)
        out = pack(c, rows, u["id"])
        if ival("read", 1):
            mx = c.execute("SELECT COALESCE(MAX(id),0) FROM messages WHERE room_id=?", (room,)).fetchone()[0]
            c.execute("INSERT INTO reads VALUES(?,?,?) ON CONFLICT(user_id,room_id) "
                      "DO UPDATE SET last_id=MAX(last_id, excluded.last_id)", (u["id"], room, mx))
        typing = [n for k, (n, t) in list(_typing.get(room, {}).items()) if k != u["id"] and now - t < 5]
        if rrow["kind"] in ("dm", "private"):
            room_members = [x[0] for x in c.execute("SELECT user_id FROM room_members WHERE room_id=?", (room,))]
        if rrow["kind"] == "dm":
            other = c.execute("SELECT u.id, u.receipts FROM room_members rm JOIN users u ON u.id=rm.user_id "
                              "WHERE rm.room_id=? AND rm.user_id!=?", (room, u["id"])).fetchone()
            if other and u["receipts"] != 0 and other["receipts"] != 0:
                pr = c.execute("SELECT last_id FROM reads WHERE user_id=? AND room_id=?", (other["id"], room)).fetchone()
                peer_read = pr["last_id"] if pr else 0
    rooms = c.execute(ROOMS_SQL, {"u": u["id"]}).fetchall()
    members = c.execute("SELECT id, name, avatar, status, enc_pub AS pub, last_seen>? AS online FROM users "
                        "ORDER BY online DESC, name", (now - 25,)).fetchall()
    banner = get_meta(c, "banner")
    c.commit()
    return jsonify(room_ok=ok, messages=out, more=more, rev=rev, typing=typing, last_read=last_read,
                   peer_read=peer_read, room_members=room_members, banner=banner,
                   rooms=[dict(r) for r in rooms], members=[dict(m) for m in members])


@app.get("/api/older")
@guard
def older():
    c = db()
    if not room_for(c, ival("room"), g.user):
        return err("Room not found", 404)
    rows = c.execute(MSG_SQL + "WHERE m.room_id=? AND m.id<? AND m.kind!='expired' ORDER BY m.id DESC LIMIT 51",
                     (ival("room"), ival("before"))).fetchall()
    return jsonify(messages=pack(c, list(reversed(rows[:50])), g.user["id"]), more=len(rows) > 50)


@app.post("/api/typing")
@guard
def typing():
    rid = int(body().get("room", 0) or 0)
    if room_for(db(), rid, g.user):
        _typing.setdefault(rid, {})[g.user["id"]] = (g.user["name"], time.time())
    return jsonify(ok=True)


@app.post("/api/send")
@guard
def send():
    d, c = body(), db()
    text = str(d.get("text", "")).strip()
    if blocked("send:%d" % g.user["id"], 15, 10):
        return err("Slow down a little")
    hit("send:%d" % g.user["id"])
    rid = int(d.get("room", 0) or 0)
    room = room_for(c, rid, g.user)
    if not room:
        return err("Room not found", 404)
    is_dm = room["kind"] == "dm"
    kind = "text"
    pl = d.get("poll")
    if pl is not None:
        if is_dm:
            return err("Polls aren't available in encrypted DMs")
        if not isinstance(pl, dict):
            return err("Invalid poll")
        q = str(pl.get("q", "")).strip()[:200]
        opts = [str(o).strip()[:80] for o in (pl.get("options") or []) if str(o).strip()][:6]
        if not q or len(opts) < 2:
            return err("A poll needs a question and at least two options")
        text, kind = json.dumps({"q": q, "o": opts, "m": bool(pl.get("multi"))}), "poll"
    elif is_dm:
        if not text.startswith(E2E) or len(text) > MAX_E2E:
            return err("Direct messages must be encrypted. Reload the page and try again.")
    elif len(text) > 2000:
        return err("Message must be 2000 characters or fewer")
    img = iw = ih = fname = fsize = None
    if d.get("image") and kind == "text":
        up = c.execute("SELECT * FROM uploads WHERE name=? AND user_id=? AND used=0",
                       (str(d["image"]), g.user["id"])).fetchone()
        if not up:
            return err("That attachment expired. Please attach it again.")
        if up["name"].endswith(".bin") != is_dm:
            return err("That attachment can't be sent here")
        img, iw, ih, fname, fsize = up["name"], up["iw"], up["ih"], up["fname"], up["fsize"]
    if not text and not img:
        return err("Message is empty")
    reply = None
    if d.get("reply_to"):
        rm = c.execute("SELECT id FROM messages WHERE id=? AND room_id=?", (int(d["reply_to"]), rid)).fetchone()
        reply = rm["id"] if rm else None
    rev = next_rev(c)
    c.execute("INSERT INTO messages(room_id,user_id,text,ts,rev,image,iw,ih,reply_to,fname,fsize,kind) "
              "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
              (rid, g.user["id"], text, time.time(), rev, img, iw, ih, reply, fname, fsize, kind))
    if img:
        c.execute("UPDATE uploads SET used=1 WHERE name=?", (img,))
    c.commit()
    _typing.get(rid, {}).pop(g.user["id"], None)
    return jsonify(ok=True)


@app.post("/api/edit/<int:mid>")
@guard
def edit(mid):
    c = db()
    m = c.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    text = str(body().get("text", "")).strip()
    room = room_for(c, m["room_id"], g.user) if m else None
    if not m or m["deleted"] or m["kind"] == "poll" or m["user_id"] != g.user["id"] or not room:
        return err("You can only edit your own messages", 403)
    if room["kind"] == "dm":
        if not text.startswith(E2E) or len(text) > MAX_E2E:
            return err("Direct messages must be encrypted. Reload the page and try again.")
    elif (not text and not m["image"]) or len(text) > 2000:
        return err("Message must be 1-2000 characters")
    c.execute("UPDATE messages SET text=?, edited=1, rev=? WHERE id=?", (text, next_rev(c), mid))
    c.commit()
    return jsonify(ok=True)


@app.post("/api/delete/<int:mid>")
@guard
def delete_msg(mid):
    c = db()
    m = c.execute("SELECT m.*, r.kind AS rkind FROM messages m JOIN rooms r ON r.id=m.room_id WHERE m.id=?",
                  (mid,)).fetchone()
    if not m or m["deleted"] or not room_for(c, m["room_id"], g.user):
        return err("Not allowed", 403)
    # admins can moderate public channels, but never read or touch private chats or DMs
    if m["user_id"] != g.user["id"] and not (g.user["admin"] and m["rkind"] == "channel"):
        return err("Not allowed", 403)
    for t in ("reactions", "pins", "poll_votes", "bookmarks"):
        c.execute("DELETE FROM %s WHERE message_id=?" % t, (mid,))
    c.execute("UPDATE messages SET text='', deleted=1, image=NULL, iw=NULL, ih=NULL, fname=NULL, fsize=NULL, "
              "kind='text', rev=? WHERE id=?", (next_rev(c), mid))
    drop_files(c, [m["image"]])
    c.commit()
    return jsonify(ok=True)


@app.post("/api/react/<int:mid>")
@guard
def react(mid):
    c = db()
    emoji = body().get("emoji")
    if emoji not in REACTIONS:
        return err("Unsupported reaction")
    m = c.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if not m or m["deleted"] or not room_for(c, m["room_id"], g.user):
        return err("Message not found", 404)
    if blocked("react:%d" % g.user["id"], 30, 10):
        return err("Slow down a little")
    hit("react:%d" % g.user["id"])
    cur = c.execute("DELETE FROM reactions WHERE message_id=? AND user_id=? AND emoji=?",
                    (mid, g.user["id"], emoji))
    if cur.rowcount == 0:
        c.execute("INSERT INTO reactions VALUES(?,?,?)", (mid, g.user["id"], emoji))
    c.execute("UPDATE messages SET rev=? WHERE id=?", (next_rev(c), mid))
    c.commit()
    return jsonify(ok=True)


def live_message(c, mid):
    """A message the current user can see and that has not been deleted."""
    m = c.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if not m or m["deleted"] or not room_for(c, m["room_id"], g.user):
        return None
    return m


@app.post("/api/vote/<int:mid>")
@guard
def vote(mid):
    c = db()
    m = live_message(c, mid)
    if not m or m["kind"] != "poll":
        return err("Poll not found", 404)
    if blocked("vote:%d" % g.user["id"], 30, 10):
        return err("Slow down a little")
    hit("vote:%d" % g.user["id"])
    try:
        p = json.loads(m["text"])
        opt = int(body().get("opt"))
        assert 0 <= opt < len(p["o"])
    except (TypeError, ValueError, KeyError, AssertionError):
        return err("Invalid vote")
    mine = [x[0] for x in c.execute("SELECT opt FROM poll_votes WHERE message_id=? AND user_id=?", (mid, g.user["id"]))]
    if opt in mine:
        c.execute("DELETE FROM poll_votes WHERE message_id=? AND user_id=? AND opt=?", (mid, g.user["id"], opt))
    else:
        if not p.get("m"):
            c.execute("DELETE FROM poll_votes WHERE message_id=? AND user_id=?", (mid, g.user["id"]))
        c.execute("INSERT INTO poll_votes VALUES(?,?,?)", (mid, g.user["id"], opt))
    c.execute("UPDATE messages SET rev=? WHERE id=?", (next_rev(c), mid))
    c.commit()
    return jsonify(ok=True)


@app.post("/api/pin/<int:mid>")
@guard
def pin(mid):
    c = db()
    m = live_message(c, mid)
    if not m:
        return err("Message not found", 404)
    if c.execute("SELECT 1 FROM pins WHERE message_id=?", (mid,)).fetchone():
        c.execute("DELETE FROM pins WHERE message_id=?", (mid,))
        pinned = False
    else:
        c.execute("INSERT INTO pins VALUES(?,?,?,?)", (mid, m["room_id"], g.user["id"], time.time()))
        pinned = True
    c.execute("UPDATE messages SET rev=? WHERE id=?", (next_rev(c), mid))
    c.commit()
    return jsonify(pinned=pinned)


@app.post("/api/save/<int:mid>")
@guard
def save_msg(mid):
    c = db()
    if not live_message(c, mid):
        return err("Message not found", 404)
    cur = c.execute("DELETE FROM bookmarks WHERE user_id=? AND message_id=?", (g.user["id"], mid))
    if cur.rowcount == 0:
        c.execute("INSERT INTO bookmarks VALUES(?,?,?)", (g.user["id"], mid, time.time()))
    c.commit()
    return jsonify(saved=cur.rowcount == 0)


@app.get("/api/pins")
@guard
def pins_list():
    c = db()
    rid = ival("room")
    if not room_for(c, rid, g.user):
        return err("Room not found", 404)
    rows = c.execute("SELECT m.*, u.name, u.avatar AS av FROM pins p JOIN messages m ON m.id=p.message_id "
                     "JOIN users u ON u.id=m.user_id WHERE p.room_id=? AND m.deleted=0 "
                     "ORDER BY p.ts DESC LIMIT 50", (rid,)).fetchall()
    return jsonify(messages=pack(c, rows, g.user["id"]))


@app.get("/api/saved")
@guard
def saved_list():
    c = db()
    rows = c.execute(
        "SELECT m.*, u.name, u.avatar AS av FROM bookmarks b JOIN messages m ON m.id=b.message_id "
        "JOIN users u ON u.id=m.user_id JOIN rooms r ON r.id=m.room_id "
        "WHERE b.user_id=? AND m.deleted=0 AND (r.kind='channel' OR EXISTS("
        "SELECT 1 FROM room_members rm WHERE rm.room_id=r.id AND rm.user_id=?)) "
        "ORDER BY b.ts DESC LIMIT 100", (g.user["id"], g.user["id"])).fetchall()
    return jsonify(messages=pack(c, rows, g.user["id"]))


@app.get("/api/media")
@guard
def media_list():
    c = db()
    rid = ival("room")
    if not room_for(c, rid, g.user):
        return err("Room not found", 404)
    rows = c.execute(MSG_SQL + "WHERE m.room_id=? AND m.image IS NOT NULL AND m.deleted=0 "
                     "ORDER BY m.id DESC LIMIT 120", (rid,)).fetchall()
    return jsonify(messages=pack(c, rows, g.user["id"]))


@app.get("/api/search")
@guard
def search():
    c = db()
    q = str(request.args.get("q", "")).strip()
    if len(q) < 2 or len(q) > 60:
        return jsonify(messages=[])
    if blocked("search:%d" % g.user["id"], 20, 10):
        return err("Slow down a little")
    hit("search:%d" % g.user["id"])
    like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = c.execute(
        MSG_SQL + "JOIN rooms r ON r.id=m.room_id WHERE m.deleted=0 AND m.kind='text' AND m.text LIKE ? ESCAPE '\\' "
        "AND (r.kind='channel' OR (r.kind='private' AND EXISTS("
        "SELECT 1 FROM room_members rm WHERE rm.room_id=r.id AND rm.user_id=?))) "
        "ORDER BY m.id DESC LIMIT 50", (like, g.user["id"])).fetchall()
    return jsonify(messages=pack(c, rows, g.user["id"]))


@app.post("/api/mute")
@guard
def mute():
    c, d = db(), body()
    rid = int(d.get("room", 0) or 0)
    if not room_for(c, rid, g.user):
        return err("Room not found", 404)
    c.execute("INSERT INTO room_prefs VALUES(?,?,?) ON CONFLICT(user_id,room_id) DO UPDATE SET muted=excluded.muted",
              (g.user["id"], rid, 1 if d.get("muted") else 0))
    c.commit()
    return jsonify(ok=True)


# ---------- uploads (photos, voice messages, files, encrypted blobs) ----------
def clean_filename(n):
    base = os.path.basename(str(n or "").replace("\\", "/"))
    base = re.sub(r"[\x00-\x1f\x7f]", "", base).strip()[:120]
    return base or "file"


@app.post("/api/upload")
@guard
def upload():
    f = request.files.get("file")
    if not f:
        return err("No file received")
    if blocked("up:%d" % g.user["id"], 20, 60):
        return err("Too many uploads. Wait a minute.", 429)
    hit("up:%d" % g.user["id"])
    kind = request.form.get("kind", "image")
    enc = request.form.get("enc") == "1"      # end-to-end encrypted blob for DMs: stored opaque
    limit = MAX_FILE if (enc or kind == "file") else (MAX_AUDIO if kind == "audio" else MAX_UPLOAD)
    data = f.read(limit + 2048)
    if len(data) > limit + (1024 if enc else 0):
        return err("That file is too large (limit %d MB)" % (limit // 1048576), 413)
    w = h = fname = fsize = None
    if enc:
        out, ext = data, "bin"
        if len(out) < 29:
            return err("Invalid upload")
    elif kind == "audio":
        if data[:4] == b"\x1a\x45\xdf\xa3":
            ext = "webm"
        elif data[:4] == b"OggS":
            ext = "ogg"
        elif data[4:8] == b"ftyp":
            ext = "m4a"
        else:
            return err("Unsupported audio format")
        out = data
        try:
            w = max(0, min(3600, int(float(request.form.get("dur", 0)))))
        except ValueError:
            w = 0
    elif kind == "file":
        out, ext = data, "file"
        fname, fsize = clean_filename(f.filename), len(data)
    else:
        try:
            im = Image.open(io.BytesIO(data))
            fmt = im.format
            if fmt not in IMG_EXT:
                return err("Use a PNG, JPEG, GIF or WebP image")
            im.load()
            if fmt == "GIF":
                out = data
            else:
                im = ImageOps.exif_transpose(im)
                buf = io.BytesIO()
                if fmt == "JPEG":
                    im.convert("RGB").save(buf, "JPEG", quality=90, optimize=True)
                elif fmt == "PNG":
                    im.save(buf, "PNG", optimize=True)
                else:
                    im.save(buf, "WEBP", quality=90)
                out = buf.getvalue()
            w, h = im.size
            ext = IMG_EXT[fmt]
        except Exception:
            return err("That doesn't look like a valid image")
    name = secrets.token_hex(16) + "." + ext
    with open(os.path.join(UPLOADS, name), "wb") as fh:
        fh.write(out)
    c = db()
    c.execute("INSERT INTO uploads(name,user_id,iw,ih,ts,fname,fsize) VALUES(?,?,?,?,?,?,?)",
              (name, g.user["id"], w, h, time.time(), fname, fsize))
    c.commit()
    return jsonify(name=name, iw=w, ih=h, fname=fname, fsize=fsize)


@app.get("/uploads/<name>")
def serve_upload(name):
    u = me()
    if not u:
        return "", 401
    if not UP_RE.match(name):
        return "", 404
    c = db()
    m = c.execute("SELECT room_id, fname FROM messages WHERE image=?", (name,)).fetchone()
    if m:
        ok, fname = room_for(c, m["room_id"], u) is not None, m["fname"]
    else:
        up = c.execute("SELECT user_id, fname FROM uploads WHERE name=?", (name,)).fetchone()
        ok, fname = bool(up and up["user_id"] == u["id"]), (up["fname"] if up else None)
    if not ok:
        return "", 404
    ext = name.rsplit(".", 1)[1]
    if ext == "file":
        resp = send_from_directory(UPLOADS, name, mimetype="application/octet-stream", as_attachment=True,
                                   download_name=fname or "file", max_age=86400)
        resp.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    else:
        resp = send_from_directory(UPLOADS, name, mimetype=IMG_MIME[ext], max_age=86400)
    resp.headers["Cache-Control"] = "private, max-age=86400"
    return resp


# ---------- rooms, private rooms and direct messages ----------
def add_member(c, rid, uid):
    c.execute("INSERT OR IGNORE INTO room_members VALUES(?,?)", (rid, uid))
    mx = c.execute("SELECT COALESCE(MAX(id),0) FROM messages WHERE room_id=?", (rid,)).fetchone()[0]
    c.execute("INSERT OR REPLACE INTO reads VALUES(?,?,?)", (uid, rid, mx))


@app.post("/api/rooms")
@guard
def create_room():
    c, d = db(), body()
    name = re.sub(r"\s+", "-", str(d.get("name", "")).strip().lower()).lstrip("#")
    if not ROOM_RE.match(name):
        return err("Room name: letters, numbers and dashes, up to 24 characters")
    private = bool(d.get("private"))
    try:
        cur = c.execute("INSERT INTO rooms(name,created,kind,created_by) VALUES(?,?,?,?)",
                        (name, time.time(), "private" if private else "channel", g.user["id"]))
    except sqlite3.IntegrityError:
        return err("That room already exists")
    rid = cur.lastrowid
    if private:
        wanted = {g.user["id"]}
        for x in d.get("members") or []:
            try:
                wanted.add(int(x))
            except (TypeError, ValueError):
                pass
        for uid in wanted:
            if c.execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone():
                add_member(c, rid, uid)
    c.commit()
    return jsonify(id=rid)


@app.post("/api/rooms/<int:rid>/delete")
@guard
def delete_room(rid):
    c = db()
    r = room_for(c, rid, g.user)
    if rid == 1 or not r or r["kind"] not in ("channel", "private"):
        return err("That room can't be deleted")
    if r["kind"] == "channel" and not g.user["admin"]:
        return err("Only admins can delete public rooms", 403)
    if r["kind"] == "private" and r["created_by"] != g.user["id"]:
        return err("Only the person who created this room can delete it", 403)
    names = [x[0] for x in c.execute("SELECT image FROM messages WHERE room_id=? AND image IS NOT NULL", (rid,))]
    c.execute("DELETE FROM reads WHERE room_id=?", (rid,))
    c.execute("DELETE FROM room_prefs WHERE room_id=?", (rid,))
    c.execute("DELETE FROM rooms WHERE id=?", (rid,))
    drop_files(c, names)
    c.commit()
    return jsonify(ok=True)


@app.post("/api/rooms/<int:rid>/settings")
@guard
def room_settings(rid):
    c, d = db(), body()
    r = room_for(c, rid, g.user)
    if not r:
        return err("Room not found", 404)
    kind, admin = r["kind"], bool(g.user["admin"])
    creator = r["created_by"] == g.user["id"]
    if "topic" in d:
        if not ((kind == "channel" and admin) or kind == "private"):
            return err("You can't change the topic here", 403)
        c.execute("UPDATE rooms SET topic=? WHERE id=?", (re.sub(r"\s+", " ", str(d["topic"])).strip()[:120], rid))
    if "ttl" in d:
        if not (kind == "dm" or (kind == "channel" and admin) or (kind == "private" and creator)):
            return err("You can't change disappearing messages here", 403)
        try:
            ttl = int(d["ttl"])
        except (TypeError, ValueError):
            return err("Invalid timer")
        if ttl not in TTL_OPTIONS:
            return err("Invalid timer")
        c.execute("UPDATE rooms SET ttl=?, ttl_since=? WHERE id=?", (ttl, time.time(), rid))
    c.commit()
    return jsonify(ok=True)


@app.post("/api/rooms/<int:rid>/members")
@guard
def room_members(rid):
    c, d = db(), body()
    r = room_for(c, rid, g.user)
    if not r or r["kind"] != "private":
        return err("Room not found", 404)
    if r["created_by"] != g.user["id"]:
        return err("Only the person who created this room can change who is in it", 403)
    for x in d.get("add") or []:
        try:
            uid = int(x)
        except (TypeError, ValueError):
            continue
        if c.execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone():
            add_member(c, rid, uid)
    for x in d.get("remove") or []:
        try:
            uid = int(x)
        except (TypeError, ValueError):
            continue
        if uid != g.user["id"]:
            c.execute("DELETE FROM room_members WHERE room_id=? AND user_id=?", (rid, uid))
            c.execute("DELETE FROM reads WHERE room_id=? AND user_id=?", (rid, uid))
    c.commit()
    return jsonify(ok=True)


@app.post("/api/rooms/<int:rid>/leave")
@guard
def leave_room(rid):
    c = db()
    r = room_for(c, rid, g.user)
    if not r or r["kind"] != "private":
        return err("Room not found", 404)
    c.execute("DELETE FROM room_members WHERE room_id=? AND user_id=?", (rid, g.user["id"]))
    c.execute("DELETE FROM reads WHERE room_id=? AND user_id=?", (rid, g.user["id"]))
    left = c.execute("SELECT MIN(user_id) FROM room_members WHERE room_id=?", (rid,)).fetchone()[0]
    if left is None:
        names = [x[0] for x in c.execute("SELECT image FROM messages WHERE room_id=? AND image IS NOT NULL", (rid,))]
        c.execute("DELETE FROM rooms WHERE id=?", (rid,))
        drop_files(c, names)
    elif r["created_by"] == g.user["id"]:
        c.execute("UPDATE rooms SET created_by=? WHERE id=?", (left, rid))
    c.commit()
    return jsonify(ok=True)


@app.post("/api/dm")
@guard
def open_dm():
    c = db()
    try:
        other = int(body().get("user", 0))
    except (TypeError, ValueError):
        other = 0
    if other == g.user["id"] or not c.execute("SELECT 1 FROM users WHERE id=?", (other,)).fetchone():
        return err("Pick another member")
    a, b = sorted((g.user["id"], other))
    key = "dm:%d:%d" % (a, b)
    r = c.execute("SELECT id FROM rooms WHERE name=?", (key,)).fetchone()
    if r:
        return jsonify(id=r["id"])
    cur = c.execute("INSERT INTO rooms(name,created,kind,created_by) VALUES(?,?, 'dm', ?)",
                    (key, time.time(), g.user["id"]))
    rid = cur.lastrowid
    for uid in (a, b):
        c.execute("INSERT INTO room_members VALUES(?,?)", (rid, uid))
        c.execute("INSERT OR REPLACE INTO reads VALUES(?,?,0)", (uid, rid))
    c.commit()
    return jsonify(id=rid)


# ---------- admin ----------
def dir_size(path):
    size = n = 0
    for f in os.scandir(path):
        size += f.stat().st_size
        n += 1
    return size, n


@app.get("/api/admin/users")
@admin_only
def admin_users():
    c = db()
    rows = c.execute("SELECT id,name,admin,created, enc_pub IS NOT NULL AS enc FROM users ORDER BY id").fetchall()
    size, n = dir_size(UPLOADS)
    stats = {"messages": c.execute("SELECT COUNT(*) FROM messages WHERE deleted=0").fetchone()[0],
             "images": n, "mb": round(size / 1048576, 1)}
    return jsonify(users=[dict(r) for r in rows], registration=reg_open(c), stats=stats, banner=get_meta(c, "banner"))


@app.post("/api/admin/users/<int:uid>")
@admin_only
def admin_user(uid):
    c, d = db(), body()
    t = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not t:
        return err("No such user", 404)
    act = d.get("action")
    if act in ("remove", "toggle_admin") and uid == g.user["id"]:
        return err("You can't do that to yourself")
    if act == "remove":
        names = [x[0] for x in c.execute(
            "SELECT image FROM messages WHERE image IS NOT NULL AND (user_id=? OR room_id IN "
            "(SELECT rm.room_id FROM room_members rm JOIN rooms r ON r.id=rm.room_id "
            "WHERE rm.user_id=? AND r.kind='dm'))", (uid, uid))]
        names += [x[0] for x in c.execute("SELECT name FROM uploads WHERE user_id=?", (uid,))]
        c.execute("DELETE FROM rooms WHERE kind='dm' AND id IN (SELECT room_id FROM room_members WHERE user_id=?)", (uid,))
        c.execute("DELETE FROM users WHERE id=?", (uid,))
        c.execute("UPDATE rooms SET created_by=(SELECT MIN(user_id) FROM room_members WHERE room_id=rooms.id) "
                  "WHERE kind='private' AND created_by=?", (uid,))
        c.execute("DELETE FROM reads WHERE user_id=? OR room_id NOT IN (SELECT id FROM rooms)", (uid,))
        drop_files(c, names)
        drop_avatar(t["avatar"])
    elif act == "toggle_admin":
        c.execute("UPDATE users SET admin=1-admin WHERE id=?", (uid,))
    elif act == "reset":
        pw = str(d.get("password", ""))
        if len(pw) < 8 or len(pw) > 200:
            return err("Password must be at least 8 characters")
        # a reset also resets their encryption keys (old DMs become unreadable)
        c.execute("UPDATE users SET pw=?, pwv=pwv+1, enc_pub=NULL, enc_priv=NULL WHERE id=?",
                  (generate_password_hash(pw), uid))
    else:
        return err("Unknown action")
    c.commit()
    return jsonify(ok=True)


@app.post("/api/admin/settings")
@admin_only
def admin_settings():
    c, d = db(), body()
    if "registration" in d:
        c.execute("UPDATE meta SET v=? WHERE k='registration'", ("open" if d["registration"] else "closed",))
    if "banner" in d:
        c.execute("UPDATE meta SET v=? WHERE k='banner'", (re.sub(r"\s+", " ", str(d["banner"])).strip()[:200],))
    c.commit()
    return jsonify(ok=True)


@app.post("/api/admin/invite")
@admin_only
def admin_invite():
    c, d = db(), body()
    try:
        uses = max(1, min(100, int(d.get("uses", 1))))
        days = max(1, min(90, int(d.get("days", 7))))
    except (TypeError, ValueError):
        return err("Invalid invite")
    code = secrets.token_urlsafe(9)
    c.execute("INSERT INTO invites VALUES(?,?,?,?)", (code, g.user["id"], uses, time.time() + days * 86400))
    c.commit()
    return jsonify(code=code)


# ---------- static pages ----------
TRUST_PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Trust Haven</title>
<style>body{font:16px/1.55 system-ui,sans-serif;background:#0f1117;color:#e8eaf2;margin:0;padding:24px}
main{max-width:640px;margin:0 auto}h1{font-size:24px}h2{font-size:17px;margin:22px 0 6px}
a.btn{display:inline-block;background:linear-gradient(135deg,#7c6cff,#5b8cff);color:#fff;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:600}
p,li{color:#b9bed2}code{background:#1a1e2c;padding:1px 6px;border-radius:5px}a{color:#8fb0ff}</style></head><body><main>
<h1>Make Haven fully secure on this device</h1>
<p>Haven encrypts everything between your device and the server. Because Haven runs on your own network, it uses its own private certificate. Install it once and the browser warning goes away for good.</p>
<p><a class="btn" href="/ca.crt">Download certificate</a></p>
<h2>iPhone / iPad</h2><ol><li>Open the downloaded file and choose <b>Allow</b>.</li><li>Settings &rarr; <b>Profile Downloaded</b> &rarr; Install.</li><li>Settings &rarr; General &rarr; About &rarr; <b>Certificate Trust Settings</b> &rarr; turn on the Haven certificate.</li></ol>
<h2>Android</h2><ol><li>Settings &rarr; Security (or Security &amp; privacy) &rarr; <b>Encryption &amp; credentials</b> &rarr; Install a certificate &rarr; <b>CA certificate</b>.</li><li>Pick the downloaded file.</li></ol>
<h2>Windows</h2><ol><li>Double-click the file &rarr; Install Certificate.</li><li>Choose <b>Place all certificates in the following store</b> &rarr; <b>Trusted Root Certification Authorities</b>.</li></ol>
<h2>Mac</h2><ol><li>Double-click the file (opens Keychain Access).</li><li>Open the certificate, expand <b>Trust</b>, set it to <b>Always Trust</b>.</li></ol>
<h2>Linux (Firefox / Chrome)</h2><p>Browser settings &rarr; Privacy &amp; Security &rarr; Certificates &rarr; Authorities &rarr; Import.</p>
<p>Then reload Haven. Prefer to skip this? You can still tap "continue anyway" in the browser warning, but trusting the certificate is recommended, and it lets you add Haven to your home screen.</p>
<p><a href="/">Back to Haven</a></p></main></body></html>
"""

PAGE = r"""<!doctype html>
<html lang="en" data-theme="dark"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0f1117"><meta name="color-scheme" content="dark light">
<meta name="mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"><meta name="apple-mobile-web-app-title" content="Haven">
<link rel="manifest" href="/manifest.webmanifest"><link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="icon" href="/icon-192.png" type="image/png"><title>Haven</title>
<style>
:root{--bg:#0f1117;--panel:#141722;--panel2:#1b1f2e;--line:#262b3d;--text:#e9ebf3;--mut:#8f95ab;--acc:#7c6cff;--acc2:#5b8cff;--bad:#ff6b7a;--ok:#3ddc97;--hover:#232840;--sel:#262c4a;--mh:#171b29;--code:#0b0d14;--accbg:#2a2470;--shadow:0 10px 40px #0007;--r:14px}
:root[data-theme=light]{--bg:#f5f6fb;--panel:#fff;--panel2:#eef0f8;--line:#e0e3ef;--text:#1b1e2b;--mut:#666d86;--hover:#e3e6f3;--sel:#e7e4ff;--mh:#f0f1f9;--code:#eceef7;--accbg:#e4e1ff;--shadow:0 10px 40px #2b2f5522}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}html,body{height:100%;margin:0;overscroll-behavior:none}
body{background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
button,input,textarea,select{font:inherit;color:inherit}.hidden{display:none!important}
.ico{width:18px;height:18px;flex:none;vertical-align:-3px}
button{cursor:pointer;border:0;background:var(--panel2);padding:8px 14px;border-radius:10px;transition:background .12s}
button:hover{background:var(--hover)}button:disabled{opacity:.5;cursor:default}
.primary{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;font-weight:600}
.primary:hover{filter:brightness(1.08);background:linear-gradient(135deg,var(--acc),var(--acc2))}
.ghost{background:none}.danger{color:var(--bad)}
input,textarea,select{background:var(--panel2);border:1px solid var(--line);border-radius:11px;padding:10px 12px;outline:none;width:100%}
input:focus,textarea:focus{border-color:var(--acc)}
.logo{display:inline-grid;place-items:center;width:32px;height:32px;border-radius:10px;background:linear-gradient(135deg,var(--acc),var(--acc2));font-weight:800;color:#fff}
.sub{color:var(--mut);margin:0}.small{font-size:12px}
/* auth */
.auth{min-height:100%;display:grid;place-items:center;padding:20px;background:radial-gradient(900px 500px at 50% -10%,var(--accbg) 0%,transparent 60%)}
.acard{width:100%;max-width:390px;background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:30px;display:grid;gap:12px;box-shadow:var(--shadow)}
.acard h1{margin:0;font-size:24px;display:flex;gap:10px;align-items:center}
.link{background:none;color:var(--acc2);padding:4px;text-align:center;font-size:14px}a{color:var(--acc2)}
.msgerr{color:var(--bad);min-height:1.2em;font-size:14px}
/* layout */
.app{height:100%;height:var(--vh,100dvh);display:flex;position:relative}
aside{width:272px;background:var(--panel);border-right:1px solid var(--line);display:flex;flex-direction:column;min-height:0;z-index:12}
.brand{padding:18px 16px 10px;font-weight:700;font-size:18px;display:flex;gap:10px;align-items:center}
.brand .sec-ok{margin-left:auto;color:var(--ok)}
.navs{flex:1;overflow:auto;padding-bottom:8px}
.sec{padding:14px 16px 4px;color:var(--mut);font-size:11.5px;text-transform:uppercase;letter-spacing:.08em;display:flex;justify-content:space-between;align-items:center}
.sec button{padding:2px 6px;background:none;color:var(--mut)}.sec button:hover{color:var(--text)}
.navs nav,#members{padding:0 8px}
.room{display:flex;justify-content:space-between;align-items:center;gap:6px;padding:8px 10px;border-radius:10px;color:var(--mut);cursor:pointer}
.room>span:first-child{display:flex;align-items:center;gap:9px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.room:hover{background:var(--panel2)}.room.on{background:var(--sel);color:var(--text)}.room.unread{color:var(--text);font-weight:600}
.badge{background:var(--acc);color:#fff;border-radius:99px;font-size:11.5px;padding:0 7px;font-weight:700;min-width:20px;text-align:center}
.mem{padding:5px 10px;color:var(--mut);display:flex;gap:10px;align-items:center;font-size:14px;border-radius:10px;min-width:0}
.mem.click{cursor:pointer}.mem.click:hover{background:var(--panel2);color:var(--text)}.hint{font-size:13px}
.mem .t{min-width:0;overflow:hidden}.mem .t div{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.mem .st{font-size:12px;opacity:.75}
.av{width:34px;height:34px;border-radius:50%;display:grid;place-items:center;font-weight:700;font-size:13px;color:#fff;flex:none;object-fit:cover;position:relative}
.av.s{width:26px;height:26px;font-size:10.5px}.av.l{width:84px;height:84px;font-size:28px}
.avw{position:relative;flex:none;display:inline-block;line-height:0}
.avw .dot{position:absolute;right:-1px;bottom:-1px;border:2px solid var(--panel);width:11px;height:11px}
.dot{width:8px;height:8px;border-radius:50%;background:#4a5169;flex:none}.dot.on{background:var(--ok)}
.meb{border-top:1px solid var(--line);padding:10px 12px;display:flex;align-items:center;gap:10px;width:100%;background:none;border-radius:0;text-align:left}
.meb:hover{background:var(--panel2)}.meb .nm{flex:1;min-width:0;line-height:1.25}.meb .nm b,.meb .nm span{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
main{flex:1;display:flex;flex-direction:column;min-width:0;min-height:0;position:relative}
main.drag::after{content:"Drop a file to attach it";position:absolute;inset:8px;border:2px dashed var(--acc);border-radius:16px;background:#7c6cff22;display:grid;place-items:center;font-weight:600;z-index:5;pointer-events:none}
header{display:flex;align-items:center;gap:8px;padding:10px 14px;padding-top:calc(10px + env(safe-area-inset-top));border-bottom:1px solid var(--line);background:var(--panel)}
header .ttl{flex:1;min-width:0}header h2{margin:0;font-size:16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:flex;gap:7px;align-items:center}
header .ttl .sub{font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ib{padding:8px;background:none;border-radius:10px;color:var(--mut);display:inline-grid;place-items:center}.ib:hover{color:var(--text)}
#menu{display:none}#search{max-width:210px;padding:7px 11px;font-size:14px}
.scrim{display:none}
#msgs{flex:1;overflow:auto;padding:8px 16px 6px;-webkit-overflow-scrolling:touch}
.col{max-width:920px;margin:0 auto}
.day{text-align:center;color:var(--mut);font-size:12px;margin:16px 0 6px}
.newdiv{display:flex;align-items:center;gap:10px;color:var(--bad);font-size:12px;font-weight:600;margin:10px 0 2px}.newdiv::before,.newdiv::after{content:"";height:1px;background:var(--bad);opacity:.5;flex:1}
.more{display:block;margin:6px auto}
.msg{display:flex;gap:12px;padding:3px 10px;border-radius:12px;position:relative}
.msg:hover,.msg.sel{background:var(--mh)}.msg.first{margin-top:12px}
.msg.mention{background:#ffcf5a14;box-shadow:inset 3px 0 #ffcf5a}
.sp{width:34px;flex:none}.bd{min-width:0;flex:1}
.hd{display:flex;gap:8px;align-items:baseline}.hd b{font-size:14px}.hd span{color:var(--mut);font-size:12px}
.tx{white-space:pre-wrap;word-wrap:break-word;overflow-wrap:anywhere}
.tx code{background:var(--code);border:1px solid var(--line);padding:1px 5px;border-radius:5px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.tx pre{margin:4px 0;background:var(--code);border:1px solid var(--line);border-radius:10px;padding:10px 12px;overflow:auto;white-space:pre}.tx pre code{border:0;padding:0;background:none}
.tx a{color:var(--acc2)}.tx .bq{display:block;border-left:3px solid var(--line);padding-left:10px;color:var(--mut)}
.del{color:var(--mut);font-style:italic}.ed{color:var(--mut);font-size:11px}
.at{background:#7c6cff33;border-radius:4px;padding:0 3px}.at.me{background:#ffcf5a55}
.quote{border-left:3px solid var(--acc);padding:1px 8px;margin:2px 0;color:var(--mut);font-size:13px;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.quote b{color:var(--text)}
.pic{display:block;margin-top:4px;max-width:min(100%,380px);max-height:340px;width:auto;height:auto;border-radius:14px;cursor:zoom-in;border:1px solid var(--line);background:var(--panel2)}
.rx{display:flex;flex-wrap:wrap;gap:5px;margin-top:5px}
.chip{border:1px solid var(--line);border-radius:99px;padding:1px 10px;font-size:13px;background:var(--panel2)}.chip.mine{border-color:var(--acc);background:var(--accbg)}
.acts{position:absolute;right:10px;top:-16px;display:none;gap:1px;background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:2px;z-index:2;box-shadow:var(--shadow)}
.acts button{padding:6px 8px;background:none;border-radius:8px;color:var(--mut)}.acts button:hover{background:var(--hover);color:var(--text)}
.msg.sel .acts{display:flex}@media(hover:hover){.msg:hover .acts{display:flex}}
.jump{position:absolute;right:18px;bottom:112px;z-index:4;background:var(--panel);border:1px solid var(--line);border-radius:99px;padding:7px 14px;box-shadow:var(--shadow);display:flex;gap:6px;align-items:center}
#typing{height:20px;padding:0 22px;color:var(--mut);font-size:13px}
.ctx{padding:6px 16px;color:var(--mut);font-size:13px;display:flex;gap:10px;align-items:center;border-top:1px solid var(--line)}
.ctx span{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ctx button{padding:3px 10px;font-size:13px}.ctx img{height:48px;border-radius:8px}
.note{padding:10px 16px;background:var(--accbg);font-size:14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.composer{display:flex;gap:8px;padding:8px 14px calc(12px + env(safe-area-inset-bottom));align-items:flex-end}
.cbox{flex:1;display:flex;align-items:flex-end;gap:2px;background:var(--panel2);border:1px solid var(--line);border-radius:18px;padding:4px 6px;min-width:0}
.cbox:focus-within{border-color:var(--acc)}
.cbox textarea{border:0;background:none;resize:none;max-height:160px;padding:9px 6px}.cbox .ib{padding:8px}
.send{width:44px;height:44px;border-radius:50%;padding:0;display:grid;place-items:center;flex:none}
#pick{position:fixed;z-index:30;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:6px;display:flex;flex-wrap:wrap;gap:2px;max-width:min(330px,92vw);box-shadow:var(--shadow)}
#pick button{background:none;font-size:21px;padding:4px 6px}#pick button:hover{background:var(--hover)}
#umenu{position:fixed;z-index:30;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:6px;min-width:220px;box-shadow:var(--shadow)}
#umenu button,#umenu a{display:flex;gap:10px;align-items:center;width:100%;text-align:left;background:none;padding:10px 12px;border-radius:9px;color:var(--text);text-decoration:none;font-size:14.5px}
#umenu button:hover,#umenu a:hover{background:var(--hover)}
#lb{position:fixed;inset:0;background:#000d;display:grid;place-items:center;z-index:40;cursor:zoom-out}
#lb img{max-width:94vw;max-height:86vh;border-radius:8px}#lb a{position:fixed;bottom:calc(18px + env(safe-area-inset-bottom));color:#fff;font-size:14px}
#modal{position:fixed;inset:0;background:#000a;display:grid;place-items:center;padding:16px;z-index:20}
.mcard{background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:22px;width:100%;max-width:520px;max-height:88vh;overflow:auto;display:grid;gap:10px;box-shadow:var(--shadow)}
.mcard h3{margin:0;font-size:19px}.mcard h4{margin:10px 0 0;font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.07em}
.row{display:flex;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid var(--line);flex-wrap:wrap}
.row .n{flex:1;min-width:120px}.row button{font-size:13px;padding:5px 10px}
.tag{font-size:11px;background:var(--accbg);border-radius:99px;padding:1px 8px}
.prof{display:flex;gap:16px;align-items:center}.code{font-family:ui-monospace,Menlo,monospace;font-size:15px;letter-spacing:.04em;background:var(--code);border:1px solid var(--line);border-radius:10px;padding:10px;text-align:center;user-select:all}
#toast{position:fixed;left:50%;bottom:calc(96px + env(safe-area-inset-bottom));transform:translateX(-50%);background:var(--panel2);border:1px solid var(--line);padding:10px 18px;border-radius:12px;z-index:50;box-shadow:var(--shadow);max-width:90vw}
@media(max-width:760px){
 body{font-size:16px}input,textarea,select{font-size:16px}
 aside{position:fixed;inset:0 auto 0 0;transform:translateX(-102%);transition:transform .22s;width:84%;max-width:320px;padding-top:env(safe-area-inset-top);box-shadow:var(--shadow)}
 aside.open{transform:none}.scrim{position:fixed;inset:0;background:#0009;z-index:11;opacity:0;pointer-events:none;transition:opacity .2s;display:block}
 aside.open~.scrim{opacity:1;pointer-events:auto}
 #menu{display:inline-grid}#search{display:none;position:absolute;left:52px;right:52px;top:calc(8px + env(safe-area-inset-top));max-width:none;z-index:3}
 header.s-open #search{display:block}header.s-open .ttl{visibility:hidden}
 #msgs{padding:6px 8px}.msg{padding:3px 6px;gap:10px}.acts{right:6px}
 .composer{padding-left:8px;padding-right:8px}.room,.mem{padding-top:11px;padding-bottom:11px}
 .mcard{border-radius:20px 20px 0 0;align-self:end;max-height:92vh}#modal{padding:0}
 .jump{bottom:100px}
}
:root[data-theme=black]{--bg:#000;--panel:#07080c;--panel2:#11131b;--line:#1b1e2c;--hover:#191c2a;--sel:#1b1f3b;--mh:#0b0d14;--code:#04050a}
html[data-accent=blue]{--acc:#3b82f6;--acc2:#06b6d4;--accbg:#1d3557}
html[data-accent=green]{--acc:#22c55e;--acc2:#14b8a6;--accbg:#14412f}
html[data-accent=pink]{--acc:#ec4899;--acc2:#f43f5e;--accbg:#4a1d35}
html[data-accent=orange]{--acc:#f59e0b;--acc2:#f97316;--accbg:#4a3114}
body{font-size:var(--fs,15px)}
body.compact .msg{padding-top:1px;padding-bottom:1px}body.compact .msg.first{margin-top:6px}
.banner{display:flex;align-items:center;gap:10px;padding:8px 14px;background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;font-size:14px}
.banner span{flex:1}.banner .ib{color:#fff;padding:4px}
.aa{font-weight:700;font-size:14px;letter-spacing:-.5px;min-width:38px}
.ac{max-height:240px;overflow:auto;border-top:1px solid var(--line);background:var(--panel);padding:4px 8px}
.ac button{display:flex;gap:10px;align-items:center;width:100%;text-align:left;background:none;padding:7px 10px;border-radius:9px}
.ac button.on,.ac button:hover{background:var(--hover)}.ac .em{font-size:20px}
#fmtp{position:fixed;z-index:30;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:8px;box-shadow:var(--shadow);width:min(300px,92vw)}
#fmtp .fgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:4px}
#fmtp button{display:grid;gap:2px;justify-items:center;background:none;padding:8px 2px;border-radius:10px}
#fmtp button:hover{background:var(--hover)}#fmtp .g{font-size:17px;min-height:24px;display:grid;place-items:center}#fmtp .l{font-size:11px;color:var(--mut)}#fmtp p{margin:6px 4px 0}
.rec{flex:1;display:flex;align-items:center;gap:12px;background:var(--panel2);border:1px solid var(--line);border-radius:18px;padding:6px 8px 6px 16px}.rec .grow{flex:1}
.reddot{width:10px;height:10px;border-radius:50%;background:var(--bad);animation:pulse 1s infinite}@keyframes pulse{50%{opacity:.25}}
.spoiler{background:var(--text);color:transparent;border-radius:4px;cursor:pointer;user-select:none}.spoiler.on{background:var(--code);color:inherit;user-select:auto}
.tx u{text-underline-offset:2px}.tx i{font-style:italic}.li{display:block;padding-left:4px}.li i{font-style:normal;color:var(--mut);display:inline-block;min-width:1.4em}
.file{display:flex;align-items:center;gap:12px;margin-top:4px;max-width:340px;width:100%;background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:10px 14px;color:var(--text);text-decoration:none;text-align:left}
.file span{flex:1;min-width:0;display:grid}.file b{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:14px}.file small{color:var(--mut)}
.voice{display:flex;align-items:center;gap:10px;margin-top:4px}.voice audio{height:38px;max-width:260px}
.poll{margin-top:4px;max-width:420px;background:var(--panel2);border:1px solid var(--line);border-radius:14px;padding:12px;display:grid;gap:6px}.pq{font-weight:600}
.po{position:relative;display:flex;justify-content:space-between;gap:10px;align-items:center;text-align:left;overflow:hidden;background:var(--panel);border:1px solid var(--line);padding:8px 12px}
.po .bar{position:absolute;inset:0 auto 0 0;background:var(--accbg);z-index:0}.po.mine{border-color:var(--acc)}.po .pt,.po .pc{position:relative;z-index:1}.po .pc{color:var(--mut)}
.rcpt{font-size:11px;color:var(--mut);margin-top:2px}
.flags{position:absolute;right:12px;top:4px;display:flex;gap:4px;color:var(--mut);opacity:.85}.flags .ico{width:13px;height:13px}
.msg.flash{animation:flash 1.8s}@keyframes flash{0%,60%{background:var(--sel)}100%{background:transparent}}
.room.muted{opacity:.6}.badge.mutedb{background:var(--panel2);color:var(--mut)}
.tabs{display:flex;gap:6px;flex-wrap:wrap}.tabs button{padding:6px 12px;font-size:14px}.tabs button.on{background:var(--accbg)}
.lcard{border:1px solid var(--line);border-radius:12px;padding:10px 12px;margin-bottom:8px;cursor:pointer}.lcard:hover{background:var(--hover)}
.lh{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:4px}.lt{overflow-wrap:anywhere;max-height:120px;overflow:hidden}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(96px,1fr));gap:6px}.grid img{width:100%;aspect-ratio:1;object-fit:cover;border-radius:10px;cursor:pointer;background:var(--panel2)}
.qs{display:flex;justify-content:space-between;width:100%;text-align:left;background:none;border-radius:10px;padding:10px 12px}.qs.on,.qs:hover{background:var(--hover)}
.swatch{width:26px;height:26px;border-radius:50%;padding:0;border:2px solid transparent;margin-left:6px}.swatch.on{border-color:var(--text)}
.s-violet{background:linear-gradient(135deg,#7c6cff,#5b8cff)}.s-blue{background:linear-gradient(135deg,#3b82f6,#06b6d4)}.s-green{background:linear-gradient(135deg,#22c55e,#14b8a6)}
.s-pink{background:linear-gradient(135deg,#ec4899,#f43f5e)}.s-orange{background:linear-gradient(135deg,#f59e0b,#f97316)}
#umenu hr{border:0;border-top:1px solid var(--line);margin:4px 0}#umenu .danger{color:var(--bad)}
#ttl{cursor:pointer}
@media(max-width:760px){.ac{max-height:180px}.acts button{padding:8px 9px}.voice audio{max-width:210px}#fmtp .g{font-size:19px}}
</style></head><body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true">
<defs><style>.i{fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}</style></defs>
<symbol id="i-menu" viewBox="0 0 24 24"><g class="i"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></g></symbol>
<symbol id="i-search" viewBox="0 0 24 24"><g class="i"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></g></symbol>
<symbol id="i-plus" viewBox="0 0 24 24"><g class="i"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></g></symbol>
<symbol id="i-clip" viewBox="0 0 24 24"><g class="i"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></g></symbol>
<symbol id="i-smile" viewBox="0 0 24 24"><g class="i"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></g></symbol>
<symbol id="i-send" viewBox="0 0 24 24"><g class="i"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></g></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><g class="i"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></g></symbol>
<symbol id="i-user" viewBox="0 0 24 24"><g class="i"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></g></symbol>
<symbol id="i-shield" viewBox="0 0 24 24"><g class="i"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></g></symbol>
<symbol id="i-out" viewBox="0 0 24 24"><g class="i"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></g></symbol>
<symbol id="i-reply" viewBox="0 0 24 24"><g class="i"><polyline points="9 14 4 9 9 4"/><path d="M20 20v-7a4 4 0 0 0-4-4H4"/></g></symbol>
<symbol id="i-edit" viewBox="0 0 24 24"><g class="i"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></g></symbol>
<symbol id="i-trash" viewBox="0 0 24 24"><g class="i"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></g></symbol>
<symbol id="i-down" viewBox="0 0 24 24"><g class="i"><polyline points="6 9 12 15 18 9"/></g></symbol>
<symbol id="i-hash" viewBox="0 0 24 24"><g class="i"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></g></symbol>
<symbol id="i-x" viewBox="0 0 24 24"><g class="i"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></g></symbol>
<symbol id="i-cert" viewBox="0 0 24 24"><g class="i"><circle cx="12" cy="8" r="6"/><path d="M15.5 13.5L17 22l-5-3-5 3 1.5-8.5"/></g></symbol>
<symbol id="i-pin" viewBox="0 0 24 24"><g class="i"><line x1="12" y1="17" x2="12" y2="22"/><path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24z"/></g></symbol>
<symbol id="i-star" viewBox="0 0 24 24"><g class="i"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></g></symbol>
<symbol id="i-info" viewBox="0 0 24 24"><g class="i"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></g></symbol>
<symbol id="i-mic" viewBox="0 0 24 24"><g class="i"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></g></symbol>
<symbol id="i-more" viewBox="0 0 24 24"><g class="i"><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/></g></symbol>
<symbol id="i-file" viewBox="0 0 24 24"><g class="i"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></g></symbol>
<symbol id="i-image" viewBox="0 0 24 24"><g class="i"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></g></symbol>
<symbol id="i-poll" viewBox="0 0 24 24"><g class="i"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></g></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><g class="i"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></g></symbol>
<symbol id="i-bell-off" viewBox="0 0 24 24"><g class="i"><path d="M13.73 21a2 2 0 0 1-3.46 0"/><path d="M18.63 13A17.89 17.89 0 0 1 18 8"/><path d="M6.26 6.26A5.86 5.86 0 0 0 6 8c0 7-3 9-3 9h14"/><path d="M18 8a6 6 0 0 0-9.33-5"/><line x1="1" y1="1" x2="23" y2="23"/></g></symbol>
<symbol id="i-download" viewBox="0 0 24 24"><g class="i"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></g></symbol>
</svg>

<div id="auth" class="auth hidden"><div class="acard">
 <h1><span class="logo">H</span> Haven</h1>
 <p class="sub" id="aSub"></p>
 <input id="aName" placeholder="Username" autocomplete="username" autocapitalize="off" autocorrect="off">
 <input id="aPass" type="password" placeholder="Password" autocomplete="current-password">
 <input id="aPass2" type="password" placeholder="Repeat password" autocomplete="new-password" class="hidden">
 <div class="msgerr" id="aErr"></div>
 <button class="primary" id="aGo">Sign in</button>
 <button class="link" id="aSwap"></button>
 <a class="small sub" href="/trust" style="text-align:center">Browser warning? Install the certificate</a>
</div></div>

<div id="app" class="app hidden">
 <aside id="side">
  <div class="brand"><span class="logo">H</span> Haven <span class="sec-ok" title="Encrypted connection"><svg class="ico"><use href="#i-lock"/></svg></span></div>
  <div class="navs">
   <div class="sec">Rooms <button id="addRoom" title="New room"><svg class="ico"><use href="#i-plus"/></svg></button></div>
   <nav id="rooms"></nav>
   <div class="sec">Direct messages</div>
   <nav id="dms"></nav>
   <div class="sec">Members</div>
   <div id="members"></div>
  </div>
  <button class="meb" id="meBtn"></button>
 </aside>
 <div class="scrim" id="scrim"></div>
 <main id="main">
  <div id="banner" class="banner hidden"></div>
  <header id="hdr">
   <button class="ib" id="menu" title="Menu"><svg class="ico"><use href="#i-menu"/></svg></button>
   <div class="ttl" id="ttl"><h2 id="rName"></h2><p class="sub" id="rSub"></p></div>
   <button class="ib hidden" id="bLock" title="Encryption details"><svg class="ico"><use href="#i-lock"/></svg></button>
   <button class="ib" id="bLib" title="Pinned, saved, photos, files and search"><svg class="ico"><use href="#i-pin"/></svg></button>
   <button class="ib" id="bInfo" title="Chat details"><svg class="ico"><use href="#i-info"/></svg></button>
   <input id="search" placeholder="Filter this chat">
   <button class="ib" id="bSearch" title="Filter this chat"><svg class="ico"><use href="#i-search"/></svg></button>
  </header>
  <div id="msgs"></div>
  <button class="jump hidden" id="jump"><svg class="ico"><use href="#i-down"/></svg><span id="jumpN"></span></button>
  <div id="typing"></div>
  <div id="note" class="note hidden"></div>
  <div id="ctx" class="ctx hidden"></div>
  <div id="att" class="ctx hidden"></div>
  <div id="ac" class="ac hidden"></div>
  <div class="composer">
   <div class="cbox" id="cbox">
    <button class="ib" id="bAttach" title="Attach a photo, file or poll" data-openmenu><svg class="ico"><use href="#i-plus"/></svg></button>
    <button class="ib aa" id="bFmt" title="Formatting" data-openfmt>Aa</button>
    <textarea id="box" rows="1" maxlength="2000" placeholder="Message" enterkeyhint="send"></textarea>
    <button class="ib" id="bEmoji" title="Emoji" data-openpick><svg class="ico"><use href="#i-smile"/></svg></button>
   </div>
   <div id="rec" class="rec hidden"><span class="reddot"></span><b id="recT">0:00</b><span class="grow"></span><button id="recX">Cancel</button><button id="recOk" class="primary">Send</button></div>
   <button class="primary send" id="send" title="Send"><svg class="ico"><use href="#i-send"/></svg></button>
   <button class="primary send hidden" id="mic" title="Record a voice message"><svg class="ico"><use href="#i-mic"/></svg></button>
   <input type="file" id="file" class="hidden">
   <input type="file" id="avfile" accept="image/png,image/jpeg,image/gif,image/webp" class="hidden">
  </div>
 
 </main>
</div>
<div id="pick" class="hidden"></div>
<div id="fmtp" class="hidden"></div>
<div id="umenu" class="hidden"></div>
<div id="lb" class="hidden"><img id="lbImg" alt=""><a id="lbOpen" target="_blank" rel="noopener">Open original</a></div>
<div id="modal" class="hidden"><div class="mcard" id="mcard"></div></div>
<div id="toast" class="hidden"></div>

<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ico=n=>'<svg class="ico"><use href="#i-'+n+'"/></svg>';
function applyTheme(t){document.documentElement.dataset.theme=t;document.querySelector('meta[name=theme-color]').content=({light:'#ffffff',black:'#000000'})[t]||'#0f1117';}
applyTheme(localStorage.getItem('haven_theme')||'dark');
const REACTS=['👍','❤️','😂','😮','😢','🎉','🔥','👀','🙏','✅'];
const EMOJIS='😀 😃 😄 😁 😆 😅 😂 🤣 🙂 😉 😊 😍 🥰 😘 😎 🤔 😐 🙄 😴 😢 😭 😡 🤯 😱 🥳 👍 👎 👏 🙌 🙏 💪 👀 ❤️ 🔥 ✨ 🎉 💯 ✅ ❌ ⭐ ☕ 🍕 🎮 🚀 💡'.split(' ');

/*CRYPTO-START*/
const te=new TextEncoder(),td=new TextDecoder();
const b64=u=>{let s='';const a=new Uint8Array(u);for(let i=0;i<a.length;i+=0x8000)s+=String.fromCharCode.apply(null,a.subarray(i,i+0x8000));return btoa(s);};
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const ECDH={name:'ECDH',namedCurve:'P-256'};
async function pwKey(pw,salt,usages){const base=await crypto.subtle.importKey('raw',te.encode(pw),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:250000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,usages);}
async function wrapJwk(jwkStr,pw){const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
  const k=await pwKey(pw,salt,['encrypt']);const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,te.encode(jwkStr));
  return JSON.stringify({v:1,s:b64(salt),i:b64(iv),c:b64(ct)});}
async function unwrapJwk(wrapped,pw){const w=JSON.parse(wrapped);const k=await pwKey(pw,unb64(w.s),['decrypt']);
  return td.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(w.i)},k,unb64(w.c)));}
async function newKeypair(){const kp=await crypto.subtle.generateKey(ECDH,true,['deriveBits']);
  const priv=await crypto.subtle.exportKey('jwk',kp.privateKey),pub=await crypto.subtle.exportKey('jwk',kp.publicKey);
  return {privJwk:JSON.stringify(priv),pubJwk:JSON.stringify({kty:pub.kty,crv:pub.crv,x:pub.x,y:pub.y})};}
const importPriv=jwkStr=>crypto.subtle.importKey('jwk',JSON.parse(jwkStr),ECDH,false,['deriveBits']);
async function dmKey(priv,pubJwkStr){const pub=await crypto.subtle.importKey('jwk',JSON.parse(pubJwkStr),ECDH,false,[]);
  const bits=await crypto.subtle.deriveBits({name:'ECDH',public:pub},priv,256);
  const hk=await crypto.subtle.importKey('raw',bits,'HKDF',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(32),info:te.encode('haven-dm-v1')},hk,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}
async function sealBytes(key,bytes,aad){const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:te.encode(aad)},key,bytes));
  const out=new Uint8Array(12+ct.length);out.set(iv);out.set(ct,12);return out;}
async function openBytes(key,data,aad){const a=new Uint8Array(data);
  return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:a.slice(0,12),additionalData:te.encode(aad)},key,a.slice(12)));}
const sealText=async(key,obj,room)=>'e2e:1:'+b64(await sealBytes(key,te.encode(JSON.stringify(obj)),'haven-dm:'+room));
const openText=async(key,s,room)=>JSON.parse(td.decode(await openBytes(key,unb64(s.slice(6)),'haven-dm:'+room)));
async function fp(str){const h=new Uint8Array(await crypto.subtle.digest('SHA-256',te.encode(str)));
  return Array.from(h.slice(0,10),x=>x.toString(16).padStart(2,'0')).join('').match(/.{1,4}/g).join(' ');}
const pubId=s=>{const j=JSON.parse(s);return j.x+'.'+j.y;};
const pairCode=(a,b)=>fp([pubId(a),pubId(b)].sort().join('|'));
/*CRYPTO-END*/

const idb={open(){return new Promise((res,rej)=>{const r=indexedDB.open('haven',1);r.onupgradeneeded=()=>r.result.createObjectStore('keys');r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error);});},
 async get(k){try{const d=await this.open();return await new Promise((res,rej)=>{const r=d.transaction('keys').objectStore('keys').get(k);r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error);});}catch(e){return null;}},
 async put(k,v){try{const d=await this.open();await new Promise((res,rej)=>{const t=d.transaction('keys','readwrite');t.objectStore('keys').put(v,k);t.oncomplete=res;t.onerror=()=>rej(t.error);});return true;}catch(e){return false;}}};

async function api(path,body){
  const o={headers:{'X-Haven':'1'}};
  if(body!==undefined){o.method='POST';o.headers['Content-Type']='application/json';o.body=JSON.stringify(body);}
  const r=await fetch(path,o);let d={};try{d=await r.json();}catch(e){}
  if(!r.ok){const e=new Error(d.error||'Something went wrong');e.status=r.status;throw e;}
  return d;
}
function toast(t){const e=$('toast');e.textContent=t;e.classList.remove('hidden');clearTimeout(toast.t);toast.t=setTimeout(()=>e.classList.add('hidden'),3400);}
function color(n){let h=0;for(const c of n)h=(h*31+c.charCodeAt(0))%360;return 'hsl('+h+',55%,45%)';}
function avatar(n,av,cls){cls=cls||'';
  return av?'<img class="av '+cls+'" src="/avatars/'+esc(av)+'" alt="">':'<div class="av '+cls+'" style="background:'+color(n)+'">'+esc(n.slice(0,2).toUpperCase())+'</div>';}
const memberOf=name=>S.members.find(m=>m.name===name);

const SHORT={smile:'😄',grin:'😁',joy:'😂',rofl:'🤣',wink:'😉',blush:'😊',heart_eyes:'😍',kiss:'😘',cool:'😎',thinking:'🤔',neutral:'😐',eyeroll:'🙄',sleepy:'😴',cry:'😢',sob:'😭',angry:'😡',scream:'😱',mindblown:'🤯',party:'🥳',thumbsup:'👍',thumbsdown:'👎',clap:'👏',raised_hands:'🙌',pray:'🙏',muscle:'💪',eyes:'👀',heart:'❤️',fire:'🔥',sparkles:'✨',tada:'🎉',hundred:'💯',check:'✅',x:'❌',star:'⭐',coffee:'☕',pizza:'🍕',game:'🎮',rocket:'🚀',bulb:'💡',wave:'👋',ok:'👌',skull:'💀',poop:'💩',cat:'🐱',dog:'🐶',sun:'☀️',moon:'🌙',rain:'🌧️',cake:'🎂',beer:'🍺',gift:'🎁',bell:'🔔',lock:'🔒',warning:'⚠️',question:'❓',rainbow:'🌈',ghost:'👻',robot:'🤖',unicorn:'🦄',laugh:'😆',sweat:'😅',hug:'🤗',salute:'🫡',shrug:'🤷',facepalm:'🤦',plus1:'👍',minus1:'👎',zzz:'💤',pencil:'📝',book:'📖',music:'🎵',phone:'📱',home:'🏠',car:'🚗',plane:'✈️',earth:'🌍'};
const SLASH=[
 {c:'poll',d:'Create a poll: /poll Question | Option 1 | Option 2'},
 {c:'me',d:'Say something about yourself: /me waves'},
 {c:'shrug',d:'Add ¯\\_(ツ)_/¯ to your message'},
 {c:'roll',d:'Roll dice: /roll 2d6'},
 {c:'flip',d:'Flip a coin'},
 {c:'spoiler',d:'Hide your message behind a spoiler'},
 {c:'tableflip',d:'(╯°□°)╯︵ ┻━┻'},
 {c:'unflip',d:'┬─┬ ノ( ゜-゜ノ)'},
 {c:'help',d:'Show what you can do'}
];

function inline(t){
  const keep=[];
  const s=esc(t).replace(/\[([^\]\n]+)\]\((https?:\/\/[^\s)<]+)\)/g,(m,txt,u)=>{keep.push('<a href="'+u+'" target="_blank" rel="noopener noreferrer">'+txt+'</a>');return '\u0000'+(keep.length-1)+'\u0000';});
  return s.split(/(https?:\/\/[^\s<]+)/g).map((p,i)=>{
    if(i%2)return '<a href="'+p+'" target="_blank" rel="noopener noreferrer">'+p+'</a>';
    p=p.replace(/^&gt; ?(.*)(\n|$)/gm,'<span class="bq">$1</span>')
       .replace(/^[-•] (.*)(\n|$)/gm,'<span class="li"><i>•</i>$1</span>')
       .replace(/^(\d{1,2})\. (.*)(\n|$)/gm,'<span class="li"><i>$1.</i>$2</span>');
    p=p.replace(/`([^`\n]+)`/g,'<code>$1</code>').replace(/\*\*([^*\n]+)\*\*/g,'<b>$1</b>').replace(/__([^_\n]+)__/g,'<u>$1</u>')
       .replace(/~~([^~\n]+)~~/g,'<s>$1</s>').replace(/\|\|([^|\n]+)\|\|/g,'<span class="spoiler">$1</span>');
    p=p.replace(/(^|[\s(>])\*([^*\n]+)\*(?=[\s).,!?:;<]|$)/g,'$1<i>$2</i>').replace(/(^|[\s(>])_([^_\n]+)_(?=[\s).,!?:;<]|$)/g,'$1<i>$2</i>');
    return p.replace(/@([A-Za-z0-9_.-]{3,20})/g,(m,n)=>{const k=S.names.get(n.toLowerCase());
      return k?'<span class="at'+(k===S.user.name?' me':'')+'">@'+esc(k)+'</span>':m;});
  }).join('').replace(/\u0000(\d+)\u0000/g,(m,i)=>keep[+i]);
}
function fmt(t){return t.split(/(```[\s\S]*?```)/g).map(seg=>(seg.length>=6&&seg.startsWith('```')&&seg.endsWith('```'))?'<pre><code>'+esc(seg.slice(3,-3).replace(/^\n/,''))+'</code></pre>':inline(seg)).join('');}
const fmtDur=s=>{s=Math.max(0,Math.round(s||0));return Math.floor(s/60)+':'+String(s%60).padStart(2,'0');};
const fsize=n=>{n=+n||0;return n<1024?n+' B':n<1048576?(n/1024).toFixed(0)+' KB':(n/1048576).toFixed(1)+' MB';};
const rand=n=>{const a=new Uint32Array(1);crypto.getRandomValues(a);return a[0]%n;};
const TTL_LABEL={0:'Off',3600:'1 hour',86400:'1 day',604800:'1 week',2592000:'30 days'};
const IMGX=['png','jpg','gif','webp'],AUDX=['webm','ogg','m4a'];
const extOf=n=>(n||'').split('.').pop();
const safeMime=m=>['image/png','image/jpeg','image/gif','image/webp'].includes(m)?m:'application/octet-stream';
const safeAudio=m=>['audio/webm','audio/ogg','audio/mp4'].includes(m)?m:'audio/webm';
const PH='data:image/gif;base64,R0lGODlhAQABAAAAACw=';

const S={user:null,enc:{},priv:null,rooms:[],room:null,msgs:new Map(),since:0,more:false,members:[],names:new Map(),roomMembers:[],
  editing:null,replying:null,pending:null,sel:null,lastTotal:null,unreadMap:null,first:true,rendered:false,lastRead:null,away:0,
  version:'',peerRead:null,lastPeer:null,jump:null,invite:null};
let rec=null;let timer=null,gen=0,authMode='login',regOpen=true,first=false;
const keyCache=new Map(),imgUrls=new Map();
const drafts=(()=>{try{return JSON.parse(localStorage.getItem('haven_drafts')||'{}');}catch(e){return {};}})();

/* ---------- appearance ---------- */
function applyLook(){
  const d=document.documentElement;
  d.dataset.accent=localStorage.getItem('haven_accent')||'violet';
  document.body.classList.toggle('compact',localStorage.getItem('haven_density')==='compact');
  d.style.setProperty('--fs',({small:'14px',normal:'15px',large:'17px'})[localStorage.getItem('haven_size')||'normal']);
}
applyLook();

/* ---------- auth ---------- */
function showAuth(){clearTimeout(timer);gen++;S.user=null;$('app').classList.add('hidden');$('auth').classList.remove('hidden');setMode(first||S.invite?'register':'login');}
function setMode(m){
  authMode=m;const r=m==='register';
  $('aPass2').classList.toggle('hidden',!r);
  $('aSub').textContent=r?(first?'Create the admin account to get started.':(S.invite?'You were invited to Haven. Create your account.':'Create your account.')):'Sign in to continue.';
  $('aGo').textContent=r?'Create account':'Sign in';
  $('aSwap').textContent=r?'Already have an account? Sign in':'New here? Create an account';
  $('aSwap').classList.toggle('hidden',first||(!r&&!regOpen&&!S.invite));
  $('aPass').autocomplete=r?'new-password':'current-password';$('aErr').textContent='';
}
$('aSwap').onclick=()=>setMode(authMode==='login'?'register':'login');
async function authGo(){
  const name=$('aName').value.trim(),password=$('aPass').value;
  if(authMode==='register'&&password!==$('aPass2').value){$('aErr').textContent='Passwords do not match';return;}
  $('aGo').disabled=true;
  try{
    await api(authMode==='login'?'/api/login':'/api/register',authMode==='login'?{name,password}:{name,password,invite:S.invite||''});
    $('aPass').value='';$('aPass2').value='';
    if(S.invite){S.invite=null;history.replaceState(null,'',location.pathname);}
    await boot(password);
  }catch(e){$('aErr').textContent=e.message;}
  $('aGo').disabled=false;
}
$('aGo').onclick=authGo;
['aName','aPass','aPass2'].forEach(i=>$(i).addEventListener('keydown',e=>{if(e.key==='Enter')authGo();}));
async function signOut(){try{await api('/api/logout',{});}catch(e){}S.priv=null;keyCache.clear();await boot();}

/* ---------- encryption keys ---------- */
async function ensureKeys(pw){
  const srv=S.enc||{};S.priv=null;keyCache.clear();
  const loc=await idb.get('u'+S.user.id);
  if(loc&&srv.pub&&loc.pub===srv.pub){S.priv=loc.priv;return true;}
  if(!pw)return false;
  let privJwk,pub=srv.pub;
  if(srv.pub&&srv.wrapped){privJwk=await unwrapJwk(srv.wrapped,pw);}
  else{const kp=await newKeypair();privJwk=kp.privJwk;pub=kp.pubJwk;const wrapped=await wrapJwk(privJwk,pw);
    await api('/api/keys',{password:pw,pub,wrapped});S.enc={pub,wrapped};}
  S.priv=await importPriv(privJwk);await idb.put('u'+S.user.id,{priv:S.priv,pub});return true;
}
async function keyFor(room){
  if(!room||!S.priv)return null;const o=memberOf(room.name);if(!o||!o.pub)return null;
  const ck=o.id+':'+o.pub;if(!keyCache.has(ck))keyCache.set(ck,await dmKey(S.priv,o.pub));return keyCache.get(ck);
}
const keyForId=id=>keyFor(S.rooms.find(r=>r.id===id&&r.kind==='dm'));
async function decryptMsgs(list){
  const cache=new Map();
  for(const m of list){
    if(m.deleted||m.kind==='poll')continue;
    const rm=S.rooms.find(r=>r.id===m.room);
    if(!rm||rm.kind!=='dm')continue;
    if(!m.text.startsWith('e2e:1:')){if(m.text||m.image)m.legacy=true;continue;}
    if(!cache.has(rm.id))cache.set(rm.id,await keyFor(rm));
    const key=cache.get(rm.id);
    if(!key){m.text='🔒 Encrypted message. Unlock to read it.';m.locked=true;m.img=m.aud=m.fil=null;continue;}
    try{const o=await openText(key,m.text,m.room);m.text=o.t||'';m.img=o.i||null;m.aud=o.a||null;m.fil=o.f||null;}
    catch(e){m.text='🔒 Could not decrypt this message';m.bad=true;m.img=m.aud=m.fil=null;}
  }
}
function openUnlock(){
  modal('<h3>Unlock encrypted DMs</h3><p class="sub">Enter your password once on this device. Your messages are decrypted here in your browser, and the server never sees them.</p>'+
    '<input id="ulPw" type="password" placeholder="Your password" autocomplete="current-password"><div class="msgerr" id="ulErr"></div>'+
    '<button class="primary" id="ulGo">Unlock</button><button data-close>Not now</button>');
  const go=async()=>{try{await ensureKeys($('ulPw').value);closeModal();toast('Encrypted DMs unlocked');resetRoom();poll();}
    catch(e){$('ulErr').textContent=e.name==='OperationError'?'Wrong password':e.message;}};
  $('ulGo').onclick=go;$('ulPw').addEventListener('keydown',e=>{if(e.key==='Enter')go();});setTimeout(()=>$('ulPw').focus(),50);
}

/* ---------- boot / rooms / drafts ---------- */
async function boot(pw){
  const mh=location.hash.match(/invite=([\w-]+)/);if(mh)S.invite=mh[1];
  const st=await api('/api/state');regOpen=st.registration;first=st.first;S.version=st.version;
  if(!st.user){showAuth();return;}
  S.user=st.user;S.enc=st.enc||{};S.room=Number(localStorage.getItem('haven_room'))||1;S.lastTotal=null;S.unreadMap=null;S.members=[];
  $('auth').classList.add('hidden');$('app').classList.remove('hidden');renderMe();
  try{await ensureKeys(pw);}catch(e){toast('Could not set up encrypted DMs: '+(e.name==='OperationError'?'wrong password':e.message));}
  resetRoom();loadDraft();poll();
}
function renderMe(){
  $('meBtn').innerHTML=avatar(S.user.name,S.user.avatar)+'<div class="nm"><b>'+esc(S.user.name)+'</b><span class="sub small">'+esc(S.user.status||'Set a status')+'</span></div>'+ico('down');
}
function saveDraft(){
  if(!S.room||S.editing)return;const v=$('box').value;
  if(v.trim())drafts[S.room]=v;else delete drafts[S.room];
  try{localStorage.setItem('haven_drafts',JSON.stringify(drafts));}catch(e){}
}
function loadDraft(){const v=drafts[S.room];if(v&&!$('box').value){$('box').value=v;autosize();}}
window.addEventListener('beforeunload',saveDraft);
function resetRoom(){S.msgs=new Map();S.since=0;S.more=false;S.first=true;S.rendered=false;S.sel=null;S.lastRead=null;S.away=0;S.pending=null;S.peerRead=null;S.lastPeer=null;
  cancelCtx();renderAtt();$('msgs').innerHTML='';$('typing').textContent='';$('jump').classList.add('hidden');closeAc();gen++;}
function switchRoom(id){saveDraft();$('box').value='';S.room=id;localStorage.setItem('haven_room',id);resetRoom();loadDraft();closeSide();poll();}
async function openDm(uid){try{const d=await api('/api/dm',{user:uid});switchRoom(d.id);}catch(e){toast(e.message);}}
const curRoom=()=>S.rooms.find(r=>r.id===S.room);
const isNear=()=>{const b=$('msgs');return b.scrollHeight-b.scrollTop-b.clientHeight<140;};
function setBanner(t){
  const b=$('banner');t=t||'';
  if(!t||localStorage.getItem('haven_banner')===t){b.classList.add('hidden');return;}
  b.innerHTML='<span>📣 '+esc(t)+'</span><button class="ib" data-x title="Dismiss">'+ico('x')+'</button>';b.dataset.t=t;b.classList.remove('hidden');
}
$('banner').onclick=e=>{if(e.target.closest('[data-x]')){localStorage.setItem('haven_banner',$('banner').dataset.t||'');$('banner').classList.add('hidden');}};

/* ---------- polling ---------- */
async function poll(){
  clearTimeout(timer);const g=gen;
  try{
    const d=await api('/api/poll?room='+S.room+'&since='+S.since+'&read='+(document.hidden?0:1));
    if(g!==gen)return;
    S.rooms=d.rooms;S.members=d.members;S.names=new Map(d.members.map(m=>[m.name.toLowerCase(),m.name]));
    S.roomMembers=d.room_members||[];S.peerRead=d.peer_read;setBanner(d.banner);
    if(!d.room_ok){switchRoom(d.rooms[0].id);return;}
    if(S.since===0){S.more=d.more;S.lastRead=d.last_read;}
    await decryptMsgs(d.messages);
    if(g!==gen)return;
    const near=isNear();let changed=false,incoming=0;
    for(const m of d.messages){
      if(m.kind==='expired'){if(S.msgs.delete(m.id))changed=true;continue;}
      if(!S.msgs.has(m.id)&&S.rendered&&m.uid!==S.user.id&&!m.deleted)incoming++;
      S.msgs.set(m.id,m);changed=true;
    }
    S.since=d.rev;
    if(incoming&&!near)S.away+=incoming;
    renderSide();
    if(changed||!S.rendered||S.peerRead!==S.lastPeer){renderMsgs(true);S.rendered=true;S.lastPeer=S.peerRead;}
    $('typing').textContent=d.typing.length?d.typing.join(', ')+(d.typing.length>1?' are':' is')+' typing…':'';
    notifyUnread(d);
    processJump();
    timer=setTimeout(poll,document.hidden?4000:1500);
  }catch(e){
    if(e.status===401){boot();return;}
    timer=setTimeout(poll,4000);
  }
}
function pollNow(){gen++;poll();}
function notifyUnread(d){
  const live=S.rooms.filter(r=>!r.muted),total=live.reduce((a,r)=>a+r.unread,0);
  const prev=S.unreadMap;S.unreadMap=new Map(S.rooms.map(r=>[r.id,r.unread]));
  if(S.lastTotal!==null&&total>S.lastTotal){beep();
    if(localStorage.getItem('haven_notify')==='on'&&window.Notification&&Notification.permission==='granted'&&prev){
      for(const r of live){const before=prev.get(r.id)||0;if(r.unread>before){
        let body=(r.unread-before)+' new message'+(r.unread-before>1?'s':'');
        if(r.id===S.room){const last=[...d.messages].reverse().find(m=>m.uid!==S.user.id&&!m.deleted);if(last)body=last.name+': '+(last.text||(last.poll?'poll':'attachment')).slice(0,100);}
        try{const n=new Notification((r.kind==='dm'?'@ ':'# ')+r.name,{body,tag:'haven-'+r.id,icon:'/icon-192.png'});n.onclick=()=>{window.focus();switchRoom(r.id);n.close();};}catch(e){}
      }}
    }
  }
  S.lastTotal=total;document.title=(total?'('+total+') ':'')+'Haven';
}
function beep(){
  if(localStorage.getItem('haven_sound')==='off')return;
  try{const a=new(window.AudioContext||window.webkitAudioContext)(),o=a.createOscillator(),g=a.createGain();
  o.frequency.value=660;g.gain.value=.05;o.connect(g);g.connect(a.destination);o.start();o.stop(a.currentTime+.12);}catch(e){}
}
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&S.user)pollNow();});
async function loadOlder(){
  const f=Math.min(...S.msgs.keys());
  const d=await api('/api/older?room='+S.room+'&before='+f);await decryptMsgs(d.messages);
  d.messages.forEach(m=>S.msgs.set(m.id,m));S.more=d.more;
}
async function processJump(){
  if(!S.jump||!S.rendered)return;const id=S.jump;S.jump=null;let tries=0;
  try{while(!S.msgs.has(id)&&S.more&&tries<10){tries++;await loadOlder();}}catch(e){}
  renderMsgs(false);
  const el=document.querySelector('.msg[data-id="'+id+'"]');
  if(el){el.scrollIntoView({block:'center'});el.classList.add('flash');setTimeout(()=>el.classList.remove('flash'),1800);}
  else toast('That message is no longer available');
}
function goTo(room,id){
  closeModal();
  if(room===S.room){S.jump=id;processJump();}else{S.jump=id;switchRoom(room);}
}

/* ---------- render ---------- */
function roomLabel(r){return r.kind==='dm'?'@ '+r.name:'# '+r.name;}
function renderSide(){
  const item=(r,label)=>'<div class="room'+(r.id===S.room?' on':'')+(r.unread&&!r.muted?' unread':'')+(r.muted?' muted':'')+'" data-room="'+r.id+'"><span>'+label+'</span>'+(r.unread?'<span class="badge'+(r.muted?' mutedb':'')+'">'+r.unread+'</span>':(r.muted?ico('bell-off'):''))+'</div>';
  $('rooms').innerHTML=S.rooms.filter(r=>r.kind!=='dm').map(r=>item(r,ico(r.kind==='private'?'lock':'hash')+esc(r.name))).join('');
  $('dms').innerHTML=S.rooms.filter(r=>r.kind==='dm').map(r=>{const m=memberOf(r.name)||{};
    return item(r,'<span class="avw">'+avatar(r.name,m.avatar,'s')+'<span class="dot'+(m.online?' on':'')+'"></span></span>'+esc(r.name));}).join('')||'<div class="mem hint">Click a member to start a chat</div>';
  $('members').innerHTML=S.members.map(m=>{const you=m.id===S.user.id;
    return '<div class="mem'+(you?'':' click')+'"'+(you?'':' data-user="'+m.id+'"')+'><span class="avw">'+avatar(m.name,m.avatar,'s')+'<span class="dot'+(m.online?' on':'')+'"></span></span><div class="t"><div>'+esc(m.name)+(you?' <span class="ed">(you)</span>':'')+'</div>'+(m.status?'<div class="st">'+esc(m.status)+'</div>':'')+'</div></div>';}).join('');
  const cur=curRoom(),dm=cur&&cur.kind==='dm',o=dm?memberOf(cur.name):null;
  $('rName').innerHTML=cur?(dm?esc(cur.name)+' <span class="tag">'+ico('lock')+' encrypted</span>':ico(cur.kind==='private'?'lock':'hash')+esc(cur.name)+(cur.kind==='private'?' <span class="tag">private</span>':'')):'';
  let sub='';
  if(cur){
    if(dm)sub=o?(o.status||(o.online?'Online':'Offline')):'';
    else if(cur.kind==='private')sub=(cur.topic?cur.topic+' · ':'')+S.roomMembers.length+' members';
    else sub=cur.topic||(S.members.filter(m=>m.online).length+' online · '+S.members.length+' members');
    if(cur.ttl)sub+=' · ⏱ disappear after '+TTL_LABEL[cur.ttl];
  }
  $('rSub').textContent=sub;
  $('bLock').classList.toggle('hidden',!dm);
  updateComposer();
}
function updateComposer(){
  const cur=curRoom(),dm=cur&&cur.kind==='dm';let note='';
  if(dm){const o=memberOf(cur.name);
    if(!S.priv)note='🔒 Unlock encrypted DMs on this device to read and send messages here. <button id="noteBtn" class="primary">Unlock</button>';
    else if(!o||!o.pub)note='🔒 '+esc(cur.name)+' hasn\'t turned on encrypted messages yet. They just need to sign in once.';}
  $('note').innerHTML=note;$('note').classList.toggle('hidden',!note);
  for(const id of ['box','send','mic','bAttach','bFmt','bEmoji'])$(id).disabled=!!note;
  $('box').placeholder=dm?'Encrypted message':'Message';
}
$('note').onclick=e=>{if(e.target.id==='noteBtn')openUnlock();};
function dayLabel(d){const t=new Date(),y=new Date(Date.now()-864e5);
  if(d.toDateString()===t.toDateString())return 'Today';if(d.toDateString()===y.toDateString())return 'Yesterday';
  return d.toLocaleDateString(undefined,{weekday:'long',month:'short',day:'numeric'});}
function attHtml(m){
  if(!m.image)return '';
  const n=m.image,ext=extOf(n),r=m.room;
  if(ext==='bin'){
    if(m.img)return '<img class="pic" data-enc="1" data-room="'+r+'" data-name="'+esc(n)+'" data-mime="'+esc(safeMime(m.img.m))+'" src="'+PH+'" width="'+(+m.img.w||240)+'" height="'+(+m.img.h||180)+'" alt="encrypted image">';
    if(m.aud)return '<div class="voice"><audio controls preload="metadata" data-enc="1" data-room="'+r+'" data-name="'+esc(n)+'" data-mime="'+esc(safeAudio(m.aud.m))+'"></audio><span class="sub small">'+fmtDur(m.aud.d)+'</span></div>';
    if(m.fil)return '<button class="file" data-dlenc="1" data-room="'+r+'" data-name="'+esc(n)+'" data-fname="'+esc(m.fil.n||'file')+'">'+ico('file')+'<span><b>'+esc(m.fil.n||'file')+'</b><small>'+fsize(m.fil.s)+' · encrypted</small></span>'+ico('download')+'</button>';
    return '';
  }
  if(IMGX.includes(ext))return '<img class="pic" src="/uploads/'+esc(n)+'" width="'+(+m.iw||240)+'" height="'+(+m.ih||180)+'" loading="lazy" alt="image">';
  if(AUDX.includes(ext))return '<div class="voice"><audio controls preload="metadata" src="/uploads/'+esc(n)+'"></audio><span class="sub small">'+fmtDur(m.iw)+'</span></div>';
  return '<a class="file" href="/uploads/'+esc(n)+'" download>'+ico('file')+'<span><b>'+esc(m.fname||'file')+'</b><small>'+fsize(m.fsize)+'</small></span>'+ico('download')+'</a>';
}
function pollHtml(m){
  const p=m.poll,voters=new Set(p.options.flatMap(o=>o.who)),total=voters.size;
  return '<div class="poll"><div class="pq">'+ico('poll')+' '+esc(p.q)+'</div>'+p.options.map((o,i)=>{
    const n=o.who.length,pct=total?Math.round(n*100/total):0,mine=o.who.includes(S.user.name);
    return '<button class="po'+(mine?' mine':'')+'" data-vote="'+i+'" title="'+esc(o.who.join(', ')||'No votes yet')+'"><span class="bar" style="width:'+pct+'%"></span><span class="pt">'+(mine?'✓ ':'')+esc(o.t)+'</span><span class="pc">'+n+'</span></button>';}).join('')+
    '<div class="sub small">'+total+' vote'+(total===1?'':'s')+(p.multi?' · pick as many as you like':' · pick one')+'</div></div>';
}
function renderMsgs(stick){
  const box=$('msgs'),near=isNear();
  const q=$('search').value.trim().toLowerCase(),cur=curRoom(),dm=cur&&cur.kind==='dm';
  const canMod=S.user.admin&&cur&&cur.kind==='channel';
  const meRe=new RegExp('@'+S.user.name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'(?![A-Za-z0-9_.-])','i');
  const list=[...S.msgs.values()].sort((a,b)=>a.id-b.id).filter(m=>!q||(!m.deleted&&((m.text||'').toLowerCase().includes(q)||(m.poll&&m.poll.q.toLowerCase().includes(q))||m.name.toLowerCase().includes(q))));
  let lastMine=0;if(dm&&S.peerRead!==null)for(const m of list)if(m.uid===S.user.id&&!m.deleted)lastMine=m.id;
  let h='<div class="col">'+(S.more&&!q?'<button class="more" id="more">Load earlier messages</button>':'');
  let prev=null,lastDay='',divDone=false;
  for(const m of list){
    const d=new Date(m.ts*1000),day=d.toDateString();
    if(day!==lastDay){h+='<div class="day">'+esc(dayLabel(d))+'</div>';lastDay=day;prev=null;}
    if(!q&&!divDone&&S.lastRead!==null&&m.id>S.lastRead&&m.uid!==S.user.id){h+='<div class="newdiv"><span>New messages</span></div>';divDone=true;prev=null;}
    const grp=prev&&prev.uid===m.uid&&!m.reply&&m.ts-prev.ts<300;
    const ment=!dm&&!m.deleted&&m.uid!==S.user.id&&meRe.test(m.text||'');
    const mine=m.uid===S.user.id;
    let inner='';
    if(m.reply){let rt;if(m.reply.deleted)rt='<i>deleted message</i>';else{const p=dm?S.msgs.get(m.reply.id):null;rt=esc(dm?(p?(p.text||(p.poll?'poll':'attachment')):'message'):(m.reply.text||'attachment'));}
      inner+='<div class="quote" data-jump="'+m.reply.id+'"><b>'+esc(m.reply.name)+'</b> '+rt+'</div>';}
    if(m.deleted)inner+='<div class="tx del">message deleted</div>';
    else{
      if(m.poll)inner+=pollHtml(m);
      if(m.text)inner+='<div class="tx">'+fmt(m.text)+(m.edited?' <span class="ed">(edited)</span>':'')+(dm&&m.legacy?' <span class="ed" title="Sent before encryption was added">(not encrypted)</span>':'')+'</div>';
      inner+=attHtml(m);
      if(m.reactions.length)inner+='<div class="rx">'+m.reactions.map(r=>'<button class="chip'+(r.who.includes(S.user.name)?' mine':'')+'" data-e="'+r.e+'" title="'+esc(r.who.join(', '))+'">'+r.e+' '+r.who.length+'</button>').join('')+'</div>';
      if(m.id===lastMine)inner+='<div class="rcpt">'+(S.peerRead>=m.id?'✓✓ Seen':'✓ Sent')+'</div>';
    }
    h+='<div class="msg'+(grp?'':' first')+(m.id===S.sel?' sel':'')+(ment?' mention':'')+'" data-id="'+m.id+'">'+(grp?'<div class="sp"></div>':avatar(m.name,m.av))+'<div class="bd">'+
      (grp?'':'<div class="hd"><b style="color:'+color(m.name)+'">'+esc(m.name)+'</b><span>'+d.toLocaleTimeString([],{hour:'numeric',minute:'2-digit'})+'</span></div>')+inner+'</div>'+
      ((m.pinned||m.saved)&&!m.deleted?'<span class="flags">'+(m.pinned?'<span title="Pinned">'+ico('pin')+'</span>':'')+(m.saved?'<span title="Saved">'+ico('star')+'</span>':'')+'</span>':'');
    if(!m.deleted&&!m.locked&&!m.bad)h+='<div class="acts"><button data-act="react" data-openpick title="React">'+ico('smile')+'</button><button data-act="reply" title="Reply">'+ico('reply')+'</button>'+
      (mine&&m.kind!=='poll'?'<button data-act="edit" title="Edit">'+ico('edit')+'</button>':'')+'<button data-act="more" data-openmenu title="More">'+ico('more')+'</button></div>';
    h+='</div>';prev=m;
  }
  if(!list.length)h+='<div class="day">'+(q?'No matches':(dm?'No messages yet. Everything here is end-to-end encrypted.':'No messages yet. Say hello!'))+'</div>';
  box.innerHTML=h+'</div>';
  if(stick&&(near||S.first)){box.scrollTop=box.scrollHeight;S.away=0;}
  S.first=false;updateJump();
  hydrate(box);
}
async function hydrate(root){
  for(const el of root.querySelectorAll('[data-enc]')){
    const n=el.dataset.name;
    if(imgUrls.has(n)){el.src=imgUrls.get(n);continue;}
    if(el.dataset.busy)continue;el.dataset.busy='1';
    try{
      const rid=+el.dataset.room,key=await keyForId(rid);if(!key)throw 0;
      const r=await fetch('/uploads/'+n);if(!r.ok)throw 0;
      const bytes=await openBytes(key,await r.arrayBuffer(),(el.tagName==='AUDIO'?'haven-aud:':'haven-img:')+rid);
      const url=URL.createObjectURL(new Blob([bytes],{type:el.dataset.mime}));imgUrls.set(n,url);
      document.querySelectorAll('[data-name="'+n+'"][data-enc]').forEach(x=>x.src=url);
    }catch(e){el.alt='Could not load this attachment';}
  }
}
async function downloadEnc(b){
  try{
    const rid=+b.dataset.room,key=await keyForId(rid);if(!key)throw 0;
    const r=await fetch('/uploads/'+b.dataset.name);if(!r.ok)throw 0;
    const bytes=await openBytes(key,await r.arrayBuffer(),'haven-file:'+rid);
    const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([bytes],{type:'application/octet-stream'}));a.download=b.dataset.fname||'file';
    document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove();},1500);
  }catch(e){toast('Could not decrypt that file');}
}
function updateJump(){const far=$('msgs').scrollHeight-$('msgs').scrollTop-$('msgs').clientHeight>300;
  $('jump').classList.toggle('hidden',!far);$('jumpN').textContent=S.away?S.away+' new':'';}
$('msgs').addEventListener('scroll',()=>{if(isNear())S.away=0;updateJump();});
$('jump').onclick=()=>{$('msgs').scrollTo({top:$('msgs').scrollHeight,behavior:'smooth'});S.away=0;};
$('search').oninput=()=>renderMsgs(false);
$('bSearch').onclick=()=>{const h=$('hdr');h.classList.toggle('s-open');if(h.classList.contains('s-open'))$('search').focus();else{$('search').value='';renderMsgs(false);}};

/* ---------- message interactions ---------- */
$('msgs').onclick=async e=>{
  const t=e.target;
  if(t.id==='more'){const box=$('msgs'),h0=box.scrollHeight;try{await loadOlder();renderMsgs(false);box.scrollTop=box.scrollHeight-h0;}catch(x){toast(x.message);}return;}
  const sp=t.closest('.spoiler');if(sp){sp.classList.toggle('on');return;}
  const dl=t.closest('[data-dlenc]');if(dl){downloadEnc(dl);return;}
  const pic=t.closest('.pic');if(pic&&pic.src&&pic.src!==PH){openLb(pic.src);return;}
  const jump=t.closest('[data-jump]');
  if(jump){const el=document.querySelector('.msg[data-id="'+jump.dataset.jump+'"]');
    if(el){el.scrollIntoView({block:'center'});el.classList.add('flash');setTimeout(()=>el.classList.remove('flash'),1500);}else toast('That message is older than what is loaded');return;}
  const row=t.closest('.msg');if(!row)return;
  const id=Number(row.dataset.id),m=S.msgs.get(id);
  const vt=t.closest('[data-vote]');if(vt){try{await api('/api/vote/'+id,{opt:+vt.dataset.vote});pollNow();}catch(x){toast(x.message);}return;}
  const chip=t.closest('.chip');if(chip){react(id,chip.dataset.e);return;}
  const b=t.closest('[data-act]');
  if(b){
    const a=b.dataset.act;
    if(a==='react')openPick(b,REACTS,em=>react(id,em));
    else if(a==='reply'){S.replying=id;S.editing=null;renderCtx();$('box').focus();}
    else if(a==='edit'){S.editing=id;S.replying=null;$('box').value=m.text;renderCtx();$('box').focus();autosize();}
    else if(a==='more')openMore(b,m);
    return;
  }
  if(t.closest('a')||t.closest('audio')||t.closest('.file')||t.closest('.poll'))return;
  const was=row.classList.contains('sel');
  document.querySelectorAll('.msg.sel').forEach(x=>x.classList.remove('sel'));
  if(!was){row.classList.add('sel');S.sel=id;}else S.sel=null;
};
function openMore(anchor,m){
  const cur=curRoom(),mine=m.uid===S.user.id,canMod=S.user.admin&&cur&&cur.kind==='channel';
  const items=[
    {icon:'pin',label:m.pinned?'Unpin message':'Pin to this chat',fn:async()=>{try{await api('/api/pin/'+m.id,{});pollNow();}catch(e){toast(e.message);}}},
    {icon:'star',label:m.saved?'Remove from saved':'Save for later',fn:async()=>{try{const d=await api('/api/save/'+m.id,{});m.saved=d.saved;renderMsgs(false);toast(d.saved?'Saved. Find it under Saved items.':'Removed from saved');}catch(e){toast(e.message);}}}
  ];
  if(m.text)items.push({icon:'copy',label:'Copy text',fn:async()=>{try{await navigator.clipboard.writeText(m.text);toast('Copied');}catch(e){toast('Could not copy');}}});
  if(mine||canMod)items.push({sep:true},{icon:'trash',label:'Delete message',danger:true,fn:async()=>{if(confirm('Delete this message?')){try{await api('/api/delete/'+m.id,{});pollNow();}catch(e){toast(e.message);}}}});
  popMenu(anchor,items,{right:true});
}
async function react(id,emoji){try{await api('/api/react/'+id,{emoji});pollNow();}catch(e){toast(e.message);}}
$('rooms').onclick=$('dms').onclick=e=>{const r=e.target.closest('.room');if(r)switchRoom(Number(r.dataset.room));};
$('members').onclick=e=>{const m=e.target.closest('[data-user]');if(m)openDm(Number(m.dataset.user));};
function openSide(){$('side').classList.add('open');}
function closeSide(){$('side').classList.remove('open');}
$('menu').onclick=()=>$('side').classList.toggle('open');
$('scrim').onclick=closeSide;
let tx0=null,ty0=null;
document.addEventListener('touchstart',e=>{const t=e.touches[0];tx0=t.clientX;ty0=t.clientY;},{passive:true});
document.addEventListener('touchend',e=>{if(tx0===null)return;const t=e.changedTouches[0],dx=t.clientX-tx0,dy=Math.abs(t.clientY-ty0);
  if(innerWidth<=760&&dy<50){if(tx0<24&&dx>70)openSide();else if(dx<-70&&$('side').classList.contains('open'))closeSide();}tx0=null;},{passive:true});
if(window.visualViewport){const f=()=>{document.documentElement.style.setProperty('--vh',visualViewport.height+'px');if(document.activeElement===$('box'))window.scrollTo(0,0);};
  visualViewport.addEventListener('resize',f);f();}

/* ---------- popovers: emoji, formatting, menus ---------- */
function place(p,anchor,rightAlign){
  const r=anchor.getBoundingClientRect(),w=p.offsetWidth,h=p.offsetHeight;
  p.style.left=Math.max(8,Math.min(innerWidth-w-8,rightAlign?r.right-w:r.left))+'px';
  p.style.top=(r.top-h-8<8?r.bottom+8:r.top-h-8)+'px';
}
let pickCb=null;
function openPick(anchor,list,cb){
  closePops();const p=$('pick');p.innerHTML=list.map(e=>'<button data-e="'+e+'">'+e+'</button>').join('');pickCb=cb;p.classList.remove('hidden');place(p,anchor,true);
}
function popMenu(anchor,items,opts){
  closePops();const m=$('umenu');
  m.innerHTML=items.map((it,i)=>it.sep?'<hr>':'<button data-mi="'+i+'" class="'+(it.danger?'danger':'')+'">'+(it.icon?ico(it.icon):'')+' <span>'+esc(it.label)+'</span></button>').join('');
  m._items=items;m.classList.remove('hidden');place(m,anchor,!!(opts&&opts.right));
}
function closePops(){$('pick').classList.add('hidden');$('umenu').classList.add('hidden');$('fmtp').classList.add('hidden');pickCb=null;}
$('umenu').onclick=e=>{const b=e.target.closest('[data-mi]');if(!b)return;const it=$('umenu')._items[+b.dataset.mi];closePops();if(it&&it.fn)it.fn();};
document.addEventListener('click',e=>{
  const inPop=e.target.closest('#pick,#umenu,#fmtp'),opener=e.target.closest('[data-openpick],[data-openmenu],[data-openfmt]');
  if(!$('pick').classList.contains('hidden')&&pickCb){
    const b=e.target.closest('#pick [data-e]');
    if(b){const cb=pickCb;closePops();cb(b.dataset.e);return;}
  }
  if(!inPop&&!opener)closePops();
},true);
$('bEmoji').onclick=e=>openPick(e.currentTarget,EMOJIS,em=>{const b=$('box');b.setRangeText(em,b.selectionStart,b.selectionEnd,'end');b.focus();autosize();});
$('meBtn').onclick=()=>popMenu($('meBtn'),[
  {icon:'user',label:'Profile & settings',fn:openProfile},
  {icon:'star',label:'Saved items',fn:()=>openLibrary('saved')},
  ...(S.user.admin?[{icon:'shield',label:'Admin panel',fn:openAdmin}]:[]),
  {icon:'cert',label:'Install certificate',fn:()=>window.open('/trust','_blank')},
  {sep:true},{icon:'out',label:'Sign out',danger:true,fn:signOut}]);
$('meBtn').setAttribute('data-openmenu','');
function openLb(url){$('lbImg').src=url;$('lbOpen').href=url;$('lb').classList.remove('hidden');}
$('lb').onclick=e=>{if(e.target.tagName!=='A')$('lb').classList.add('hidden');};

/* ---------- formatting panel ---------- */
function wrap(l,r,ph){const b=$('box'),s=b.selectionStart,e=b.selectionEnd,sel=b.value.slice(s,e)||ph;
  b.setRangeText(l+sel+r,s,e,'end');b.setSelectionRange(s+l.length,s+l.length+sel.length);b.focus();autosize();}
function lines(fn){const b=$('box'),v=b.value,s=b.selectionStart,e=b.selectionEnd,ls=v.lastIndexOf('\n',s-1)+1;let le=v.indexOf('\n',e);if(le<0)le=v.length;
  b.setRangeText(v.slice(ls,le).split('\n').map((l,i)=>fn(l,i)).join('\n'),ls,le,'select');b.focus();autosize();}
function linkFmt(){const b=$('box'),s=b.selectionStart,e=b.selectionEnd,sel=b.value.slice(s,e)||'link text';
  b.setRangeText('['+sel+'](https://)',s,e,'end');const u=s+sel.length+3+8;b.setSelectionRange(u,u);b.focus();autosize();}
const FMT=[
 {l:'Bold',g:'<b>B</b>',tip:'Ctrl+B',fn:()=>wrap('**','**','bold text')},
 {l:'Italic',g:'<i>I</i>',tip:'Ctrl+I',fn:()=>wrap('_','_','italic text')},
 {l:'Underline',g:'<u>U</u>',tip:'Ctrl+U',fn:()=>wrap('__','__','underlined')},
 {l:'Strike',g:'<s>S</s>',tip:'Ctrl+Shift+X',fn:()=>wrap('~~','~~','struck out')},
 {l:'Code',g:'&lt;/&gt;',tip:'Ctrl+E',fn:()=>wrap('`','`','code')},
 {l:'Code block',g:'{ }',fn:()=>wrap('```\n','\n```','code here')},
 {l:'Quote',g:'❝',fn:()=>lines(l=>'> '+l)},
 {l:'Bullets',g:'•',fn:()=>lines(l=>'- '+l)},
 {l:'Numbers',g:'1.',fn:()=>lines((l,i)=>(i+1)+'. '+l)},
 {l:'Link',g:'🔗',fn:linkFmt},
 {l:'Spoiler',g:'▮',fn:()=>wrap('||','||','spoiler')},
 {l:'Mention',g:'@',fn:()=>{const b=$('box');b.setRangeText('@',b.selectionStart,b.selectionEnd,'end');b.focus();updateAc();}}
];
$('bFmt').onclick=e=>{
  closePops();const p=$('fmtp');
  p.innerHTML='<div class="fgrid">'+FMT.map((f,i)=>'<button data-f="'+i+'" title="'+esc(f.l+(f.tip?' ('+f.tip+')':''))+'"><span class="g">'+f.g+'</span><span class="l">'+f.l+'</span></button>').join('')+
    '</div><p class="sub small">Select some text first, then pick a style. Shortcuts: Ctrl+B, I, U, E.</p>';
  p.classList.remove('hidden');place(p,e.currentTarget,false);
};
$('fmtp').addEventListener('mousedown',e=>e.preventDefault());
$('fmtp').onclick=e=>{const b=e.target.closest('[data-f]');if(!b)return;closePops();FMT[+b.dataset.f].fn();};

/* ---------- autocomplete: @people, /commands, :emoji: ---------- */
let AC=null;
function closeAc(){AC=null;$('ac').classList.add('hidden');}
function updateAc(){
  const b=$('box'),pos=b.selectionStart,before=b.value.slice(0,pos);let items=[],m,start=0;
  if((m=before.match(/(^|\s)@([A-Za-z0-9_.-]{0,20})$/))){
    const q=m[2].toLowerCase();start=pos-m[2].length-1;
    items=S.members.filter(x=>x.id!==S.user.id&&x.name.toLowerCase().startsWith(q)).slice(0,6).map(x=>({h:avatar(x.name,x.avatar,'s')+'<b>@'+esc(x.name)+'</b><span class="sub small">'+esc(x.status||'')+'</span>',ins:'@'+x.name+' '}));
  }else if((m=before.match(/^\/([a-z]{0,10})$/))){
    start=0;items=SLASH.filter(x=>x.c.startsWith(m[1])).slice(0,8).map(x=>({h:'<b>/'+x.c+'</b><span class="sub small">'+esc(x.d)+'</span>',ins:'/'+x.c+' '}));
  }else if((m=before.match(/(^|\s):([a-z0-9_+-]{2,20})$/))){
    const q=m[2];start=pos-q.length-1;
    const keys=Object.keys(SHORT),hits=keys.filter(k=>k.startsWith(q)).concat(keys.filter(k=>!k.startsWith(q)&&k.includes(q))).slice(0,8);
    items=hits.map(k=>({h:'<span class="em">'+SHORT[k]+'</span><b>:'+esc(k)+':</b>',ins:SHORT[k]+' '}));
  }
  if(!items.length){closeAc();return;}
  AC={items,idx:0,start,end:pos};renderAc();
}
function renderAc(){
  const p=$('ac');p.innerHTML=AC.items.map((it,i)=>'<button data-ai="'+i+'" class="'+(i===AC.idx?'on':'')+'">'+it.h+'</button>').join('');p.classList.remove('hidden');
}
function applyAc(i){
  const it=AC.items[i],b=$('box');b.setRangeText(it.ins,AC.start,AC.end,'end');closeAc();b.focus();autosize();updateAc();
}
$('ac').addEventListener('mousedown',e=>e.preventDefault());
$('ac').onclick=e=>{const b=e.target.closest('[data-ai]');if(b)applyAc(+b.dataset.ai);};

/* ---------- composer ---------- */
function syncSend(){
  const has=$('box').value.trim().length>0||!!S.pending;
  const canMic=!!(navigator.mediaDevices&&navigator.mediaDevices.getUserMedia&&window.MediaRecorder)&&!S.editing&&!rec;
  $('send').classList.toggle('hidden',!has&&canMic);$('mic').classList.toggle('hidden',has||!canMic);
}
function autosize(){const b=$('box');b.style.height='auto';b.style.height=Math.min(b.scrollHeight,160)+'px';syncSend();}
function renderCtx(){
  const b=$('ctx');
  if(S.editing){b.innerHTML='<span>Editing message</span><button data-x>Cancel</button>';b.classList.remove('hidden');}
  else if(S.replying){const m=S.msgs.get(S.replying);
    b.innerHTML='<span>Replying to <b>'+esc(m?m.name:'')+'</b>: '+esc(m?(m.text||(m.poll?'poll':'attachment')):'')+'</span><button data-x>Cancel</button>';b.classList.remove('hidden');}
  else b.classList.add('hidden');
  syncSend();
}
function renderAtt(){
  const b=$('att'),p=S.pending;
  if(p){b.innerHTML=(p.preview?'<img src="'+esc(p.preview)+'" alt="">':ico('file'))+'<span>'+esc(p.kind==='image'?'Photo ready to send':(p.fname||p.n||'File')+' · '+fsize(p.fsize||p.s))+'</span><button data-x>Remove</button>';b.classList.remove('hidden');}
  else b.classList.add('hidden');
  syncSend();
}
function cancelCtx(){const was=S.editing;S.editing=null;S.replying=null;if(was){$('box').value='';autosize();}renderCtx();}
$('ctx').onclick=e=>{if(e.target.dataset.x!==undefined)cancelCtx();};
$('att').onclick=e=>{if(e.target.dataset.x!==undefined){S.pending=null;renderAtt();}};

async function runCommand(t,dm){
  const m=t.match(/^\/(\w+)(?:\s+([\s\S]*))?$/);if(!m)return {text:t};
  const cmd=m[1].toLowerCase(),arg=(m[2]||'').trim();
  switch(cmd){
    case 'shrug':return {text:(arg?arg+' ':'')+'¯\\_(ツ)_/¯'};
    case 'tableflip':return {text:(arg?arg+' ':'')+'(╯°□°)╯︵ ┻━┻'};
    case 'unflip':return {text:(arg?arg+' ':'')+'┬─┬ ノ( ゜-゜ノ)'};
    case 'me':if(!arg)return {handled:true};return {text:'*'+S.user.name+' '+arg+'*'};
    case 'spoiler':if(!arg)return {handled:true};return {text:'||'+arg+'||'};
    case 'flip':return {text:'🪙 flipped a coin: **'+(rand(2)?'Heads':'Tails')+'**'};
    case 'roll':{
      const r=arg.match(/^(\d{1,2})?d(\d{1,4})$/i)||(arg===''?[null,'1','6']:null);
      if(!r){toast('Try /roll 2d6');return {handled:true};}
      const n=Math.min(20,+r[1]||1),s=Math.max(2,+r[2]),rolls=Array.from({length:n},()=>1+rand(s));
      return {text:'🎲 rolled '+n+'d'+s+': '+rolls.join(' + ')+(n>1?' = **'+rolls.reduce((a,b)=>a+b,0)+'**':'')};
    }
    case 'poll':{
      if(dm){toast('Polls are not available in encrypted DMs');return {handled:true};}
      const parts=arg.split('|').map(x=>x.trim()).filter(Boolean);
      if(parts.length<3){toast('Use: /poll Question | Option 1 | Option 2');return {handled:true};}
      return {poll:{q:parts[0],options:parts.slice(1,7),multi:false}};
    }
    case 'help':toast('Commands: '+SLASH.map(x=>'/'+x.c).join('  '));return {handled:true};
    default:return {text:t};
  }
}
async function send(){
  let t=$('box').value.trim();
  if(!t&&!(S.pending&&!S.editing))return;
  const cur=curRoom(),dm=cur&&cur.kind==='dm';
  let poll=null;
  if(!S.editing&&t.startsWith('/')){
    const r=await runCommand(t,dm);
    if(r.handled){return;}
    if(r.text!==undefined)t=r.text;poll=r.poll||null;
  }
  t=t.replace(/:([a-z0-9_+-]{2,20}):/g,(m,k)=>SHORT[k]||m);
  const wasEdit=S.editing,att=S.pending,rep=S.replying;
  $('box').value='';closeAc();autosize();
  try{
    if(poll){await api('/api/send',{room:S.room,poll,reply_to:rep});S.replying=null;}
    else if(dm){
      const key=await keyFor(cur);if(!key)throw new Error('Encryption is not ready for this chat yet');
      if(wasEdit){const old=S.msgs.get(wasEdit)||{},keep={t};if(old.img)keep.i=old.img;if(old.aud)keep.a=old.aud;if(old.fil)keep.f=old.fil;
        await api('/api/edit/'+wasEdit,{text:await sealText(key,keep,S.room)});S.editing=null;}
      else{const o={t};if(att){if(att.kind==='image')o.i={w:att.w,h:att.h,m:att.m};else o.f={n:att.n,s:att.s,m:att.m};}
        await api('/api/send',{room:S.room,text:await sealText(key,o,S.room),image:att?att.name:null,reply_to:rep});S.pending=null;S.replying=null;}
    }else{
      if(wasEdit){await api('/api/edit/'+wasEdit,{text:t});S.editing=null;}
      else{await api('/api/send',{room:S.room,text:t,image:att?att.name:null,reply_to:rep});S.pending=null;S.replying=null;}
    }
    delete drafts[S.room];renderCtx();renderAtt();pollNow();setTimeout(()=>{$('msgs').scrollTop=$('msgs').scrollHeight;},300);
  }catch(e){$('box').value=t;autosize();toast(e.message);}
}
$('send').onclick=send;
let lastTyping=0;
$('box').addEventListener('input',()=>{autosize();updateAc();const n=Date.now();
  if($('box').value&&n-lastTyping>3000){lastTyping=n;api('/api/typing',{room:S.room}).catch(()=>{});}});
$('box').addEventListener('click',updateAc);
$('box').addEventListener('keydown',e=>{
  if(AC){
    if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();AC.idx=(AC.idx+(e.key==='ArrowDown'?1:AC.items.length-1))%AC.items.length;renderAc();return;}
    if(e.key==='Enter'||e.key==='Tab'){e.preventDefault();applyAc(AC.idx);return;}
    if(e.key==='Escape'){e.preventDefault();closeAc();return;}
  }
  const mod=e.ctrlKey||e.metaKey,k=e.key.toLowerCase();
  if(mod&&!e.shiftKey&&k==='b'){e.preventDefault();FMT[0].fn();return;}
  if(mod&&!e.shiftKey&&k==='i'){e.preventDefault();FMT[1].fn();return;}
  if(mod&&!e.shiftKey&&k==='u'){e.preventDefault();FMT[2].fn();return;}
  if(mod&&e.shiftKey&&k==='x'){e.preventDefault();FMT[3].fn();return;}
  if(mod&&!e.shiftKey&&k==='e'){e.preventDefault();FMT[4].fn();return;}
  if(e.key==='Enter'&&!e.shiftKey&&!/Android|iPhone|iPad/.test(navigator.userAgent)){e.preventDefault();send();}
  else if(e.key==='Escape'){cancelCtx();}
  else if(e.key==='ArrowUp'&&!$('box').value&&!S.editing){
    const mine=[...S.msgs.values()].filter(m=>m.uid===S.user.id&&!m.deleted&&m.text&&!m.bad&&!m.locked&&m.kind!=='poll').sort((a,b)=>b.id-a.id)[0];
    if(mine){e.preventDefault();S.editing=mine.id;S.replying=null;$('box').value=mine.text;renderCtx();autosize();}
  }
});

/* ---------- attachments: photos, files, paste, drag and drop ---------- */
$('bAttach').onclick=e=>{
  const cur=curRoom(),dm=cur&&cur.kind==='dm';
  popMenu(e.currentTarget,[
    {icon:'image',label:'Photo',fn:()=>{$('file').accept='image/png,image/jpeg,image/gif,image/webp';$('file').dataset.kind='image';$('file').click();}},
    {icon:'file',label:'File (up to 25 MB)',fn:()=>{$('file').accept='';$('file').dataset.kind='file';$('file').click();}},
    ...(dm?[]:[{icon:'poll',label:'Poll',fn:()=>openPollCreator()}])]);
};
$('file').onchange=e=>{uploadFile(e.target.files[0],e.target.dataset.kind);e.target.value='';};
async function prepEncImage(f){
  let bytes=new Uint8Array(await f.arrayBuffer()),bmp=null;
  try{bmp=await createImageBitmap(f);}catch(e){}
  if(!bmp)throw new Error('Could not read that image');
  let w=bmp.width,h=bmp.height;
  if(f.type==='image/jpeg'){                       // re-encode: strips photo metadata and shrinks huge photos
    const sc=Math.min(1,2048/Math.max(w,h));w=Math.round(w*sc);h=Math.round(h*sc);
    const cv=document.createElement('canvas');cv.width=w;cv.height=h;cv.getContext('2d').drawImage(bmp,0,0,w,h);
    const blob=await new Promise(r=>cv.toBlob(r,'image/jpeg',0.9));if(blob)bytes=new Uint8Array(await blob.arrayBuffer());
  }
  return {bytes,w,h};
}
async function uploadFile(f,kind){
  if(!f)return;
  kind=kind||(f.type.startsWith('image/')?'image':'file');
  if(kind==='image'&&(!f.type.startsWith('image/')||f.size>8*1024*1024))kind='file';
  if(f.size>25*1024*1024){toast('That file is over 25 MB');return;}
  const cur=curRoom(),dm=cur&&cur.kind==='dm',fd=new FormData();let meta={kind};toast('Uploading…');
  try{
    if(dm){
      const key=await keyFor(cur);if(!key)throw new Error('Encryption is not ready for this chat yet');
      let bytes,aad;
      if(kind==='image'){const p=await prepEncImage(f);bytes=p.bytes;aad='haven-img:';meta={kind,w:p.w,h:p.h,m:f.type,preview:URL.createObjectURL(f)};}
      else{bytes=new Uint8Array(await f.arrayBuffer());aad='haven-file:';meta={kind,n:f.name,s:f.size,m:f.type||'application/octet-stream'};}
      fd.append('file',new Blob([await sealBytes(key,bytes,aad+S.room)]),'e.bin');fd.append('enc','1');
    }else{fd.append('file',f);fd.append('kind',kind);if(kind==='image')meta.preview=URL.createObjectURL(f);}
    const r=await fetch('/api/upload',{method:'POST',headers:{'X-Haven':'1'},body:fd});
    const d=await r.json();if(!r.ok)throw new Error(d.error||'Upload failed');
    S.pending=Object.assign({name:d.name,fname:d.fname,fsize:d.fsize},meta);renderAtt();$('toast').classList.add('hidden');$('box').focus();
  }catch(e){toast(e.message);}
}
$('box').addEventListener('paste',e=>{
  for(const it of e.clipboardData.items)if(it.kind==='file'){e.preventDefault();const f=it.getAsFile();uploadFile(f,f.type.startsWith('image/')?'image':'file');return;}
});
const main=$('main');let dragN=0;
main.addEventListener('dragenter',e=>{e.preventDefault();dragN++;main.classList.add('drag');});
main.addEventListener('dragleave',()=>{if(--dragN<=0){dragN=0;main.classList.remove('drag');}});
main.addEventListener('dragover',e=>e.preventDefault());
main.addEventListener('drop',e=>{e.preventDefault();dragN=0;main.classList.remove('drag');const f=e.dataTransfer.files[0];if(f)uploadFile(f,f.type.startsWith('image/')?'image':'file');});

/* ---------- voice messages ---------- */

function showRec(on){$('rec').classList.toggle('hidden',!on);$('cbox').classList.toggle('hidden',on);if(on){$('send').classList.add('hidden');$('mic').classList.add('hidden');}else syncSend();}
async function startRec(){
  if(rec)return;
  try{
    const st=await navigator.mediaDevices.getUserMedia({audio:true});
    const mt=['audio/webm;codecs=opus','audio/ogg;codecs=opus','audio/mp4','audio/webm'].find(t=>MediaRecorder.isTypeSupported(t))||'';
    const mr=new MediaRecorder(st,mt?{mimeType:mt}:undefined),chunks=[];
    const r={mr,st,chunks,t0:Date.now(),cancel:false,timer:null};rec=r;
    mr.ondataavailable=e=>{if(e.data.size)chunks.push(e.data);};
    mr.onstop=()=>{
      st.getTracks().forEach(x=>x.stop());clearInterval(r.timer);rec=null;showRec(false);
      if(r.cancel)return;const dur=Math.round((Date.now()-r.t0)/1000);
      if(dur<1){toast('Recording was too short');return;}
      const mime=(mr.mimeType||mt||'audio/webm').split(';')[0];
      sendVoice(new Blob(chunks,{type:mime}),dur,mime);
    };
    mr.start();showRec(true);$('recT').textContent='0:00';
    r.timer=setInterval(()=>{const s=Math.round((Date.now()-r.t0)/1000);$('recT').textContent=fmtDur(s);if(s>=300)stopRec(false);},250);
  }catch(e){rec=null;toast(e.name==='NotAllowedError'?'Microphone access was blocked in your browser':'Could not start recording');}
}
function stopRec(cancel){if(!rec)return;rec.cancel=!!cancel;try{rec.mr.stop();}catch(e){}}
$('mic').onclick=startRec;$('recX').onclick=()=>stopRec(true);$('recOk').onclick=()=>stopRec(false);
async function sendVoice(blob,dur,mime){
  const cur=curRoom(),dm=cur&&cur.kind==='dm',fd=new FormData(),rep=S.replying;toast('Sending voice message…');
  try{
    let key=null;
    if(dm){key=await keyFor(cur);if(!key)throw new Error('Encryption is not ready for this chat yet');
      fd.append('file',new Blob([await sealBytes(key,new Uint8Array(await blob.arrayBuffer()),'haven-aud:'+S.room)]),'v.bin');fd.append('enc','1');}
    else{fd.append('file',blob,'voice');fd.append('kind','audio');fd.append('dur',dur);}
    const r=await fetch('/api/upload',{method:'POST',headers:{'X-Haven':'1'},body:fd});
    const d=await r.json();if(!r.ok)throw new Error(d.error||'Upload failed');
    const text=dm?await sealText(key,{t:'',a:{m:mime,d:dur}},S.room):'';
    await api('/api/send',{room:S.room,text,image:d.name,reply_to:rep});
    S.replying=null;renderCtx();$('toast').classList.add('hidden');pollNow();setTimeout(()=>{$('msgs').scrollTop=$('msgs').scrollHeight;},300);
  }catch(e){toast(e.message);}
}

/* ---------- rooms: create, details ---------- */
function modal(html){$('mcard').innerHTML=html;$('modal').classList.remove('hidden');}
function closeModal(){$('modal').classList.add('hidden');}
$('modal').onclick=e=>{if(e.target.id==='modal'||e.target.dataset.close!==undefined)closeModal();};
$('addRoom').onclick=openNewRoom;
function openNewRoom(){
  modal('<h3>New room</h3><input id="nrName" maxlength="24" placeholder="room-name" autocapitalize="off">'+
    '<label class="row"><input type="checkbox" id="nrPriv" style="width:auto"> <span class="n">Private (invite only, hidden from everyone else)</span></label>'+
    '<div id="nrMem" class="hidden">'+S.members.filter(m=>m.id!==S.user.id).map(m=>'<label class="row"><input type="checkbox" class="nrm" value="'+m.id+'" style="width:auto"> '+avatar(m.name,m.avatar,'s')+' <span class="n">'+esc(m.name)+'</span></label>').join('')+'</div>'+
    '<p class="sub small" id="nrNote">Public rooms are visible to everyone. Private rooms are visible only to the people you add (messages in them are not end-to-end encrypted).</p>'+
    '<div class="msgerr" id="nrErr"></div><button class="primary" id="nrGo">Create room</button><button data-close>Cancel</button>');
  $('nrPriv').onchange=e=>$('nrMem').classList.toggle('hidden',!e.target.checked);
  $('nrGo').onclick=async()=>{
    try{const d=await api('/api/rooms',{name:$('nrName').value,private:$('nrPriv').checked,members:[...document.querySelectorAll('.nrm:checked')].map(x=>+x.value)});closeModal();switchRoom(d.id);}
    catch(e){$('nrErr').textContent=e.message;}};
  setTimeout(()=>$('nrName').focus(),50);
}
$('ttl').onclick=()=>openRoomInfo();
$('bInfo').onclick=()=>openRoomInfo();
$('bLib').onclick=()=>openLibrary('pinned');
function openRoomInfo(){
  const r=curRoom();if(!r)return;
  const dm=r.kind==='dm',priv=r.kind==='private',creator=r.created_by===S.user.id,admin=S.user.admin;
  const canTopic=(r.kind==='channel'&&admin)||priv,canTtl=dm||(r.kind==='channel'&&admin)||(priv&&creator),canDel=(r.kind==='channel'&&admin&&r.id!==1)||(priv&&creator);
  const inRoom=new Set(S.roomMembers);
  modal('<h3>'+(dm?'@ ':ico(priv?'lock':'hash')+' ')+esc(r.name)+'</h3>'+
    (r.kind==='channel'||priv?'<h4>Topic</h4><input id="riTopic" maxlength="120" placeholder="What is this room about?" value="'+esc(r.topic||'')+'"'+(canTopic?'':' disabled')+'>'+(canTopic?'<button id="riTopicGo">Save topic</button>':''):'')+
    '<h4>Shortcuts</h4><div class="row" style="border:0"><button id="riPins">'+ico('pin')+' Pinned</button><button id="riMedia">'+ico('image')+' Media</button><button id="riFiles">'+ico('file')+' Files</button></div>'+
    '<label class="row"><input type="checkbox" id="riMute" style="width:auto"'+(r.muted?' checked':'')+'> <span class="n">Mute this chat (no sounds or notifications)</span></label>'+
    '<h4>Disappearing messages</h4><select id="riTtl"'+(canTtl?'':' disabled')+'>'+Object.keys(TTL_LABEL).map(k=>'<option value="'+k+'"'+(+k===(r.ttl||0)?' selected':'')+'>'+TTL_LABEL[k]+'</option>').join('')+'</select>'+
    '<p class="sub small">'+(canTtl?'New messages are deleted for everyone after the chosen time. Older messages are not affected.':'Only '+(priv?'the creator of this room':'an admin')+' can change this.')+'</p>'+
    (priv?'<h4>People ('+S.roomMembers.length+')</h4>'+S.members.filter(m=>inRoom.has(m.id)).map(m=>'<div class="row" data-u="'+m.id+'">'+avatar(m.name,m.avatar,'s')+'<span class="n">'+esc(m.name)+(m.id===r.created_by?' <span class="tag">creator</span>':'')+'</span>'+(creator&&m.id!==S.user.id?'<button data-rm="'+m.id+'" class="danger">Remove</button>':'')+'</div>').join('')+
      (creator?'<h4>Add people</h4>'+(S.members.filter(m=>!inRoom.has(m.id)).map(m=>'<div class="row">'+avatar(m.name,m.avatar,'s')+'<span class="n">'+esc(m.name)+'</span><button data-add="'+m.id+'">Add</button></div>').join('')||'<p class="sub small">Everyone is already in this room.</p>'):'')+
      '<button id="riLeave" class="danger">Leave room</button>':'')+
    (dm?'<p class="sub small">'+ico('lock')+' Direct messages are end-to-end encrypted.</p>':'')+
    (canDel?'<button id="riDel" class="danger">Delete room</button>':'')+'<button class="primary" data-close>Done</button>');
  const set=async(patch,msg)=>{try{await api('/api/rooms/'+r.id+'/settings',patch);toast(msg);pollNow();}catch(e){toast(e.message);}};
  if($('riTopicGo'))$('riTopicGo').onclick=()=>set({topic:$('riTopic').value},'Topic saved');
  $('riTtl').onchange=e=>set({ttl:+e.target.value},e.target.value==='0'?'Disappearing messages off':'Disappearing messages on');
  $('riMute').onchange=async e=>{try{await api('/api/mute',{room:r.id,muted:e.target.checked});toast(e.target.checked?'Muted':'Unmuted');pollNow();}catch(x){toast(x.message);}};
  $('riPins').onclick=()=>openLibrary('pinned');$('riMedia').onclick=()=>openLibrary('media');$('riFiles').onclick=()=>openLibrary('files');
  const mem=async body=>{try{await api('/api/rooms/'+r.id+'/members',body);pollNow();setTimeout(openRoomInfo,400);}catch(e){toast(e.message);}};
  document.querySelectorAll('[data-rm]').forEach(b=>b.onclick=()=>mem({remove:[+b.dataset.rm]}));
  document.querySelectorAll('[data-add]').forEach(b=>b.onclick=()=>mem({add:[+b.dataset.add]}));
  if($('riLeave'))$('riLeave').onclick=async()=>{if(!confirm('Leave this room? You will no longer see its messages.'))return;try{await api('/api/rooms/'+r.id+'/leave',{});closeModal();switchRoom(1);}catch(e){toast(e.message);}};
  if($('riDel'))$('riDel').onclick=async()=>{if(!confirm('Delete this room and all its messages and files?'))return;try{await api('/api/rooms/'+r.id+'/delete',{});closeModal();switchRoom(1);}catch(e){toast(e.message);}};
}
$('bLock').onclick=async()=>{
  const cur=curRoom(),o=cur&&memberOf(cur.name);
  if(!o||!o.pub||!S.enc.pub){toast('Encryption is not ready for this chat yet');return;}
  const code=await pairCode(S.enc.pub,o.pub);
  modal('<h3>'+ico('lock')+' End-to-end encrypted</h3><p class="sub">Messages, photos, voice messages and files in this chat are encrypted in your browser before they leave your device. The server only stores scrambled data.</p>'+
    '<h4>Security code</h4><div class="code">'+esc(code)+'</div><p class="sub small">Compare this code with '+esc(cur.name)+' in person or over a call. If it matches on both screens, nobody is intercepting your chat.</p><button data-close>Close</button>');
};

/* ---------- polls ---------- */
function openPollCreator(){
  modal('<h3>Create a poll</h3><input id="pqIn" maxlength="200" placeholder="Ask a question"><div id="pOpts" style="display:grid;gap:8px">'+
    [1,2].map(i=>'<input class="poIn" maxlength="80" placeholder="Option '+i+'">').join('')+'</div><button id="pAdd" class="ghost">+ Add option</button>'+
    '<label class="row"><input type="checkbox" id="pMulti" style="width:auto"> <span class="n">Allow multiple answers</span></label><div class="msgerr" id="pcErr"></div>'+
    '<button class="primary" id="pcGo">Post poll</button><button data-close>Cancel</button>');
  $('pAdd').onclick=()=>{const n=document.querySelectorAll('.poIn').length;if(n>=6){toast('Up to 6 options');return;}
    const i=document.createElement('input');i.className='poIn';i.maxLength=80;i.placeholder='Option '+(n+1);$('pOpts').appendChild(i);i.focus();};
  $('pcGo').onclick=async()=>{
    const options=[...document.querySelectorAll('.poIn')].map(x=>x.value.trim()).filter(Boolean);
    try{await api('/api/send',{room:S.room,poll:{q:$('pqIn').value,options,multi:$('pMulti').checked}});closeModal();pollNow();}
    catch(e){$('pcErr').textContent=e.message;}};
  setTimeout(()=>$('pqIn').focus(),50);
}

/* ---------- library: pinned, saved, media, files, search ---------- */
const isImg=m=>m.image&&(extOf(m.image)==='bin'?!!m.img:IMGX.includes(extOf(m.image)));
const attLabel=m=>{const x=extOf(m.image||'');return m.aud||AUDX.includes(x)?'Voice message':(m.fil||x==='file')?(m.fil?m.fil.n:(m.fname||'File')):(m.image?'Photo':'');};
function libCards(list,showRoom){
  if(!list.length)return '<p class="sub">Nothing here yet.</p>';
  return list.map(m=>{const rm=S.rooms.find(r=>r.id===m.room);
    return '<div class="lcard" data-go="'+m.room+':'+m.id+'"><div class="lh">'+avatar(m.name,m.av,'s')+'<b>'+esc(m.name)+'</b>'+(showRoom&&rm?'<span class="tag">'+esc(roomLabel(rm))+'</span>':'')+
      '<span class="sub small">'+esc(new Date(m.ts*1000).toLocaleString([],{month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}))+'</span></div><div class="lt">'+
      (m.poll?ico('poll')+' '+esc(m.poll.q):(m.text?fmt(m.text):'<i>'+esc(attLabel(m))+'</i>'))+'</div></div>';}).join('');
}
function libGrid(list){
  const imgs=list.filter(isImg);
  if(!imgs.length)return '<p class="sub">No photos yet.</p>';
  return '<div class="grid">'+imgs.map(m=>extOf(m.image)==='bin'
    ?'<img data-enc="1" data-room="'+m.room+'" data-name="'+esc(m.image)+'" data-mime="'+esc(safeMime(m.img.m))+'" data-go="'+m.room+':'+m.id+'" src="'+PH+'" alt="">'
    :'<img src="/uploads/'+esc(m.image)+'" loading="lazy" data-go="'+m.room+':'+m.id+'" alt="">').join('')+'</div>';
}
async function openLibrary(tab){
  const cur=curRoom();
  const tabs=[['pinned','Pinned'],['saved','Saved'],['media','Photos'],['files','Files'],['search','Search']];
  modal('<h3>Library</h3><div class="tabs">'+tabs.map(t=>'<button data-tab="'+t[0]+'" class="'+(t[0]===tab?'on':'')+'">'+t[1]+'</button>').join('')+'</div><p class="sub small" id="libNote"></p><div id="libBody"></div><button data-close>Close</button>');
  $('mcard').onclick=async e=>{
    const go=e.target.closest('[data-go]');if(go){const p=go.dataset.go.split(':');goTo(+p[0],+p[1]);return;}
    const tb=e.target.closest('[data-tab]');if(tb)openLibrary(tb.dataset.tab);
  };
  const body=$('libBody'),note=$('libNote');
  try{
    if(tab==='search'){
      note.textContent='Searches public rooms and private rooms you are in. Encrypted DMs can only be searched inside the chat itself.';
      body.innerHTML='<input id="gsIn" placeholder="Search all messages" autocomplete="off"><div id="gsOut" style="margin-top:8px"></div>';
      let t=null;$('gsIn').oninput=()=>{clearTimeout(t);t=setTimeout(async()=>{const q=$('gsIn').value.trim();
        if(q.length<2){$('gsOut').innerHTML='';return;}
        try{const d=await api('/api/search?q='+encodeURIComponent(q));$('gsOut').innerHTML=libCards(d.messages,true);}catch(x){$('gsOut').innerHTML='<p class="msgerr">'+esc(x.message)+'</p>';}},300);};
      setTimeout(()=>$('gsIn').focus(),50);return;
    }
    if(tab==='saved'){note.textContent='Messages you saved, from every chat.';const d=await api('/api/saved');await decryptMsgs(d.messages);body.innerHTML=libCards(d.messages,true);hydrate(body);return;}
    if(!cur)return;
    note.textContent='In '+roomLabel(cur);
    if(tab==='pinned'){const d=await api('/api/pins?room='+cur.id);await decryptMsgs(d.messages);body.innerHTML=libCards(d.messages,false);return;}
    const d=await api('/api/media?room='+cur.id);await decryptMsgs(d.messages);
    if(tab==='media'){body.innerHTML=libGrid(d.messages);hydrate(body);}
    else body.innerHTML=libCards(d.messages.filter(m=>!isImg(m)),false);
  }catch(e){body.innerHTML='<p class="msgerr">'+esc(e.message)+'</p>';}
}

/* ---------- quick switcher (Ctrl+K) ---------- */
function openSwitcher(){
  if(!S.user)return;
  const items=[
    ...S.rooms.map(r=>({label:roomLabel(r),tag:r.kind==='dm'?'DM':(r.kind==='private'?'private':'room'),n:r.unread,fn:()=>switchRoom(r.id)})),
    ...S.members.filter(m=>m.id!==S.user.id&&!S.rooms.some(r=>r.kind==='dm'&&r.name===m.name)).map(m=>({label:'@ '+m.name,tag:'start DM',fn:()=>openDm(m.id)})),
    {label:'Profile & settings',tag:'action',fn:openProfile},{label:'Saved items',tag:'action',fn:()=>openLibrary('saved')},
    {label:'Search all messages',tag:'action',fn:()=>openLibrary('search')},{label:'New room',tag:'action',fn:openNewRoom}];
  let list=items,idx=0;
  modal('<input id="qsIn" placeholder="Jump to a room, person or action…" autocomplete="off"><div id="qsList"></div><p class="sub small">↑ ↓ to move · Enter to open · Esc to close · Ctrl+K from anywhere</p>');
  const draw=()=>{$('qsList').innerHTML=list.slice(0,9).map((it,i)=>'<button data-qs="'+i+'" class="qs'+(i===idx?' on':'')+'"><span>'+esc(it.label)+'</span><span class="sub small">'+esc(it.tag)+(it.n?' · '+it.n+' new':'')+'</span></button>').join('')||'<p class="sub">No matches</p>';};
  const run=i=>{const it=list[i];if(it){closeModal();it.fn();}};
  $('qsIn').oninput=()=>{const q=$('qsIn').value.toLowerCase().replace(/^[@#]\s*/,'');list=items.filter(it=>it.label.toLowerCase().includes(q));idx=0;draw();};
  $('qsIn').onkeydown=e=>{
    if(e.key==='ArrowDown'){e.preventDefault();idx=Math.min(idx+1,Math.min(list.length,9)-1);draw();}
    else if(e.key==='ArrowUp'){e.preventDefault();idx=Math.max(idx-1,0);draw();}
    else if(e.key==='Enter'){e.preventDefault();run(idx);}};
  $('qsList').onclick=e=>{const b=e.target.closest('[data-qs]');if(b)run(+b.dataset.qs);};
  draw();setTimeout(()=>$('qsIn').focus(),30);
}
document.addEventListener('keydown',e=>{
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();openSwitcher();return;}
  if(e.key==='Escape'){
    if(!$('modal').classList.contains('hidden'))closeModal();
    else if(!$('lb').classList.contains('hidden'))$('lb').classList.add('hidden');
    else closePops();
  }
});

/* ---------- profile & settings ---------- */
function openProfile(){
  const th=localStorage.getItem('haven_theme')||'dark',snd=localStorage.getItem('haven_sound')!=='off',nt=localStorage.getItem('haven_notify')==='on';
  const acc=localStorage.getItem('haven_accent')||'violet',den=localStorage.getItem('haven_density')||'comfortable',sz=localStorage.getItem('haven_size')||'normal';
  const canNote=!!window.Notification,opt=(v,cur,l)=>'<option value="'+v+'"'+(v===cur?' selected':'')+'>'+l+'</option>';
  modal('<h3>Profile & settings</h3>'+
   '<div class="prof"><div id="avBox">'+avatar(S.user.name,S.user.avatar,'l')+'</div><div style="display:grid;gap:6px"><b>'+esc(S.user.name)+(S.user.admin?' <span class="tag">admin</span>':'')+'</b>'+
   '<div><button id="avUp">Change picture</button> <button id="avRm" class="ghost"'+(S.user.avatar?'':' disabled')+'>Remove</button></div></div></div>'+
   '<input id="stIn" maxlength="60" placeholder="Status (for example: At work)" value="'+esc(S.user.status||'')+'"><button id="stGo">Save status</button>'+
   '<h4>Appearance</h4>'+
   '<label class="row"><span class="n">Theme</span><select id="thSel" style="width:auto">'+opt('dark',th,'Dark')+opt('black',th,'Black (OLED)')+opt('light',th,'Light')+'</select></label>'+
   '<div class="row"><span class="n">Accent colour</span><span class="sw">'+['violet','blue','green','pink','orange'].map(a=>'<button data-acc="'+a+'" class="swatch s-'+a+(a===acc?' on':'')+'" title="'+a+'"></button>').join('')+'</span></div>'+
   '<label class="row"><span class="n">Message spacing</span><select id="denSel" style="width:auto">'+opt('comfortable',den,'Comfortable')+opt('compact',den,'Compact')+'</select></label>'+
   '<label class="row"><span class="n">Text size</span><select id="szSel" style="width:auto">'+opt('small',sz,'Small')+opt('normal',sz,'Normal')+opt('large',sz,'Large')+'</select></label>'+
   '<h4>Notifications and privacy</h4>'+
   '<label class="row"><input type="checkbox" id="sndChk" style="width:auto"'+(snd?' checked':'')+'> <span class="n">Play a sound for new messages</span></label>'+
   (canNote?'<label class="row"><input type="checkbox" id="ntChk" style="width:auto"'+(nt?' checked':'')+'> <span class="n">Show desktop notifications</span></label>':'')+
   '<label class="row"><input type="checkbox" id="rcChk" style="width:auto"'+(S.user.receipts?' checked':'')+'> <span class="n">Send read receipts in DMs (if off, you will not see theirs either)</span></label>'+
   '<h4>Encryption</h4><p class="sub small">'+(S.priv?'Encrypted DMs are active on this device.':'Encrypted DMs are locked on this device.')+' Your keys are protected by your password, so the server cannot read your DMs.</p>'+
   '<h4>Password</h4><input id="pOld" type="password" placeholder="Current password" autocomplete="current-password">'+
   '<input id="pNew" type="password" placeholder="New password (8+ characters)" autocomplete="new-password">'+
   '<div class="msgerr" id="pErr"></div><button id="pGo">Change password</button>'+
   '<p class="sub small">Haven '+esc(S.version||'')+' · press Ctrl+K to jump anywhere</p><button class="primary" data-close>Done</button>');
  $('avUp').onclick=()=>$('avfile').click();
  $('avRm').onclick=async()=>{try{await api('/api/avatar/remove',{});S.user.avatar=null;renderMe();openProfile();pollNow();}catch(e){toast(e.message);}};
  $('stGo').onclick=async()=>{try{const d=await api('/api/profile',{status:$('stIn').value});S.user.status=d.status;renderMe();toast('Status saved');pollNow();}catch(e){toast(e.message);}};
  $('thSel').onchange=e=>{localStorage.setItem('haven_theme',e.target.value);applyTheme(e.target.value);};
  document.querySelectorAll('[data-acc]').forEach(b=>b.onclick=()=>{localStorage.setItem('haven_accent',b.dataset.acc);applyLook();document.querySelectorAll('[data-acc]').forEach(x=>x.classList.toggle('on',x===b));});
  $('denSel').onchange=e=>{localStorage.setItem('haven_density',e.target.value);applyLook();};
  $('szSel').onchange=e=>{localStorage.setItem('haven_size',e.target.value);applyLook();};
  $('sndChk').onchange=e=>localStorage.setItem('haven_sound',e.target.checked?'on':'off');
  $('rcChk').onchange=async e=>{try{await api('/api/profile',{receipts:e.target.checked});S.user.receipts=e.target.checked;pollNow();}catch(x){toast(x.message);}};
  if(canNote)$('ntChk').onchange=async e=>{
    if(e.target.checked){const p=await Notification.requestPermission();if(p!=='granted'){e.target.checked=false;toast('Notifications are blocked in your browser settings');return;}}
    localStorage.setItem('haven_notify',e.target.checked?'on':'off');};
  $('pGo').onclick=changePassword;
}
async function changePassword(){
  const oldPw=$('pOld').value,newPw=$('pNew').value;
  try{
    const body={old:oldPw,new:newPw};
    if(S.enc&&S.enc.pub&&S.enc.wrapped){let jwk;try{jwk=await unwrapJwk(S.enc.wrapped,oldPw);}catch(e){throw new Error('Current password is wrong');}
      if(newPw.length>=8)body.wrapped=await wrapJwk(jwk,newPw);}
    await api('/api/password',body);if(body.wrapped)S.enc.wrapped=body.wrapped;
    closeModal();toast('Password changed. Other devices were signed out.');
  }catch(e){$('pErr').textContent=e.message;}
}
$('avfile').onchange=async e=>{
  const f=e.target.files[0];e.target.value='';if(!f)return;
  const fd=new FormData();fd.append('file',f);
  try{const r=await fetch('/api/avatar',{method:'POST',headers:{'X-Haven':'1'},body:fd});const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Upload failed');S.user.avatar=d.avatar;renderMe();openProfile();pollNow();toast('Picture updated');}
  catch(x){toast(x.message);}
};

/* ---------- admin ---------- */
async function openAdmin(){
  let d;try{d=await api('/api/admin/users');}catch(e){toast(e.message);return;}
  modal('<h3>Admin</h3><p class="sub">'+d.users.length+' members · '+d.stats.messages+' messages · '+d.stats.images+' files ('+d.stats.mb+' MB)</p>'+
    '<label class="row"><input type="checkbox" id="reg" style="width:auto"'+(d.registration?' checked':'')+'> <span class="n">Anyone on the network can create an account</span></label>'+
    '<h4>Invite link</h4><div class="row" style="border:0"><select id="invUses" style="width:auto"><option value="1">1 person</option><option value="5">5 people</option><option value="25">25 people</option></select>'+
    '<select id="invDays" style="width:auto"><option value="1">1 day</option><option value="7" selected>7 days</option><option value="30">30 days</option></select><button id="invGo">Create link</button></div><div id="invOut"></div>'+
    '<p class="sub small">Invite links let people join even when open sign-up is turned off.</p>'+
    '<h4>Announcement</h4><input id="banIn" maxlength="200" placeholder="Shown to everyone at the top (leave empty to clear)" value="'+esc(d.banner||'')+'"><button id="banGo">Save announcement</button>'+
    '<h4>Members</h4>'+d.users.map(u=>'<div class="row" data-u="'+u.id+'"><span class="n">'+esc(u.name)+(u.admin?' <span class="tag">admin</span>':'')+(u.enc?' <span class="tag" title="Has encrypted DMs">'+ico('lock')+'</span>':'')+'</span>'+
     '<button data-a="reset">Reset password</button>'+(u.id!==S.user.id?'<button data-a="toggle_admin">'+(u.admin?'Remove admin':'Make admin')+'</button><button data-a="remove" class="danger">Remove</button>':'')+'</div>').join('')+
    '<p class="sub small">Resetting a password also resets that person\'s encryption keys, so their old DMs can no longer be read.</p><button data-close>Close</button>');
  $('reg').onchange=async()=>{try{await api('/api/admin/settings',{registration:$('reg').checked});toast('Saved');}catch(e){toast(e.message);}};
  $('banGo').onclick=async()=>{try{await api('/api/admin/settings',{banner:$('banIn').value});toast('Announcement saved');pollNow();}catch(e){toast(e.message);}};
  $('invGo').onclick=async()=>{try{const r=await api('/api/admin/invite',{uses:+$('invUses').value,days:+$('invDays').value});
    const link=location.origin+'/#invite='+r.code;$('invOut').innerHTML='<input readonly value="'+esc(link)+'" onclick="this.select()"><button id="invCp" class="ghost">Copy link</button>';
    $('invCp').onclick=async()=>{try{await navigator.clipboard.writeText(link);toast('Link copied');}catch(e){$('invOut').querySelector('input').select();}};}catch(e){toast(e.message);}};
  $('mcard').querySelectorAll('[data-a]').forEach(b=>b.onclick=async()=>{
    const id=Number(b.closest('[data-u]').dataset.u),a=b.dataset.a,body={action:a};
    if(a==='reset'){const p=prompt('Set a new password for this user (8+ characters).\nTheir encrypted DM history will become unreadable.');if(!p)return;body.password=p;}
    if(a==='remove'&&!confirm('Remove this user and all of their messages, files and DMs?'))return;
    try{await api('/api/admin/users/'+id,body);toast('Done');openAdmin();}catch(e){toast(e.message);}
  });
}
boot().catch(()=>{$('auth').classList.remove('hidden');$('aErr').textContent='Cannot reach the server';});
</script></body></html>
"""


# ---------- command line ----------
def cli(args):
    c = connect()
    if args[0] == "--list-users":
        for r in c.execute("SELECT name, admin FROM users ORDER BY id"):
            print(r["name"], "(admin)" if r["admin"] else "")
        return
    if args[0] == "--make-admin" and len(args) == 2:
        n = c.execute("UPDATE users SET admin=1 WHERE name=?", (args[1],)).rowcount
        c.commit()
        print("Done." if n else "No such user.")
        return
    if args[0] == "--reset-password" and len(args) == 2:
        u = c.execute("SELECT id FROM users WHERE name=?", (args[1],)).fetchone()
        if not u:
            sys.exit("No such user")
        pw = getpass.getpass("New password (8+ chars): ")
        if len(pw) < 8:
            sys.exit("Too short")
        c.execute("UPDATE users SET pw=?, pwv=pwv+1, enc_pub=NULL, enc_priv=NULL WHERE id=?",
                  (generate_password_hash(pw), u["id"]))
        c.commit()
        print("Password updated. (Their encrypted DM keys were reset, so old DMs are unreadable.)")
        return
    sys.exit("Usage: haven-admin --list-users | --make-admin USER | --reset-password USER")


if __name__ == "__main__":
    init()
    if len(sys.argv) > 1:
        cli(sys.argv[1:])
    else:
        from waitress import serve
        print("Haven %s listening on %s:%d" % (VERSION, BIND, PORT), flush=True)
        threading.Thread(target=reaper, daemon=True).start()
        serve(app, host=BIND, port=PORT, threads=16, max_request_body_size=30 * 1024 * 1024)
HAVEN_PY
}

# --------------------------------------------------------------------------
san_list() {
  local s="DNS:localhost,IP:127.0.0.1,DNS:$(hostname),DNS:$(hostname).local" ip
  for ip in $(hostname -I 2>/dev/null); do
    if [[ "$ip" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then s="$s,IP:$ip"; fi
  done
  echo "$s"
}

cert_covers_ips() {
  [ -f "$TLS_DIR/server.crt" ] || return 1
  local sans ip; sans="$(openssl x509 -in "$TLS_DIR/server.crt" -noout -ext subjectAltName 2>/dev/null || true)"
  for ip in $(hostname -I 2>/dev/null); do
    if [[ "$ip" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
      echo "$sans" | grep -q "IP Address:$ip" || return 1
    fi
  done
  return 0
}

make_server_cert() {
  local d="$TLS_DIR"
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/server.key"
  openssl req -new -key "$d/server.key" -subj "/CN=haven" -out "$d/server.csr"
  printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' "$(san_list)" > "$d/server.ext"
  openssl x509 -req -in "$d/server.csr" -CA "$d/ca.crt" -CAkey "$d/ca.key" -CAcreateserial \
    -out "$d/server.crt" -days 825 -sha256 -extfile "$d/server.ext" >/dev/null 2>&1
  rm -f "$d/server.csr" "$d/server.ext"
  chmod 600 "$d/server.key"; chmod 644 "$d/server.crt"
}

ensure_certs() {
  mkdir -p "$TLS_DIR"; chmod 755 "$CONF_DIR" "$TLS_DIR"
  if [ ! -f "$TLS_DIR/ca.key" ]; then
    say "Creating your private certificate authority"
    openssl ecparam -name prime256v1 -genkey -noout -out "$TLS_DIR/ca.key"
    openssl req -x509 -new -key "$TLS_DIR/ca.key" -sha256 -days 3650 -subj "/CN=Haven CA $(hostname)" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -out "$TLS_DIR/ca.crt"
    chmod 600 "$TLS_DIR/ca.key"; chmod 644 "$TLS_DIR/ca.crt"
  fi
  if ! cert_covers_ips; then
    say "Creating HTTPS certificate for this server's addresses"
    make_server_cert
  fi
}

write_nginx() {
cat > "$NGINX_CONF" <<'NGX'
# Haven: HTTPS front door on port 6060, app runs privately on 127.0.0.1:6061
server {
    listen 6060 ssl;
    server_name _;
    ssl_certificate     /etc/haven/tls/server.crt;
    ssl_certificate_key /etc/haven/tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:haven:5m;
    client_max_body_size 30m;
    # people who type http:// get sent to https:// automatically
    error_page 497 =301 https://$host:6060$request_uri;
    location / {
        proxy_pass http://127.0.0.1:6061;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 60s;
    }
}
NGX
}

reload_nginx() {
  nginx -t >/dev/null 2>&1 || { nginx -t || true; die "nginx rejected the Haven config (see above)."; }
  systemctl enable nginx >/dev/null 2>&1 || true
  if systemctl is-active --quiet nginx; then systemctl reload nginx; else systemctl start nginx; fi
}

# --------------------------------------------------------------------------
do_backup() {
  need_root backup
  [ -f "$DATA_DIR/haven.db" ] || die "No Haven data found in $DATA_DIR"
  local ts out
  ts="$(date +%Y%m%d-%H%M%S)"; out="/var/backups/haven-$ts.tar.gz"
  install -d -o haven -g haven -m 700 "$DATA_DIR/.tmp"
  sudo -u haven python3 - <<'PY'
import sqlite3
src = sqlite3.connect("/var/lib/haven/haven.db")
dst = sqlite3.connect("/var/lib/haven/.tmp/haven.db")
src.backup(dst); dst.close(); src.close()
PY
  mkdir -p "$DATA_DIR/uploads" "$DATA_DIR/avatars" /var/backups
  local extra=()
  [ -d "$TLS_DIR" ] && extra=(-C "$CONF_DIR" tls)
  tar -czf "$out" -C "$DATA_DIR" --transform='s,^\.tmp/,,' .tmp/haven.db uploads avatars secret.key "${extra[@]}"
  rm -rf "$DATA_DIR/.tmp"
  chmod 600 "$out"
  # keep only the newest backups
  ls -1t /var/backups/haven-*.tar.gz 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm -f
  say "Backup saved: $out"
}

do_restore() {
  need_root restore "$@"
  local f="${1:-}"
  [ -n "$f" ] && [ -f "$f" ] || die "Usage: sudo haven restore /var/backups/haven-YYYYMMDD-HHMMSS.tar.gz"
  local tmp; tmp="$(mktemp -d)"
  tar -xzf "$f" -C "$tmp"
  [ -f "$tmp/haven.db" ] || { rm -rf "$tmp"; die "That doesn't look like a Haven backup."; }
  say "Stopping Haven"
  systemctl stop haven 2>/dev/null || true
  if [ -d "$DATA_DIR" ]; then
    local aside="$DATA_DIR.before-restore-$(date +%Y%m%d-%H%M%S)"
    mv "$DATA_DIR" "$aside"; say "Your current data was kept at $aside"
  fi
  mkdir -p "$DATA_DIR"
  cp -a "$tmp/haven.db" "$tmp/secret.key" "$DATA_DIR/" 2>/dev/null || true
  [ -d "$tmp/uploads" ] && cp -a "$tmp/uploads" "$DATA_DIR/" || mkdir -p "$DATA_DIR/uploads"
  [ -d "$tmp/avatars" ] && cp -a "$tmp/avatars" "$DATA_DIR/" || mkdir -p "$DATA_DIR/avatars"
  if [ -d "$tmp/tls" ] && [ ! -f "$TLS_DIR/ca.key" ]; then mkdir -p "$CONF_DIR"; cp -a "$tmp/tls" "$CONF_DIR/"; fi
  chown -R haven:haven "$DATA_DIR"; chmod 700 "$DATA_DIR"
  rm -rf "$tmp"
  systemctl start haven
  say "Restored from $f"
}

do_regen_cert() {
  need_root regen-cert
  [ -f "$TLS_DIR/ca.key" ] || die "Haven isn't installed yet."
  make_server_cert
  reload_nginx
  say "HTTPS certificate refreshed for: $(san_list)"
  echo "    Devices that already trust your Haven certificate keep working with no changes."
}

do_status() {
  echo "${B}Haven status${N}"
  if systemctl is-active --quiet haven 2>/dev/null; then echo "  App        : ${G}running${N}"; else echo "  App        : ${R}not running${N}"; fi
  if systemctl is-active --quiet nginx 2>/dev/null; then echo "  HTTPS      : ${G}nginx running${N}"; else echo "  HTTPS      : ${R}nginx not running${N}"; fi
  [ -f "$APP_DIR/VERSION" ] && echo "  Version    : $(cat "$APP_DIR/VERSION")" || echo "  Version    : not installed"
  if health && health_https; then echo "  Health     : ${G}ok${N}"; else echo "  Health     : ${R}not responding${N}"; fi
  echo "  Address    : https://$(lan_ip):$PORT"
  echo "  Trust page : https://$(lan_ip):$PORT/trust"
  if [ -f "$TLS_DIR/server.crt" ]; then
    echo "  Certificate: expires $(openssl x509 -in "$TLS_DIR/server.crt" -noout -enddate | cut -d= -f2)"
    cert_covers_ips || warn "This server's IP changed. Run: sudo haven regen-cert"
  fi
  [ -d "$DATA_DIR" ] && echo "  Data       : $DATA_DIR ($(du -sh "$DATA_DIR" 2>/dev/null | cut -f1))"
  local last; last="$(ls -1t /var/backups/haven-*.tar.gz 2>/dev/null | head -1 || true)"
  echo "  Last backup: ${last:-none yet}"
  echo "  Logs       : sudo journalctl -u haven -f"
}

do_install() {
  need_root
  . /etc/os-release 2>/dev/null || true
  case "${ID:-}${ID_LIKE:-}" in *ubuntu*|*debian*) ;; *) warn "This script is made for Ubuntu/Debian; continuing anyway." ;; esac

  local upgrade=0
  [ -f "$APP_DIR/app.py" ] && upgrade=1

  say "Installing packages (Flask, Waitress, Pillow, nginx, OpenSSL)"
  export DEBIAN_FRONTEND=noninteractive
  local had_nginx=0
  dpkg -s nginx >/dev/null 2>&1 && had_nginx=1
  apt-get update -y -qq
  apt-get install -y -qq python3 python3-flask python3-waitress python3-pil nginx openssl
  if [ "$had_nginx" -eq 0 ]; then
    rm -f /etc/nginx/sites-enabled/default      # we installed nginx just for Haven: drop the sample page
    mkdir -p "$CONF_DIR"; : > "$CONF_DIR/nginx-installed-by-haven"
  fi

  say "Preparing service user and folders"
  id haven >/dev/null 2>&1 || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin haven
  mkdir -p "$APP_DIR" "$DATA_DIR/uploads" "$DATA_DIR/avatars" "$CONF_DIR"
  chown -R haven:haven "$DATA_DIR"; chmod 700 "$DATA_DIR"

  if [ "$upgrade" -eq 1 ] && [ -f "$DATA_DIR/haven.db" ]; then
    say "Existing install found. Taking a safety backup before upgrading"
    do_backup
  fi
  systemctl stop haven 2>/dev/null || true      # frees port 6060 if an older version was using it

  if [ ! -f "$NGINX_CONF" ]; then
    for p in "$PORT" "$APP_PORT"; do
      port_busy "$p" && die "Port $p is already in use by something else. Free it and run this again."
    done
  fi

  ensure_certs

  say "Installing Haven $HAVEN_VERSION"
  write_app
  chmod 644 "$APP_DIR/app.py"
  echo "$HAVEN_VERSION" > "$APP_DIR/VERSION"

  cat > "$WRAPPER" <<'WRAP'
#!/usr/bin/env bash
exec sudo -u haven python3 /opt/haven/app.py "$@"
WRAP
  chmod 755 "$WRAPPER"

  if [ -f "$0" ] && [ "$(readlink -f "$0")" != "$CTL" ]; then
    install -m 755 "$0" "$CTL"
  fi

  cat > "$UNIT" <<'UNITFILE'
[Unit]
Description=Haven chat
After=network.target

[Service]
User=haven
Group=haven
Environment=HAVEN_TLS=1
Environment=HAVEN_PORT=6061
Environment=HAVEN_BIND=127.0.0.1
ExecStart=/usr/bin/python3 /opt/haven/app.py
Restart=always
RestartSec=3
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/haven

[Install]
WantedBy=multi-user.target
UNITFILE

  cat > "$BK_SERVICE" <<'BKS'
[Unit]
Description=Haven nightly backup

[Service]
Type=oneshot
ExecStart=/usr/local/bin/haven backup
BKS
  cat > "$BK_TIMER" <<'BKT'
[Unit]
Description=Haven nightly backup

[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
BKT

  write_nginx
  systemctl daemon-reload
  systemctl enable haven >/dev/null 2>&1
  systemctl restart haven
  [ -x "$CTL" ] && systemctl enable --now haven-backup.timer >/dev/null 2>&1 || true

  local ok=0
  for _ in $(seq 1 20); do if health; then ok=1; break; fi; sleep 1; done
  [ "$ok" -eq 1 ] || { echo; die "Haven did not start. Check:  sudo journalctl -u haven -n 50 --no-pager"; }

  reload_nginx

  if ufw_active; then
    local subnet; subnet="$(lan_subnet)"
    if [ -n "$subnet" ]; then
      ufw allow from "$subnet" to any port "$PORT" proto tcp >/dev/null
      say "Firewall: port $PORT opened for your LAN only ($subnet)"
    else
      warn "UFW is active but I couldn't detect your LAN subnet. Run: sudo ufw allow from YOUR.LAN.0/24 to any port $PORT proto tcp"
    fi
  fi

  sleep 1
  health_https || warn "HTTPS check failed. Run: sudo haven status"

  echo
  if [ "$upgrade" -eq 1 ]; then say "${B}Haven upgraded to $HAVEN_VERSION${N}. Your accounts and messages are intact."
  else say "${B}Haven $HAVEN_VERSION is installed and running${N}. It starts automatically on boot."; fi
  echo "    Open:   ${B}https://$(lan_ip):$PORT${N}"
  echo "    Your browser will warn about the certificate the first time. Open"
  echo "    ${B}https://$(lan_ip):$PORT/trust${N} on each device to install it (takes a minute)."
  [ "$upgrade" -eq 0 ] && echo "    The first account you create becomes the admin."
  echo
  echo "    sudo haven status      check on it"
  echo "    sudo haven backup      backup now (it also backs up every night, keeping $KEEP_BACKUPS)"
  echo "    sudo haven uninstall   remove it (keeps your data unless you add --purge)"
}

do_uninstall() {
  need_root uninstall "$@"
  local purge=0 yes=0
  for a in "$@"; do case "$a" in --purge) purge=1 ;; --yes|-y) yes=1 ;; esac; done
  if [ "$yes" -ne 1 ]; then
    [ -t 0 ] || die "Not interactive. Re-run with --yes to confirm."
    if [ "$purge" -eq 1 ]; then
      warn "This removes Haven AND permanently deletes all accounts, messages and images."
    else
      echo "This removes the Haven app and service. Your accounts, messages and images are kept."
    fi
    read -r -p "Continue? [y/N] " ans
    [ "$ans" = "y" ] || [ "$ans" = "Y" ] || die "Cancelled."
  fi

  if [ "$purge" -eq 1 ] && [ -f "$DATA_DIR/haven.db" ]; then
    say "Saving a final backup first"
    do_backup
  fi

  say "Stopping and removing Haven"
  systemctl disable --now haven-backup.timer >/dev/null 2>&1 || true
  systemctl disable --now haven >/dev/null 2>&1 || true
  rm -f "$UNIT" "$BK_SERVICE" "$BK_TIMER" "$WRAPPER" "$NGINX_CONF"
  systemctl daemon-reload
  rm -rf "$APP_DIR"
  if command -v nginx >/dev/null 2>&1 && systemctl is-active --quiet nginx; then
    nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
  fi

  if ufw_active; then
    local subnet; subnet="$(lan_subnet)"
    if [ -n "$subnet" ]; then ufw delete allow from "$subnet" to any port "$PORT" proto tcp >/dev/null 2>&1 || true; fi
  fi

  local self="$CTL"
  if [ "$purge" -eq 1 ]; then
    rm -rf "$DATA_DIR" "$TLS_DIR"
    id haven >/dev/null 2>&1 && userdel haven 2>/dev/null || true
    say "Haven and all of its data were removed. The final backup is in /var/backups."
  else
    say "Haven was removed. Your data is still in $DATA_DIR (certificates in $TLS_DIR)."
    echo "    Reinstall later with:  sudo bash haven5.sh   (accounts and messages come back)"
    echo "    Delete the data too:   sudo haven uninstall --purge"
    self=""
  fi
  [ -n "$self" ] && rm -f "$self"
  if [ -f "$CONF_DIR/nginx-installed-by-haven" ] && [ "$purge" -eq 1 ]; then
    echo "    nginx was installed for Haven. Remove it if nothing else uses it:  sudo apt remove nginx"
  fi
  echo "    Optional cleanup:  sudo apt remove python3-waitress python3-pil"
}

do_help() { sed -n '2,19p' "$0" | sed 's/^# \{0,2\}//'; }

case "${1:-install}" in
  install)    do_install ;;
  uninstall)  shift; do_uninstall "$@" ;;
  backup)     do_backup ;;
  restore)    shift; do_restore "$@" ;;
  regen-cert) do_regen_cert ;;
  status)     do_status ;;
  help|-h|--help) do_help ;;
  *) die "Unknown command '$1'. Try:  bash $0 help" ;;
esac
