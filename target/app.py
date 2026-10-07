"""argos test target — a deliberately vulnerable web application.

    python target/app.py     # serves http://127.0.0.1:5000

DO NOT DEPLOY. For verifying argos detections on a machine you control only.
"""

from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template_string, request, session
from lxml import etree

app = Flask(__name__)
app.secret_key = "argos-demo-secret"  # noqa: S105 — demo only

UPLOAD_DIR = Path(__file__).parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# --- database -----------------------------------------------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute(
    "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, "
    "password TEXT, role TEXT, ssn TEXT)"
)
db.executemany(
    "INSERT INTO users (name, email, password, role, ssn) VALUES (?,?,?,?,?)",
    [
        ("admin", "admin@target.local", "admin123", "admin", "000-00-0000"),
        ("alice", "alice@target.local", "wonderland", "user", "111-11-1111"),
        ("bob", "bob@target.local", "ilovebob", "user", "222-22-2222"),
    ],
)
db.commit()

INDEX = """<!doctype html><html><head><title>argos target</title>
<link rel="canonical" href="http://{{ request.headers.get('X-Forwarded-Host', request.host) }}/">
<script src="/static/jquery-3.4.1.min.js"></script>
<script src="/leak.js"></script></head>
<body>
<h1>argos vulnerable target</h1>
<ul>
  <li><a href="/search?q=alice">search (SQLi)</a></li>
  <li><a href="/reflect?name=bob">reflect (XSS)</a></li>
  <li><a href="/hello?name=world">hello (SSTI)</a></li>
  <li><a href="/download?file=notes.txt">download (traversal)</a></li>
  <li><a href="/fetch?url=http://127.0.0.1:5000/">fetch (SSRF)</a></li>
  <li><a href="/cmd?ip=127.0.0.1">cmd (command injection)</a></li>
  <li><a href="/login">login (broken auth)</a></li>
  <li><a href="/profile?id=1">profile (IDOR)</a></li>
  <li><a href="/admin">admin (forced browse)</a></li>
  <li><a href="/administrator">administrator (unauth panel)</a></li>
  <li><a href="/jwt/profile">jwt profile</a></li>
  <li><a href="/redirect?url=/">redirect (open redirect)</a></li>
  <li><a href="/upload">upload</a></li>
  <li><a href="/api/xml">xml (XXE)</a></li>
</ul>
<form method=post action=/comment>
  <input name=name placeholder=name><input name=text placeholder=comment>
  <button>post comment</button>
</form>
</body></html>"""


@app.route("/")  # noqa: PLR0903 — demo app
def index():
    return render_template_string(INDEX)


@app.route("/leak.js")  # fake secrets built at runtime (never committed as literals)
def leak_js():
    aws = "AK" + "IA" + "FAKEKEY01234ABCD"  # AKIA + 16 chars
    gh = "gh" + "p_" + "A" * 36
    body = (
        "// demo front-end config\n"
        f"const AWS_ACCESS_KEY = '{aws}';\n"
        f"const GITHUB_TOKEN = '{gh}';\n"
        "const password = 'supersecretpass1';\n"
    )
    return body, 200, {"Content-Type": "application/javascript"}


@app.route("/search")  # SQL injection: string-concatenated query, errors disclosed
def search():
    q = request.args.get("q", "")
    try:
        rows = db.execute(f"SELECT id, name, email FROM users WHERE name LIKE '%{q}%'").fetchall()
    except Exception as exc:  # noqa: BLE001 — deliberate: error shown to client
        return f"<p>query failed: {exc}</p>", 200
    out = "".join(f"<li>{r[0]} {r[1]} {r[2]}</li>" for r in rows)
    return f"<ul>{out}</ul>"


@app.route("/reflect")  # reflected XSS: raw concatenation into HTML
def reflect():
    name = request.args.get("name", "")
    return f"<html><body><h1>Hello {name}</h1></body></html>"


@app.route("/hello")  # SSTI: user input rendered as a Jinja2 template
def hello():
    name = request.args.get("name", "world")
    return render_template_string(f"<html><body><h1>Hello {name}</h1></body></html>")


@app.route("/download")  # path traversal: unsanitized file path
def download():
    filename = request.args.get("file", "notes.txt")
    try:
        return Path(filename).read_text(errors="replace")
    except OSError as exc:
        return f"error: {exc}", 200


@app.route("/fetch")  # SSRF: server-side request to attacker URL
def fetch():
    url = request.args.get("url", "")
    try:
        import urllib.request

        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 — deliberate
            body = resp.read(4096).decode("utf-8", "replace")
        return f"<pre>{body}</pre>"
    except Exception as exc:  # noqa: BLE001
        return f"fetch error: {exc}", 200


@app.route("/cmd")  # OS command injection: shell=True with user input
def cmd():
    ip = request.args.get("ip", "127.0.0.1")
    try:
        out = subprocess.getoutput(f"ping -n 1 {ip}")  # noqa: S602 — deliberate
    except Exception as exc:  # noqa: BLE001
        out = f"error: {exc}"
    return f"<pre>{out}</pre>"


@app.route("/api/xml", methods=["GET", "POST"])  # XXE: entities resolved
def api_xml():
    if request.method == "GET":
        return (
            '<?xml version="1.0"?><request><name>demo</name></request>',
            200,
            {"Content-Type": "application/xml"},
        )
    data = request.get_data()
    try:
        parser = etree.XMLParser(
            resolve_entities=True, no_network=False, load_dtd=True, huge_tree=True
        )
        root = etree.fromstring(data, parser)
        return "".join(root.itertext()), 200, {"Content-Type": "application/xml"}
    except Exception as exc:  # noqa: BLE001
        return f"xml error: {exc}", 200, {"Content-Type": "application/xml"}


# --- broken access control (phase 4) ------------------------------------------


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username", "")
        pw = request.form.get("password", "")
        row = db.execute(
            "SELECT role FROM users WHERE name=? AND password=?", (user, pw)
        ).fetchone()
        if row:
            session["user"] = user
            session["role"] = row[0]
            return redirect("/")
        return "<p>login failed</p>", 401
    return """<form method=post>
      <input name=username><input name=password type=password>
      <button>login</button></form>
      <p>hint: admin/admin123 or alice/wonderland</p>"""


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/profile")  # IDOR + horizontal escalation: any id, no ownership check
def profile():
    uid = request.args.get("id", "1")
    row = db.execute(
        "SELECT id, name, email, role, ssn FROM users WHERE id=?", (uid,)
    ).fetchone()
    if not row:
        return "not found", 404
    return jsonify(dict(zip(["id", "name", "email", "role", "ssn"], row, strict=False)))


@app.route("/administrator")  # admin panel with NO auth check at all
def administrator():
    return (
        "<html><head><title>Administrator Panel</title></head>"
        "<body><h1>Administrator Panel</h1>"
        "<p>secret: super-admin-panel-key</p></body></html>"
    )


JWT_KEY = b"argos-jwt-key"  # noqa: S105 — demo only


def _b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(seg: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _jwt_sign(header: str, payload: str) -> str:
    import hashlib
    import hmac

    return hmac.new(JWT_KEY, f"{header}.{payload}".encode(), hashlib.sha256).hexdigest()


@app.route("/jwt/profile")  # accepts alg=none (unsigned) tokens
def jwt_profile():
    import json

    raw = request.cookies.get("jwt", "")
    parts = raw.split(".")
    if len(parts) == 3:
        header_b64, payload_b64, sig = parts
        try:
            header = json.loads(_b64d(header_b64))
            data = json.loads(_b64d(payload_b64))
        except Exception:  # noqa: BLE001
            header, data = {}, {}
        if header.get("alg") == "none":  # deliberate: signature never checked
            return (
                f"<p>welcome {data.get('sub')} role={data.get('role')} "
                "SECRET=jwt-admin-secret</p>"
            )
        if sig == _jwt_sign(header_b64, payload_b64):
            return f"<p>profile: {data.get('sub')} ({data.get('role')})</p>"
    return "<p>401 unauthorized: invalid jwt</p>", 401


@app.route("/admin")  # forced browsing: admin panel behind weak session check
def admin():
    if session.get("role") == "admin":
        return "<h1>admin panel</h1><p>secret: root-password-here</p>"
    return redirect("/login")


@app.route("/user/<uid>")  # API IDOR
def user_api(uid: str):
    row = db.execute(
        "SELECT id, name, email, role, ssn FROM users WHERE id=?", (uid,)
    ).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(zip(["id", "name", "email", "role", "ssn"], row, strict=False)))


@app.route("/comment", methods=["POST"])  # no CSRF token required
def comment():
    return f"comment stored: {request.form.get('text', '')}"


@app.route("/redirect")  # open redirect
def open_redirect():
    return redirect(request.args.get("url", "/"))


@app.route("/upload", methods=["GET", "POST"])  # unrestricted file upload
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            dest = UPLOAD_DIR / f.filename
            f.save(dest)
            return f"saved /uploads/{f.filename}"
        return "no file", 400
    return """<form method=post enctype=multipart/form-data>
      <input type=file name=file><button>upload</button></form>"""


@app.route("/uploads/<path:name>")
def uploaded(name: str):
    return (UPLOAD_DIR / name).read_text(errors="replace")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
