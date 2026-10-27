#!/usr/bin/env python3
"""Simple bill tracker for a CA firm with two offices.

Data backend: if the DATABASE_URL environment variable is set, data
lives in that PostgreSQL database (used on Render, so data survives
restarts and redeploys). Otherwise data lives in a local SQLite file
(bill_tracker.db) next to this file, so backing up is just copying
that one file. PostgreSQL needs psycopg2-binary (see requirements.txt).

Start:  python3 app.py
Then open in a browser:  http://<server-computer-IP>:8000
First login:  admin / admin123  (change it immediately on the Users page)

Staff in the second office reach it over the office network, a VPN,
or a secure tunnel (see README.md). Do NOT expose port 8000
directly to the public internet without HTTPS in front of it.
"""
import hashlib
import html
import os
import secrets
import sqlite3
import re
import urllib.parse
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "bill_tracker.db")
PORT = int(os.environ.get("BILL_TRACKER_PORT", "8000"))
SESSIONS = {}  # token -> (username, role)
STATUSES = ["Draft", "Sent", "Paid", "Part-paid", "Overdue", "Settled", "Balance billed"]
CYCLES = ["Monthly", "Quarterly", "Yearly", "One-time"]


DATABASE_URL = os.environ.get("DATABASE_URL", "")

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    _PG_ERROR = (psycopg2.IntegrityError,)
except Exception:
    psycopg2 = None
    _PG_ERROR = ()
INTEGRITY_ERRORS = (sqlite3.IntegrityError,) + _PG_ERROR


class Con:
    """Thin wrapper so the same code works on SQLite and PostgreSQL."""
    def __init__(self, raw, is_pg):
        self.raw = raw
        self.is_pg = is_pg

    def execute(self, sql, params=()):
        if self.is_pg:
            sql = sql.replace("?", "%s")
            cur = self.raw.cursor(cursor_factory=RealDictCursor)
        else:
            cur = self.raw.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self.raw.commit()

    def close(self):
        self.raw.close()


def db():
    if DATABASE_URL and psycopg2:
        url = DATABASE_URL
        if "sslmode=" not in url:
            url += ("&" if "?" in url else "?") + "sslmode=require"
        return Con(psycopg2.connect(url), True)
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return Con(con, False)


def init_db():
    con = db()
    id_type = "SERIAL PRIMARY KEY" if con.is_pg else "INTEGER PRIMARY KEY"
    for stmt in [
        f"""CREATE TABLE IF NOT EXISTS users (
            id {id_type}, username TEXT UNIQUE NOT NULL,
            pass_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL)""",
        f"""CREATE TABLE IF NOT EXISTS clients (
            id {id_type}, name TEXT NOT NULL, gstin TEXT,
            contact TEXT, phone TEXT, email TEXT, office TEXT,
            cycle TEXT NOT NULL DEFAULT 'Monthly', fee REAL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1, created_at TEXT)""",
        f"""CREATE TABLE IF NOT EXISTS bills (
            id {id_type}, bill_no TEXT UNIQUE NOT NULL,
            client_id INTEGER NOT NULL REFERENCES clients(id),
            period_label TEXT NOT NULL, bill_date TEXT NOT NULL,
            due_date TEXT, amount REAL NOT NULL, gst_percent REAL DEFAULT 18,
            total REAL NOT NULL, status TEXT NOT NULL DEFAULT 'Draft',
            notes TEXT, created_by TEXT, amount_paid REAL DEFAULT 0, issued_by TEXT, created_at TEXT, bill_kind TEXT DEFAULT 'Final', balance_bill_id INTEGER, heading TEXT)""",
    ]:
        con.execute(stmt)
    # Commit the base tables first. On PostgreSQL a failed statement
    # aborts the whole transaction, so the ALTERs below (which fail
    # on a fresh database, where the columns already exist in the
    # CREATE TABLE above) must run in their own transactions —
    # otherwise the audit_log CREATE after them crashes with
    # InFailedSqlTransaction, which is exactly what broke the
    # first Neon deploy.
    con.commit()
    for alter in [
        "ALTER TABLE bills ADD COLUMN amount_paid REAL DEFAULT 0",
        "ALTER TABLE clients ADD COLUMN created_by TEXT",
        "ALTER TABLE bills ADD COLUMN issued_by TEXT",
        "ALTER TABLE bills ADD COLUMN created_at TEXT",
        "ALTER TABLE clients ADD COLUMN created_at TEXT",
        "ALTER TABLE bills ADD COLUMN bill_kind TEXT DEFAULT 'Final'",
        "ALTER TABLE bills ADD COLUMN balance_bill_id INTEGER",
        "ALTER TABLE bills ADD COLUMN heading TEXT",
    ]:
        try:
            con.execute(alter)
            con.commit()
        except Exception:
            if con.is_pg:
                con.raw.rollback()
    con.execute(f"""CREATE TABLE IF NOT EXISTS payments (
        id {id_type}, bill_id INTEGER NOT NULL, pay_date TEXT, amount REAL NOT NULL,
        mode TEXT, note TEXT, recorded_by TEXT, created_at TEXT, final_settlement INTEGER DEFAULT 0)""")
    con.execute(f"""CREATE TABLE IF NOT EXISTS audit_log (
        id {id_type}, at TEXT NOT NULL, username TEXT NOT NULL,
        action TEXT NOT NULL, detail TEXT)""")
    if not con.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        salt = secrets.token_hex(16)
        h = hashlib.pbkdf2_hmac("sha256", b"admin123", salt.encode(), 100000).hex()
        con.execute("INSERT INTO users (username, pass_hash, salt, role) VALUES (?,?,?,?)",
                    ("admin", h, salt, "admin"))
    con.commit()
    con.close()


def log_action(con, username, action, detail=""):
    con.execute("INSERT INTO audit_log (at, username, action, detail) VALUES (?,?,?,?)",
                (now_ist().strftime("%Y-%m-%d %H:%M"), username, action, detail))


def check_pw(username, password):
    con = db()
    row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    con.close()
    if not row:
        return None
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), row["salt"].encode(), 100000).hex()
    return row["role"] if h == row["pass_hash"] else None


def current_period(cycle, today=None):
    d = today or date.today()
    if cycle == "Monthly":
        return f"{d.year}-{d.month:02d}"
    if cycle == "Quarterly":
        return f"{d.year}-Q{(d.month - 1) // 3 + 1}"
    if cycle == "Yearly":
        return str(d.year)
    return ""


def firm_code(issued_by):
    if not issued_by:
        return ""
    words = [w for w in re.split(r"[^A-Za-z0-9]+", issued_by) if w and w.lower() not in ("and", "the", "&")]
    if not words:
        return ""
    if len(words) == 1:
        return words[0][:4].upper()
    return "".join(w[0] for w in words)[:4].upper()


def next_bill_no(con, kind="Final", issued_by=""):
    year = date.today().year
    prefix = "PF" if kind == "Pro forma" else "BILL"
    code = firm_code(issued_by)
    pat = f"{prefix}-{code}-{year}-%" if code else f"{prefix}-{year}-%"
    row = con.execute("SELECT bill_no FROM bills WHERE bill_no LIKE ? ORDER BY id DESC LIMIT 1", (pat,)).fetchone()
    try:
        n = int(row["bill_no"].rsplit("-", 1)[1]) + 1 if row else 1
    except Exception:
        n = 1
    return f"{prefix}-{code}-{year}-{n:04d}" if code else f"{prefix}-{year}-{n:04d}"


def esc(x):
    return html.escape("" if x is None else str(x))


def now_ist():
    from datetime import datetime, timezone
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(timezone.utc).astimezone(ZoneInfo("Asia/Kolkata"))
    except Exception:
        from datetime import timedelta
        return datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)


def fmt_ts(ts):
    if not ts:
        return "-"
    try:
        from datetime import datetime
        return datetime.strptime(ts, "%Y-%m-%d %H:%M").strftime("%d %b %Y, %I:%M %p")
    except Exception:
        return str(ts)


def badge(status):
    cls = {"Draft": "b-draft", "Sent": "b-sent", "Paid": "b-paid", "Settled": "b-paid", "Balance billed": "b-sent",
           "Part-paid": "b-part", "Overdue": "b-over"}.get(status, "b-draft")
    return f'<span class="badge {cls}">{esc(status)}</span>'


def page(title, user, body):
    if not user:
        return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} - Narayan Bijur Bill Tracker</title><style>
body{{font-family:Inter,system-ui,-apple-system,Segoe UI,Arial,sans-serif;background:#f1f4f9;color:#1f2937;margin:0}}
.wrap{{max-width:460px;margin:80px auto;padding:0 16px}}
.card{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:28px;box-shadow:0 4px 18px rgba(15,40,80,.08)}}
h1{{background:linear-gradient(135deg,#1d4ed8,#7c3aed);-webkit-background-clip:text;background-clip:text;color:transparent;font-size:26px;margin:0 0 4px}} h2{{font-size:18px;margin:0 0 16px;color:#334155}}
input{{width:100%;padding:10px;margin:6px 0;border:1px solid #cbd5e1;border-radius:8px;box-sizing:border-box}}
button{{background:#1a7ae6;color:#fff;border:0;padding:11px 18px;border-radius:8px;cursor:pointer;font-weight:600;width:100%}}
button:hover{{transform:translateY(-1px);box-shadow:0 8px 20px rgba(37,99,235,.4)}} .red{{color:#b00020}} .muted{{color:#64748b;font-size:14px}}
</style></head><body><div class="wrap"><div class="card"><h1>Narayan Bijur Bill Tracker</h1>
<p class="muted">Bills, clients and outstanding amounts — in one place.</p><h2>{esc(title)}</h2>{body}</div></div></body></html>"""
    nav = f"""<aside>
<div class="brand">Narayan Bijur<br><span>Bill Tracker</span></div>
<a href="/dashboard">Dashboard</a><a href="/clients">Clients</a><a href="/import-clients">Import clients</a><a href="/bills">Bills</a>
<a href="/not-billed">Not billed yet</a><a href="/export.csv">Export CSV</a><a href="/export.xlsx">Export Excel</a>
<a href="/users">Users</a><a href="/activity">Activity — who did what</a>{'<a href="/change-password">Change password</a>' if user[1] == 'admin' else ''}
<a href="/logout">Logout ({esc(user[0])})</a></aside>"""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} - Narayan Bijur Bill Tracker</title><style>
*{{box-sizing:border-box}} body{{font-family:Inter,system-ui,-apple-system,Segoe UI,Arial,sans-serif;background:linear-gradient(180deg,#eef2ff 0%,#f8fafc 320px);color:#1f2937;margin:0}}
.layout{{display:flex;min-height:100vh}} aside{{width:240px;background:linear-gradient(180deg,#0f2a4d,#1e3a8a 55%,#312e81);color:#fff;padding:22px 14px;flex-shrink:0;position:sticky;top:0;height:100vh}}
.brand{{font-size:20px;font-weight:800;margin:0 0 26px 8px;line-height:1.2}} .brand span{{font-size:14px;font-weight:600;color:#93c5fd;letter-spacing:.4px;text-transform:uppercase}} aside a{{display:block;color:#cbd5e1;text-decoration:none;padding:10px 12px;border-radius:8px;margin:2px 0}}
aside a:hover{{background:#1e3f66;color:#fff}} main{{flex:1;padding:28px 32px;max-width:1280px}}
h1{{font-size:22px;margin:0 0 18px}} .kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}}
.kpi{{background:#fff;border:1px solid #e2e8f0;border-left:4px solid #2563eb;border-radius:14px;padding:18px;box-shadow:0 2px 10px rgba(15,40,80,.06)}} .kpi:nth-child(2){{border-left-color:#059669}} .kpi:nth-child(3){{border-left-color:#7c3aed}} .kpi:nth-child(4){{border-left-color:#dc2626}} .kpi b{{font-size:22px;display:block;margin-top:4px}}
.kpi span{{color:#64748b;font-size:13px}} .card{{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:20px;margin-bottom:16px;box-shadow:0 4px 16px rgba(15,40,80,.06)}}
table{{border-collapse:collapse;width:100%;font-size:14px}} th{{text-align:left;color:#64748b;font-size:12px;text-transform:uppercase;padding:10px 8px;border-bottom:1px solid #e2e8f0}}
td{{padding:11px 8px;border-bottom:1px solid #f1f5f9}} tr:hover td{{background:#f8fafc}} .amt{{text-align:right;font-variant-numeric:tabular-nums}}
input,select{{padding:9px 11px;margin:3px;border:1px solid #cbd5e1;border-radius:8px;font-size:14px}}
button,.btn{{background:linear-gradient(135deg,#2563eb,#7c3aed);transition:transform .15s ease,box-shadow .15s ease;box-shadow:0 4px 14px rgba(37,99,235,.35);color:#fff;border:0;padding:10px 16px;border-radius:8px;cursor:pointer;font-weight:600;text-decoration:none;display:inline-block}}
button:hover{{transform:translateY(-1px);box-shadow:0 8px 20px rgba(37,99,235,.4)}} .badge{{padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600}}
.b-draft{{background:#e2e8f0;color:#475569}} .b-sent{{background:#dbeafe;color:#1d4ed8}} .b-paid{{background:#dcfce7;color:#15803d}}
.b-part{{background:#fef3c7;color:#b45309}} .b-over{{background:#fee2e2;color:#b91c1c}}
.topbar{{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}}
.topbar form input{{width:260px}}
@media print{{aside,.topbar,.btn,button{{display:none!important}} main{{padding:0}} .card{{box-shadow:none;border:0}}}}
.invoice-head{{display:flex;justify-content:space-between;align-items:flex-start}}
.invoice-head h2{{font-size:26px;margin:0}} .invoice-meta{{text-align:right;color:#64748b}}
.totals{{width:320px;margin-left:auto}} .totals td{{border:0}}
.chart{{display:flex;align-items:flex-end;gap:10px;height:120px;padding-top:10px}}
.bar{{flex:1;background:linear-gradient(180deg,#60a5fa,#2563eb);border-radius:6px 6px 0 0;min-height:4px}}
.bar-wrap{{flex:1;text-align:center;font-size:11px;color:#64748b}}
.warn{{background:#fffbeb;border:1px solid #fde68a;padding:12px;border-radius:10px}} .red{{color:#b91c1c}} .muted{{color:#64748b}}
@media(max-width:1024px){{main{{padding:20px}} .kpis{{grid-template-columns:1fr 1fr}}}} @media(max-width:760px){{.layout{{flex-direction:column}} aside{{width:100%;height:auto;position:static}} .kpis{{grid-template-columns:1fr}}}}
</style></head><body><div class="layout">{nav}<main><div class="topbar"><div><a class="btn" href="/clients">+ New client</a>
<a class="btn" href="/bills">+ New bill</a></div>
<form method="get" action="/bills"><input name="search" placeholder="Search bill or client…"></form></div>
<h1>{esc(title)}</h1>{body}</main></div></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def user(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                return SESSIONS.get(part[8:])
        return None

    def send_html(self, body, status=200):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, loc):
        self.send_response(303)
        self.send_header("Location", loc)
        self.end_headers()

    def form(self):
        n = int(self.headers.get("Content-Length", 0))
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}

    def do_GET(self):
        u = self.user()
        path = urllib.parse.urlparse(self.path).path
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if path == "/login":
            return self.send_html(page("Login", None, """
<form method="post" action="/login"><p>Username <input name="username" required>
Password <input type="password" name="password" required></p>
<button>Login</button></form>
<p>First login: <b>admin / admin123</b> — change it on the Users page.</p>"""))
        if not u:
            return self.redirect("/login")
        if path in ("/", "/dashboard"):
            return self.dashboard(u)
        if path == "/clients":
            return self.clients_page(u)
        if path.startswith("/clients/") and path.rsplit("/", 1)[-1].isdigit():
            return self.client_detail_page(u, int(path.rsplit("/", 1)[-1]))
        if path == "/bills":
            return self.bills_page(u, qs)
        if path == "/not-billed":
            return self.not_billed_page(u)
        if path == "/users":
            return self.users_page(u)
        if path == "/activity":
            con = db()
            rows = con.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
            con.close()
            if u[1] != "admin":
                rows = [r for r in rows if r["username"] == u[0]]
            tr = "".join(f"<tr><td>{fmt_ts(r['at'])}</td><td><b>{esc(r['username'])}</b></td>"
                         f"<td>{esc(r['action'])}</td><td>{esc(r['detail'])}</td></tr>" for r in rows)
            return self.send_html(page("Activity — who did what", u, f"""<div class="card">
<p class="muted">Every entry, payment, status change and password change is recorded here with the staff member who did it and the time.</p>
<table><tr><th>When</th><th>Staff</th><th>Action</th><th>Detail</th></tr>{tr}</table></div>"""))
        if path.startswith("/edit-client/") and path.rsplit("/", 1)[-1].isdigit():
            return self.edit_client_page(u, int(path.rsplit("/", 1)[-1]))
        if path == "/import-clients":
            if u[1] != "admin":
                return self.send_html(page("Import clients", u, "<p>Only an admin can import clients.</p>"), 403)
            return self.send_html(page("Import clients", u, """<div class="card">
<p class="muted">Paste one client per line, comma-separated. Only the name is required — cycle and fee can be left blank and set later (see Clients &rarr; Edit, or the “Save this amount as usual fee” box on a bill).</p>
<p><b>Columns:</b> name, GSTIN, contact, phone, email, office, cycle, fee<br>
<span class="muted">Example: Acme Pvt Ltd, 27ABCDE1234F1Z5, Rahul, 9876543210, rahul@acme.com, Office 1, Monthly, 10000</span></p>
<form method="post" action="/import-clients"><p><textarea name="csv_text" rows="12" style="width:100%" placeholder="Acme Pvt Ltd, 27ABCDE1234F1Z5, Rahul, 9876543210, rahul@acme.com, Office 1"></textarea></p>
<button>Import clients</button></form></div>"""))
        if path.startswith("/edit-bill/") and path.rsplit("/", 1)[-1].isdigit():
            return self.edit_bill_page(u, int(path.rsplit("/", 1)[-1]))
        if path == "/change-password":
            if u[1] != "admin":
                return self.send_html(page("Change password", u, "<p>Only an admin can change passwords. Ask your admin to set a new password for you on the Users page.</p>"), 403)
            return self.send_html(page("Change password", u, """
<form method="post" action="/change-password">
<p>Current password <input type="password" name="current" required></p>
<p>New password <input type="password" id="npw1" name="new" required></p>
<p>Confirm new password <input type="password" id="npw2" name="confirm" required></p>
<label style="display:flex;align-items:center;gap:6px"><input type="checkbox" onclick="var a=document.getElementById('npw1'),b=document.getElementById('npw2');a.type=b.type=this.checked?'text':'password'"> Show password</label>
<button type="button" onclick="navigator.clipboard.writeText(document.getElementById('npw1').value);this.textContent='Copied!'">Copy password</button>
<button>Change password</button></form>
<p class="muted">Use this on your first login too: log in with the temporary
password your admin gave you, then set your own here.</p>"""))
        if path == "/logout":
            SESSIONS.pop(self.headers.get("Cookie", "").split("session=")[-1].split(";")[0], None)
            return self.redirect("/login")
        if path == "/export.csv":
            if u[1] != "admin":
                return self.send_html(page("Export", u, "<p>Only an admin can export.</p>"), 403)
            return self.export_csv()
        if path == "/export.xlsx":
            if u[1] != "admin":
                return self.send_html(page("Export", u, "<p>Only an admin can export.</p>"), 403)
            return self.export_xlsx()
        if path.startswith("/bills/") and path[7:].isdigit():
            return self.bill_detail_page(u, int(path[7:]))
        return self.send_html(page("Not found", u, "<p>Page not found.</p>"), 404)

    def dashboard(self, u):
        con = db()
        bills = con.execute("SELECT * FROM bills").fetchall()
        clients = con.execute("SELECT COUNT(*) c FROM clients WHERE active=1").fetchone()["c"]
        recent = con.execute("""SELECT b.*, c.name AS cname FROM bills b
            JOIN clients c ON c.id=b.client_id ORDER BY b.id DESC LIMIT 5""").fetchall()
        con.close()
        _money = [b for b in bills if (b["bill_kind"] or "Final") != "Pro forma"]
        billed = sum(b["total"] for b in _money)
        paid = sum(b["amount_paid"] or 0 for b in _money)
        settled_writeoff = sum(b["total"] - (b["amount_paid"] or 0) for b in _money if b["status"] in ("Settled", "Balance billed"))
        proforma_total = sum(b["total"] for b in bills if (b["bill_kind"] or "Final") == "Pro forma")
        settled_writeoff = sum(b["total"] - (b["amount_paid"] or 0) for b in bills if b["status"] in ("Settled", "Balance billed"))
        overdue = [b for b in bills if b["status"] == "Overdue"]
        from collections import defaultdict
        from datetime import date as _d
        by_period = defaultdict(float)
        for b in _money:
            by_period[b["period_label"]] += b["total"]
        con2 = db()
        top = con2.execute("""SELECT c.name AS n, SUM(b.total) AS t FROM bills b
            JOIN clients c ON c.id=b.client_id WHERE b.bill_kind IS NULL OR b.bill_kind <> 'Pro forma' GROUP BY c.name ORDER BY t DESC LIMIT 5""").fetchall()
        con2.close()
        periods = sorted(by_period)[-6:]
        mx = max(by_period.values()) if by_period else 1
        bars = "".join(f"<div class='bar-wrap'><div class='bar' style='height:{by_period[pp]/mx*100:.0f}%'></div>{esc(pp)}<br>&#8377;{by_period[pp]:,.0f}</div>" for pp in periods)
        top_tr = "".join(f"<tr><td>{esc(r['n'])}</td><td class='amt'>&#8377;{r['t']:,.2f}</td></tr>" for r in top)
        today = _d.today().isoformat()
        aging = {"0-30 days": 0, "31-60 days": 0, "60+ days": 0}
        for b in _money:
            if b["status"] in ("Paid", "Settled", "Balance billed") or not b["due_date"] or b["due_date"] >= today:
                continue
            days = (_d.fromisoformat(today) - _d.fromisoformat(b["due_date"])).days
            k = "0-30 days" if days <= 30 else "31-60 days" if days <= 60 else "60+ days"
            aging[k] += (b["total"] - (b["amount_paid"] or 0))
        aging_tr = "".join(f"<tr><td>{k}</td><td class='amt'>&#8377;{v:,.2f}</td></tr>" for k, v in aging.items())
        tr = "".join(f"<tr><td><a href='/bills/{r['id']}'>{esc(r['bill_no'])}</a></td><td><a href='/clients/{r['client_id']}'>{esc(r['cname'])}</a></td>"
                     f"<td>{esc(r['period_label'])}</td><td class='amt'>&#8377;{r['total']:,.2f}</td>"
                     f"<td>{badge(r['status'])}</td></tr>" for r in recent)
        if u[1] != "admin":
            bills = [b for b in bills if b["created_by"] == u[0]]
            recent = [r for r in recent if r["created_by"] == u[0]]
            from collections import Counter as _C
            sc = _C(b["status"] for b in bills)
            str_ = "".join(f"<tr><td>{esc(k)}</td><td>{v}</td></tr>" for k, v in sorted(sc.items()))
            str_recent = "".join(f"<tr><td><a href='/bills/{r['id']}'>{esc(r['bill_no'])}</a></td><td>{esc(r['cname'])}</td><td>{esc(r['period_label'])}</td><td>{badge(r['status'])}</td></tr>" for r in recent)
            self.send_html(page("Dashboard", u, f"""<div class="card"><b>Bills by status</b>
<table><tr><th>Status</th><th>Count</th></tr>{str_}</table>
<p class="muted">Staff view: bill status only — totals and amounts are shown to admin only.</p></div>
<div class="card"><b>Recent bills</b>
<table><tr><th>Bill</th><th>Client</th><th>Period</th><th>Status</th></tr>{str_recent}</table></div>"""))
            return
        body = f"""<div class="kpis">
<div class="kpi"><span>Active clients</span><b>{clients}</b></div>
<div class="kpi"><span>Total billed</span><b>&#8377;{billed:,.2f}</b></div>
<div class="kpi"><span>Paid</span><b>&#8377;{paid:,.2f}</b></div>
<div class="kpi"><span>Outstanding</span><b class="red">&#8377;{billed - paid - settled_writeoff:,.2f}</b></div></div>
<p class="muted">Pro forma bills (not counted above): &#8377;{proforma_total:,.2f} — pro forma totals are shown separately and never added to billed or outstanding.</p>
<div class="card"><b>Overdue bills: <span class="red">{len(overdue)}</span></b> &nbsp;|&nbsp;
Check <a href="/not-billed">Not billed yet</a> before month-end so no company is missed.</div>
<div class="card"><b>Billed by period</b><div class="chart">{bars}</div></div>
<div class="card"><b>Top clients by billed amount</b>
<table><tr><th>Client</th><th style="text-align:right">Billed</th></tr>{top_tr}</table></div>
<div class="card"><b>Overdue ageing (unpaid, past due date)</b>
<table><tr><th>Age</th><th style="text-align:right">Outstanding</th></tr>{aging_tr}</table></div>
<div class="card"><b>Billed by firm name</b>
<table><tr><th>Firm</th><th style="text-align:right">Billed</th></tr>{"".join(f"<tr><td>{esc(k or '(not set)')}</td><td class='amt'>&#8377;{v:,.2f}</td></tr>" for k, v in sorted(((lambda d: d)(__import__('collections').defaultdict(float, {kk: sum(b['total'] for b in _money if (b['issued_by'] or '') == kk) for kk in {bb['issued_by'] or '' for bb in _money}}))).items(), key=lambda x: -x[1]))}</table></div>
<div class="card"><b>Recent bills</b>
<table><tr><th>Bill</th><th>Client</th><th>Period</th><th style="text-align:right">Total</th><th>Status</th></tr>{tr}</table></div>"""
        self.send_html(page("Dashboard", u, body))

    def clients_page(self, u):
        con = db()
        rows = con.execute("SELECT * FROM clients ORDER BY name").fetchall()
        con.close()
        tr = "".join(f"<tr><td><a href='/clients/{r['id']}'>{esc(r['name'])}</a></td><td>{esc(r['gstin'])}</td>"
                     f"<td>{esc(r['office'])}</td><td>{esc(r['cycle'])}</td>"
                     f"{'<td>&#8377;' + format(r['fee'], ',.2f') + '</td>' if u[1] == 'admin' else ''}<td>{'Yes' if r['active'] else 'No'}</td>"
                     f"{'<td>' + fmt_ts(r['created_at']) + '</td>' if u[1] == 'admin' else ''}"
                     f"<td>{'<a href=\'/edit-client/' + str(r['id']) + '\'>Edit</a>' if u[1] == 'admin' or r['created_by'] == u[0] else ''}</td></tr>"
                     for r in rows)
        body = f"""<form method="post" action="/clients"><p>
<input name="name" placeholder="Company / client name" required>
<input name="gstin" placeholder="GSTIN (optional)">
<input name="contact" placeholder="Contact person">
<input name="phone" placeholder="Phone">
<input name="email" placeholder="Email">
<input name="office" placeholder="Office (e.g. Office 1)">
<select name="cycle">{''.join(f'<option>{c}</option>' for c in CYCLES)}</select>
<input name="fee" type="number" step="0.01" placeholder="Usual fee">
<button>Add client</button></p></form>
<table><tr><th>Client</th><th>GSTIN</th><th>Office</th><th>Cycle</th>{'<th>Fee</th>' if u[1] == 'admin' else ''}<th>Active</th>{'<th>Added</th>' if u[1] == 'admin' else ''}<th></th></tr>{tr}</table><p class="muted">Cycle and fee are optional when a client is added. Set them later with Edit, or tick “Save this amount as usual fee” when you make the client’s first bill — from then on that amount is pre-filled for new bills.</p>"""
        self.send_html(page("Clients", u, body))

    def bills_page(self, u, qs):
        con = db()
        clients = con.execute("SELECT * FROM clients WHERE active=1 ORDER BY name").fetchall()
        status = qs.get("status", [""])[0]
        sql = """SELECT b.*, c.name AS cname FROM bills b JOIN clients c ON c.id=b.client_id"""
        args = []
        if status:
            sql += " WHERE b.status=?"; args.append(status)
        rows = con.execute(sql + " ORDER BY b.id DESC", args).fetchall()
        if u[1] != "admin":
            rows = [r for r in rows if r["created_by"] == u[0]]
            firms = con.execute("SELECT DISTINCT issued_by FROM bills WHERE issued_by<>'' AND issued_by IS NOT NULL AND created_by=? ORDER BY issued_by", (u[0],)).fetchall()
        else:
            firms = con.execute("SELECT DISTINCT issued_by FROM bills WHERE issued_by<>'' AND issued_by IS NOT NULL ORDER BY issued_by").fetchall()
        con.close()
        opts = "".join(f"<option value='{r['id']}' data-fee='{r['fee']}'>{esc(r['name'])}</option>" for r in clients)
        firm_opts = "".join(f"<option>{esc(r['issued_by'])}</option>" for r in firms)
        firm_filter = qs.get("firm", [""])[0]
        if firm_filter:
            rows = [r for r in rows if (r["issued_by"] or "") == firm_filter]
        kind_filter = qs.get("kind", [""])[0]
        if kind_filter:
            rows = [r for r in rows if (r["bill_kind"] or "Final") == kind_filter]
        tr = "".join(f"<tr><td><a href='/bills/{r['id']}'>{esc(r['bill_no'])}</a></td><td><a href='/clients/{r['client_id']}'>{esc(r['cname'])}</a></td>"
                     f"<td>{esc(r['bill_kind'] or 'Final')}</td><td>{esc(r['heading'] or '')}</td><td>{esc(r['period_label'])}</td><td>{esc(r['bill_date'])}</td>"
                     f"{'<td class=\'amt\'>&#8377;' + format(r['total'], ',.2f') + '</td>' if u[1] == 'admin' else ''}<td>{badge(r['status'])}</td><td>{esc(r['created_by'])}</td><td>{esc(r['issued_by'] or '')}</td>{'<td>' + fmt_ts(r['created_at']) + '</td>' if u[1] == 'admin' else ''}<td><a href='/edit-bill/{r['id']}'>Edit</a></td></tr>" for r in rows)
        search = qs.get("search", [""])[0].lower()
        if search:
            rows = [r for r in rows if search in r["bill_no"].lower() or search in r["cname"].lower() or search in (r["heading"] or "").lower()]
        filt = "".join(f"<option {'selected' if s == status else ''}>{s}</option>" for s in [""] + STATUSES)
        body = f"""<form method="post" action="/bills"><p>
<select name="client_id" id="bill_client" required onchange="var o=this.options[this.selectedIndex];var a=document.getElementById('bill_amount');if(o&&o.dataset.fee&&parseFloat(o.dataset.fee)>0)a.value=o.dataset.fee">{opts}</select>
<select name="bill_kind"><option>Final</option><option>Pro forma</option></select>
<input name="period_label" placeholder="Period e.g. 2026-10" required>
<input name="heading" placeholder="Heading e.g. Professional fees — Oct 2026">
<input name="bill_date" type="date" required>
<input name="due_date" type="date">
<input name="amount" id="bill_amount" type="number" step="0.01" placeholder="Amount (ex-GST)" required>
<label style="display:flex;align-items:center;gap:6px"><input type="checkbox" name="remember_fee"> Save this amount as this client’s usual fee for future bills</label>
<input name="gst_percent" type="number" step="0.01" value="18" placeholder="GST %">
<select name="status">{''.join(f'<option>{s}</option>' for s in STATUSES)}</select>
<input name="issued_by" list="firms" placeholder="Issued by (firm name)">
<datalist id="firms">{firm_opts}</datalist>
<input name="notes" placeholder="Notes (service, etc.)">
<button>Add bill</button></p></form>
<form method="get"><input name="search" placeholder="Search bill no., client or heading" value="{esc(qs.get("search", [""])[0])}">
<select name="status" onchange="this.form.submit()">{filt}</select>
<select name="firm" onchange="this.form.submit()"><option value="">All firms</option>{firm_opts}</select>
<select name="kind" onchange="this.form.submit()"><option value="">All kinds</option><option {'selected' if qs.get("kind", [""])[0] == 'Final' else ''}>Final</option><option {'selected' if qs.get("kind", [""])[0] == 'Pro forma' else ''}>Pro forma</option></select> <button>Search</button></form>
<table><tr><th>Bill no.</th><th>Client</th><th>Kind</th><th>Heading</th><th>Period</th><th>Date</th>{"<th style=\"text-align:right\">Total</th>" if u[1] == "admin" else ""}<th>Status</th><th>Created by</th><th>Issued by</th>{"<th>Put in</th>" if u[1] == "admin" else ""}<th></th></tr>{tr}</table>
<p>To change a bill's status, use the form below: bill number + new status.</p>
<form method="post" action="/bill-status"><p><input name="bill_no" placeholder="Bill no. e.g. BILL-2026-0001" required>
<select name="status">{''.join(f'<option>{s}</option>' for s in STATUSES)}</select>
<button>Update status</button></p></form>"""
        self.send_html(page("Bills", u, body))

    def not_billed_page(self, u):
        con = db()
        clients = con.execute("SELECT * FROM clients WHERE active=1 ORDER BY name").fetchall()
        missing = []
        for c in clients:
            if c["cycle"] == "One-time":
                continue
            p = current_period(c["cycle"])
            hit = con.execute("SELECT 1 FROM bills WHERE client_id=? AND period_label=?",
                              (c["id"], p)).fetchone()
            if not hit:
                missing.append((c, p))
        con.close()
        if not missing:
            body = "<p><b>Nothing missing.</b> Every active client has a bill for the current period.</p>"
        else:
            tr = "".join(f"<tr><td>{esc(c['name'])}</td><td>{esc(c['office'])}</td>"
                         f"<td>{esc(c['cycle'])}</td><td>{esc(p)}</td></tr>" for c, p in missing)
            body = f"""<div class="card warn">These <b>{len(missing)}</b> clients have
<b>no bill for the current period</b>. This is the list to clear before month-end.</div>
<table><tr><th>Client</th><th>Office</th><th>Cycle</th><th>Period missing</th></tr>{tr}</table>"""
        self.send_html(page("Not billed yet", u, body))

    def bill_detail_page(self, u, bill_id):
        con = db()
        r = con.execute("""SELECT b.*, c.name AS cname, c.gstin AS cgstin, c.contact AS ccontact,
            c.email AS cemail, c.office AS coffice FROM bills b
            JOIN clients c ON c.id=b.client_id WHERE b.id=?""", (bill_id,)).fetchone()
        _pays = con.execute("SELECT * FROM payments WHERE bill_id=? ORDER BY id", (bill_id,)).fetchall() if r else []
        con.close()
        if not r:
            return self.send_html(page("Bill not found", u, "<p>No such bill.</p>"), 404)
        if u[1] != "admin" and r["created_by"] != u[0]:
            return self.send_html(page("Bill", u, "<p>You can only see bills you put in.</p>"), 403)
        paid = r["amount_paid"] or 0
        balance = r["total"] - paid
        _pay_rows = "".join(f"<tr><td>{esc(py['pay_date']) or '-'}</td><td class='amt'>&#8377;{py['amount']:,.2f}</td>"
            f"<td>{esc(py['mode']) or ''}</td><td>{esc(py['note']) or ''}</td><td>{esc(py['recorded_by']) or ''}</td>"
            f"<td>{'Final settlement' if py['final_settlement'] else ''}</td></tr>" for py in _pays)
        _pay_sum = sum(py["amount"] for py in _pays)
        if paid > _pay_sum + 0.01:
            _pay_rows += f"<tr><td>-</td><td class='amt'>&#8377;{paid - _pay_sum:,.2f}</td><td colspan='4' class='muted'>Earlier payments (before payment history tracking)</td></tr>"
        _gst_rate = r["gst_percent"] or 0
        _pay_table = f"""<div class="card"><b>Payment history</b>
<table><tr><th>Date</th><th style="text-align:right">Amount</th><th>Mode</th><th>Note</th><th>Recorded by</th><th></th></tr>{_pay_rows if _pay_rows else '<tr><td colspan="6" class="muted">No payments recorded yet.</td></tr>'}</table>
<p class="muted">GST portion of a payment (at { _gst_rate:.0f}%): amount x {_gst_rate:.0f} / (100 + {_gst_rate:.0f}). For a part payment, that is the part-bill GST for that payment.</p></div>"""
        if u[1] != "admin":
            self.send_html(page(f"Invoice {r['bill_no']}", u, f"""<div class="card"><div class="invoice-head"><div>
<h2>Invoice {esc(r['bill_no'])}</h2><p><b>{esc(r['heading'] or '')}</b></p><p class="muted">Period: {esc(r['period_label'])} | Kind: {esc(r['bill_kind'] or 'Final')}</p>
{'<p class="muted"><b>PRO FORMA BILL</b> — not a final tax invoice. Convert it to a final bill when the amount is agreed.</p>' if (r['bill_kind'] or '') == 'Pro forma' else ''}
{'<p class="muted"><b>Settled</b> — paid &#8377;' + format(paid, ',.2f') + ', balance &#8377;' + format(balance, ',.2f') + ' accepted as final settlement, not outstanding.</p>' if r['status'] == 'Settled' else ''}</div>
<div class="invoice-meta"><div>{badge(r['status'])}</div><div>Bill date: {esc(r['bill_date'])}</div>
<div>Due date: {esc(r['due_date']) or '-'}</div><div>Put in: {fmt_ts(r['created_at'])}</div></div></div>
<p><b>Issued by:</b> {esc(r['issued_by'] or '')}<br><b>Bill to:</b> {esc(r['cname'])}<br>{esc(r['cgstin'])}<br>{esc(r['ccontact'])} {esc(r['cemail'])}<br>Office: {esc(r['coffice'])}</p>
<table><tr><th>Description</th><th style="text-align:right">Amount</th></tr>
<tr><td>Professional services — {esc(r['period_label'])}<br><span class="muted">{esc(r['notes'])}</span></td>
<td class="amt">&#8377;{r['amount']:,.2f}</td></tr></table>
<table class="totals"><tr><td>Subtotal</td><td class="amt">&#8377;{r['amount']:,.2f}</td></tr>
<tr><td>GST ({r['gst_percent']:.0f}%)</td><td class="amt">&#8377;{r['total'] - r['amount']:,.2f}</td></tr>
<tr><td><b>Total</b></td><td class="amt"><b>&#8377;{r['total']:,.2f}</b></td></tr>
<tr><td>Paid</td><td class="amt">&#8377;{paid:,.2f}</td></tr>
<tr><td><b>Balance due</b></td><td class="amt"><b>&#8377;{balance if r['status'] != 'Settled' else 0:,.2f}</b></td></tr>
{'<tr><td>Settled / written off</td><td class="amt">&#8377;' + format(balance, ',.2f') + '</td></tr>' if r['status'] == 'Settled' else ''}</table>
{_pay_table}
<p><button onclick="window.print()">Print / Save as PDF</button></p>
{'<form method="post" action="/delete-bill" onsubmit="return confirm(\'Delete this bill? Its payment history is also removed. This cannot be undone.\')"><input type="hidden" name="bill_id" value="' + str(bill_id) + '"><button>Delete bill (admin only)</button></form>' if u[1] == 'admin' else ''}
{'<form method="post" action="/convert-final"><input type="hidden" name="bill_id" value="' + str(bill_id) + '"><button>Convert to final bill</button></form>' if (r['bill_kind'] or '') == 'Pro forma' else ''}
{'<p class="muted">Balance billed separately as bill id ' + str(r['balance_bill_id']) + ' — this bill\'s remaining balance is tracked there, not here.</p>' if r['balance_bill_id'] else ''}
{'<form method="post" action="/raise-balance-bill"><input type="hidden" name="bill_id" value="' + str(bill_id) + '"><p><input name="bill_date" type="date" value="' + now_ist().strftime("%Y-%m-%d") + '" required> <button>Raise separate bill for balance</button></p><p class="muted">Creates a new bill for this bill\'s remaining balance (same client, same GST %). This bill then becomes “Balance billed” so the balance is not counted twice. Use this only when the part payment is NOT a final settlement — if it is, tick final settlement on the payment instead.</p></form>' if r['status'] == 'Part-paid' else ''}
<p class="muted">This bill only — no totals across clients are shown on the Dashboard.</p></div>
<div class="card"><b>Record payment</b>
<form method="post" action="/bill-payment"><input type="hidden" name="bill_id" value="{bill_id}">
<input name="amount" type="number" step="0.01" placeholder="Amount received" required>
<input name="pay_date" type="date">
<select name="mode"><option>Bank transfer</option><option>Cash</option><option>Cheque</option><option>UPI</option><option>Other</option></select>
<input name="note" placeholder="Note (e.g. cheque no., UTR)">
<label style="display:flex;align-items:center;gap:6px"><input type="checkbox" name="final_settlement" value="1"> This payment is the final settlement — close this bill even if a balance remains</label>
<button>Record payment</button></form>
<p class="muted">Recording the full balance marks the bill Paid; a part payment marks it Part-paid.</p></div>"""))
            return
        body = f"""<div class="card"><div class="invoice-head"><div>
<h2>Invoice {esc(r['bill_no'])}</h2><p><b>{esc(r['heading'] or '')}</b></p><p class="muted">Period: {esc(r['period_label'])} | Kind: {esc(r['bill_kind'] or 'Final')}</p>
{'<p class="muted"><b>PRO FORMA BILL</b> — not a final tax invoice. Convert it to a final bill when the amount is agreed.</p>' if (r['bill_kind'] or '') == 'Pro forma' else ''}
{'<p class="muted"><b>Settled</b> — paid &#8377;' + format(paid, ',.2f') + ', balance &#8377;' + format(balance, ',.2f') + ' accepted as final settlement, not outstanding.</p>' if r['status'] == 'Settled' else ''}</div>
<div class="invoice-meta"><div>{badge(r['status'])}</div><div>Bill date: {esc(r['bill_date'])}</div>
<div>Due date: {esc(r['due_date']) or '-'}</div><div>Put in: {fmt_ts(r['created_at'])}</div></div></div>
<p><b>Issued by:</b> {esc(r['issued_by'] or '')}<br><b>Bill to:</b> {esc(r['cname'])}<br>{esc(r['cgstin'])}<br>{esc(r['ccontact'])} {esc(r['cemail'])}<br>Office: {esc(r['coffice'])}</p>
<table><tr><th>Description</th><th style="text-align:right">Amount</th></tr>
<tr><td>Professional services — {esc(r['period_label'])}<br><span class="muted">{esc(r['notes'])}</span></td>
<td class="amt">&#8377;{r['amount']:,.2f}</td></tr></table>
<table class="totals"><tr><td>Subtotal</td><td class="amt">&#8377;{r['amount']:,.2f}</td></tr>
<tr><td>GST ({r['gst_percent']:.0f}%)</td><td class="amt">&#8377;{r['total'] - r['amount']:,.2f}</td></tr>
<tr><td><b>Total</b></td><td class="amt"><b>&#8377;{r['total']:,.2f}</b></td></tr>
<tr><td>Paid</td><td class="amt">&#8377;{paid:,.2f}</td></tr>
<tr><td><b>Balance due</b></td><td class="amt"><b>&#8377;{balance if r['status'] != 'Settled' else 0:,.2f}</b></td></tr>
{'<tr><td>Settled / written off</td><td class="amt">&#8377;' + format(balance, ',.2f') + '</td></tr>' if r['status'] == 'Settled' else ''}</table>
{_pay_table}
<p><button onclick="window.print()">Print / Save as PDF</button></p>
{'<form method="post" action="/delete-bill" onsubmit="return confirm(\'Delete this bill? Its payment history is also removed. This cannot be undone.\')"><input type="hidden" name="bill_id" value="' + str(bill_id) + '"><button>Delete bill (admin only)</button></form>' if u[1] == 'admin' else ''}
{'<form method="post" action="/convert-final"><input type="hidden" name="bill_id" value="' + str(bill_id) + '"><button>Convert to final bill</button></form>' if (r['bill_kind'] or '') == 'Pro forma' else ''}
{'<p class="muted">Balance billed separately as bill id ' + str(r['balance_bill_id']) + ' — this bill\'s remaining balance is tracked there, not here.</p>' if r['balance_bill_id'] else ''}
{'<form method="post" action="/raise-balance-bill"><input type="hidden" name="bill_id" value="' + str(bill_id) + '"><p><input name="bill_date" type="date" value="' + now_ist().strftime("%Y-%m-%d") + '" required> <button>Raise separate bill for balance</button></p><p class="muted">Creates a new bill for this bill\'s remaining balance (same client, same GST %). This bill then becomes “Balance billed” so the balance is not counted twice. Use this only when the part payment is NOT a final settlement — if it is, tick final settlement on the payment instead.</p></form>' if r['status'] == 'Part-paid' else ''}</div>
<div class="card"><b>Record payment</b>
<form method="post" action="/bill-payment"><input type="hidden" name="bill_id" value="{bill_id}">
<input name="amount" type="number" step="0.01" placeholder="Amount received" required>
<input name="pay_date" type="date">
<select name="mode"><option>Bank transfer</option><option>Cash</option><option>Cheque</option><option>UPI</option><option>Other</option></select>
<input name="note" placeholder="Note (e.g. cheque no., UTR)">
<label style="display:flex;align-items:center;gap:6px"><input type="checkbox" name="final_settlement" value="1"> This payment is the final settlement — close this bill even if a balance remains</label>
<button>Record payment</button></form>
<p class="muted">Recording the full balance marks the bill Paid; a part payment marks it Part-paid.</p></div>"""
        self.send_html(page(f"Invoice {r['bill_no']}", u, body))

    def client_detail_page(self, u, cid):
        con = db()
        c = con.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
        if not c:
            con.close()
            return self.send_html(page("Client not found", u, "<p>No such client.</p>"), 404)
        if u[1] != "admin":
            bills = con.execute("""SELECT * FROM bills WHERE client_id=? AND created_by=? ORDER BY id DESC""", (cid, u[0])).fetchall()
        else:
            bills = con.execute("""SELECT * FROM bills WHERE client_id=? ORDER BY id DESC""", (cid,)).fetchall()
        con.close()
        _money = [b for b in bills if (b["bill_kind"] or "Final") != "Pro forma"]
        billed = sum(b["total"] for b in _money)
        paid = sum(b["amount_paid"] or 0 for b in _money)
        settled_writeoff = sum(b["total"] - (b["amount_paid"] or 0) for b in _money if b["status"] in ("Settled", "Balance billed"))
        proforma_total = sum(b["total"] for b in bills if (b["bill_kind"] or "Final") == "Pro forma")
        tr = "".join(f"<tr><td><a href='/bills/{b['id']}'>{esc(b['bill_no'])}</a></td><td>{esc(b['heading'] or '')}</td><td>{esc(b['period_label'])}</td>"
                     f"<td>{esc(b['bill_date'])}</td><td class='amt'>&#8377;{b['total']:,.2f}</td>"
                     f"<td class='amt'>&#8377;{(b['amount_paid'] or 0):,.2f}</td><td>{badge(b['status'])}</td>"
                     f"<td>{esc(b['issued_by'] or '')}</td><td>{fmt_ts(b['created_at'])}</td></tr>" for b in bills)
        scope = "Your bills for this client only." if u[1] != "admin" else "All bills for this client."
        edit = f"<a href='/edit-client/{cid}'>Edit client</a>" if u[1] == "admin" or c["created_by"] == u[0] else ""
        body = f"""<div class="card"><h2>{esc(c['name'])}</h2>
<p>{esc(c['gstin'])}<br>{esc(c['contact'])} {esc(c['phone'])} {esc(c['email'])}<br>Office: {esc(c['office'])} | Cycle: {esc(c['cycle'])} | Usual fee: &#8377;{c['fee']:,.2f}</p>
<p>{edit}</p></div>
<div class="card"><b>Bills for this client</b> <span class="muted">{scope}</span>
<table><tr><th>Bill</th><th>Heading</th><th>Period</th><th>Date</th><th style="text-align:right">Total</th><th style="text-align:right">Paid</th><th>Status</th><th>Issued by</th><th>Put in</th></tr>{tr}</table>
<table class="totals"><tr><td><b>Total for this client</b></td><td class="amt"><b>&#8377;{billed:,.2f}</b></td></tr>
<tr><td>Paid</td><td class="amt">&#8377;{paid:,.2f}</td></tr>
<tr><td>Settled / written off for this client</td><td class="amt">&#8377;{settled_writeoff:,.2f}</td></tr>
<tr><td><b>Outstanding for this client</b></td><td class="amt"><b>&#8377;{billed - paid - settled_writeoff:,.2f}</b></td></tr>
<tr><td>Pro forma for this client (not in totals above)</td><td class="amt">&#8377;{proforma_total:,.2f}</td></tr></table>
<p class="muted">This is money for this one client only — the Dashboard never totals across all clients for staff.</p></div>"""
        self.send_html(page(c["name"], u, body))

    def edit_client_page(self, u, cid):
        con = db()
        r = con.execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
        con.close()
        if not r:
            return self.send_html(page("Client not found", u, "<p>No such client.</p>"), 404)
        if u[1] != "admin" and r["created_by"] != u[0]:
            return self.send_html(page("Edit client", u, "<p>You can only edit clients you put in.</p>"), 403)
        opts = "".join(f"<option {'selected' if c == r['cycle'] else ''}>{c}</option>" for c in CYCLES)
        body = f"""<form method="post" action="/client-edit"><input type="hidden" name="id" value="{cid}"><p>
<input name="name" value="{esc(r['name'])}" required>
<input name="gstin" value="{esc(r['gstin'])}" placeholder="GSTIN">
<input name="contact" value="{esc(r['contact'])}" placeholder="Contact person">
<input name="phone" value="{esc(r['phone'])}" placeholder="Phone">
<input name="email" value="{esc(r['email'])}" placeholder="Email">
<input name="office" value="{esc(r['office'])}" placeholder="Office">
<select name="cycle">{opts}</select>
<input name="fee" type="number" step="0.01" value="{r['fee']}" placeholder="Usual fee">
<button>Save client</button></p></form>
<p class="muted">Set the billing cycle and usual fee here the first time, and the fee will be pre-filled on future bills for this client.</p>"""
        self.send_html(page("Edit client", u, body))

    def edit_bill_page(self, u, bid):
        con = db()
        r = con.execute("""SELECT b.*, c.name AS cname FROM bills b JOIN clients c ON c.id=b.client_id WHERE b.id=?""", (bid,)).fetchone()
        con.close()
        if not r:
            return self.send_html(page("Bill not found", u, "<p>No such bill.</p>"), 404)
        if u[1] != "admin" and r["created_by"] != u[0]:
            return self.send_html(page("Edit bill", u, "<p>You can only edit bills you put in.</p>"), 403)
        opts = "".join(f"<option {'selected' if st == r['status'] else ''}>{st}</option>" for st in STATUSES)
        body = f"""<form method="post" action="/bill-edit"><input type="hidden" name="id" value="{bid}"><p>
Bill: <b>{esc(r['bill_no'])}</b> — {esc(r['cname'])}<br>
<input name="heading" value="{esc(r['heading'] or '')}" placeholder="Heading">
<input name="period_label" value="{esc(r['period_label'])}" required>
<input name="bill_date" type="date" value="{esc(r['bill_date'])}" required>
<input name="due_date" type="date" value="{esc(r['due_date']) or ''}">
<input name="amount" type="number" step="0.01" value="{r['amount']}" required>
<input name="gst_percent" type="number" step="0.01" value="{r['gst_percent']}">
<select name="status">{opts}</select>
<select name="bill_kind"><option {'selected' if (r['bill_kind'] or 'Final') == 'Final' else ''}>Final</option><option {'selected' if r['bill_kind'] == 'Pro forma' else ''}>Pro forma</option></select>
{f'<input name="created_by" value="{esc(r["created_by"] or "")}" placeholder="Created by (admin: reassign to another username)">' if u[1] == 'admin' else ''}
<input name="issued_by" value="{esc(r['issued_by'] or '')}" placeholder="Issued by (firm name)">
<input name="notes" value="{esc(r['notes'])}" placeholder="Notes">
<button>Save bill</button></p></form>
<p class="muted">Changing the amount recalculates the total with the GST % above.</p>"""
        self.send_html(page("Edit bill", u, body))

    def users_page(self, u):
        if u[1] != "admin":
            return self.send_html(page("Users", u, "<p>Only an admin can manage users.</p>"), 403)
        con = db()
        rows = con.execute("SELECT username, role FROM users ORDER BY username").fetchall()
        con.close()
        def _row(r):
            uname = esc(r['username'])
            if r['username'] == u[0]:
                actions = "<span class='muted'>This is you — use Change password for your own password, and you cannot remove yourself.</span>"
            else:
                actions = (f"<form method='post' action='/reset-password' style='display:inline'>"
                           f"<input type='hidden' name='username' value='{uname}'>"
                           f"<input name='password' type='password' placeholder='New password' required> "
                           f"<input name='confirm' type='password' placeholder='Type again' required> "
                           f"<button>Change password</button></form> "
                           f"<form method='post' action='/delete-user' style='display:inline' onsubmit=\"return confirm('Remove {uname}? Their bills, clients and activity stay in the tracker under their name — only their login stops working.')\">"
                           f"<input type='hidden' name='username' value='{uname}'>"
                           f"<button>Remove</button></form>")
            return f"<tr><td>{uname}</td><td>{esc(r['role'])}</td><td>{actions}</td></tr>"
        tr = "".join(_row(r) for r in rows)
        body = f"""<form method="post" action="/users"><p>
<input name="username" placeholder="New staff username" required>
<input name="password" id="pw1" type="password" placeholder="Password" required>
<input name="confirm" id="pw2" type="password" placeholder="Type password again" required>
<label style="display:flex;align-items:center;gap:6px"><input type="checkbox" onclick="var a=document.getElementById('pw1'),b=document.getElementById('pw2');a.type=b.type=this.checked?'text':'password'"> Show password</label>
<button type="button" onclick="navigator.clipboard.writeText(document.getElementById('pw1').value);this.textContent='Copied!'">Copy password</button>
<select name="role"><option>staff</option><option>admin</option></select>
<button>Add user</button></p></form>
<table><tr><th>Username</th><th>Role</th><th>Actions</th></tr>{tr}</table>
<form method="post" action="/reassign"><p><b>Reassign entries (e.g. when staff leaves):</b><br>
<input name="from_user" placeholder="From username" required>
<input name="to_user" placeholder="To username" required>
<button>Reassign all bills and clients</button></p></form>
<p><b>Removing a staff member only stops their login.</b> Their bills, clients and activity stay in the tracker under their name, so nothing they put in is lost when they leave.</p>
<p>Give each staff member their own username with a password you set here.
Staff cannot change their own password — only an admin can, from this page.
The first admin login is <b>admin / admin123</b> — change
it on the Change password page straight away.</p>"""
        self.send_html(page("Users", u, body))

    def export_csv(self):
        import csv, io
        con = db()
        rows = con.execute("""SELECT b.bill_no, c.name, b.period_label, b.bill_date,
            b.due_date, b.amount, b.gst_percent, b.total, b.status, b.notes, b.issued_by, b.heading
            FROM bills b JOIN clients c ON c.id=b.client_id ORDER BY b.id""").fetchall()
        con.close()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Bill no", "Client", "Period", "Date", "Due", "Amount", "GST %", "Total", "Status", "Notes", "Issued by", "Heading"])
        cols = ["bill_no", "name", "period_label", "bill_date", "due_date",
                "amount", "gst_percent", "total", "status", "notes", "issued_by", "heading"]
        w.writerows([[r[c] for c in cols] for r in rows])
        data = buf.getvalue().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Disposition", "attachment; filename=bills.csv")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def export_xlsx(self):
        import io
        try:
            import openpyxl
        except ImportError:
            return self.send_html(page("Export Excel", self.user(), "<p>Excel export is not available on this server.</p>"), 500)
        con = db()
        wb = openpyxl.Workbook()
        def sheet(name, headers, rows, cols):
            ws = wb.active if name == "Bills" else wb.create_sheet(name)
            if name == "Bills":
                ws.title = name
            ws.append(headers)
            for r in rows:
                ws.append([r[c] for c in cols])
            for col in ws.columns:
                ws.column_dimensions[col[0].column_letter].width = 18
        bills = con.execute("""SELECT b.bill_no, c.name, b.period_label, b.bill_date, b.due_date,
            b.amount, b.gst_percent, b.total, b.amount_paid, b.status, b.notes, b.created_by, b.issued_by, b.heading
            FROM bills b JOIN clients c ON c.id=b.client_id ORDER BY b.id""").fetchall()
        clients = con.execute("SELECT * FROM clients ORDER BY name").fetchall()
        activity = con.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 500").fetchall()
        con.close()
        sheet("Bills", ["Bill no", "Client", "Period", "Date", "Due", "Amount", "GST %", "Total", "Paid", "Status", "Notes", "Created by", "Issued by", "Heading"],
              bills, ["bill_no", "name", "period_label", "bill_date", "due_date", "amount", "gst_percent", "total", "amount_paid", "status", "notes", "created_by", "issued_by", "heading"])
        pays = con.execute("""SELECT b.bill_no, c.name, p.pay_date, p.amount, p.mode, p.note, p.recorded_by, p.final_settlement
            FROM payments p JOIN bills b ON b.id=p.bill_id JOIN clients c ON c.id=b.client_id ORDER BY p.id""").fetchall()
        sheet("Payments", ["Bill no", "Client", "Date", "Amount", "Mode", "Note", "Recorded by", "Final settlement"],
              pays, ["bill_no", "name", "pay_date", "amount", "mode", "note", "recorded_by", "final_settlement"])
        sheet("Clients", ["Client", "GSTIN", "Contact", "Phone", "Email", "Office", "Cycle", "Fee", "Active", "Created by"],
              clients, ["name", "gstin", "contact", "phone", "email", "office", "cycle", "fee", "active", "created_by"])
        sheet("Activity", ["When", "Staff", "Action", "Detail"],
              activity, ["at", "username", "action", "detail"])
        buf = io.BytesIO()
        wb.save(buf)
        data = buf.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.send_header("Content-Disposition", "attachment; filename=bill-tracker.xlsx")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        u = self.user()
        path = urllib.parse.urlparse(self.path).path
        f = self.form()
        if path == "/login":
            role = check_pw(f.get("username", ""), f.get("password", ""))
            if not role:
                return self.send_html(page("Login", None, "<p class='red'>Wrong username or password.</p>"), 401)
            token = secrets.token_hex(24)
            SESSIONS[token] = (f["username"], role)
            self.send_response(303)
            self.send_header("Set-Cookie", f"session={token}; HttpOnly; Path=/; SameSite=Lax")
            self.send_header("Location", "/dashboard")
            self.end_headers()
            return
        if not u:
            return self.redirect("/login")
        if path == "/activity":
            con = db()
            rows = con.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
            con.close()
            if u[1] != "admin":
                rows = [r for r in rows if r["username"] == u[0]]
            tr = "".join(f"<tr><td>{fmt_ts(r['at'])}</td><td><b>{esc(r['username'])}</b></td>"
                         f"<td>{esc(r['action'])}</td><td>{esc(r['detail'])}</td></tr>" for r in rows)
            return self.send_html(page("Activity — who did what", u, f"""<div class="card">
<p class="muted">Every entry, payment, status change and password change is recorded here with the staff member who did it and the time.</p>
<table><tr><th>When</th><th>Staff</th><th>Action</th><th>Detail</th></tr>{tr}</table></div>"""))
        if path.startswith("/edit-client/") and path.rsplit("/", 1)[-1].isdigit():
            return self.edit_client_page(u, int(path.rsplit("/", 1)[-1]))
        if path == "/change-password":
            if u[1] != "admin":
                return self.send_html(page("Change password", u, "<p>Only an admin can change passwords.</p>"), 403)
            if check_pw(u[0], f.get("current", "")) is None:
                return self.send_html(page("Change password", u, "<p class='red'>Current password is wrong.</p>"), 401)
            if f.get("new", "") != f.get("confirm", "") or len(f.get("new", "")) < 8:
                return self.send_html(page("Change password", u, "<p class='red'>New passwords do not match, or are shorter than 8 characters.</p>"), 400)
            con = db()
            salt = secrets.token_hex(16)
            h = hashlib.pbkdf2_hmac("sha256", f["new"].encode(), salt.encode(), 100000).hex()
            con.execute("UPDATE users SET pass_hash=?, salt=? WHERE username=?", (h, salt, u[0]))
            log_action(con, u[0], "Changed password", "")
            con.commit(); con.close()
            return self.send_html(page("Password changed", u, "<p><b>Password changed.</b> Use your new password next time you log in. <a href='/dashboard'>Back to Dashboard</a></p>"))
        if path == "/bill-payment":
            con = db()
            if u[1] != "admin":
                _own = con.execute("SELECT created_by FROM bills WHERE id=?", (int(f["bill_id"]),)).fetchone()
                if not _own or _own["created_by"] != u[0]:
                    con.close()
                    return self.send_html(page("Record payment", u, "<p>You can only record payments on bills you put in.</p>"), 403)
            r = con.execute("SELECT total, amount_paid FROM bills WHERE id=?", (int(f["bill_id"]),)).fetchone()
            if r:
                new_paid = (r["amount_paid"] or 0) + float(f["amount"])
                if f.get("final_settlement"):
                    status = "Settled"
                else:
                    status = "Paid" if new_paid >= r["total"] - 0.01 else "Part-paid"
                con.execute("UPDATE bills SET amount_paid=?, status=? WHERE id=?", (new_paid, status, int(f["bill_id"])))
                con.execute("""INSERT INTO payments (bill_id, pay_date, amount, mode, note, recorded_by, created_at, final_settlement)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (int(f["bill_id"]), f.get("pay_date") or now_ist().strftime("%Y-%m-%d"), float(f["amount"]),
                     f.get("mode", ""), f.get("note", ""), u[0], now_ist().strftime("%Y-%m-%d %H:%M"),
                     1 if f.get("final_settlement") else 0))
                log_action(con, u[0], "Recorded payment", f"Bill id {f['bill_id']}: Rs {f['amount']} -> {status}" + (" (final settlement, balance Rs " + format(r["total"] - new_paid, ",.2f") + " accepted)" if status == "Settled" else ""))
                con.commit()
            con.close()
            return self.redirect(f"/bills/{f['bill_id']}")
        con = db()
        try:
            if path == "/reset-password" and u[1] == "admin":
                if f.get("password") != f.get("confirm", "") or len(f.get("password", "")) < 8:
                    con.close()
                    return self.send_html(page("Error", u, "<p>New passwords do not match, or are shorter than 8 characters.</p>"), 400)
                salt = secrets.token_hex(16)
                h = hashlib.pbkdf2_hmac("sha256", f["password"].encode(), salt.encode(), 100000).hex()
                con.execute("UPDATE users SET pass_hash=?, salt=? WHERE username=?", (h, salt, f["username"]))
                log_action(con, u[0], "Changed user password", f["username"])
                con.commit(); con.close()
                return self.redirect("/users")
            if path == "/delete-user" and u[1] == "admin":
                target = f["username"]
                if target == u[0]:
                    con.close()
                    return self.send_html(page("Error", u, "<p>You cannot remove your own login.</p>"), 400)
                row = con.execute("SELECT role FROM users WHERE username=?", (target,)).fetchone()
                if not row:
                    con.close()
                    return self.send_html(page("Error", u, "<p>No such user.</p>"), 404)
                if row["role"] == "admin" and con.execute("SELECT COUNT(*) c FROM users WHERE role='admin'").fetchone()["c"] <= 1:
                    con.close()
                    return self.send_html(page("Error", u, "<p>Cannot remove the only admin.</p>"), 400)
                # Only the login is removed. Bills, clients and activity keep
                # created_by / username as plain text, so nothing they put in is deleted.
                con.execute("DELETE FROM users WHERE username=?", (target,))
                log_action(con, u[0], "Removed user", target)
                con.commit(); con.close()
                for tok in [t for t, v in list(SESSIONS.items()) if v[0] == target]:
                    SESSIONS.pop(tok, None)
                return self.redirect("/users")
            if path == "/raise-balance-bill":
                bill = con.execute("SELECT * FROM bills WHERE id=?", (int(f["bill_id"]),)).fetchone()
                if not bill:
                    con.close()
                    return self.send_html(page("Balance bill", u, "<p>No such bill.</p>"), 404)
                if u[1] != "admin" and bill["created_by"] != u[0]:
                    con.close()
                    return self.send_html(page("Balance bill", u, "<p>You can only raise a balance bill for bills you put in.</p>"), 403)
                if bill["status"] == "Settled":
                    con.close()
                    return self.send_html(page("Balance bill", u, "<p>This bill is already settled — there is no balance to bill separately.</p>"), 400)
                balance = round(bill["total"] - (bill["amount_paid"] or 0), 2)
                if balance <= 0:
                    con.close()
                    return self.send_html(page("Balance bill", u, "<p>There is no balance left on this bill.</p>"), 400)
                gst = bill["gst_percent"] or 0
                gst_amt = round(balance * gst / (100 + gst), 2) if gst else 0
                amt = round(balance - gst_amt, 2)
                new_no = next_bill_no(con, bill["bill_kind"] or "Final", bill["issued_by"] or "")
                cur = con.execute("""INSERT INTO bills (bill_no, client_id, period_label, bill_date, due_date,
                    amount, gst_percent, total, status, notes, created_by, issued_by, created_at, bill_kind, heading)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (new_no, bill["client_id"], bill["period_label"], f.get("bill_date") or now_ist().strftime("%Y-%m-%d"),
                     bill["due_date"], amt, gst, balance, "Draft",
                     f"Balance bill for {bill['bill_no']} (part payment Rs {bill['amount_paid']:,.2f} received, balance Rs {balance:,.2f})",
                     u[0], bill["issued_by"] or "", now_ist().strftime("%Y-%m-%d %H:%M"), bill["bill_kind"] or "Final",
                     (("Balance — " + bill["heading"]) if bill["heading"] else "Balance bill")))
                new_id = cur.lastrowid if hasattr(cur, "lastrowid") else con.execute("SELECT id FROM bills WHERE bill_no=?", (new_no,)).fetchone()["id"]
                con.execute("UPDATE bills SET status='Balance billed', balance_bill_id=? WHERE id=?", (new_id, bill["id"]))
                log_action(con, u[0], "Raised balance bill", f"{bill['bill_no']} -> {new_no} for balance Rs {balance:,.2f}")
                con.commit(); con.close()
                return self.redirect(f"/bills/{new_id}")
            if path == "/delete-bill" and u[1] == "admin":
                con.execute("DELETE FROM payments WHERE bill_id=?", (int(f["bill_id"]),))
                _bn = con.execute("SELECT bill_no FROM bills WHERE id=?", (int(f["bill_id"]),)).fetchone()
                con.execute("DELETE FROM bills WHERE id=?", (int(f["bill_id"]),))
                log_action(con, u[0], "Deleted bill", _bn["bill_no"] if _bn else str(f["bill_id"]))
                con.commit(); con.close()
                return self.redirect("/bills")
            if path == "/reassign" and u[1] == "admin":
                _from, _to = f["from_user"], f["to_user"]
                if _from == _to:
                    con.close()
                    return self.send_html(page("Reassign", u, "<p>From and To are the same user.</p>"), 400)
                if not con.execute("SELECT 1 FROM users WHERE username=?", (_to,)).fetchone():
                    con.close()
                    return self.send_html(page("Reassign", u, "<p>To user does not exist.</p>"), 400)
                _nb = con.execute("UPDATE bills SET created_by=? WHERE created_by=?", (_to, _from)).rowcount
                _nc = con.execute("UPDATE clients SET created_by=? WHERE created_by=?", (_to, _from)).rowcount
                log_action(con, u[0], "Reassigned entries", f"{_from} -> {_to}: {_nb} bills, {_nc} clients")
                con.commit(); con.close()
                return self.send_html(page("Reassigned", u, f"<p><b>{_nb} bills and {_nc} clients</b> moved from {_from} to {_to}. The moved entries now belong to {_to} for staff-scope purposes; their history and amounts are unchanged.</p><p><a href='/users'>Back to Users</a></p>"))
            if path == "/convert-final":
                if u[1] != "admin":
                    _own = con.execute("SELECT created_by FROM bills WHERE id=?", (int(f["bill_id"]),)).fetchone()
                    if not _own or _own["created_by"] != u[0]:
                        con.close()
                        return self.send_html(page("Convert bill", u, "<p>You can only convert bills you put in.</p>"), 403)
                con.execute("UPDATE bills SET bill_kind='Final' WHERE id=?", (int(f["bill_id"]),))
                log_action(con, u[0], "Converted pro forma to final", f"Bill id {f['bill_id']}")
                con.commit(); con.close()
                return self.redirect(f"/bills/{f['bill_id']}")
            if path == "/bill-edit":
                if u[1] != "admin":
                    _own = con.execute("SELECT created_by FROM bills WHERE id=?", (int(f["id"]),)).fetchone()
                    if not _own or _own["created_by"] != u[0]:
                        con.close()
                        return self.send_html(page("Edit bill", u, "<p>You can only edit bills you put in.</p>"), 403)
                amt = float(f["amount"]); gst = float(f.get("gst_percent") or 18)
                con.execute("""UPDATE bills SET period_label=?, bill_date=?, due_date=?, amount=?, gst_percent=?,
                    total=?, status=?, notes=?, issued_by=?, bill_kind=?, heading=? WHERE id=?""",
                    (f["period_label"], f["bill_date"], f.get("due_date") or None, amt, gst,
                     round(amt * (1 + gst / 100), 2), f.get("status", "Draft"), f.get("notes", ""),
                     f.get("issued_by", ""), f.get("bill_kind", "Final"), f.get("heading", ""), int(f["id"])))
                if u[1] == "admin" and f.get("created_by"):
                    con.execute("UPDATE bills SET created_by=? WHERE id=?", (f["created_by"], int(f["id"])))
                log_action(con, u[0], "Edited bill", f"Bill id {f['id']}")
                con.commit(); con.close()
                return self.redirect("/bills")
            if path == "/client-edit":
                if u[1] != "admin":
                    _own = con.execute("SELECT created_by FROM clients WHERE id=?", (int(f["id"]),)).fetchone()
                    if not _own or _own["created_by"] != u[0]:
                        con.close()
                        return self.send_html(page("Edit client", u, "<p>You can only edit clients you put in.</p>"), 403)
                con.execute("""UPDATE clients SET name=?, gstin=?, contact=?, phone=?, email=?, office=?, cycle=?, fee=?
                    WHERE id=?""",
                    (f["name"], f.get("gstin", ""), f.get("contact", ""), f.get("phone", ""),
                     f.get("email", ""), f.get("office", ""), f.get("cycle", "Monthly"),
                     float(f.get("fee") or 0), int(f["id"])))
                log_action(con, u[0], "Updated client", f["name"] + " (cycle/fee set)")
                con.commit(); con.close()
                return self.redirect("/clients")
            if path == "/import-clients":
                if u[1] != "admin":
                    con.close()
                    return self.send_html(page("Import clients", u, "<p>Only an admin can import clients.</p>"), 403)
                import csv as _csv, io as _io
                added = skipped = 0
                existing = {(r["name"].lower()) for r in con.execute("SELECT name FROM clients").fetchall()}
                existing_gstin = {(r["gstin"]) for r in con.execute("SELECT gstin FROM clients WHERE gstin<>''").fetchall()}
                for row in _csv.reader(_io.StringIO(f.get("csv_text", ""))):
                    if not row or not row[0].strip():
                        continue
                    vals = [c.strip() for c in row] + [""] * 8
                    name, gstin = vals[0], vals[1]
                    if name.lower() in existing or (gstin and gstin in existing_gstin):
                        skipped += 1; continue
                    cycle = vals[6] if vals[6] in CYCLES else "Monthly"
                    try: fee = float(vals[7]) if vals[7] else 0
                    except ValueError: fee = 0
                    con.execute("""INSERT INTO clients (name, gstin, contact, phone, email, office, cycle, fee, created_by, created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?)""",
                        (name, gstin, vals[2], vals[3], vals[4], vals[5], cycle, fee, u[0], now_ist().strftime("%Y-%m-%d %H:%M")))
                    existing.add(name.lower())
                    if gstin: existing_gstin.add(gstin)
                    added += 1
                log_action(con, u[0], "Imported clients", f"{added} added, {skipped} skipped (already present)")
                con.commit(); con.close()
                return self.send_html(page("Import clients", u, f"<p><b>{added} clients added, {skipped} skipped</b> (already present). Cycle and fee were left as given, or Monthly / 0 where blank — set them later on Clients &rarr; Edit, or via a first bill.</p><p><a href='/clients'>Back to Clients</a></p>"))
            if path == "/clients":
                con.execute("""INSERT INTO clients (name, gstin, contact, phone, email, office, cycle, fee, created_by, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (f["name"], f.get("gstin", ""), f.get("contact", ""), f.get("phone", ""),
                     f.get("email", ""), f.get("office", ""), f.get("cycle", "Monthly"),
                     float(f.get("fee") or 0), u[0], now_ist().strftime("%Y-%m-%d %H:%M")))
                log_action(con, u[0], "Added client", f["name"])
            elif path == "/bills":
                _dup = con.execute("""SELECT bill_no FROM bills WHERE client_id=? AND period_label=? AND bill_kind=? AND COALESCE(heading,'')=?
                    """, (int(f["client_id"]), f["period_label"], f.get("bill_kind", "Final"), f.get("heading", ""))).fetchone()
                if _dup:
                    con.close()
                    return self.send_html(page("Duplicate bill", u, f"<p>A bill already exists for this client, period, kind and heading: <b>{esc(_dup['bill_no'])}</b>. Change the heading or period, or edit that bill instead.</p><p><a href='/bills'>Back to Bills</a></p>"), 400)
                amt = float(f["amount"]); gst = float(f.get("gst_percent") or 18)
                con.execute("""INSERT INTO bills (bill_no, client_id, period_label, bill_date, due_date,
                    amount, gst_percent, total, status, notes, created_by, issued_by, created_at, bill_kind, heading)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (next_bill_no(con, f.get("bill_kind", "Final"), f.get("issued_by", "")), int(f["client_id"]), f["period_label"], f["bill_date"],
                     f.get("due_date") or None, amt, gst, round(amt * (1 + gst / 100), 2),
                     f.get("status", "Draft"), f.get("notes", ""), u[0], f.get("issued_by", ""),
                     now_ist().strftime("%Y-%m-%d %H:%M"), f.get("bill_kind", "Final"), f.get("heading", "")))
                if f.get("remember_fee"):
                    con.execute("UPDATE clients SET fee=? WHERE id=?", (amt, int(f["client_id"])))
                log_action(con, u[0], "Added bill", f"{f['period_label']} for client id {f['client_id']}")
            elif path == "/bill-status":
                if u[1] != "admin":
                    _own = con.execute("SELECT created_by FROM bills WHERE bill_no=?", (f["bill_no"],)).fetchone()
                    if not _own or _own["created_by"] != u[0]:
                        con.close()
                        return self.send_html(page("Bill status", u, "<p>You can only change bills you put in.</p>"), 403)
                con.execute("UPDATE bills SET status=? WHERE bill_no=?", (f["status"], f["bill_no"]))
                log_action(con, u[0], "Changed bill status", f"{f['bill_no']} -> {f['status']}")
            elif path == "/users" and u[1] == "admin":
                if f.get("password") != f.get("confirm", ""):
                    con.close()
                    return self.send_html(page("Error", u, "<p>Passwords do not match. Go back and type the password again.</p>"), 400)
                salt = secrets.token_hex(16)
                h = hashlib.pbkdf2_hmac("sha256", f["password"].encode(), salt.encode(), 100000).hex()
                con.execute("INSERT INTO users (username, pass_hash, salt, role) VALUES (?,?,?,?)",
                            (f["username"], h, salt, f.get("role", "staff")))
                log_action(con, u[0], "Added user", f["username"] + " (" + f.get("role", "staff") + ")")
            con.commit()
        except INTEGRITY_ERRORS:
            con.close()
            return self.send_html(page("Error", u, "<p>That username or bill already exists. Go back and try again.</p>"), 400)
        con.close()
        self.redirect("/clients" if path == "/clients" else "/users" if path == "/users" else "/bills")


if __name__ == "__main__":
    init_db()
    print(f"Bill Tracker running on http://0.0.0.0:{PORT}  (open http://localhost:{PORT} on this computer)")
    print("First login: admin / admin123  — change it on the Users page.")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
