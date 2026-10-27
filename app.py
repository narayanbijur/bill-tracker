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
import urllib.parse
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "bill_tracker.db")
PORT = int(os.environ.get("BILL_TRACKER_PORT", "8000"))
SESSIONS = {}  # token -> (username, role)
STATUSES = ["Draft", "Sent", "Paid", "Part-paid", "Overdue"]
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
            active INTEGER NOT NULL DEFAULT 1)""",
        f"""CREATE TABLE IF NOT EXISTS bills (
            id {id_type}, bill_no TEXT UNIQUE NOT NULL,
            client_id INTEGER NOT NULL REFERENCES clients(id),
            period_label TEXT NOT NULL, bill_date TEXT NOT NULL,
            due_date TEXT, amount REAL NOT NULL, gst_percent REAL DEFAULT 18,
            total REAL NOT NULL, status TEXT NOT NULL DEFAULT 'Draft',
            notes TEXT, created_by TEXT)""",
    ]:
        con.execute(stmt)
    if not con.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        salt = secrets.token_hex(16)
        h = hashlib.pbkdf2_hmac("sha256", b"admin123", salt.encode(), 100000).hex()
        con.execute("INSERT INTO users (username, pass_hash, salt, role) VALUES (?,?,?,?)",
                    ("admin", h, salt, "admin"))
    con.commit()
    con.close()


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


def next_bill_no(con):
    year = date.today().year
    row = con.execute("SELECT bill_no FROM bills WHERE bill_no LIKE ? ORDER BY id DESC LIMIT 1",
                      (f"BILL-{year}-%",)).fetchone()
    n = int(row["bill_no"].rsplit("-", 1)[1]) + 1 if row else 1
    return f"BILL-{year}-{n:04d}"


def esc(x):
    return html.escape("" if x is None else str(x))


def badge(status):
    cls = {"Draft": "b-draft", "Sent": "b-sent", "Paid": "b-paid",
           "Part-paid": "b-part", "Overdue": "b-over"}.get(status, "b-draft")
    return f'<span class="badge {cls}">{esc(status)}</span>'


def page(title, user, body):
    if not user:
        return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} - Bill Tracker</title><style>
body{{font-family:Inter,system-ui,-apple-system,Segoe UI,Arial,sans-serif;background:#f1f4f9;color:#1f2937;margin:0}}
.wrap{{max-width:460px;margin:80px auto;padding:0 16px}}
.card{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:28px;box-shadow:0 4px 18px rgba(15,40,80,.08)}}
h1{{color:#0f4c9c;font-size:26px;margin:0 0 4px}} h2{{font-size:18px;margin:0 0 16px;color:#334155}}
input{{width:100%;padding:10px;margin:6px 0;border:1px solid #cbd5e1;border-radius:8px;box-sizing:border-box}}
button{{background:#1a7ae6;color:#fff;border:0;padding:11px 18px;border-radius:8px;cursor:pointer;font-weight:600;width:100%}}
button:hover{{background:#0f63c7}} .red{{color:#b00020}} .muted{{color:#64748b;font-size:14px}}
</style></head><body><div class="wrap"><div class="card"><h1>Bill Tracker</h1>
<p class="muted">Bills, clients and outstanding amounts — in one place.</p><h2>{esc(title)}</h2>{body}</div></div></body></html>"""
    nav = f"""<aside>
<div class="brand">Bill Tracker</div>
<a href="/dashboard">Dashboard</a><a href="/clients">Clients</a><a href="/bills">Bills</a>
<a href="/not-billed">Not billed yet</a><a href="/export.csv">Export CSV</a>
<a href="/users">Users</a><a href="/change-password">Change password</a>
<a href="/logout">Logout ({esc(user[0])})</a></aside>"""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} - Bill Tracker</title><style>
*{{box-sizing:border-box}} body{{font-family:Inter,system-ui,-apple-system,Segoe UI,Arial,sans-serif;background:#f1f4f9;color:#1f2937;margin:0}}
.layout{{display:flex;min-height:100vh}} aside{{width:210px;background:#0f2a4d;color:#fff;padding:20px 14px;flex-shrink:0}}
.brand{{font-size:20px;font-weight:700;margin:0 0 22px 8px}} aside a{{display:block;color:#cbd5e1;text-decoration:none;padding:10px 12px;border-radius:8px;margin:2px 0}}
aside a:hover{{background:#1e3f66;color:#fff}} main{{flex:1;padding:24px;max-width:1100px}}
h1{{font-size:22px;margin:0 0 18px}} .kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}}
.kpi{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:16px}} .kpi b{{font-size:22px;display:block;margin-top:4px}}
.kpi span{{color:#64748b;font-size:13px}} .card{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:18px;margin-bottom:16px;box-shadow:0 1px 4px rgba(15,40,80,.05)}}
table{{border-collapse:collapse;width:100%;font-size:14px}} th{{text-align:left;color:#64748b;font-size:12px;text-transform:uppercase;padding:10px 8px;border-bottom:1px solid #e2e8f0}}
td{{padding:11px 8px;border-bottom:1px solid #f1f5f9}} tr:hover td{{background:#f8fafc}} .amt{{text-align:right;font-variant-numeric:tabular-nums}}
input,select{{padding:9px 11px;margin:3px;border:1px solid #cbd5e1;border-radius:8px;font-size:14px}}
button,.btn{{background:#1a7ae6;color:#fff;border:0;padding:10px 16px;border-radius:8px;cursor:pointer;font-weight:600;text-decoration:none;display:inline-block}}
button:hover{{background:#0f63c7}} .badge{{padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600}}
.b-draft{{background:#e2e8f0;color:#475569}} .b-sent{{background:#dbeafe;color:#1d4ed8}} .b-paid{{background:#dcfce7;color:#15803d}}
.b-part{{background:#fef3c7;color:#b45309}} .b-over{{background:#fee2e2;color:#b91c1c}}
.warn{{background:#fffbeb;border:1px solid #fde68a;padding:12px;border-radius:10px}} .red{{color:#b91c1c}} .muted{{color:#64748b}}
@media(max-width:760px){{.layout{{flex-direction:column}} aside{{width:100%}} .kpis{{grid-template-columns:1fr 1fr}}}}
</style></head><body><div class="layout">{nav}<main><h1>{esc(title)}</h1>{body}</main></div></body></html>"""


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
        if path == "/bills":
            return self.bills_page(u, qs)
        if path == "/not-billed":
            return self.not_billed_page(u)
        if path == "/users":
            return self.users_page(u)
        if path == "/change-password":
            return self.send_html(page("Change password", u, """
<form method="post" action="/change-password">
<p>Current password <input type="password" name="current" required></p>
<p>New password <input type="password" name="new" required></p>
<p>Confirm new password <input type="password" name="confirm" required></p>
<button>Change password</button></form>
<p class="muted">Use this on your first login too: log in with the temporary
password your admin gave you, then set your own here.</p>"""))
        if path == "/logout":
            SESSIONS.pop(self.headers.get("Cookie", "").split("session=")[-1].split(";")[0], None)
            return self.redirect("/login")
        if path == "/export.csv":
            return self.export_csv()
        return self.send_html(page("Not found", u, "<p>Page not found.</p>"), 404)

    def dashboard(self, u):
        con = db()
        bills = con.execute("SELECT * FROM bills").fetchall()
        clients = con.execute("SELECT COUNT(*) c FROM clients WHERE active=1").fetchone()["c"]
        recent = con.execute("""SELECT b.*, c.name AS cname FROM bills b
            JOIN clients c ON c.id=b.client_id ORDER BY b.id DESC LIMIT 5""").fetchall()
        con.close()
        billed = sum(b["total"] for b in bills)
        paid = sum(b["total"] for b in bills if b["status"] == "Paid")
        overdue = [b for b in bills if b["status"] == "Overdue"]
        tr = "".join(f"<tr><td>{esc(r['bill_no'])}</td><td>{esc(r['cname'])}</td>"
                     f"<td>{esc(r['period_label'])}</td><td class='amt'>&#8377;{r['total']:,.2f}</td>"
                     f"<td>{badge(r['status'])}</td></tr>" for r in recent)
        body = f"""<div class="kpis">
<div class="kpi"><span>Active clients</span><b>{clients}</b></div>
<div class="kpi"><span>Total billed</span><b>&#8377;{billed:,.2f}</b></div>
<div class="kpi"><span>Paid</span><b>&#8377;{paid:,.2f}</b></div>
<div class="kpi"><span>Outstanding</span><b class="red">&#8377;{billed - paid:,.2f}</b></div></div>
<div class="card"><b>Overdue bills: <span class="red">{len(overdue)}</span></b> &nbsp;|&nbsp;
Check <a href="/not-billed">Not billed yet</a> before month-end so no company is missed.</div>
<div class="card"><b>Recent bills</b>
<table><tr><th>Bill</th><th>Client</th><th>Period</th><th style="text-align:right">Total</th><th>Status</th></tr>{tr}</table></div>"""
        self.send_html(page("Dashboard", u, body))

    def clients_page(self, u):
        con = db()
        rows = con.execute("SELECT * FROM clients ORDER BY name").fetchall()
        con.close()
        tr = "".join(f"<tr><td>{esc(r['name'])}</td><td>{esc(r['gstin'])}</td>"
                     f"<td>{esc(r['office'])}</td><td>{esc(r['cycle'])}</td>"
                     f"<td>&#8377;{r['fee']:,.2f}</td><td>{'Yes' if r['active'] else 'No'}</td></tr>"
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
<table><tr><th>Client</th><th>GSTIN</th><th>Office</th><th>Cycle</th><th>Fee</th><th>Active</th></tr>{tr}</table>"""
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
        con.close()
        opts = "".join(f"<option value='{r['id']}'>{esc(r['name'])}</option>" for r in clients)
        tr = "".join(f"<tr><td>{esc(r['bill_no'])}</td><td>{esc(r['cname'])}</td>"
                     f"<td>{esc(r['period_label'])}</td><td>{esc(r['bill_date'])}</td>"
                     f"<td class='amt'>&#8377;{r['total']:,.2f}</td><td>{badge(r['status'])}</td></tr>" for r in rows)
        search = qs.get("search", [""])[0].lower()
        if search:
            rows = [r for r in rows if search in r["bill_no"].lower() or search in r["cname"].lower()]
        filt = "".join(f"<option {'selected' if s == status else ''}>{s}</option>" for s in [""] + STATUSES)
        body = f"""<form method="post" action="/bills"><p>
<select name="client_id" required>{opts}</select>
<input name="period_label" placeholder="Period e.g. 2026-10" required>
<input name="bill_date" type="date" required>
<input name="due_date" type="date">
<input name="amount" type="number" step="0.01" placeholder="Amount (ex-GST)" required>
<input name="gst_percent" type="number" step="0.01" value="18" placeholder="GST %">
<select name="status">{''.join(f'<option>{s}</option>' for s in STATUSES)}</select>
<input name="notes" placeholder="Notes (service, etc.)">
<button>Add bill</button></p></form>
<form method="get"><input name="search" placeholder="Search bill no. or client" value="{esc(qs.get("search", [""])[0])}">
<select name="status" onchange="this.form.submit()">{filt}</select> <button>Search</button></form>
<table><tr><th>Bill no.</th><th>Client</th><th>Period</th><th>Date</th><th style="text-align:right">Total</th><th>Status</th></tr>{tr}</table>
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

    def users_page(self, u):
        if u[1] != "admin":
            return self.send_html(page("Users", u, "<p>Only an admin can manage users.</p>"), 403)
        con = db()
        rows = con.execute("SELECT username, role FROM users ORDER BY username").fetchall()
        con.close()
        tr = "".join(f"<tr><td>{esc(r['username'])}</td><td>{esc(r['role'])}</td></tr>" for r in rows)
        body = f"""<form method="post" action="/users"><p>
<input name="username" placeholder="New staff username" required>
<input name="password" type="password" placeholder="Password" required>
<select name="role"><option>staff</option><option>admin</option></select>
<button>Add user</button></p></form>
<table><tr><th>Username</th><th>Role</th></tr>{tr}</table>
<p>Give each staff member their own username with a temporary password.
On first login they open <b>Change password</b> (left menu) and set their
own password. The first admin login is <b>admin / admin123</b> — change
it on the Change password page straight away.</p>"""
        self.send_html(page("Users", u, body))

    def export_csv(self):
        import csv, io
        con = db()
        rows = con.execute("""SELECT b.bill_no, c.name, b.period_label, b.bill_date,
            b.due_date, b.amount, b.gst_percent, b.total, b.status, b.notes
            FROM bills b JOIN clients c ON c.id=b.client_id ORDER BY b.id""").fetchall()
        con.close()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Bill no", "Client", "Period", "Date", "Due", "Amount", "GST %", "Total", "Status", "Notes"])
        cols = ["bill_no", "name", "period_label", "bill_date", "due_date",
                "amount", "gst_percent", "total", "status", "notes"]
        w.writerows([[r[c] for c in cols] for r in rows])
        data = buf.getvalue().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Disposition", "attachment; filename=bills.csv")
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
        if path == "/change-password":
            if check_pw(u[0], f.get("current", "")) is None:
                return self.send_html(page("Change password", u, "<p class='red'>Current password is wrong.</p>"), 401)
            if f.get("new", "") != f.get("confirm", "") or len(f.get("new", "")) < 8:
                return self.send_html(page("Change password", u, "<p class='red'>New passwords do not match, or are shorter than 8 characters.</p>"), 400)
            con = db()
            salt = secrets.token_hex(16)
            h = hashlib.pbkdf2_hmac("sha256", f["new"].encode(), salt.encode(), 100000).hex()
            con.execute("UPDATE users SET pass_hash=?, salt=? WHERE username=?", (h, salt, u[0]))
            con.commit(); con.close()
            return self.send_html(page("Password changed", u, "<p><b>Password changed.</b> Use your new password next time you log in. <a href='/dashboard'>Back to Dashboard</a></p>"))
        con = db()
        try:
            if path == "/clients":
                con.execute("""INSERT INTO clients (name, gstin, contact, phone, email, office, cycle, fee)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (f["name"], f.get("gstin", ""), f.get("contact", ""), f.get("phone", ""),
                     f.get("email", ""), f.get("office", ""), f.get("cycle", "Monthly"),
                     float(f.get("fee") or 0)))
            elif path == "/bills":
                amt = float(f["amount"]); gst = float(f.get("gst_percent") or 18)
                con.execute("""INSERT INTO bills (bill_no, client_id, period_label, bill_date, due_date,
                    amount, gst_percent, total, status, notes, created_by)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (next_bill_no(con), int(f["client_id"]), f["period_label"], f["bill_date"],
                     f.get("due_date") or None, amt, gst, round(amt * (1 + gst / 100), 2),
                     f.get("status", "Draft"), f.get("notes", ""), u[0]))
            elif path == "/bill-status":
                con.execute("UPDATE bills SET status=? WHERE bill_no=?", (f["status"], f["bill_no"]))
            elif path == "/users" and u[1] == "admin":
                salt = secrets.token_hex(16)
                h = hashlib.pbkdf2_hmac("sha256", f["password"].encode(), salt.encode(), 100000).hex()
                con.execute("INSERT INTO users (username, pass_hash, salt, role) VALUES (?,?,?,?)",
                            (f["username"], h, salt, f.get("role", "staff")))
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
