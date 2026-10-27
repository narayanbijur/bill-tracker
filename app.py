#!/usr/bin/env python3
"""Simple bill tracker for a CA firm with two offices.

Runs on the firm's own server computer with Python 3 only (no extra
packages, no internet needed at run time). Data lives in a local
SQLite file (bill_tracker.db) next to this file, so backing up is
just copying that one file.

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


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def init_db():
    con = db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            pass_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, gstin TEXT,
            contact TEXT, phone TEXT, email TEXT, office TEXT,
            cycle TEXT NOT NULL DEFAULT 'Monthly', fee REAL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS bills (
            id INTEGER PRIMARY KEY, bill_no TEXT UNIQUE NOT NULL,
            client_id INTEGER NOT NULL REFERENCES clients(id),
            period_label TEXT NOT NULL, bill_date TEXT NOT NULL,
            due_date TEXT, amount REAL NOT NULL, gst_percent REAL DEFAULT 18,
            total REAL NOT NULL, status TEXT NOT NULL DEFAULT 'Draft',
            notes TEXT, created_by TEXT);
    """)
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


def page(title, user, body):
    nav = ""
    if user:
        nav = (f'<nav><a href="/dashboard">Dashboard</a> <a href="/clients">Clients</a> '
               f'<a href="/bills">Bills</a> <a href="/not-billed">Not billed yet</a> '
               f'<a href="/export.csv">Export CSV</a> '
               f'<a href="/users">Users</a> <a href="/logout">Logout ({esc(user[0])})</a></nav>')
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title><style>
body{{font-family:system-ui,Arial,sans-serif;max-width:980px;margin:20px auto;padding:0 16px;color:#222}}
nav a{{margin-right:14px}} table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #ccc;padding:6px 8px;text-align:left}}
th{{background:#eef2f7}} .card{{border:1px solid #ccc;border-radius:8px;padding:12px;margin:10px 0}}
.warn{{background:#fff3cd;padding:10px;border-radius:6px}} input,select{{padding:6px;margin:2px}}
button{{padding:7px 14px;cursor:pointer}} .red{{color:#b00020;font-weight:bold}}
</style></head><body><h1>Bill Tracker</h1>{nav}<h2>{esc(title)}</h2>{body}</body></html>"""


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
Password <input type="password" name="password" required>
<button>Login</button></p></form>
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
        con.close()
        billed = sum(b["total"] for b in bills)
        paid = sum(b["total"] for b in bills if b["status"] == "Paid")
        overdue = [b for b in bills if b["status"] == "Overdue"]
        body = f"""<div class="card">Active clients: <b>{clients}</b> &nbsp;|&nbsp;
Total billed: <b>&#8377;{billed:,.2f}</b> &nbsp;|&nbsp; Paid: <b>&#8377;{paid:,.2f}</b>
&nbsp;|&nbsp; Outstanding: <b>&#8377;{billed - paid:,.2f}</b> &nbsp;|&nbsp;
Overdue bills: <b class="red">{len(overdue)}</b></div>
<div class="card"><b>Start here:</b> add clients on the Clients page, then add a bill
for each client. The <a href="/not-billed">Not billed yet</a> page lists every active
client who has no bill for the current period — check it before month-end so no
company is missed.</div>"""
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
                     f"<td>&#8377;{r['total']:,.2f}</td><td>{esc(r['status'])}</td></tr>" for r in rows)
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
<form method="get"><select name="status" onchange="this.form.submit()">{filt}</select></form>
<table><tr><th>Bill no.</th><th>Client</th><th>Period</th><th>Date</th><th>Total</th><th>Status</th></tr>{tr}</table>
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
<p>Give each staff member their own username. The first admin login is
<b>admin / admin123</b> — add a new admin, then delete or change the default if you can.</p>"""
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
        w.writerows([tuple(r) for r in rows])
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
        except sqlite3.IntegrityError:
            con.close()
            return self.send_html(page("Error", u, "<p>That username or bill already exists. Go back and try again.</p>"), 400)
        con.close()
        self.redirect("/clients" if path == "/clients" else "/users" if path == "/users" else "/bills")


if __name__ == "__main__":
    init_db()
    print(f"Bill Tracker running on http://0.0.0.0:{PORT}  (open http://localhost:{PORT} on this computer)")
    print("First login: admin / admin123  — change it on the Users page.")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
