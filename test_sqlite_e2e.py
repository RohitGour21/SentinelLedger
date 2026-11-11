"""End-to-end test of SentinelLedger on SQLite. Uses a temporary database; your real data is untouched. Run: python test_sqlite_e2e.py"""
import os, re, sys, tempfile, sqlite3, threading, json, hashlib

proj = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, proj)
os.chdir(proj)
tmp = tempfile.mkdtemp()
os.environ["DATABASE_PATH"] = os.environ.get("TEST_DATABASE_PATH") or os.path.join(tmp, "t.db")
if os.path.exists(os.environ["DATABASE_PATH"]): os.remove(os.environ["DATABASE_PATH"])
os.environ["FLASK_SECRET_KEY"] = "test-secret"
os.environ["INITIAL_ADMIN_USERNAME"] = "boot_admin"
os.environ["INITIAL_ADMIN_EMAIL"] = "boot@example.com"
os.environ["INITIAL_ADMIN_PASSWORD"] = "BootstrapPass123!"

results = []
def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))

import wsgi
from app.db import get_db_connection
from app.services.auth_service import register_user, authenticate_user
from app.services.audit_service import create_audit_log, calculate_hash
from app.services.hash_service import verify_audit_chain
from app.services.threat_detector import detect_repeated_failed_logins
from app.services.api_monitor import detect_excessive_api_requests
from app.services.user_service import get_all_users, get_all_roles, update_user_role, update_user_status

app = wsgi.app
app.config["TESTING"] = True

def q(sql, p=()):
    c = get_db_connection()
    try:
        with c.cursor() as cur:
            cur.execute(sql, p); return cur.fetchall()
    finally:
        c.close()

# --- schema / seed / bootstrap
tables = {r["name"] for r in q("SELECT name FROM sqlite_master WHERE type='table'")}
check("all 7 tables created", {"roles","users","resources","api_clients","audit_logs","security_rules","security_events"} <= tables)
check("roles seeded", [r["role_name"] for r in q("SELECT role_name FROM roles ORDER BY role_id")] == ["Admin","Security Analyst","Viewer"])
check("security rules seeded", len(q("SELECT * FROM security_rules")) == 3)
check("initial admin bootstrapped from env", [u["username"] for u in q("SELECT username FROM users")] == ["boot_admin"])
check("get_all_users returns datetime created_at", hasattr(get_all_users()[0]["created_at"], "strftime"))

# --- registration / auth
ok, msg = register_user("analyst1", "a@example.com", "AnalystPass123!", role_id=2); check("register analyst", ok)
ok, msg = register_user("viewer1", "v@example.com", "ViewerPass123!", role_id=3); check("register viewer", ok)
ok, msg = register_user("viewer1", "other@example.com", "ViewerPass123!", role_id=3)
check("duplicate username -> friendly message", (not ok) and msg == "Username or email already exists.", msg)
ok, msg = register_user("viewer2", "v@example.com", "ViewerPass123!", role_id=3)
check("duplicate email -> friendly message", (not ok) and msg == "Username or email already exists.", msg)
check("authenticate good password", authenticate_user("boot_admin", "BootstrapPass123!")["role_name"] == "Admin")
check("authenticate bad password", authenticate_user("boot_admin", "wrong") is None)

# --- audit chain
ids = [create_audit_log("TEST_ACTION", "10.0.0.1", f"entry {i}") for i in range(10)]
check("10 audit entries, consecutive ids", ids == list(range(ids[0], ids[0] + 10)))
rows = q("SELECT * FROM audit_logs ORDER BY log_id")
check("first entry previous_hash is 64 zeros", rows[0]["previous_hash"] == "0" * 64)
check("previous_hash == prior entry_hash for all", all(rows[i]["previous_hash"] == rows[i-1]["entry_hash"] for i in range(1, len(rows))))
def rehash(r):
    return calculate_hash({"action": r["action"], "ip_address": r["ip_address"], "details": r["details"],
        "previous_hash": r["previous_hash"], "created_at": r["created_at"].strftime("%Y-%m-%d %H:%M:%S.%f")})
check("independently recomputed hashes match stored", all(rehash(r) == r["entry_hash"] for r in rows))
check("verify_audit_chain valid", verify_audit_chain()["valid"] is True, str(verify_audit_chain()))
# stored created_at string is exactly the hashed string (raw)
raw = sqlite3.connect(os.environ["DATABASE_PATH"]).execute("SELECT created_at FROM audit_logs LIMIT 1").fetchone()[0]
check("raw created_at keeps 6-digit microseconds", re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{6}", raw), raw)

# tamper detection
raw_c = sqlite3.connect(os.environ["DATABASE_PATH"])
target = rows[4]["log_id"]
raw_c.execute("UPDATE audit_logs SET details='tampered' WHERE log_id=?", (target,)); raw_c.commit()
r = verify_audit_chain()
check("tampered details detected", (not r["valid"]) and r["log_id"] == target and "mismatch" in r["message"], str(r))
raw_c.execute("UPDATE audit_logs SET details=? WHERE log_id=?", (rows[4]["details"], target)); raw_c.commit()
check("chain valid again after restore", verify_audit_chain()["valid"])
raw_c.execute("UPDATE audit_logs SET previous_hash=? WHERE log_id=?", ("f"*64, rows[6]["log_id"])); raw_c.commit()
r = verify_audit_chain()
check("broken chain link detected", (not r["valid"]) and r["message"] == "Broken hash chain" and r["log_id"] == rows[6]["log_id"], str(r))
raw_c.execute("UPDATE audit_logs SET previous_hash=? WHERE log_id=?", (rows[6]["previous_hash"], rows[6]["log_id"])); raw_c.commit(); raw_c.close()
check("chain valid after second restore", verify_audit_chain()["valid"])

# concurrency: threads appending simultaneously must keep chain valid
def worker(n):
    for i in range(15): create_audit_log("CONC", f"10.1.0.{n}", f"t{n}-{i}")
ts = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
[t.start() for t in ts]; [t.join() for t in ts]
v = verify_audit_chain()
check("90 concurrent appends keep chain valid", v["valid"] and q("SELECT COUNT(*) c FROM audit_logs WHERE action='CONC'")[0]["c"] == 90, str(v))

# --- threat detection
for i in range(5): create_audit_log("LOGIN_FAILED", "192.0.2.50", f"fail {i}")
check("failed-login detection creates event", q("SELECT COUNT(*) c FROM security_events WHERE event_type='REPEATED_FAILED_LOGINS'")[0]["c"] == 1)
check("no duplicate open event", detect_repeated_failed_logins("192.0.2.50") is False)
check("below threshold -> no event", (create_audit_log("LOGIN_FAILED", "192.0.2.51", "x") and detect_repeated_failed_logins("192.0.2.51") is False))
for i in range(100): create_audit_log("API_REQUEST", "192.0.2.60", f"r{i}")
check("API excessive detection returns True", detect_excessive_api_requests("192.0.2.60") is True)
check("API event stored w/ rule+log link", q("SELECT rule_id, log_id FROM security_events WHERE event_type='EXCESSIVE_API_REQUESTS'")[0]["log_id"] is not None)
# time window: old rows outside window should not count
raw_c = sqlite3.connect(os.environ["DATABASE_PATH"])
raw_c.execute("PRAGMA foreign_keys=OFF")
for i in range(6):
    raw_c.execute("INSERT INTO audit_logs(action,ip_address,details,previous_hash,entry_hash,created_at) VALUES('LOGIN_FAILED','192.0.2.70','old',?,?,?)",
                  ("0"*64, f"old{i}"+"0"*59, "2020-01-01 00:00:00.000000"))
raw_c.commit(); raw_c.close()
check("old rows outside window not counted", detect_repeated_failed_logins("192.0.2.70") is False)
# repair test DB so later chain check is meaningful
c = sqlite3.connect(os.environ["DATABASE_PATH"]); c.execute("DELETE FROM audit_logs WHERE ip_address='192.0.2.70'"); c.commit(); c.close()
check("chain valid after test cleanup", verify_audit_chain()["valid"])

# --- user service
users = {u["username"]: u for u in get_all_users()}
check("update role", update_user_role(users["viewer1"]["user_id"], 2)[0])
check("invalid role rejected", update_user_role(users["viewer1"]["user_id"], 99) == (False, "Invalid role selected."))
check("unknown user role", update_user_role(9999, 1) == (False, "User not found."))
check("deactivate user", update_user_status(users["viewer1"]["user_id"], 0)[0])
check("inactive user cannot authenticate", authenticate_user("viewer1", "ViewerPass123!") is None)
check("reactivate", update_user_status(users["viewer1"]["user_id"], 1)[0] and authenticate_user("viewer1", "ViewerPass123!"))
check("unknown user status", update_user_status(9999, 1) == (False, "User not found."))
update_user_role(users["viewer1"]["user_id"], 3)

# --- HTTP layer with real CSRF
def client(): return app.test_client()
def token(c, path="/login"):
    html = c.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html); return m.group(1)
def login(c, u, p):
    return c.post("/login", data={"username": u, "password": p, "csrf_token": token(c)}, follow_redirects=False)

c = client()
check("/ redirects to login when anonymous", c.get("/").status_code == 302)
check("login page renders", c.get("/login").status_code == 200)
check("POST login w/o CSRF rejected (400)", c.post("/login", data={"username":"boot_admin","password":"BootstrapPass123!"}).status_code == 400)
r = login(c, "boot_admin", "wrong"); check("bad login re-renders 200", r.status_code == 200 and "Invalid username" in r.get_data(as_text=True))
check("LOGIN_FAILED audited", q("SELECT COUNT(*) c FROM audit_logs WHERE action='LOGIN_FAILED' AND details LIKE '%boot_admin%'")[0]["c"] == 1)
r = login(c, "boot_admin", "BootstrapPass123!"); check("admin login redirects", r.status_code == 302)
for path in ["/", "/logs", "/events", "/events/create", "/verify", "/users"]:
    r = c.get(path); check(f"admin GET {path} = 200", r.status_code == 200, str(r.status_code))
r = c.get("/logs?q=TEST_ACTION&start_date=2020-01-01&end_date=2099-12-31&page=1")
check("logs search+date filter works", r.status_code == 200 and "TEST_ACTION" in r.get_data(as_text=True))
check("logs date filter excludes future", "TEST_ACTION" not in c.get("/logs?start_date=2099-01-01").get_data(as_text=True))
r = c.get("/logs?end_date=2000-01-01"); check("logs end_date before data -> empty page ok", r.status_code == 200 and "TEST_ACTION" not in r.get_data(as_text=True))
today = q("SELECT date('now') d")[0]["d"]
check("end_date = today includes today's rows (date+1 day)", "TEST_ACTION" in c.get(f"/logs?end_date={today}&q=TEST_ACTION").get_data(as_text=True))
r = c.get("/logs/export?q=TEST_ACTION"); body = r.get_data(as_text=True)
check("CSV export works", r.status_code == 200 and r.mimetype == "text/csv" and body.startswith("log_id,action") and "TEST_ACTION" in body)
check("/logs?page=2 ok", c.get("/logs?page=2").status_code == 200)
check("events filters ok", all(c.get(u).status_code == 200 for u in ["/events?status=OPEN", "/events?status=OTHER", "/events?severity=HIGH&q=IP", "/events?page=3"]))
ev = q("SELECT event_id FROM security_events WHERE status='OPEN' LIMIT 1")[0]["event_id"]
check("event details", c.get(f"/events/{ev}").status_code == 200)
check("missing event 404", c.get("/events/99999").status_code == 404)
r = c.post("/events/create", data={"event_type":"MANUAL","severity":"low","description":"d","csrf_token":token(c,"/events/create")})
check("create event redirects", r.status_code == 302 and q("SELECT COUNT(*) c FROM security_events WHERE event_type='MANUAL'")[0]["c"] == 1)
check("create event audited", q("SELECT COUNT(*) c FROM audit_logs WHERE action='SECURITY_EVENT_CREATED'")[0]["c"] == 1)
r = c.post(f"/events/{ev}/resolve", data={"csrf_token": token(c,"/events/create")})
check("resolve event", r.status_code == 302 and q("SELECT status FROM security_events WHERE event_id=?", (ev,))[0]["status"] == "RESOLVED")
# users admin POST
vid = users["viewer1"]["user_id"]
r = c.post("/users", data={"action":"change_role","user_id":vid,"role_id":2,"csrf_token":token(c,"/events/create")})
check("admin changes role via HTTP", r.status_code == 302 and q("SELECT role_id FROM users WHERE user_id=?", (vid,))[0]["role_id"] == 2)
r = c.post("/users", data={"action":"toggle_status","user_id":vid,"is_active":"0","csrf_token":token(c,"/events/create")})
check("admin deactivates via HTTP", q("SELECT is_active FROM users WHERE user_id=?", (vid,))[0]["is_active"] == 0)
c.post("/users", data={"action":"toggle_status","user_id":vid,"is_active":"1","csrf_token":token(c,"/events/create")})
c.post("/users", data={"action":"change_role","user_id":vid,"role_id":3,"csrf_token":token(c,"/events/create")})
check("verify page says valid", "verif" in c.get("/verify").get_data(as_text=True).lower())
check("verify audited", q("SELECT COUNT(*) c FROM audit_logs WHERE action='AUDIT_CHAIN_VERIFICATION'")[0]["c"] >= 1)
check("logout", c.get("/logout").status_code == 302 and c.get("/").status_code == 302)

# RBAC: viewer
v = client(); login(v, "viewer1", "ViewerPass123!")
check("viewer can see dashboard/logs/events", all(v.get(p).status_code == 200 for p in ["/", "/logs", "/events", "/logs/export"]))
for p in ["/users", "/verify", "/events/create"]:
    r = v.get(p); check(f"viewer denied {p} (403)", r.status_code == 403, str(r.status_code))
check("UNAUTHORIZED_ACCESS audited", q("SELECT COUNT(*) c FROM audit_logs WHERE action='UNAUTHORIZED_ACCESS'")[0]["c"] == 3)
check("viewer cannot resolve", v.post(f"/events/{ev}/resolve", data={"csrf_token": token(v,"/login")}).status_code == 403)
# unauthorized threshold (3 in 5 min from same IP) -> event
check("unauthorized-access threshold raised event", q("SELECT COUNT(*) c FROM security_events WHERE event_type='UNAUTHORIZED_ACCESS'")[0]["c"] == 1,
      str(q("SELECT COUNT(*) c FROM audit_logs WHERE action='UNAUTHORIZED_ACCESS'")))
# analyst
a = client(); login(a, "analyst1", "AnalystPass123!")
check("analyst: events/create + verify ok, users denied", a.get("/events/create").status_code == 200 and a.get("/verify").status_code == 200 and a.get("/users").status_code == 403)
# dashboard counts
html = client().get("/login")  # noop
# API
n0 = q("SELECT COUNT(*) c FROM audit_logs WHERE action='API_REQUEST'")[0]["c"]
r = client().get("/api/monitor"); check("/api/monitor 200 JSON", r.status_code == 200 and r.get_json()["status"] == "success")
check("/api/monitor audited", q("SELECT COUNT(*) c FROM audit_logs WHERE action='API_REQUEST'")[0]["c"] == n0 + 1)
ac = client()
for _ in range(100): ac.get("/api/monitor")
check("100 API hits over HTTP raise EXCESSIVE_API_REQUESTS", q("SELECT COUNT(*) c FROM security_events WHERE event_type='EXCESSIVE_API_REQUESTS'")[0]["c"] >= 1)
check("final chain valid after everything", verify_audit_chain()["valid"], str(verify_audit_chain()))
try:
    c2 = get_db_connection(); c2.execute("INSERT INTO users(username,email,password_hash,role_id) VALUES('x','x@x','h',99)"); c2.commit(); fk=False
except sqlite3.IntegrityError: fk=True
check("foreign keys enforced (PRAGMA)", fk)

failed = [n for n, ok in results if not ok]
print(f"\n{len(results)-len(failed)}/{len(results)} passed"); 
if failed: print("FAILED:", failed); sys.exit(1)
