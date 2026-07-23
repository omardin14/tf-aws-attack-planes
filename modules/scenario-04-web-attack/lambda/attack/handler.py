"""Simulated web-plane attacker.

The web plane is the odd one out: the attacker has no credentials and no
foothold, just the public URL. So this Lambda doesn't drive a box or call an AWS
API - it makes plain outbound HTTP requests to the ALB, in three waves, each a
signature from the theory:

  1. SQLi - classic injection payloads on the query string. The AWS-managed SQLi
     rule group inspects the query string and BLOCKs these (403).
  2. Burst - a rapid run of GETs to "/". Past the rate-based rule's per-IP
     threshold WAF starts blocking (some 200, then 403).
  3. Scan - a spray of requests to sensitive-looking paths. These aren't "/", so
     the ALB's default action returns 404 (unless a managed rule blocks first).

Nothing here needs to succeed; the requests ARE the signal. Per-request errors
(403/404 come back as HTTPError) are swallowed and tallied so one blocked
request never aborts the run.
"""

import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

# Query-string payloads the SQLi managed rule group should catch.
SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1'; DROP TABLE users; --",
    "1' UNION SELECT username, password FROM users --",
    "admin'--",
    "1 OR 1=1",
    "' OR 1=1 UNION SELECT NULL, version() --",
    "1'; EXEC xp_cmdshell('whoami'); --",
]


def _get(url, timeout=5):
    """GET a URL, returning the HTTP status code. 403/404/5xx come back as an
    HTTPError whose .code we want; connection errors return None."""
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "atkplane-s4/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"[.] request to {url} failed to connect: {exc}")
        return None


def _wait_for_alb(base_url, attempts=20, delay=15):
    """The ALB's DNS name can take a couple of minutes to resolve/serve after
    create. Poll "/" until we get any HTTP status back before firing the waves."""
    for i in range(attempts):
        code = _get(base_url + "/")
        if code is not None:
            print(f"[+] ALB reachable (GET / -> {code})")
            return True
        print(f"[.] attempt {i + 1}: ALB not reachable yet; sleeping {delay}s")
        time.sleep(delay)
    raise RuntimeError(f"ALB at {base_url} never became reachable")


def handler(event, context):
    base_url = os.environ["ALB_URL"].rstrip("/")
    sqli_count = int(os.environ.get("SQLI_COUNT", "30"))
    scan_count = int(os.environ.get("SCAN_COUNT", "25"))
    burst_count = int(os.environ.get("BURST_COUNT", "150"))
    scan_paths = [p.strip() for p in os.environ.get("SCAN_PATHS", "").split(",") if p.strip()]

    _wait_for_alb(base_url)

    tally = Counter()

    # --- Wave 1: SQL injection on the query string (-> SQLi rule -> 403) -------
    print(f"[+] wave 1: {sqli_count} SQLi-shaped requests")
    for i in range(sqli_count):
        payload = urllib.parse.quote(SQLI_PAYLOADS[i % len(SQLI_PAYLOADS)])
        code = _get(f"{base_url}/?id={payload}")
        tally[f"sqli:{code}"] += 1

    # --- Wave 2: request burst to "/" (-> rate rule -> some 200, then 403) -----
    print(f"[+] wave 2: {burst_count} rapid requests to /")
    for _ in range(burst_count):
        code = _get(f"{base_url}/")
        tally[f"burst:{code}"] += 1

    # --- Wave 3: path scanning (-> default action -> 404) ---------------------
    print(f"[+] wave 3: scanning {len(scan_paths)} paths x {scan_count} rounds")
    for _ in range(scan_count):
        for path in scan_paths:
            code = _get(f"{base_url}{path}")
            tally[f"scan:{code}"] += 1

    summary = dict(sorted(tally.items()))
    print(f"[i] status tally: {summary}")
    blocked = sum(v for k, v in tally.items() if k.endswith(":403"))
    print(f"[+] {blocked} requests blocked by WAF (403)")

    return {
        "status": "attack dispatched",
        "alb_url": base_url,
        "blocked_403": blocked,
        "tally": summary,
    }
