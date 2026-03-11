#!/usr/bin/env python3

import argparse
import json
import re
from pathlib import PureWindowsPath, Path
from urllib.parse import urlsplit


def iter_docs(path: Path):
    decoder = json.JSONDecoder()
    text = path.read_text(errors="ignore")
    pos = 0
    length = len(text)
    while pos < length:
        while pos < length and text[pos].isspace():
            pos += 1
        if pos >= length:
            break
        doc, pos = decoder.raw_decode(text, pos)
        yield doc


def normalize_ws(value: str) -> str:
    return " ".join(value.split())


def normalize_hku_to_hkcu(path: str) -> str:
    return re.sub(r"^HKU\\S-[0-9-]+\\", r"HKCU\\", path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract the control challenge answers from index_new.json")
    parser.add_argument("json_path", nargs="?", default="index_new.json")
    args = parser.parse_args()

    docs = list(iter_docs(Path(args.json_path)))

    answer1 = answer2 = answer3 = answer4 = answer5 = None
    answer6 = answer7 = answer8 = answer9 = answer10 = None

    control_evt = None
    rundll_evt = None

    for doc in docs:
        src = doc.get("_source", {})
        wl = src.get("winlog", {})
        ed = wl.get("event_data", {})
        proc = src.get("process", {})
        registry = src.get("registry", {})
        event_id = str(wl.get("event_id", ""))

        if answer1 is None and event_id == "15":
            contents = ed.get("Contents", "")
            if "HostUrl=" in contents and ".cpl" in contents:
                host_url = contents.split("HostUrl=", 1)[1].split()[0]
                parsed = urlsplit(host_url)
                answer1 = PureWindowsPath(parsed.path).name
                answer2 = f"{parsed.hostname}:{parsed.port}"

        if event_id == "1" and proc.get("name") == "control.exe":
            cmd = proc.get("command_line", "")
            if "MicrosoftUpdate.cpl" in cmd and proc.get("parent", {}).get("name") == "explorer.exe":
                control_evt = proc

        if event_id == "1" and proc.get("name") == "rundll32.exe":
            cmd = proc.get("command_line", "")
            if "MicrosoftUpdate.cpl" in cmd and proc.get("parent", {}).get("name") == "control.exe":
                rundll_evt = proc

        if answer4 is None and event_id == "10":
            target = ed.get("TargetImage", "")
            if proc.get("executable") == r"C:\Users\Public\explorer.exe" and target.lower().endswith(r"\msedge.exe"):
                answer4 = PureWindowsPath(target).name

        if answer5 is None and event_id == "13":
            target = registry.get("path", "")
            if target.endswith(r"\Run\MicrosoftUpdate"):
                answer5 = normalize_hku_to_hkcu(target)

        if answer6 is None and event_id == "1" and proc.get("name") == "powershell.exe":
            cmd = normalize_ws(proc.get("command_line", ""))
            if "Get-LocalUser" in cmd:
                answer6 = cmd

        if answer7 is None and event_id == "1" and proc.get("name") == "RunasCs.exe":
            answer7 = normalize_ws(proc.get("command_line", ""))

        if answer8 is None and event_id == "1" and proc.get("name") == "GodPotato-NET4.exe":
            answer8 = normalize_ws(proc.get("command_line", ""))

        if answer9 is None and event_id == "4672":
            privs = ed.get("PrivilegeList", [])
            if isinstance(privs, list) and "SeImpersonatePrivilege" in privs:
                answer9 = "SeImpersonatePrivilege"

        if answer10 is None and event_id == "10":
            target = ed.get("TargetImage", "")
            if proc.get("executable") == r"C:\Users\Public\explorer.exe" and target.lower().endswith(r"\lsass.exe"):
                answer10 = proc.get("executable")

    if control_evt and rundll_evt:
        answer3 = f"{control_evt.get('parent', {}).get('name')}-{control_evt.get('name')}-{rundll_evt.get('name')}"

    answers = {
        "Q1": answer1,
        "Q2": answer2,
        "Q3": answer3,
        "Q4": answer4,
        "Q5": answer5,
        "Q6": answer6,
        "Q7": answer7,
        "Q8": answer8,
        "Q9": answer9,
        "Q10": answer10,
    }

    missing = [key for key, value in answers.items() if not value]
    if missing:
        raise SystemExit(f"missing answers: {', '.join(missing)}")

    for key, value in answers.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
