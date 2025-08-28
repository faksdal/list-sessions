#!/usr/bin/env python3
# file: list-sessions.py

"""List sessions from FlexBuff hosts over SSH.

Features:
- Positional hosts with a default of 10.0.109.33 when none are provided.
- Per-host headers for readability (can disable with --no-headers).
- Collects unique **session base names** like "m25209" (drops antenna postfix like _ns/_nn) by parsing the filename column.
- Optional fallback regex extractors if your output format differs.

Usage examples:
  # default host (10.0.109.33)
  ./list-sessions.py

  # multiple hosts, show which host has each unique session base
  ./list-sessions.py 10.0.109.33 10.0.109.34 --unique-detail

  # override username/command/timeout
  ./list-sessions.py -u oper -c "vbs_ls -l" -t 5 10.0.109.34

  # custom base-name regex (with a capturing group)
  ./list-sessions.py --base-regex '^(\w+)_\w+(?:_|$)'
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Set

import asyncssh


def errln(*parts: object) -> None:
    """Write a single line to stderr (avoids accidental unterminated f-strings)."""
    sys.stderr.write(" ".join(str(p) for p in parts) + "")


DEFAULT_HOSTS: List[str] = ["10.0.109.33"]
DEFAULT_USER = "oper"
DEFAULT_COMMAND = "vbs_ls -l"
DEFAULT_TIMEOUT = 5.0
# Capture base before antenna code, e.g. m25209_ns_... -> m25209
DEFAULT_BASE_REGEX = r"^([A-Za-z0-9]+)_[A-Za-z]+(?:_|$)"
# Optional fallback extractors if upstream prints explicit session fields
DEFAULT_ID_REGEXES: List[str] = [r"(?i)session[ _:=-]+([A-Za-z0-9_.-]+)"]


async def run_one(host: str, *, username: str, command: str, timeout: float) -> Dict[str, str]:
    """Run a single SSH command on *host* and return a result dict."""
    try:
        async with asyncssh.connect(
            host,
            username=username,
            connect_timeout=timeout,
        ) as conn:
            result = await conn.run(command, check=False)
            return {
                "host": host,
                "rc": str(result.exit_status),
                "err": (result.stderr or "").strip(),
                "out": (result.stdout or "").strip(),
            }
    except (asyncssh.Error, OSError) as exc:
        return {"host": host, "rc": "255", "out": "", "err": str(exc)}


def session_base_from_filename(name: str, base_regex: str) -> Optional[str]:
    """Return session base (e.g. "m25209") from a filename like "m25209_ns_...".

    Why: IP already encodes antenna; we want an antenna-agnostic key.
    """
    m = re.match(base_regex, name)
    if m:
        return m.group(1)
    # Fallback: split at first underscore if regex doesn't match
    if "_" in name:
        return name.split("_", 1)[0]
    return None


def extract_ids(text: str, base_regex: str, patterns: Iterable[str]) -> Set[str]:
    """Extract session base IDs from *text* via filename parsing; fallback to regex *patterns*."""
    ids: Set[str] = set()

    # 1) Filename-based extraction (assume last whitespace-delimited token is the filename)
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        name = parts[-1]
        base = session_base_from_filename(name, base_regex)
        if base:
            ids.add(base)

    # 2) Optional fallback regex extractors
    for pat in patterns:
        try:
            regex = re.compile(pat)
        except re.error as e:
            errln("[id-regex error]", repr(pat) + ":", e)
            continue
        for m in regex.finditer(text):
            if m.lastindex:
                ids.add(m.group(1))
            else:
                ids.add(m.group(0))

    return ids


def print_unique_summary(unique_map: Mapping[str, Set[str]], *, detail: bool) -> None:
    ids_sorted = sorted(unique_map.keys())
    print()
    print(f"=== Unique session bases ({len(ids_sorted)}) ===")
    for sid in ids_sorted:
        if detail:
            hosts = ", ".join(sorted(unique_map[sid]))
            print(f"- {sid}  [hosts: {hosts}]")
        else:
            print(f"- {sid}")


async def main_async(hosts:  List[str],
                     *,
                    username: str,
                    command: str,
                    timeout: float,
                    headers: bool,
                    do_unique: bool,
                    id_patterns: List[str],
                    unique_detail: bool,
                    base_regex: str) -> int:
    tasks = [run_one(h, username=username, command=command, timeout=timeout) for h in hosts]
    results = await asyncio.gather(*tasks)

    exit_code = 0
    unique_map: MutableMapping[str, Set[str]] = {}

    first = True
    for r in results:
        host = r["host"]
        if headers:
            if not first:
                print()  # spacing between hosts
            print(f"=== {host} ===")
        first = False

        if r["out"]:
            #print(r["out"])  # stdout from remote
            if do_unique:
                ids = extract_ids(r["out"], base_regex, id_patterns)
                for sid in ids:
                    unique_map.setdefault(sid, set()).add(host)

        if r["err"] or r["rc"] != "0":
            exit_code = 1
            errln(f"[{host}] rc={r['rc']} err: {r['err']}")

    if do_unique:
        print_unique_summary(unique_map, detail=unique_detail)

    return exit_code


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List sessions from FlexBuff hosts over SSH",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "hosts",
        nargs="*",
        default=DEFAULT_HOSTS,
        help="Host IPs or names (space‑separated)",
    )
    parser.add_argument("-u", "--user", default=DEFAULT_USER, help="SSH username")
    parser.add_argument("-c", "--command", default=DEFAULT_COMMAND, help="Remote command to run")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="SSH connect timeout in seconds")
    parser.add_argument("--no-headers", action="store_true", help="Do not print per-host headers")
    parser.add_argument("--no-unique", action="store_true", help="Do not compute/print unique session bases")
    parser.add_argument(
        "--id-regex",
        dest="id_regexes",
        action="append",
        default=DEFAULT_ID_REGEXES.copy(),
        help="Regex to extract session IDs (repeat to add more). Use a capturing group for the ID.",
    )
    parser.add_argument("--unique-detail", action="store_true", help="Show host list per unique base name")
    parser.add_argument(
        "--base-regex",
        default=DEFAULT_BASE_REGEX,
        help="Regex with a capturing group for the base session name (default: ^([A-Za-z0-9]+)_[A-Za-z]+(?:_|$))",
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    try:
        return asyncio.run(
            main_async(
                args.hosts,
                username=args.user,
                command=args.command,
                timeout=args.timeout,
                headers=not args.no_headers,
                do_unique=not args.no_unique,
                id_patterns=args.id_regexes,
                unique_detail=args.unique_detail,
                base_regex=args.base_regex,
            )
        )
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
