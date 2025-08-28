#!/usr/bin/env python3
# file: list-sessions.py

"""List sessions from FlexBuff hosts over SSH.

Usage examples:
  # default host (10.0.109.33)
  ./list-sessions.py

  # single host
  ./list-sessions.py 10.0.109.34

  # multiple hosts
  ./list-sessions.py 10.0.109.33 10.0.109.34

  # override username/command/timeout
  ./list-sessions.py -u oper -c "vbs_ls -l" -t 5 10.0.109.34

Notes:
- Hosts are positional; providing none falls back to 10.0.109.33.
- Prints stdout from each host; non‑zero RC or SSH errors go to stderr.

List sessions from FlexBuff hosts over SSH.

Usage examples:
# default host (10.0.109.33)
./list-sessions.py

# single host
./list-sessions.py 10.0.109.34

# multiple hosts
./list-sessions.py 10.0.109.33 10.0.109.34

# override username/command/timeout
./list-sessions.py -u oper -c "vbs_ls -l" -t 5 10.0.109.34

Notes:
- Hosts are positional; providing none falls back to 10.0.109.33.
- Prints stdout from each host; non‑zero RC or SSH errors go to stderr.

List sessions from FlexBuff hosts over SSH.

Features:
- Positional hosts with a default of 10.0.109.33 when none are provided.
- Per-host headers for readability (can disable with --no-headers).
- Collects unique session IDs across all hosts using configurable regex(es).

Usage examples:
  # default host (10.0.109.33)
  ./list-sessions.py

  # multiple hosts
  ./list-sessions.py 10.0.109.33 10.0.109.34

  # override username/command/timeout
  ./list-sessions.py -u oper -c "vbs_ls -l" -t 5 10.0.109.34

  # custom ID regex (repeatable)
  ./list-sessions.py --id-regex '(?i)session_id=([A-Za-z0-9_.-]+)'

Notes:
- Unique IDs are printed at the end; disable with --no-unique.
- Add --unique-detail to see the host list per ID.


List sessions from FlexBuff hosts over SSH.

Features:
- Positional hosts with a default of 10.0.109.33 when none are provided.
- Per-host headers for readability (can disable with --no-headers).
- Collects unique session *names* like "m25209_ns" by parsing the filename column.
- Fallback: optional regex extractors if your output format differs.

Usage examples:
  # default host (10.0.109.33)
  ./list-sessions.py

  # multiple hosts, show which host has each unique session
  ./list-sessions.py 10.0.109.33 10.0.109.34 --unique-detail

  # override username/command/timeout
  ./list-sessions.py -u oper -c "vbs_ls -l" -t 5 10.0.109.34

  # custom ID regex (repeatable)
  ./list-sessions.py --id-regex '(?i)session_id=([A-Za-z0-9_.-]+)'

Notes:
- We derive the session name as the last whitespace-delimited field's prefix up to and including the marker (default: "_ns").
- If your tool outputs a different marker, set --session-marker accordingly (e.g. "_session").
"""

from __future__ import annotations

import argparse
import asyncio
import re
import sys
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Set

import asyncssh

DEFAULT_HOSTS: List[str] = ["10.0.109.33"]
DEFAULT_USER = "oper"
DEFAULT_COMMAND = "vbs_ls -l"
DEFAULT_TIMEOUT = 5.0
DEFAULT_SESSION_MARKER = "_ns"  # everything up to and including this is the session name
# Regex extractors are optional fallbacks; filename parsing handles names like m25209_ns_209-0603_0
DEFAULT_ID_REGEXES: List[str] = [r"(?i)session[ _:=-]+([A-Za-z0-9_.-]+)"]


async def run_one(host: str, *, username: str, command: str, timeout: float) -> Dict[str, str]:
    """Run a single SSH command on *host* and return a result dict.

    Why: Centralizes SSH call + error mapping so calling code stays clean.
    """
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


def session_from_filename(name: str, marker: str) -> Optional[str]:
    """Return the session prefix from *name* up to and including *marker*.

    Why: Your listings end with items like m25209_ns_209-0603_0; the session is m25209_ns.
    """
    i = name.lower().find(marker.lower())
    if i == -1:
        return None
    return name[: i + len(marker)]


def extract_ids(text: str, marker: str, patterns: Iterable[str]) -> Set[str]:
    """Extract session IDs from *text* using filename parsing and optional regex *patterns*.

    Why: Filename column is most reliable across varied listing formats.
    """
    ids: Set[str] = set()

    # 1) Filename-based extraction (last column)
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        name = parts[-1]
        base = session_from_filename(name, marker)
        if base:
            ids.add(base)

    # 2) Fallback regex extractors (optional)
    for pat in patterns:
        try:
            regex = re.compile(pat)
        except re.error as e:
            sys.stderr.write(f"[id-regex error] {pat!r}: {e}")
            continue
        for m in regex.finditer(text):
            if m.lastindex:
                ids.add(m.group(1))
            else:
                ids.add(m.group(0))

    return ids


def print_unique_summary(unique_map: Mapping[str, Set[str]], *, detail: bool) -> None:
    ids_sorted = sorted(unique_map.keys())
    print(f"=== Unique session IDs ({len(ids_sorted)}) ===")
    for sid in ids_sorted:
        if detail:
            hosts = ", ".join(sorted(unique_map[sid]))
            print(f"- {sid}  [hosts: {hosts}]")
        else:
            print(f"- {sid}")


async def main_async(
    hosts: List[str], *, username: str, command: str, timeout: float, headers: bool, do_unique: bool, id_patterns: List[str], unique_detail: bool, session_marker: str
) -> int:
    tasks = [
        run_one(h, username=username, command=command, timeout=timeout) for h in hosts
    ]
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
            """ Removed from print """
            #print(r["out"])  # stdout from remote
            if do_unique:
                ids = extract_ids(r["out"], session_marker, id_patterns)
                for sid in ids:
                    unique_map.setdefault(sid, set()).add(host)

        if r["err"] or r["rc"] != "0":
            exit_code = 1
            sys.stderr.write(f"[{host}] rc={r['rc']} err: {r['err']}")

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
    parser.add_argument("--no-unique", action="store_true", help="Do not compute/print unique session IDs")
    parser.add_argument(
        "--id-regex",
        dest="id_regexes",
        action="append",
        default=DEFAULT_ID_REGEXES.copy(),
        help="Regex to extract session IDs (repeat to add more). Use a capturing group for the ID.",
    )
    parser.add_argument("--unique-detail", action="store_true", help="Show host list per unique ID")
    parser.add_argument(
        "--session-marker",
        default=DEFAULT_SESSION_MARKER,
        help="Substring that delimits the session prefix in filenames (default: _ns)",
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
                session_marker=args.session_marker,
            )
        )
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
