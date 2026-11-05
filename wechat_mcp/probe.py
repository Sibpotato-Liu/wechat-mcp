"""Read-only compatibility probe for local or remote Windows machines.

Run this on a test machine and share the JSON output.  The report contains
account paths, table/column names, key-source labels and row counts, but no
chat content and no key material.
"""

from __future__ import annotations

import argparse
import json
import sys

from .diagnostics import collect_selfcheck


def main() -> None:
    parser = argparse.ArgumentParser(prog="wechat-mcp-probe")
    parser.add_argument("--data-root", action="append", default=None)
    parser.add_argument("--account", default="")
    parser.add_argument("--key", default=None, help="不建议在命令行使用，优先设置 WECHAT_MCP_KEY")
    parser.add_argument("--contact", default="", help="可选：只验证能否读取该联系人，不输出内容")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--no-processes", action="store_true")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()

    try:
        report = collect_selfcheck(
            account_selector=args.account,
            data_root=args.data_root,
            key=args.key,
            contact=args.contact,
            refresh=args.refresh,
            include_processes=not args.no_processes,
        )
    except Exception as exc:
        report = {"ok": False, "error": str(exc) or exc.__class__.__name__}
    print(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=None if args.compact else 2,
        )
    )
    if not report.get("ok", True):
        sys.exit(1)
    status = report.get("compatibility", {}).get("status")
    if report.get("readable") and status != "unsupported":
        return
    sys.exit(1)


if __name__ == "__main__":
    main()
