"""Small command-line client for debugging the adapter without an MCP client."""

from __future__ import annotations

import argparse
import json
import sys

from . import server


def _print(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(prog="wechat-mcp-cli")
    parser.add_argument("--data-root", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status")
    sub.add_parser("accounts")

    selfcheck = sub.add_parser("selfcheck")
    selfcheck.add_argument("account", nargs="?", default="")
    selfcheck.add_argument("--contact", default="")
    selfcheck.add_argument("--key", default=None)
    selfcheck.add_argument("--refresh", action="store_true")

    contacts = sub.add_parser("contacts")
    contacts.add_argument("account")
    contacts.add_argument("--query", default="")
    contacts.add_argument("--limit", type=int, default=50)
    contacts.add_argument("--key", default=None)

    sessions = sub.add_parser("sessions")
    sessions.add_argument("account")
    sessions.add_argument("--limit", type=int, default=30)
    sessions.add_argument("--key", default=None)

    messages = sub.add_parser("messages")
    messages.add_argument("account")
    messages.add_argument("contact")
    messages.add_argument("--start", default="")
    messages.add_argument("--end", default="")
    messages.add_argument("--limit", type=int, default=20)
    messages.add_argument("--offset", type=int, default=0)
    messages.add_argument("--key", default=None)
    messages.add_argument("--refresh", action="store_true")

    export = sub.add_parser("export")
    export.add_argument("account")
    export.add_argument("contact")
    export.add_argument("output")
    export.add_argument("--start", default="")
    export.add_argument("--end", default="")
    export.add_argument("--key", default=None)
    export.add_argument("--refresh", action="store_true")

    args = parser.parse_args()
    if args.command == "status":
        payload = server.wechat_status(args.data_root)
    elif args.command == "accounts":
        payload = server.wechat_list_accounts(args.data_root)
    elif args.command == "selfcheck":
        payload = server.wechat_selfcheck(
            args.account, args.data_root, args.key, args.contact, args.refresh
        )
    elif args.command == "contacts":
        payload = server.wechat_list_contacts(
            args.account, args.query, args.limit, args.data_root, args.key
        )
    elif args.command == "sessions":
        payload = server.wechat_list_sessions(
            args.account, args.limit, args.data_root, args.key
        )
    elif args.command == "messages":
        payload = server.wechat_get_messages(
            args.account,
            args.contact,
            args.start,
            args.end,
            args.limit,
            args.offset,
            True,
            args.data_root,
            args.key,
            args.refresh,
        )
    else:
        payload = server.wechat_export_chat(
            args.account,
            args.contact,
            args.output,
            args.start,
            args.end,
            args.data_root,
            args.key,
            args.refresh,
        )
    _print(payload)
    if not payload.get("ok"):
        sys.exit(1)


if __name__ == "__main__":
    main()
