#!/usr/bin/env python3
"""Minimal MCP-ish JSON-RPC stdio server for cassette record e2e tests.

Speaks a tiny subset: initialize, ping, tools/list, tools/call (echo).
One JSON object per line on stdin/stdout.
"""
from __future__ import annotations

import json
import sys


def write(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            write(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "parse error"},
                }
            )
            continue

        mid = msg.get("id")
        method = msg.get("method") or ""
        params = msg.get("params") or {}

        if method.startswith("notifications/"):
            continue

        if method == "initialize":
            write(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "mcp-echo", "version": "0.0.1"},
                    },
                }
            )
        elif method == "ping":
            write({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif method == "tools/list":
            write(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "result": {
                        "tools": [
                            {
                                "name": "echo",
                                "description": "echo text",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {"text": {"type": "string"}},
                                },
                            }
                        ]
                    },
                }
            )
        elif method == "tools/call":
            name = (params or {}).get("name") or ""
            args = (params or {}).get("arguments") or {}
            text = args.get("text", "")
            if name != "echo":
                write(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "error": {"code": -32601, "message": f"unknown tool {name}"},
                    }
                )
            else:
                write(
                    {
                        "jsonrpc": "2.0",
                        "id": mid,
                        "result": {
                            "content": [{"type": "text", "text": str(text)}],
                            "isError": False,
                        },
                    }
                )
        else:
            write(
                {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                }
            )


if __name__ == "__main__":
    main()
