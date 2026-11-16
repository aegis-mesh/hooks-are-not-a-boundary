#!/usr/bin/env python3
"""A remote policy server, for the 'break the hook' scenario (Technique 7).

A hook that asks a central server for its verdict is a common deployment: the
policy lives in one place and every machine's hook calls it. This serves exactly
the shared deny-list (guard_core) over HTTP, so the verdict is identical to the
local hook. Its point in the lab is what happens when it goes away: stop it, and
every hook that depends on it errors -- and by the vendors' documented default,
the agent then fails open and runs the command the healthy hook denied.

    POST /policy   body: a normalised action (same schema guard_core takes)
    200            body: {"decision": "allow"|"deny", "rule": "<id>"|null}

Run: python3 policy_server.py [port]   (default 8098)
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guard_core import _decide_local  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            action = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            action = {}
        body = json.dumps(_decide_local(action)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # keep the lab output clean
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8098
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
