"""Local stdio MCP server for the snapshot tests. Stdlib only, harmless.

It speaks just enough of both protocol eras for a tools/list client:
legacy (initialize handshake, up to 2025-11-25) and modern (per-request
_meta, server/discover, 2026-07-28). Each flag switches on one behaviour
the snapshot client has to survive or detect.
"""
import argparse
import json
import os
import random
import subprocess
import sys
import time

MODERN = "2026-07-28"
LEGACY = "2025-11-25"
META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT = "io.modelcontextprotocol/clientInfo"


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--era", choices=["legacy", "modern", "dual"], default="legacy")
    p.add_argument("--tools", required=True, help="JSON file: a list of tool definitions")
    p.add_argument("--instructions", default="Fixture server. Read-only wiki tools.")
    p.add_argument("--server-version", default="1.0.0")
    p.add_argument("--paginate", type=int, default=0, help="page size")
    p.add_argument("--cursor-loop", action="store_true", help="always return the same nextCursor")
    p.add_argument("--dup-tool", action="store_true", help="list the first tool twice")
    p.add_argument("--huge-cursor", action="store_true", help="a nextCursor far longer than any real one")
    p.add_argument("--shuffle", action="store_true", help="random tool order and key order")
    p.add_argument("--random-per-session", action="store_true",
                   help="a different description on every listing (the modern era has no session)")
    p.add_argument("--random-per-process", action="store_true",
                   help="a different description on every launch, stable within one")
    p.add_argument("--sniff-client", action="store_true",
                   help="one extra tool, shown only to a client whose name contains 'claude'")
    p.add_argument("--emit-list-changed", action="store_true")
    p.add_argument("--stdout-noise", action="store_true")
    p.add_argument("--hang", action="store_true", help="read requests, never reply")
    p.add_argument("--ignore-eof", action="store_true", help="start a child and outlive stdin")
    p.add_argument("--pid-file", help="where --ignore-eof writes the child's pid")
    p.add_argument("--huge", action="store_true", help="a tool description over the client's size cap")
    p.add_argument("--sentinel", help="touch this file at launch")
    p.add_argument("--ttl-vary", action="store_true")
    p.add_argument("--legacy-probe", default="-32601",
                   help="legacy answer to a request before initialize: an error code, or 'silent'")
    p.add_argument("--only-version", help="modern: reject every other protocol version with -32022")
    p.add_argument("--slow-discover", type=float, default=0.0, help="seconds before answering server/discover")
    return p.parse_args()


def shuffled(obj):
    if isinstance(obj, dict):
        keys = list(obj)
        random.shuffle(keys)
        return {k: shuffled(obj[k]) for k in keys}
    if isinstance(obj, list):
        return [shuffled(x) for x in obj]
    return obj


class Server(object):
    def __init__(self, a):
        self.a = a
        with open(a.tools, encoding="utf-8") as f:
            self.tools = json.load(f)
        self.initialized = False
        self.client_name = ""
        self.process_nonce = "%016x" % random.getrandbits(64)
        self.out = sys.stdout.buffer

    def write(self, obj):
        self.out.write(json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n")
        self.out.flush()

    def reply(self, rid, result=None, error=None):
        if self.a.stdout_noise:
            self.out.write(b"debug: handling a request\n{\"log\": \"not json-rpc\"}\n")
        if self.a.emit_list_changed:
            self.write({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        msg = {"jsonrpc": "2.0", "id": rid}
        if error is not None:
            msg["error"] = error
        else:
            msg["result"] = result
        self.write(msg)

    def listing(self):
        tools = json.loads(json.dumps(self.tools))
        if self.a.sniff_client and "claude" in self.client_name.lower():
            tools.append({"name": "sync_notes", "description": "Shown to one client only.",
                          "inputSchema": {"type": "object", "properties": {}}})
        if self.a.random_per_session:
            tools[0]["description"] += " [%016x]" % random.getrandbits(64)
        if self.a.random_per_process:
            tools[0]["description"] += " [%s]" % self.process_nonce
        if self.a.huge:
            tools[0]["description"] = "x" * (6 * 1024 * 1024)
        if self.a.dup_tool:
            tools.append(json.loads(json.dumps(tools[0])))
        if self.a.shuffle:
            random.shuffle(tools)
            tools = [shuffled(t) for t in tools]
        return tools

    def tools_list(self, params, modern):
        tools = self.listing()
        result = {}
        size = self.a.paginate
        if size:
            # With --shuffle the order must stay fixed across pages of one listing.
            tools = sorted(tools, key=lambda t: t["name"]) if self.a.shuffle else tools
            start = int(params.get("cursor") or 0)
            result["tools"] = tools[start:start + size]
            if self.a.huge_cursor:
                result["nextCursor"] = "0" * 200000
            elif self.a.cursor_loop:
                result["nextCursor"] = "0"
            elif start + size < len(tools):
                result["nextCursor"] = str(start + size)
        else:
            result["tools"] = tools
        if modern:
            result["resultType"] = "complete"
            result["ttlMs"] = random.randint(1, 10 ** 6) if self.a.ttl_vary else 300000
            result["cacheScope"] = random.choice(["public", "private"]) if self.a.ttl_vary else "public"
        return result

    def handle(self, msg):
        if self.a.hang or "id" not in msg:
            return
        rid, method = msg["id"], msg.get("method")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        is_modern_request = META_VERSION in meta
        era = self.a.era
        info = {"name": "fixture-server", "version": self.a.server_version}

        if is_modern_request and era in ("modern", "dual"):
            self.client_name = str((meta.get(META_CLIENT) or {}).get("name", ""))
            only = self.a.only_version
            if only and meta[META_VERSION] != only:
                return self.reply(rid, error={"code": -32022, "message": "Unsupported protocol version",
                                              "data": {"supported": [only], "requested": meta[META_VERSION]}})
            if method == "server/discover":
                if self.a.slow_discover:
                    time.sleep(self.a.slow_discover)
                return self.reply(rid, {"resultType": "complete", "supportedVersions": [only or MODERN],
                                        "capabilities": {"tools": {}},
                                        "_meta": {"io.modelcontextprotocol/serverInfo": info},
                                        "instructions": self.a.instructions, "ttlMs": 3600000,
                                        "cacheScope": "public"})
            if method == "tools/list":
                return self.reply(rid, self.tools_list(params, True))
            return self.reply(rid, error={"code": -32601, "message": "Method not found"})

        if era == "modern":
            return self.reply(rid, error={"code": -32601, "message": "Supported versions: " + MODERN})

        # Legacy semantics.
        if method == "initialize":
            self.initialized = True
            self.client_name = str((params.get("clientInfo") or {}).get("name", ""))
            return self.reply(rid, {"protocolVersion": LEGACY, "capabilities": {"tools": {"listChanged": True}},
                                    "serverInfo": info, "instructions": self.a.instructions})
        if not self.initialized:
            if self.a.legacy_probe == "silent":
                return
            return self.reply(rid, error={"code": int(self.a.legacy_probe), "message": "Not initialized"})
        if method == "tools/list":
            return self.reply(rid, self.tools_list(params, False))
        if method == "ping":
            return self.reply(rid, {})
        return self.reply(rid, error={"code": -32601, "message": "Method not found"})

    def run(self):
        if self.a.sentinel:
            with open(self.a.sentinel, "w") as f:
                f.write("launched")
        if self.a.stdout_noise:
            self.out.write(b"fixture server starting...\n")
            self.out.flush()
        child = None
        if self.a.ignore_eof:
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            if self.a.pid_file:
                with open(self.a.pid_file, "w") as f:
                    f.write("%d %d" % (os.getpid(), child.pid))
        for raw in sys.stdin.buffer:
            try:
                msg = json.loads(raw.decode("utf-8"))
            except ValueError:
                continue
            if isinstance(msg, dict):
                self.handle(msg)
        if self.a.ignore_eof:
            while True:
                time.sleep(1)


if __name__ == "__main__":
    Server(parse_args()).run()
