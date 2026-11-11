"""Local Streamable HTTP MCP endpoint for the snapshot tests. Stdlib only.

start(tools, mode=...) serves on 127.0.0.1 with a port the OS picks and
returns the running server; server.url is the endpoint, server.seen the
requests received (method, headers, body) for assertions.

Modes:
  modern        2026-07-28, application/json responses
  modern-sse    2026-07-28, text/event-stream responses
  legacy        initialize handshake with a session id; a modern request
                gets 400 with a body that is not a modern JSON-RPC error
  require-auth  401 with a WWW-Authenticate header pointing at OAuth metadata
  only-version  modern, but rejects every protocol version except
                ONLY_VERSION with 400 and an UnsupportedProtocolVersionError
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

MODERN = "2026-07-28"
LEGACY = "2025-11-25"
ONLY_VERSION = "2027-01-15"
META_VERSION = "io.modelcontextprotocol/protocolVersion"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"   # one request per connection keeps the client simple

    def log_message(self, *args):
        pass

    def _send(self, status, obj=None, sse=False, headers=None):
        body = b""
        ctype = "application/json"
        if obj is not None:
            text = json.dumps(obj, ensure_ascii=False)
            if sse:
                ctype = "text/event-stream"
                # A notification first, then the response, as a real stream may do.
                note = json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}})
                text = ": keep-alive\n\nevent: message\ndata: %s\n\nevent: message\ndata: %s\n\n" % (note, text)
            body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        srv = self.server
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            msg = json.loads(raw.decode("utf-8"))
        except ValueError:
            return self._send(400)
        hdrs = {k.lower(): v for k, v in self.headers.items()}
        srv.seen.append({"method": msg.get("method"), "headers": hdrs, "body": msg})
        rid, method = msg.get("id"), msg.get("method")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        mode = srv.mode

        if mode == "require-auth":
            return self._send(401, headers={
                "WWW-Authenticate": 'Bearer resource_metadata="http://127.0.0.1/.well-known/oauth-protected-resource"'})
        if srv.required_header:
            name, value = srv.required_header
            if hdrs.get(name.lower()) != value:
                return self._send(403)

        def ok(result, **kw):
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": result}, sse=(mode == "modern-sse"), **kw)

        def err(status, code, message, data=None):
            e = {"code": code, "message": message}
            if data is not None:
                e["data"] = data
            return self._send(status, {"jsonrpc": "2.0", "id": rid, "error": e})

        info = {"name": "fixture-http", "version": "2.0.0"}
        if mode in ("modern", "modern-sse", "only-version"):
            want = ONLY_VERSION if mode == "only-version" else MODERN
            version = meta.get(META_VERSION)
            if version is None or hdrs.get("mcp-protocol-version") != version or hdrs.get("mcp-method") != method:
                return err(400, -32020, "Header mismatch")
            if version != want:
                return err(400, -32022, "Unsupported protocol version", {"supported": [want], "requested": version})
            if method == "server/discover":
                return ok({"resultType": "complete", "supportedVersions": [want], "capabilities": {"tools": {}},
                           "_meta": {"io.modelcontextprotocol/serverInfo": info},
                           "instructions": srv.instructions, "ttlMs": 1000, "cacheScope": "public"})
            if method == "tools/list":
                return ok({"resultType": "complete", "tools": srv.tools, "ttlMs": 1000, "cacheScope": "private"})
            return err(404, -32601, "Method not found")

        # legacy
        if META_VERSION in meta:
            return self._send(400, {"error": "bad request"})
        if method == "initialize":
            return ok({"protocolVersion": LEGACY, "capabilities": {"tools": {}}, "serverInfo": info,
                       "instructions": srv.instructions}, headers={"Mcp-Session-Id": "fixture-session"})
        if hdrs.get("mcp-session-id") != "fixture-session":
            return self._send(400, {"error": "no session"})
        if method == "notifications/initialized":
            return self._send(202)
        if method == "tools/list":
            return ok({"tools": srv.tools})
        return err(200, -32601, "Method not found")


def start(tools, mode="modern", instructions="Fixture HTTP server.", required_header=None):
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    server.tools = tools
    server.mode = mode
    server.instructions = instructions
    server.required_header = required_header
    server.seen = []
    server.url = "http://127.0.0.1:%d/mcp" % server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def stop(server):
    server.shutdown()
    server.server_close()
