"""Zero-dependency server: python server.py -> http://127.0.0.1:8000"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from engine import run_pipeline

UI = Path(__file__).parent / "ui" / "index.html"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, UI.read_text(encoding="utf-8"), "text/html; charset=utf-8")
        elif self.path == "/api/run":
            try:
                self._send(200, json.dumps(run_pipeline()), "application/json")
            except Exception as e:  # surface errors to the UI
                self._send(500, json.dumps({"error": str(e)}), "application/json")
        else:
            self._send(404, "not found", "text/plain")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("PatchProof running at http://127.0.0.1:8000")
    ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
