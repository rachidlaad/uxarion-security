from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from urllib.parse import parse_qs
from urllib.parse import urlparse


HOST = "127.0.0.1"
PORT = 8081


HOME_PAGE = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Security Lab</title>
  </head>
  <body>
    <h1>Search Demo</h1>
    <p>This intentionally vulnerable page reflects user input unsafely.</p>
    <form action="/search" method="get">
      <label for="q">Search</label>
      <input id="q" name="q" type="text">
      <button type="submit">Go</button>
    </form>
    <p><a href="/safe">Safe Notes</a></p>
    <p><a href="/redirect?next=http://localhost:9090/admin">Out-of-scope redirect</a></p>
  </body>
</html>
"""


SAFE_PAGE = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Safe Notes</title>
  </head>
  <body>
    <h1>Safe Notes</h1>
    <p>This page renders only static content.</p>
    <ul>
      <li>release-notes</li>
      <li>account-help</li>
      <li>support-hours</li>
    </ul>
    <a href="/">Back</a>
  </body>
</html>
"""


class VulnerableHandler(BaseHTTPRequestHandler):
    def _write_html(self, body: str, status: int = 200) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._write_html(HOME_PAGE)
            return

        if parsed.path == "/search":
            params = parse_qs(parsed.query)
            query = params.get("q", [""])[0]
            # Intentionally unsafe reflection for local security testing.
            body = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Search Results</title>
  </head>
  <body>
    <h1>Search Results</h1>
    <p>You searched for: {query}</p>
    <a href="/">Back</a>
  </body>
</html>
"""
            self._write_html(body)
            return

        if parsed.path == "/safe":
            self._write_html(SAFE_PAGE)
            return

        if parsed.path == "/redirect":
            params = parse_qs(parsed.query)
            next_url = params.get("next", ["http://localhost:9090/admin"])[0]
            self.send_response(302)
            self.send_header("Location", next_url)
            self.end_headers()
            return

        self._write_html("<h1>Not Found</h1>", status=404)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def main() -> None:
    server = HTTPServer((HOST, PORT), VulnerableHandler)
    print(f"Security lab listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
