"""HTTP JSON-RPC stub for gateway tests, not a complete MCP server."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        tool = body.get('params', {}).get('name', '')
        print(f'RECEIVED id={body.get("id")} tool={tool}', flush=True)
        message = 'password=DEMO_ONLY' if tool == 'sensitive_search' else 'demo result'
        payload = json.dumps({
            'jsonrpc': '2.0', 'id': body.get('id'),
            'result': {'content': [{'type': 'text', 'text': message}]},
        }).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


ThreadingHTTPServer(('0.0.0.0', 9000), Handler).serve_forever()
