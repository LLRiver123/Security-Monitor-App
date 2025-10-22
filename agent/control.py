import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from .remediator import list_pending_requests, perform_disable
from .notifier import notify_console, write_alert_log


class ControlHandler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode('utf-8'))

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/pending':
            pending = list_pending_requests()
            return self._send_json({'pending': pending})
        else:
            return self._send_json({'error': 'not found'}, code=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == '/approve':
            length = int(self.headers.get('content-length', 0))
            body = self.rfile.read(length).decode('utf-8')
            try:
                data = json.loads(body or '{}')
                req_id = data.get('id')
                if not req_id:
                    return self._send_json({'error': 'id required'}, code=400)

                ok = perform_disable(req_id)
                if ok:
                    msg = f'Approved remediation {req_id}'
                    notify_console(msg)
                    write_alert_log(msg)
                    return self._send_json({'ok': True})
                else:
                    return self._send_json({'ok': False}, code=500)
            except Exception as e:
                return self._send_json({'error': str(e)}, code=500)
        else:
            return self._send_json({'error': 'not found'}, code=404)


class ControlServer:
    def __init__(self, host='127.0.0.1', port=0):
        self.host = host
        self.port = port
        self.httpd = None
        self.thread = None

    def start(self):
        self.httpd = HTTPServer((self.host, self.port), ControlHandler)
        self.port = self.httpd.server_address[1]

        def _serve():
            notify_console(f'Control server serving on http://{self.host}:{self.port}')
            try:
                self.httpd.serve_forever()
            except Exception:
                pass

        self.thread = threading.Thread(target=_serve, daemon=True)
        self.thread.start()
        return self.port

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
