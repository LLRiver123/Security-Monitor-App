import secrets
import json
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional
from datetime import datetime
from queue import Queue

logger = logging.getLogger(__name__)


class RemediationRequest:
    """Represents a pending remediation request"""
    
    def __init__(self, req_id: str, path: str, reason: str = ""):
        self.id = req_id
        self.path = path
        self.reason = reason
        self.timestamp = datetime.utcnow().isoformat()
        self.status = "pending"  # pending, approved, rejected
        self.response = None
        self.pid = None
        # Optional event signature that can be used to correlate UI rejections
        # back to in-memory agent suppression lists. Accept as an optional
        # constructor parameter (backwards-compatible).
        self.event_signature = None
    
    def to_dict(self):
        return {
            'id': self.id,
            'path': self.path,
            'reason': self.reason,
            'timestamp': self.timestamp,
            'status': self.status,
            'event_signature': self.event_signature,
            'pid': self.pid
        }


class ControlServer:
    """HTTP server for UI to query and approve remediation actions"""
    
    def __init__(self, host='127.0.0.1', port=0):
        self.host = host
        self.port = port
        self.token = secrets.token_urlsafe(32)
        self.server = None
        self.server_thread = None
        self.running = False
        
        # Storage for pending remediation requests
        self.pending_requests: Dict[str, RemediationRequest] = {}
        self.response_queue = Queue()
        self.lock = threading.Lock()

        # NEW: Callback function set by main.py to handle rejected events permanently
        self.on_rejection_callback = None
        # Optional metrics provider callable set by main; should return a dict
        self.metrics_provider = None
        # SSE clients (each is a Queue instance used to push events)
        self._sse_clients: List[Queue] = []
        
        # UI Configurable Settings
        self.auto_remediation_enabled = False
    
    def start(self) -> int:
        """Start the control server in a background thread"""
        if self.running:
            logger.warning("Control server already running")
            return self.port
        
        handler = self._create_handler()
        
        try:
            self.server = HTTPServer((self.host, self.port), handler)
            self.port = self.server.server_port
            
            self.server_thread = threading.Thread(
                target=self._run_server,
                daemon=True,
                name="ControlServer"
            )
            self.server_thread.start()
            self.running = True
            
            logger.info(f"Control server started on {self.host}:{self.port}")
            return self.port
            
        except Exception as e:
            logger.error(f"Failed to start control server: {e}")
            raise
    
    def stop(self):
        """Stop the control server"""
        if not self.running:
            return
        
        logger.info("Stopping control server...")
        self.running = False
        
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        # Close all SSE clients
        with self.lock:
            for q in list(self._sse_clients):
                try:
                    q.put({'type': 'shutdown'})
                except Exception:
                    pass
            self._sse_clients.clear()
        
        if self.server_thread:
            self.server_thread.join(timeout=5)
        
        logger.info("Control server stopped")
    
    def _run_server(self):
        """Run the HTTP server (called in thread)"""
        try:
            logger.info(f"Control server listening on {self.host}:{self.port}")
            self.server.serve_forever()
        except Exception as e:
            logger.error(f"Control server error: {e}")
        finally:
            self.running = False
    
    def queue_request(self, path: str, reason: str = "", event_signature: str = "") -> str:
        """Queue a remediation request and return its ID"""
        req_id = secrets.token_urlsafe(16)
        
        with self.lock:
            # Pass event_signature into RemediationRequest (constructor is
            # backwards-compatible); store for later correlation.
            request = RemediationRequest(req_id, path, reason)
            request.event_signature = event_signature
            self.pending_requests[req_id] = request
            logger.info(f"Queued remediation request: {req_id} for {path}")
        
        return req_id
    
    def wait_for_approval(self, req_id: str, timeout: float = None) -> Optional[bool]:
        """
        Wait for user approval/rejection of a request
        Returns True if approved, False if rejected, None if timeout
        """
        try:
            # Poll for status change
            import time
            start = time.time()
            
            while True:
                with self.lock:
                    request = self.pending_requests.get(req_id)
                    if request and request.status != "pending":
                        return request.status == "approved"
                
                if timeout and (time.time() - start) > timeout:
                    logger.warning(f"Request {req_id} timed out")
                    return None
                
                time.sleep(0.1)
                
        except Exception as e:
            logger.error(f"Error waiting for approval: {e}")
            return None
    
    # NEW METHOD to allow main.py to register the suppression logic
    def register_rejection_callback(self, callback_func):
        """Register the function to be called when a request is rejected."""
        self.on_rejection_callback = callback_func
        logger.info("Rejection callback registered.")

    def broadcast_event(self, payload: dict):
        """Broadcast a JSON-serializable payload to all connected SSE clients."""
        with self.lock:
            for q in list(self._sse_clients):
                try:
                    q.put(payload)
                except Exception:
                    logger.debug('Failed to push to SSE client queue')

    def set_metrics_provider(self, provider_callable):
        """Register a callable that returns runtime metrics as a dict.

        main.py can call this after creating the ControlServer so /health
        returns runtime metrics for the UI to display.
        """
        self.metrics_provider = provider_callable
        logger.info("Metrics provider registered.")

    def _create_handler(self):
        """Create HTTP request handler with access to server instance"""
        server_instance = self
        
        class ControlRequestHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                """Override to use our logger"""
                logger.debug(f"{self.address_string()} - {format % args}")
            
            def _check_auth(self) -> bool:
                """Verify authentication token"""
                token = self.headers.get('X-Auth-Token')
                if token != server_instance.token:
                    self.send_error(401, "Unauthorized")
                    return False
                return True
            
            def _send_json(self, data, status=200):
                """Send JSON response"""
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

            def _read_json(self):
                """Read JSON body from request"""
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length == 0:
                    return {} # <--- TRẢ VỀ DICT RỖNG NẾU BODY RỖNG HOẶC THIẾU CONTENT-LENGTH
                try:
                    body = self.rfile.read(content_length)
                    return json.loads(body.decode())
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to decode JSON body: {e}")
                    raise # Ném lại lỗi để được bắt trong do_POST
                except Exception as e:
                    logger.error(f"Error reading request body: {e}")
                    raise
            
            def do_OPTIONS(self):
                """Handle CORS preflight"""
                self.send_response(200)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Auth-Token')
                self.end_headers()
            
            def do_GET(self):
                """Handle GET requests"""
                if not self._check_auth():
                    return
                
                if self.path == '/health':
                    resp = {
                        'status': 'healthy',
                        'timestamp': datetime.utcnow().isoformat(),
                        'config': {
                            'auto_remediation': server_instance.auto_remediation_enabled
                        }
                    }
                    # Include runtime metrics if a provider is available
                    try:
                        if server_instance.metrics_provider:
                            metrics = server_instance.metrics_provider()
                            resp['metrics'] = metrics
                    except Exception as e:
                        logger.error(f"Metrics provider error: {e}")
                    self._send_json(resp)
                
                elif self.path == '/pending':
                    with server_instance.lock:
                        pending = [
                            req.to_dict()
                            for req in server_instance.pending_requests.values()
                            if req.status == "pending"
                        ]
                    self._send_json({'requests': pending})

                elif self.path == '/events':
                    # Server-Sent Events endpoint for live notifications
                    # Require auth header as above
                    try:
                        self.send_response(200)
                        self.send_header('Content-Type', 'text/event-stream')
                        self.send_header('Cache-Control', 'no-cache')
                        self.send_header('Connection', 'keep-alive')
                        self.end_headers()

                        client_q = Queue()
                        with server_instance.lock:
                            server_instance._sse_clients.append(client_q)

                        # Keep the connection open and push events
                        while server_instance.running:
                            try:
                                item = client_q.get(timeout=0.5)
                            except Exception:
                                continue

                            try:
                                # SSE data: <json> followed by double newline
                                data = json.dumps(item, ensure_ascii=False)
                                self.wfile.write(f"data: {data}\n\n".encode('utf-8'))
                                self.wfile.flush()
                            except BrokenPipeError:
                                break
                            except Exception:
                                # If writing fails, drop this client
                                break

                    finally:
                        # Remove client queue
                        with server_instance.lock:
                            try:
                                server_instance._sse_clients.remove(client_q)
                            except Exception:
                                pass
                
                else:
                    self.send_error(404, "Not Found")
            
            def do_POST(self):
                """Handle POST requests"""
                if not self._check_auth():
                    return
                
                try:
                    data = self._read_json()
                except Exception as e:
                    self.send_error(400, f"Invalid JSON: {e}")
                    return
                
                if self.path == '/approve':
                    req_id = data.get('id')
                    if not req_id:
                        self.send_error(400, "Missing 'id' field")
                        return
                    
                    with server_instance.lock:
                        request = server_instance.pending_requests.get(req_id)
                        if not request:
                            self.send_error(404, f"Request {req_id} not found")
                            return
                        # Thêm kiểm tra trạng thái
                        if request.status != "pending":
                            self.send_error(400, f"Request {req_id} status is already {request.status}")
                            return
                            
                        request.status = "approved"
                        logger.info(f"Request {req_id} approved")
                        
                    self._send_json({
                        'success': True,
                        'id': req_id,
                        'status': 'approved'
                    })

                elif self.path == '/config':
                    if 'auto_remediation' in data:
                        server_instance.auto_remediation_enabled = bool(data['auto_remediation'])
                        logger.info(f"Config updated: auto_remediation={server_instance.auto_remediation_enabled}")
                    
                    self._send_json({
                        'success': True,
                        'config': {
                            'auto_remediation': server_instance.auto_remediation_enabled
                        }
                    })
                
                elif self.path == '/reject':
                    req_id = data.get('id')
                    if not req_id:
                        self.send_error(400, "Missing 'id' field")
                        return
                    
                    with server_instance.lock:
                        request = server_instance.pending_requests.get(req_id)
                        if not request:
                            self.send_error(404, f"Request {req_id} not found")
                            return
                        # Thêm kiểm tra trạng thái
                        if request.status != "pending":
                            self.send_error(400, f"Request {req_id} status is already {request.status}")
                            return
                        request.status = "rejected"
                        logger.info(f"Request {req_id} rejected")

                        if server_instance.on_rejection_callback and request.event_signature:
                            try:
                                # Call the function registered by main.py
                                server_instance.on_rejection_callback(request.event_signature)
                                logger.debug(f"Triggered rejection callback for signature: {request.event_signature}")
                            except Exception as e:
                                logger.error(f"Error executing rejection callback for {req_id}: {e}")
                    
                elif self.path == '/notify':
                    # Accept a JSON payload and broadcast to SSE clients
                    msg = data.get('message') or data
                    try:
                        payload = {'type': 'notify', 'message': msg, 'timestamp': datetime.utcnow().isoformat()}
                        server_instance.broadcast_event(payload)
                        self._send_json({'success': True})
                    except Exception as e:
                        logger.error(f"Failed to broadcast notify: {e}")
                        self.send_error(500, f"Broadcast failed: {e}")
                    self._send_json({
                        'success': True,
                        'id': req_id,
                        'status': 'rejected'
                    })
                
                else:
                    self.send_error(404, "Not Found")
        
        return ControlRequestHandler


# Global instance for easy access
_global_control_server: Optional[ControlServer] = None


def get_control_server() -> Optional[ControlServer]:
    """Get the global control server instance"""
    return _global_control_server


def set_control_server(server: ControlServer):
    """Set the global control server instance"""
    global _global_control_server
    _global_control_server = server