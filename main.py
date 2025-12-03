import os
import sys
import json
import signal
import logging
import traceback
import threading
import queue
import time
import re
from pathlib import Path
from datetime import datetime
from typing import Set

from agent.collector import sysmon_event_stream_reverse
from agent.rules import suspicious_rule
from agent import resource_path
from agent.notifier import notify_console, notify_toast, write_alert_log
from agent.remediator import confirm_and_disable_path, queue_user_remediation
from agent.control import ControlServer, set_control_server
from agent.ai.analyzer import analyze_event
from agent.remediator import check_pending_and_execute

# Setup logging
LOG_DIR = Path(__file__).parent / 'agent'
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / 'agent.log'
AI_PROCESSING_QUEUE = queue.Queue()
NUM_AI_WORKER = 2
REVERSE_POLL_INTERVAL = 10
control_server = None
shutdown_requested = False
recent_remediations: Set[str] = set()
REMEDIATION_CACHE_SIZE = 1000
rejected_remediations: Set[str] = set()
AI_ALERT_THRESHOLD = 75  # percent threshold (0-100) for AI-generated alerts
# Controls to reduce AI summary noise
# Only emit INFO-level AI summaries when score >= AI_SUMMARY_MIN_SCORE
AI_SUMMARY_MIN_SCORE = int(os.getenv('AGENT_AI_SUMMARY_MIN_SCORE', '50'))
# Prevent repeated identical summaries for the same event within this window (seconds)
AI_SUMMARY_DEDUP_SECONDS = int(os.getenv('AGENT_AI_SUMMARY_DEDUP_SECONDS', '5'))
# small in-memory cache of last summary timestamps keyed by event_signature
_ai_summary_last: dict = {}

# Configure logging with optional JSON structured format and avoid duplicate handlers
LOG_FORMAT = os.getenv('AGENT_LOG_FORMAT', 'text').lower()
root_logger = logging.getLogger()
for h in list(root_logger.handlers):
    root_logger.removeHandler(h)

# File and stream handlers
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
stream_handler = logging.StreamHandler(sys.stdout)

if LOG_FORMAT == 'json':
    class JsonFormatter(logging.Formatter):
        def format(self, record):
            # Build a compact JSON object for ingestion
            msg = record.getMessage()
            payload = {
                'timestamp': self.formatTime(record, '%Y-%m-%dT%H:%M:%S%z'),
                'level': record.levelname,
                'logger': record.name,
                'message': msg
            }
            if record.exc_info:
                payload['exc'] = self.formatException(record.exc_info)
            return json.dumps(payload, ensure_ascii=False)

    jfmt = JsonFormatter()
    file_handler.setFormatter(jfmt)
    stream_handler.setFormatter(jfmt)
else:
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    file_handler.setFormatter(fmt)
    stream_handler.setFormatter(fmt)

root_logger.setLevel(logging.INFO)
root_logger.addHandler(file_handler)
root_logger.addHandler(stream_handler)

# Main agent logger
logger = logging.getLogger('agent')

# Global state
control_server = None
shutdown_requested = False
recent_remediations: Set[str] = set()
REMEDIATION_CACHE_SIZE = 1000

def _execute_remediation_logic(alert: str, event: dict) -> None:
    """
    Phân loại cảnh báo và gửi yêu cầu System Remediation (User) hoặc File Remediation.
    """
    global recent_remediations, REMEDIATION_CACHE_SIZE, rejected_remediations
    event_id = event.get('event_id', 'UNKNOWN')
    data = event.get('data', {})
    image_path = data.get('Image', 'NO_IMAGE')
    
    # Chữ ký: Prefix FILE: để thống nhất logic
    event_signature = f"FILE:{image_path}"
    
    try:
        # Check Permanent Rejection
        if event_signature in rejected_remediations:
            logger.info(f"Skipping permanently rejected event: {event_signature}")
            return
        # Check Recent Cache
        if event_signature in recent_remediations:
            logger.debug(f"Skipping cached event: {event_signature}")
            return
        
        req_id = None
        path_for_cache = image_path

        # --- CASE 1: USER REMEDIATION ---
        if "New local user account creation detected" in alert:
            command_line = data.get('CommandLine', '').lower()
            user_match = re.search(r'net\s+user\s+([^\s]+)\s+.*?/add', command_line)
            username_to_delete = user_match.group(1) if user_match else "eviluser"
            
            from agent.remediator import queue_user_remediation
            
            # Override cache path for Users
            path_for_cache = f"USER:{username_to_delete}"
            req_id = queue_user_remediation(username_to_delete, alert, event_signature)
            
        # --- CASE 2: MIMIKATZ / MALWARE (Fix Applied Here) ---
        elif "Mimikatz execution detected" in alert or "Known malicious binary" in alert:
            if not image_path:
                return
            
            # 💡 FIX: Do NOT use queue_process_termination. 
            # Use confirm_and_disable_path so it triggers terminate_process_by_path inside remediator.
            from agent.remediator import confirm_and_disable_path
            
            path_for_cache = image_path
            req_id = confirm_and_disable_path(image_path, alert, event_signature=event_signature)
            
        # --- CASE 3: GENERIC SUSPICIOUS FILE ---
        elif "Suspicious" in alert or "CRITICAL" in alert:
             if not image_path:
                return
             
             from agent.remediator import confirm_and_disable_path
             
             path_for_cache = image_path
             req_id = confirm_and_disable_path(image_path, alert, event_signature=event_signature)

        # --- LOGGING & CACHING ---
        if req_id:
            logger.info(f"Remediation queued: id={req_id} path={path_for_cache}")
            recent_remediations.add(event_signature)
            if len(recent_remediations) > REMEDIATION_CACHE_SIZE:
                recent_remediations.clear() 

    except Exception as e:
        logger.error(f"Remediation queuing error: {e}")
        logger.debug(traceback.format_exc())

def ai_worker():
    while True:
        try:
            event_to_analyze = AI_PROCESSING_QUEUE.get(timeout=0.1)
            
            # 1. In ra xem event nào đang được gửi đi
            event_id = event_to_analyze.get('event_id')
            # logger.info(f"[AI DEBUG] Analyzing Event ID: {event_id}") 

            ai_res = analyze_event(event_to_analyze)
            
            # 2. Handle AI result: `analyze_event` returns score in 0..100
            if ai_res:
                score = ai_res.get('score', 0)
                # Record metrics: total AI-evaluated and score histogram
                try:
                    with METRICS_LOCK:
                        METRICS['ai_evaluated'] += 1
                        # bucket 0..9, 10..19 -> index 0..9
                        b = min(9, max(0, int(score) // 10))
                        METRICS['ai_score_histogram'][b] += 1
                except Exception:
                    # Metrics should never interrupt processing
                    logger.debug('Failed to record AI metrics')
                # Debug-level output only (avoid spamming INFO logs)
                logger.debug(f"[AI DEBUG] Event {event_id} | Score: {score} | Reason: {ai_res.get('reason', 'N/A')}")

                # Emit a concise INFO-level AI summary only if score is high enough
                # and avoid repeating the same summary for the same event too often.
                try:
                    data = event_to_analyze.get('data') or {}
                    image = (data.get('Image', '') or '')
                    # Use a compact signature (event id + image) so minor timestamp
                    # differences don't defeat deduplication for repeated events.
                    sig = f"{event_id}|{image}"
                    last_ts = _ai_summary_last.get(sig)
                    now_ts = time.time()
                    # Log if score >= configured per-summary threshold OR score >= alert threshold
                    should_log = score >= AI_SUMMARY_MIN_SCORE or score >= AI_ALERT_THRESHOLD
                    if should_log:
                        if (last_ts is None) or ((now_ts - last_ts) >= AI_SUMMARY_DEDUP_SECONDS):
                            logger.info(f"[AI SUMMARY] Event {event_id} | Score: {score}")
                            _ai_summary_last[sig] = now_ts
                        else:
                            logger.debug(f"Suppressed duplicate AI summary for {sig}")
                except Exception:
                    logger.debug('AI summary logging error')

                # Only generate an alert when score meets configured percent threshold
                if score >= AI_ALERT_THRESHOLD:
                    alert_msg = (
                        f"AI Anomaly Detected: score={score:.2f} "
                        f"advice={ai_res.get('advice', 'N/A')}"
                    )
                    process_alert(alert_msg, event_to_analyze)
                else:
                    # keep quiet for low scores (debug only)
                    pass
            else:
                logger.debug(f"[AI DEBUG] Event {event_id} returned NO result from AI engine.")

            AI_PROCESSING_QUEUE.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"AI worker error: {e}")
            logger.debug(traceback.format_exc())

def start_ai_workers():
    # Pre-warm the AI models once to avoid repeated loading from multiple
    # threads (this prevents repeated SentenceTransformer INFO messages).
    try:
        import agent.ai.analyzer as _analyzer
        _analyzer._load_model()
        logger.info("Preloaded AI model for analysis")
    except Exception:
        logger.debug("AI model pre-warm failed or model unavailable")

    for _ in range(NUM_AI_WORKER):
        t = threading.Thread(target=ai_worker, daemon=True)
        t.start()
        logger.info("Started AI analysis worker thread")

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global shutdown_requested
    signal_name = signal.Signals(signum).name
    logger.info(f"Received {signal_name}, shutting down gracefully...")
    shutdown_requested = True


def write_control_file(url: str, token: str = None):
    """Write control.json for Electron discovery"""
    try:
        control_file = LOG_DIR / 'control.json'
        control_info = {
            'url': url,
            'token': token,
            'pid': os.getpid(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        with open(control_file, 'w') as f:
            json.dump(control_info, f, indent=2)
        
        logger.info(f"Control file written: {control_file}")
    except Exception as e:
        logger.error(f"Failed to write control file: {e}")


def cleanup_control_file():
    """Remove control.json on shutdown"""
    try:
        control_file = LOG_DIR / 'control.json'
        if control_file.exists():
            control_file.unlink()
            logger.info("Control file removed")
    except Exception as e:
        logger.error(f"Failed to remove control file: {e}")

AI_WHITELIST_IDS = [13, 17, 18]
# --- Simple runtime metrics ---
METRICS_LOCK = threading.Lock()
METRICS = {
    'events_processed': 0,
    'ai_evaluated': 0,
    # histogram 0-9,10-19,..90-100
    'ai_score_histogram': [0] * 10
}

def metrics_snapshot():
    """Return a copy of metrics for the control server to expose."""
    with METRICS_LOCK:
        return {
            'events_processed': METRICS['events_processed'],
            'ai_evaluated': METRICS['ai_evaluated'],
            'ai_score_histogram': list(METRICS['ai_score_histogram'])
        }
def process_event(event: dict) -> None:
    """Process a single Sysmon event"""
    try:
        # Validate event structure
        if not isinstance(event, dict):
            logger.error(f"Invalid event type: {type(event)}")
            return
        
        if "error" in event:
            logger.error(f"Event error: {event['error']}")
            return

        # Extract basic event info
        event_id = event.get('event_id', 'unknown')
        event_time = event.get('time', 'unknown')
        source = event.get('source', 'unknown')
        
        # Log event summary
        logger.debug(f"EventID={event_id} Time={event_time} Source={source}")

        # metrics: event processed
        try:
            with METRICS_LOCK:
                METRICS['events_processed'] += 1
        except Exception:
            logger.debug('Failed to increment events_processed metric')

        # Run detection rules
        alerts = suspicious_rule(event)
        
        # Process alerts
        if alerts:
            for alert in alerts:
                process_alert(alert, event)

        # Queue for AI analysis if applicable
        if event_id not in AI_WHITELIST_IDS:
            return  # Skip AI analysis for whitelisted IDs
        AI_PROCESSING_QUEUE.put(event)       

    except Exception as e:
        logger.error(f"Error processing event: {e}")
        logger.debug(traceback.format_exc())


def process_alert(alert: str, event: dict) -> None:
    """Process and handle an alert"""
    try:
        event_id = event.get('event_id', 'unknown')
        event_time = event.get('time', 'unknown')
        pid = event.get('data', {}).get('ProcessId', 'N/A')
        
        # Format alert message
        alert_msg = (
            f"[ALERT] {alert} | "
            f"EventID={event_id} | "
            f"Time={event_time} | "
            f"PID={pid}"
        )
        
        # Notify through all channels
        logger.warning(alert_msg)
        notify_console(alert_msg, level="warning")
        
        try:
            notify_toast(alert)
        except Exception as e:
            logger.debug(f"Toast notification failed: {e}")
        
        try:
            write_alert_log(alert_msg)
        except Exception as e:
            logger.error(f"Failed to write alert log: {e}")

        # Attempt remediation for suspicious executables
        _execute_remediation_logic(alert, event)

    except Exception as e:
        logger.error(f"Error processing alert: {e}")

def register_rejected_event(event_signature: str) -> None:
    """Adds an event signature to the permanent rejection cache."""
    global rejected_remediations
    # Check if we already registered it (shouldn't happen, but safe)
    if event_signature not in rejected_remediations:
        rejected_remediations.add(event_signature)
        logger.warning(f"Event signature permanently suppressed after rejection: {event_signature}")

def attempt_remediation(event: dict) -> None:
    """Queue remediation request if applicable"""
    try:
        data = event.get('data', {})
        image = data.get('Image')
        
        if not image:
            return
        
        # Skip if already queued recently
        if image in recent_remediations:
            logger.debug(f"Skipping duplicate remediation: {image}")
            return
        
        # Queue remediation request
        req_id = confirm_and_disable_path(image)
        logger.info(f"Remediation queued: id={req_id} path={image}")
        
        # Add to cache
        recent_remediations.add(image)
        
        # Prevent cache from growing indefinitely
        if len(recent_remediations) > REMEDIATION_CACHE_SIZE:
            # Remove oldest entries (in practice, use a proper LRU cache)
            recent_remediations.clear()
        
    except Exception as e:
        logger.error(f"Remediation error: {e}")
        logger.debug(traceback.format_exc())


def run_agent():
    """Main agent loop"""
    global control_server, shutdown_requested
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        logger.info("="*60)
        logger.info("Starting Security Agent")
        logger.info(f"Python version: {sys.version}")
        logger.info(f"Working directory: {os.getcwd()}")
        logger.info(f"Log file: {LOG_FILE}")
        logger.info("="*60)
        
        notify_console("[*] Starting agent. Listening to Sysmon logs...")

        # Start control server for UI communication
        try:
            control_server = ControlServer()
            set_control_server(control_server)  # Make globally accessible
            
            # Register the rejection callback
            control_server.register_rejection_callback(register_rejected_event)
            # Register metrics provider so the control server /health endpoint
            # can return runtime counters for the UI to show
            try:
                control_server.set_metrics_provider(metrics_snapshot)
            except Exception:
                logger.debug("Failed to register metrics provider with ControlServer")
            
            port = control_server.start()
            control_url = f"http://127.0.0.1:{port}"
            
            logger.info(f"Control API listening on {control_url}")
            notify_console(f"Control API listening on {control_url}")
            
            start_ai_workers()
            # Write control file for Electron
            token = getattr(control_server, 'token', None)
            write_control_file(control_url, token)
            
        except Exception as e:
            logger.error(f"Failed to start control server: {e}")
            logger.error("Continuing without control server...")

        # Main event processing loop
        event_count = 0
        error_count = 0
        
        while not shutdown_requested:
            try:
                for event in sysmon_event_stream_reverse(max_events=500):
                    if shutdown_requested:
                        break
                    process_event(event)
                    event_count += 1
                    check_pending_and_execute()
                # Sleep briefly to avoid tight loop
                
                    
            except Exception as e:
                error_count += 1
                logger.error(f"Event processing error: {e}")
                logger.debug(traceback.format_exc())
                
                # Exit if too many errors
                if error_count > 100:
                    logger.critical("Too many errors, shutting down")
                    break
            if not shutdown_requested:
                logger.info(f"Finished reverse fetch. Waiting {REVERSE_POLL_INTERVAL}s.")
                # Sử dụng vòng lặp nhỏ để kiểm tra cờ tắt máy (giúp tắt nhanh)
                for _ in range(int(REVERSE_POLL_INTERVAL / 0.1)): 
                    if shutdown_requested:
                        print("Shutdown requested, exiting wait loop")
                        break 
                    time.sleep(0.1)
        logger.info(f"Agent stopped. Processed {event_count} total events")

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    
    except Exception as e:
        logger.critical(f"Fatal error in agent: {e}")
        logger.critical(traceback.format_exc())
        sys.exit(1)
    
    finally:
        # Cleanup
        logger.info("Cleaning up...")
        
        if control_server:
            try:
                control_server.stop()
                logger.info("Control server stopped")
            except Exception as e:
                logger.error(f"Error stopping control server: {e}")
        
        cleanup_control_file()
        
        logger.info("Agent shutdown complete")
        notify_console("[*] Agent stopped")


def main():
    """Entry point with additional error handling"""
    try:
        run_agent()
    except Exception as e:
        logger.critical(f"Unhandled exception: {e}")
        logger.critical(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()