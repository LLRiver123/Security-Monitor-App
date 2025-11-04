import os
import sys
import json
import signal
import logging
import traceback
from pathlib import Path
from datetime import datetime
from typing import Set

from agent.collector import sysmon_event_stream
from agent.rules import suspicious_rule
from agent import resource_path
from agent.notifier import notify_console, notify_toast, write_alert_log
from agent.remediator import confirm_and_disable_path
from agent.control import ControlServer, set_control_server
from agent.ai.analyzer import analyze_event

# Setup logging
LOG_DIR = Path(__file__).parent / 'agent'
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / 'agent.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger('agent')

# Global state
control_server = None
shutdown_requested = False
recent_remediations: Set[str] = set()
REMEDIATION_CACHE_SIZE = 1000


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

        # Run detection rules
        alerts = suspicious_rule(event)
        
        # Run AI analysis
        try:
            ai_result = analyze_event(event)
            if ai_result and ai_result.get('score', 0) > 0.8:
                alert_msg = (
                    f"AI Anomaly Detected: score={ai_result['score']:.2f} "
                    f"advice={ai_result.get('advice', 'N/A')}"
                )
                alerts.append(alert_msg)
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")

        # Process alerts
        if alerts:
            for alert in alerts:
                process_alert(alert, event)

    except Exception as e:
        logger.error(f"Error processing event: {e}")
        logger.debug(traceback.format_exc())


def process_alert(alert: str, event: dict) -> None:
    """Process and handle an alert"""
    try:
        event_id = event.get('event_id', 'unknown')
        event_time = event.get('time', 'unknown')
        
        # Format alert message
        alert_msg = (
            f"[ALERT] {alert} | "
            f"EventID={event_id} | "
            f"Time={event_time}"
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
        attempt_remediation(event)

    except Exception as e:
        logger.error(f"Error processing alert: {e}")


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
            port = control_server.start()
            control_url = f"http://127.0.0.1:{port}"
            
            logger.info(f"Control API listening on {control_url}")
            notify_console(f"Control API listening on {control_url}")
            
            # Write control file for Electron
            token = getattr(control_server, 'token', None)
            write_control_file(control_url, token)
            
        except Exception as e:
            logger.error(f"Failed to start control server: {e}")
            logger.error("Continuing without control server...")

        # Main event processing loop
        event_count = 0
        error_count = 0
        
        for event in sysmon_event_stream():
            if shutdown_requested:
                logger.info("Shutdown requested, exiting event loop")
                break
            
            try:
                process_event(event)
                event_count += 1
                
                # Periodic status log
                if event_count % 100 == 0:
                    logger.info(
                        f"Processed {event_count} events "
                        f"({error_count} errors, "
                        f"{len(recent_remediations)} remediations)"
                    )
                    
            except Exception as e:
                error_count += 1
                logger.error(f"Event processing error: {e}")
                logger.debug(traceback.format_exc())
                
                # Exit if too many errors
                if error_count > 100:
                    logger.critical("Too many errors, shutting down")
                    break

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