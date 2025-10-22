from agent.collector import sysmon_event_stream
from agent.rules import suspicious_rule
from agent import resource_path
from agent.notifier import notify_console, notify_toast, write_alert_log
from agent.remediator import confirm_and_disable_path
from agent.control import ControlServer

from agent.ai.analyzer import analyze_event


def run_agent():
    notify_console("[*] Starting agent. Listening to Sysmon logs...")

    # start local control API for UI to approve remediation actions
    control = ControlServer()
    port = control.start()
    notify_console(f"Control API listening on http://127.0.0.1:{port}")

    for event in sysmon_event_stream():
        if "error" in event:
            notify_console(f"[!] Error reading event: {event['error']}", level="error")
            continue

        # Basic display of event summary
        notify_console(f"EventID={event.get('event_id')} Time={event.get('time')} Source={event.get('source')}")

        alerts = suspicious_rule(event)
        res = analyze_event(event)
        if res['score'] > 0.8:
            alerts.append(f"AI Anomaly Detected: score={res['score']:.2f} advice={res['advice']}")

        for alert in alerts:
            msg = f"[ALERT] {alert} | EventID={event.get('event_id')} | Time={event.get('time')}"
            notify_console(msg, level="warning")
            notify_toast(alert)
            write_alert_log(msg)

            # Example remediation prompt for file-created/executables (non-destructive)
            data = event.get('data', {})
            image = data.get('Image')
            if image:
                # queue a remediation request for the UI to approve
                try:
                    req_id = confirm_and_disable_path(image)
                    notify_console(f"Remediation queued id={req_id} path={image}")
                except Exception as e:
                    notify_console(f"Remediation error: {e}", level="error")


if __name__ == "__main__":
    run_agent()
