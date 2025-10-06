from agent.collector import sysmon_event_stream
from agent.rules import suspicious_rule

def run_agent():
    print("[*] Starting agent. Listening to Sysmon logs...")

    for event in sysmon_event_stream():
        if "error" in event:
            print("[!] Error reading event:", event["error"])
            continue
        print(event)
        input("Press Enter to continue...")
        alerts = suspicious_rule(event)

        for alert in alerts:
            print(f"[ALERT] {alert} | EventID={event['event_id']} | Time={event['time']}")

if __name__ == "__main__":
    run_agent()
