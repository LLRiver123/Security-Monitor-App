def suspicious_rule(event):
    """
    Simple example rule engine.
    Takes event dict from collector and checks conditions.
    """
    alerts = []

    # Rule 1: Suspicious parent process
    if "powershell" in str(event.get("message", "")).lower():
        alerts.append("Suspicious: PowerShell execution detected.")

    # Rule 2: Suspicious network connection
    if "cmd.exe" in str(event.get("message", "")).lower():
        alerts.append("Suspicious: CMD process observed.")

    if event.get("event_id") == 3:  # Network connection event
        alerts.append("Suspicious: Network connection event detected.")   

    return alerts
