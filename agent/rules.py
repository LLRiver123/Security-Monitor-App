import re
import uuid

# Simple whitelist for common benign images (lowercase)
WHITELIST_IMAGES = {
    r"c:\\windows\\system32\\svchost.exe",
    r"c:\\windows\\system32\\services.exe",
    r"c:\\windows\\system32\\lsass.exe",
}

OBFUSCATION_RE = re.compile(r"(-enc(oded)?|base64|powershell.*-nop|-w hidden|IEX|FromBase64String)", re.IGNORECASE)
EXTERNAL_IP_RE = re.compile(r"^(?!10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.)\d{1,3}(\.\d{1,3}){3}$")


def _make_alert(message, severity="medium", confidence=0.6, fields=None, recommendation=None):
    return {
        "id": str(uuid.uuid4()),
        "message": message,
        "severity": severity,
        "confidence": confidence,
        "fields": fields or {},
        "recommendation": recommendation,
    }


def suspicious_rule_structured(event):
    """Return a list of structured alert dicts. This is the preferred API for UI/automation.

    Input: normalized event dict from `collector.sysmon_event_stream` where
    `event['data']` contains predictable keys.
    """
    alerts = []

    if "error" in event:
        return alerts

    data = event.get("data", {})
    image = (data.get("Image") or "").lower()
    parent = (data.get("ParentImage") or "").lower()
    cmdline = (data.get("CommandLine") or "") or (data.get("Hashes") or "")

    # Skip whitelisted images early
    if image and image in WHITELIST_IMAGES:
        return alerts

    # PowerShell suspicious usage (encoded / obfuscated)
    if "powershell" in image or "powershell" in cmdline.lower():
        if OBFUSCATION_RE.search(cmdline):
            alerts.append(_make_alert("Obfuscated PowerShell usage detected.", severity="high", confidence=0.9,
                                      fields={"Image": image, "CommandLine": cmdline},
                                      recommendation={"action": "investigate", "note": "Consider terminating process and collecting memory/image."}))
        else:
            alerts.append(_make_alert("PowerShell execution detected.", severity="medium", confidence=0.6,
                                      fields={"Image": image, "CommandLine": cmdline},
                                      recommendation={"action": "review", "note": "Review the command line for legitimacy."}))

    # cmd.exe spawned from unexpected parent or with suspicious flags
    if "cmd.exe" in image:
        if "wmiprvse.exe" in parent or "explorer.exe" not in parent:
            alerts.append(_make_alert("cmd.exe spawned from unusual parent.", severity="medium", confidence=0.7,
                                      fields={"Image": image, "ParentImage": parent},
                                      recommendation={"action": "investigate", "note": "Check parent/child relationship and origin."}))
        if len(cmdline) > 300:
            alerts.append(_make_alert("Very long cmd.exe commandline (possible script dropper).", severity="high", confidence=0.8,
                                      fields={"Image": image, "CommandLine": cmdline},
                                      recommendation={"action": "quarantine", "note": "Isolate host and collect artefacts."}))

    # Network connection events (Sysmon EventID 3)
    if event.get("event_id") == 3:
        src = data.get("SourceIp")
        dst = data.get("DestinationIp")
        dst_port = data.get("DestinationPort")
        # external destination IP check
        if dst and EXTERNAL_IP_RE.match(dst):
            alerts.append(_make_alert(f"Network to external IP {dst}:{dst_port}", severity="high", confidence=0.75,
                                      fields={"SourceIp": src, "DestinationIp": dst, "DestinationPort": dst_port},
                                      recommendation={"action": "block_ip", "note": "Block or investigate external connection."}))
        else:
            # local/local-lan connection — lower priority
            if dst_port and dst_port not in ("80", "443"):
                alerts.append(_make_alert(f"Non-HTTP port connection {dst}:{dst_port}", severity="low", confidence=0.4,
                                          fields={"DestinationPort": dst_port},
                                          recommendation={"action": "log", "note": "Record for telemetry."}))

    # Execution from temp folder
    if image and ("\\temp\\" in image or "\\appdata\\local\\temp\\" in image):
        alerts.append(_make_alert("Execution from temporary folder.", severity="medium", confidence=0.7,
                                  fields={"Image": image},
                                  recommendation={"action": "review", "note": "Temporary execution may indicate droppers."}))

    # suspicious fileless/parent-child patterns
    if parent and ("wmic.exe" in parent or "schtasks.exe" in parent or "regsvr32.exe" in parent):
        alerts.append(_make_alert(f"Suspicious launcher parent: {parent}", severity="medium", confidence=0.75,
                                  fields={"ParentImage": parent},
                                  recommendation={"action": "investigate", "note": "Possible fileless or living-off-the-land activity."}))

    return alerts


def suspicious_rule(event):
    """Compatibility wrapper for existing callers: returns list of human-readable strings."""
    structured = suspicious_rule_structured(event)
    return [f"{a['severity'].upper()}: {a['message']} (confidence={a['confidence']})" for a in structured]
