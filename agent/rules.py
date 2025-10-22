# ...existing code...
import re

# Simple whitelist for common benign images (lowercase)
WHITELIST_IMAGES = {
    r"c:\\windows\\system32\\svchost.exe",
    r"c:\\windows\\system32\\services.exe",
    r"c:\\windows\\system32\\lsass.exe",
}

OBFUSCATION_RE = re.compile(r"(-enc(oded)?|base64|powershell.*-nop|-w hidden|IEX|FromBase64String)", re.IGNORECASE)
EXTERNAL_IP_RE = re.compile(r"^(?!10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.)\d{1,3}(\.\d{1,3}){3}$")

def suspicious_rule(event):
    """
    Rules operate on normalized event dicts produced by collector:
      event["data"] is a dict of Sysmon EventData fields.
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

    # Rule: PowerShell suspicious usage (encoded / obfuscated)
    if "powershell" in image or "powershell" in cmdline.lower():
        if OBFUSCATION_RE.search(cmdline):
            alerts.append("Suspicious: Obfuscated PowerShell usage detected.")
        else:
            alerts.append("Suspicious: PowerShell execution detected.")

    # Rule: cmd.exe spawned from unexpected parent or with suspicious flags
    if "cmd.exe" in image:
        if "wmiprvse.exe" in parent or "explorer.exe" not in parent:
            alerts.append("Suspicious: cmd.exe spawned from unusual parent.")
        if len(cmdline) > 300:
            alerts.append("Suspicious: Very long cmd.exe commandline (possible script dropper).")

    # Rule: Network connection events (Sysmon EventID 3)
    if event.get("event_id") == 3:
        src = data.get("SourceIp")
        dst = data.get("DestinationIp")
        dst_port = data.get("DestinationPort")
        # external destination IP check
        if dst and EXTERNAL_IP_RE.match(dst):
            alerts.append(f"Suspicious: Network to external IP {dst}:{dst_port}")
        else:
            # local/local-lan connection — lower priority
            if dst_port and dst_port not in ("80", "443"):
                alerts.append(f"Notice: Non-HTTP port connection {dst}:{dst_port}")

    # Rule: Execution from temp folder
    if image and ("\\temp\\" in image or "\\appdata\\local\\temp\\" in image):
        alerts.append("Suspicious: Execution from temporary folder.")

    # Rule: suspicious fileless/parent-child patterns
    if parent and ("wmic.exe" in parent or "schtasks.exe" in parent or "regsvr32.exe" in parent):
        alerts.append(f"Suspicious: Suspicious launcher parent: {parent}")

    return alerts
# ...existing code...