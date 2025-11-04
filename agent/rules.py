import re

# Simple whitelist for common benign images (lowercase)
# NOTE: This list should be significantly expanded in a real environment.
WHITELIST_IMAGES = {
    r"c:\\windows\\system32\\svchost.exe",
    r"c:\\windows\\system32\\services.exe",
    r"c:\\windows\\system32\\lsass.exe",
    r"c:\\windows\\system32\\explorer.exe",
    r"c:\\windows\\system32\\runtimebroker.exe",
}

# Regex for common obfuscation/evasion techniques
OBFUSCATION_RE = re.compile(
    r"(-enc(oded)?|base64|powershell.*-nop|-w hidden|IEX|FromBase64String|\\temp\\|%temp%)", 
    re.IGNORECASE
)
EXTERNAL_IP_RE = re.compile(r"^(?!10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.|127\.)\d{1,3}(\.\d{1,3}){3}$")

# Common LOLBAS binaries used for malicious execution or reconnaissance
LOLBAS_BINS = [
    "bitsadmin.exe", 
    "certutil.exe", 
    "mshta.exe", 
    "msbuild.exe",
    "psexec.exe",
    "wscript.exe",
    "cscript.exe"
]

def is_whitelisted(image):
    """Check if the image is in the simple whitelist."""
    return image and image.lower() in WHITELIST_IMAGES

def suspicious_rule(event):
    alerts = []

    if "error" in event:
        return alerts

    data = event.get("data", {})
    image = (data.get("Image") or "").lower()
    parent = (data.get("ParentImage") or "").lower()
    cmdline = (data.get("CommandLine") or "").lower()

    if is_whitelisted(image):
        return alerts

    # --- T1059: Command and Scripting Interpreter (High Suspicion) ---

    # Rule 1: PowerShell Obfuscation/Evasion (High Suspicion)
    if "powershell" in image or "powershell" in cmdline:
        if OBFUSCATION_RE.search(cmdline):
            alerts.append("CRITICAL: Obfuscated PowerShell execution (T1059.001/T1027).")
        # Log all other non-whitelisted PowerShell executions as suspicious
        else:
            alerts.append("Suspicious: Direct PowerShell execution detected.")

    # Rule 2: Execution from Temp/User Folders (T1059 / T1566)
    if image and ("\\temp\\" in image or "\\appdata\\local\\temp\\" in image or "\\users\\public\\" in image) and "explorer.exe" not in parent:
        alerts.append("CRITICAL: Execution from high-risk temporary or public folder.")

    # Rule 3: cmd.exe with Suspicious Parent or Long Commandline
    if "cmd.exe" in image:
        if "wmiprvse.exe" in parent or "services.exe" in parent:
            alerts.append("CRITICAL: cmd.exe spawned from services or WMI process (T1059.003).")
        if len(cmdline) > 300:
            alerts.append("Suspicious: Very long cmd.exe commandline.")

    # Rule 4: Suspicious LOLBAS Usage (T1218, T1197, etc.)
    for bin_name in LOLBAS_BINS:
        if bin_name in image:
            alerts.append(f"CRITICAL: Execution of suspicious LOLBAS binary: {bin_name} (T1036).")
            break # Only alert once per event for LOLBAS

    # --- T1098: Account Manipulation (Sysmon EventID 1) ---

    # Rule 5: User Account Creation
    if event.get("event_id") == 1 and "net.exe" in image and "user" in cmdline and ("add" in cmdline or "/add" in cmdline):
        alerts.append("CRITICAL: New local user account creation detected (net user /add - T1136).")
        
    # --- T1547: Boot/Logon Autostart Execution (Sysmon EventID 13 - Registry) ---

    # Rule 6: Registry Persistence via Run Key (Highly Suspicious)
    if event.get("event_id") == 13: 
        target = (data.get("TargetObject") or "").lower()
        # Look for changes in common Run/RunOnce keys
        if "run" in target and ("software\\microsoft\\windows\\currentversion" in target):
             alerts.append("CRITICAL: Persistence attempt via Registry Run Key (T1547.001).")

    # --- T1048: Exfiltration over Alternate Protocol (Sysmon EventID 3) ---

    # Rule 7: Network Connection to External/Non-standard Port (High Suspicion)
    if event.get("event_id") == 3:
        dst = data.get("DestinationIp")
        dst_port = data.get("DestinationPort")
        
        # External IP on a non-standard port (e.g., C2 or exfiltration)
        if dst and EXTERNAL_IP_RE.match(dst):
            if dst_port and dst_port not in ("80", "443", "53"): 
                 alerts.append(f"CRITICAL: External network connection on non-standard port {dst}:{dst_port} (Possible C2/Exfil).")
            # All other external connections should still be logged for review
            else:
                 alerts.append(f"Suspicious: External network connection to {dst}:{dst_port}.")


    return alerts
