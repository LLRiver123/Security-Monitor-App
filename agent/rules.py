import re

# Simple whitelist for common benign images (lowercase)
# NOTE: This list should be significantly expanded in a real environment.
WHITELIST_IMAGES = {
    r"c:\windows\system32\svchost.exe",
    r"c:\windows\system32\services.exe",
    r"c:\windows\system32\lsass.exe",
    r"c:\windows\system32\explorer.exe",
    r"c:\windows\system32\runtimebroker.exe",
    r"c:\windows\system32\dllhost.exe",
    r"c:\windows\system32\taskhostw.exe",
}

# Whitelist patterns for legitimate applications (use 'in' check, so partial match)
WHITELIST_PATTERNS = [
    # "\\windows\\system32\\",
    # "\\program files\\",
    # "\\program files (x86)\\",
    "\\windows defender\\",
    "\\githubdesktop\\",
    # "\\google\\chrome\\",
    # "\\mozilla firefox\\",
    # "\\microsoft\\edge\\",
    "python.exe",  # Python interpreter
    "git-remote-https.exe",  # Git operations
]

# Regex for common obfuscation/evasion techniques
OBFUSCATION_RE = re.compile(
    r"(-enc(oded(command)?)?|base64|powershell.*-nop|-w\s+hidden|-windowstyle\s+hidden|"
    r"IEX|Invoke-Expression|FromBase64String|DownloadString|DownloadFile|"
    r"\\temp\\|%temp%|-exec\s+bypass|-executionpolicy\s+bypass)", 
    re.IGNORECASE
)

# Enhanced external IP detection (excludes private ranges and loopback)
EXTERNAL_IP_RE = re.compile(
    r"^(?!10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.|127\.|169\.254\.|224\.)"
    r"\d{1,3}(\.\d{1,3}){3}$"
)

# Common LOLBAS binaries used for malicious execution or reconnaissance
LOLBAS_BINS = [
    "bitsadmin.exe", 
    "certutil.exe", 
    "mshta.exe", 
    "msbuild.exe",
    "psexec.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "netsh.exe",
]

# Common legitimate ports
COMMON_PORTS = { "443", "53", "22", "21", "25", "587", "993", "995"}

# High-risk temp/public directories (excluding legitimate system paths)
HIGH_RISK_DIRS = [
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\windows\\temp\\",
]

# Suspicious parent processes for cmd.exe
SUSPICIOUS_CMD_PARENTS = [
    "wmiprvse.exe",
    "services.exe",
    "winlogon.exe",
    "w3wp.exe",
    "sqlservr.exe",
]

def is_whitelisted(image):
    """Check if the image is in the simple whitelist or matches whitelist patterns."""
    if not image:
        return False
    image_lower = image.lower()
    
    # Check exact whitelist
    if image_lower in WHITELIST_IMAGES:
        return True
    
    # Check pattern whitelist
    for pattern in WHITELIST_PATTERNS:
        if pattern in image_lower:
            return True
    
    return False

def is_high_risk_location(path):
    """Check if the path is in a high-risk directory."""
    if not path:
        return False
    path_lower = path.lower()
    return any(risk_dir in path_lower for risk_dir in HIGH_RISK_DIRS)

def suspicious_rule(event):
    alerts = []

    if "error" in event:
        return alerts

    data = event.get("data", {})
    image = (data.get("Image") or "").lower()
    parent = (data.get("ParentImage") or "").lower()
    cmdline = (data.get("CommandLine") or "").lower()
    event_id = event.get("event_id")

    if event_id == 3 :
        dst_ip = data.get("DestinationIp")
        if dst_ip == "1.1.1.1" :
            alerts.append("CRITICAL: Connection to known C2 server 1.1.1.1 detected.")
            return alerts # Bắt được là return ngay, bất chấp Whitelist

    if "ransomware" in image or "ransomware" in cmdline:
        alerts.append("CRITICAL: Ransomware behavior detected (Demo Signature).")
        # Không return ngay để nó có thể dính thêm các rule khác nếu có
    
    if "spyware" in image or "spyware" in cmdline:
        alerts.append("CRITICAL: Spyware behavior detected (Demo Signature).")

    if is_whitelisted(image):
        return alerts

    # Rule 1: PowerShell Obfuscation/Evasion (High Suspicion)
    if "powershell" in image or "powershell" in cmdline:
        if OBFUSCATION_RE.search(cmdline):
            alerts.append("CRITICAL: Obfuscated PowerShell execution (T1059.001/T1027).")
        # Check for suspicious parent processes
        elif parent and any(susp in parent for susp in ["wmiprvse.exe", "w3wp.exe", "sqlservr.exe"]):
            alerts.append("CRITICAL: PowerShell spawned from suspicious parent process.")
        # Log all other non-whitelisted PowerShell executions as suspicious
        else:
            alerts.append("Suspicious: Direct PowerShell execution detected.")

    # Rule 2: Execution from Temp/User Folders (T1059 / T1566)
    if is_high_risk_location(image) and "explorer.exe" not in parent:
        alerts.append("CRITICAL: Execution from high-risk temporary or public folder.")

    # Rule 3: cmd.exe with Suspicious Parent or Long Commandline
    if "cmd.exe" in image:
        parent_match = any(susp in parent for susp in SUSPICIOUS_CMD_PARENTS)
        if parent_match:
            alerts.append("CRITICAL: cmd.exe spawned from services or WMI process (T1059.003).")
        if len(cmdline) > 300:
            alerts.append("Suspicious: Very long cmd.exe commandline (possible obfuscation).")
        # Check for common malicious patterns
        if any(pattern in cmdline for pattern in ["&", "&&", "|", "||", "^"]) and len(cmdline) > 100:
            alerts.append("Suspicious: cmd.exe with command chaining or special characters.")

    # Rule 4: Suspicious LOLBAS Usage (T1218, T1197, etc.)
    for bin_name in LOLBAS_BINS:
        if bin_name in image:
            alerts.append(f"CRITICAL: Execution of suspicious LOLBAS binary: {bin_name} (T1218).")
            break  # Only alert once per event for LOLBAS

    # --- T1136: Create Account ---

    # Rule 5: User Account Creation
    if event_id == 1 and "net.exe" in image:
        if "user" in cmdline and ("add" in cmdline or "/add" in cmdline):
            alerts.append("CRITICAL: New local user account creation detected (net user /add - T1136.001).")
        # Also check for net localgroup additions
        elif "localgroup" in cmdline and ("administrators" in cmdline or "/add" in cmdline):
            alerts.append("CRITICAL: User added to local administrators group (T1098).")
        
    # --- T1547: Boot/Logon Autostart Execution (Sysmon EventID 13 - Registry) ---

    # Rule 6: Registry Persistence via Run Key (Highly Suspicious)
    if event_id == 13: 
        target = (data.get("TargetObject") or "").lower()
        # Look for changes in common Run/RunOnce keys
        if "\\run" in target and "software\\microsoft\\windows\\currentversion" in target:
            alerts.append("CRITICAL: Persistence attempt via Registry Run Key (T1547.001).")
        # Check for other persistence mechanisms
        elif any(key in target for key in ["\\winlogon\\", "\\userinit", "\\shell\\", "\\load"]):
            alerts.append("CRITICAL: Potential persistence via critical registry key modification.")

    # --- T1048: Exfiltration over Alternate Protocol (Sysmon EventID 3) ---

    # Rule 7: Network Connection to External/Non-standard Port (High Suspicion)
    if event_id == 3:
        dst = data.get("DestinationIp")
        dst_port = str(data.get("DestinationPort", ""))
        
        # Skip alerts for whitelisted processes
        if is_whitelisted(image):
            return alerts
        
        # External IP on a non-standard port (e.g., C2 or exfiltration)
        if dst and EXTERNAL_IP_RE.match(dst):
            if dst_port and dst_port not in COMMON_PORTS: 
                alerts.append(f"CRITICAL: External network connection on non-standard port {dst}:{dst_port} (Possible C2/Exfil - T1048).")
            # Don't log standard HTTPS/HTTP connections from legitimate apps
            # Only log if it's from a suspicious or unknown process
        
        # Check for suspicious processes making network connections
        if image and any(proc in image for proc in ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]):
            alerts.append(f"Suspicious: Scripting process making network connection to {dst}:{dst_port}.")

    # --- T1003: Credential Dumping ---

    # Rule 8: Mimikatz or credential dumping detection
    if event_id == 1:
        # Mimikatz execution
        if "mimikatz" in image or "mimikatz" in cmdline:
            alerts.append("CRITICAL: Mimikatz execution detected (T1003.001).")
        # LSASS dumping attempts
        if "procdump" in image and "lsass" in cmdline:
            alerts.append("CRITICAL: Potential LSASS memory dumping (T1003.001).")
    
    # Process access to LSASS (EventID 10)
    if event_id == 10:
        target_image = (data.get("TargetImage") or "").lower()
        if "lsass.exe" in target_image and not is_whitelisted(image):
            alerts.append("CRITICAL: Suspicious process accessing LSASS memory (T1003.001).")

    return alerts