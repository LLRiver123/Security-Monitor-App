"""Lightweight policy engine for simple auto-approval decisions.

This module is intentionally small and conservative: it only returns
one of three strings: 'approve', 'reject', or 'manual'. The agent can
call this before presenting remediation requests to a human UI to
optionally auto-approve safe demo artifacts or follow an environment
override.

Configuration:
- AGENT_POLICY_AUTO_APPROVE_ALL=1 : auto-approve every request (use with care)
"""
from pathlib import Path
import os
from agent.control import get_control_server


def evaluate_request(path: str, reason: str = "", event_signature: str = "") -> str:
    """Evaluate a remediation request and return one of: 'approve', 'reject', 'manual'.

    Rules are intentionally conservative:
    - If AGENT_POLICY_AUTO_APPROVE_ALL=1 -> 'approve'
    - If ControlServer.auto_remediation_enabled=True AND threat is CRITICAL -> 'approve'
    - Do not auto-approve system/process/user/ip objects (return 'manual') unless Critical & Auto-Remediate
    - Auto-approve obvious demo artifacts (filenames containing 'demo')
    - Default to 'manual'
    """
    try:
        if os.getenv('AGENT_POLICY_AUTO_APPROVE_ALL', '0') == '1':
            return 'approve'

        # Check Dynamic UI Config for Auto-Remediation
        server = get_control_server()
        if server and server.auto_remediation_enabled:
            
            # --- SAFETY NET: SYSTEM IMMUNITY ---
            # Never auto-kill system processes, even if flagged as critical.
            # User must manually approve these to prevent system instability.
            path_lower = path.lower()
            if "windows\\system32" in path_lower or "windows\\syswow64" in path_lower:
                return 'manual'

            # --- TARGETED AUTO-REMEDIATION ---
            reason_lower = reason.lower()
            
            # 1. High Confidence: Explicit Ransomware Behavior (Rapid file mods)
            if "ransomware" in reason_lower:
                return 'approve'

            # 2. Safe Targets: Explicit Demo/Simulation files
            if "simulation" in path_lower or "demo" in path_lower or "dummy" in path_lower:
                return 'approve'
            
            # Note: We removed generic "critical" check to avoid killing 
            # admin PowerShell scripts or other false positives.

        if not path:
            return 'manual'

        # System/object prefixes: prefer manual handling
        if path.startswith('USER:') or path.startswith('IP:') or path.startswith('pid_'):
            # Allow auto-remediation for processes ONLY if it's the Ransomware signature
            if server and server.auto_remediation_enabled and path.startswith('pid_'):
                 reason_lower = reason.lower()
                 if "ransomware" in reason_lower:
                     return 'approve'
            return 'manual'

        # For file paths, inspect filename
        try:
            p = Path(path)
            name = p.name.lower()
        except Exception:
            name = str(path).lower()

        # Demo/test artifacts are allowed to auto-approve for demo workflows
        if 'demo' in name:
            return 'approve'

        # Never auto-approve python or core system binaries
        if name in ('python.exe', 'python', 'cmd.exe', 'powershell.exe'):
            return 'manual'

        return 'manual'

    except Exception:
        # Fail-safe: do not auto-decide on unexpected errors
        return 'manual'
