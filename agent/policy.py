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


def evaluate_request(path: str, reason: str = "", event_signature: str = "") -> str:
    """Evaluate a remediation request and return one of: 'approve', 'reject', 'manual'.

    Rules are intentionally conservative:
    - If AGENT_POLICY_AUTO_APPROVE_ALL=1 -> 'approve'
    - Do not auto-approve system/process/user/ip objects (return 'manual')
    - Auto-approve obvious demo artifacts (filenames containing 'demo')
    - Default to 'manual'
    """
    try:
        if os.getenv('AGENT_POLICY_AUTO_APPROVE_ALL', '0') == '1':
            return 'approve'

        if not path:
            return 'manual'

        # System/object prefixes: prefer manual handling
        if path.startswith('USER:') or path.startswith('IP:') or path.startswith('pid_'):
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
