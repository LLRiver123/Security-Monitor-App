"""Safe action execution helpers for the agent.

This module exposes functions that map recommended actions from rules
to implemented, safe operations. By default actions are logged and
not executed. Callers should request user confirmation before running
anything destructive.
"""
import logging

logger = logging.getLogger(__name__)


def perform_action(action, fields=None, confirm=False):
    """Perform a recommended action.

    action: dict or string describing action (e.g. {"action": "block_ip", ...})
    fields: optional dict with context
    confirm: if True, execute; otherwise only log.

    Returns a dict with result metadata.
    """
    if isinstance(action, dict):
        act = action.get("action")
    else:
        act = action

    logger.info("Requested action: %s, fields=%s, confirm=%s", act, fields, confirm)

    if not confirm:
        return {"status": "dry-run", "action": act}

    # Implement safe demonstrations only. Real implementations should
    # be carefully sandboxed and audited.
    if act == "block_ip":
        ip = fields.get("DestinationIp") if fields else None
        logger.info("(SIMULATED) Blocking IP %s", ip)
        return {"status": "ok", "action": act, "ip": ip}

    if act == "quarantine":
        target = fields.get("Image") if fields else None
        logger.info("(SIMULATED) Quarantining target %s", target)
        return {"status": "ok", "action": act, "target": target}

    if act == "investigate":
        logger.info("Investigation requested: %s", fields)
        return {"status": "ok", "action": act}

    # Unknown action
    logger.warning("Unknown action requested: %s", act)
    return {"status": "unknown_action", "action": act}
