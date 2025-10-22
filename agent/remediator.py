from . import resource_path
from .notifier import notify_console, write_alert_log
import shutil
import os
import threading
import time
import uuid

# In-memory pending request store. For production you may want persistence.
pending_requests = {}
pending_lock = threading.Lock()


def confirm_and_disable_path(path: str) -> str:
	"""Queue a remediation request for the given path and return a request id.

	The agent will not block waiting for user input. Instead the UI should
	call the control API to approve the request (see agent/control.py) which
	will call perform_disable(req_id).
	"""
	req_id = uuid.uuid4().hex
	req = {
		"id": req_id,
		"path": path,
		"action": "disable",
		"status": "pending",
		"time": time.time(),
	}
	with pending_lock:
		pending_requests[req_id] = req

	msg = f"Remediation requested: id={req_id} path={path}"
	notify_console(msg)
	write_alert_log(msg)
	return req_id


def perform_disable(req_id: str) -> bool:
	"""Perform the disable action for a pending request id. Returns True on success."""
	with pending_lock:
		req = pending_requests.get(req_id)
		if not req:
			return False
		if req.get("status") != "pending":
			return False
		path = req.get("path")
		# mark as in-progress
		req["status"] = "in-progress"

	try:
		if not os.path.exists(path):
			notify_console(f"Remediator: path does not exist: {path}", level="warning")
			req["status"] = "failed"
			return False

		target = path + ".disabled"
		shutil.move(path, target)
		msg = f"Remediator: renamed {path} -> {target}"
		notify_console(msg)
		write_alert_log(msg)

		with pending_lock:
			req["status"] = "done"
			req["result"] = {"target": target}

		return True
	except Exception as e:
		notify_console(f"Failed to rename path: {e}", level="error")
		with pending_lock:
			req["status"] = "failed"
			req["error"] = str(e)
		return False


def quarantine_sample(sample_path: str) -> bool:
	"""Move a file into a quarantine directory under the agent package.
	Returns True on success.
	"""
	try:
		quarantine_dir = resource_path("quarantine")
		quarantine_dir.mkdir(exist_ok=True)
		base = os.path.basename(sample_path)
		dest = quarantine_dir.joinpath(base)
		shutil.move(sample_path, str(dest))
		msg = f"Quarantined {sample_path} -> {dest}"
		notify_console(msg)
		write_alert_log(msg)
		return True
	except Exception as e:
		notify_console(f"Quarantine failed: {e}", level="error")
		return False


def list_pending_requests():
	with pending_lock:
		# return shallow copies
		return [dict(r) for r in pending_requests.values()]


