import platform
import subprocess
from pathlib import Path
from . import resource_path

def notify_console(message, level="info"):
	"""Simple console notifier."""
	print(f"[{level.upper()}] {message}")

def notify_toast(message, title="Security Monitor"):
	"""Try to show a native toast/notification on Windows if available.
	Falls back to console print if not available.
	"""
	if platform.system() != "Windows":
		notify_console(f"{title}: {message}")
		return

	# try:
	# 	# Use powershell to show a simple toast via BurntToast if installed, otherwise fallback
	# 	# Keep this lightweight and permission-friendly: use a balloon tip via powershell's
	# 	# [System.Windows.Forms.NotifyIcon] only if PowerShell can run scripts.
	# 	ps = (
	# 		"Add-Type -AssemblyName System.Windows.Forms;"
	# 		"$ni = New-Object System.Windows.Forms.NotifyIcon;"
	# 		"$ni.Icon = [System.Drawing.SystemIcons]::Information;"
	# 		f"$ni.BalloonTipText = '{message}'; $ni.BalloonTipTitle = '{title}';"
	# 		"$ni.Visible = $true; $ni.ShowBalloonTip(5000); Start-Sleep -Seconds 5; $ni.Dispose();"
	# 	)
	# 	subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=False)
	# except Exception:
	# 	notify_console(f"{title}: {message}")

def write_alert_log(message):
	"""Write a small alert log next to the agent package for easy access regardless of CWD."""
	try:
		log_path = resource_path("alerts.log")
		with open(log_path, "a", encoding="utf-8") as f:
			f.write(message + "\n")
	except Exception as e:
		notify_console(f"Failed to write alert log: {e}", level="error")
