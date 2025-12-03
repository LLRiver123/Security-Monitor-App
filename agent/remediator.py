import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Optional
from datetime import datetime
import psutil
import json # Đã thêm import
import stat # Đã thêm import cho chmod
import re

from agent.control import get_control_server

logger = logging.getLogger(__name__)
_rejected_event_callback = None

def set_rejected_event_callback(cb):
    """Register a callback to be called when an event remediation is rejected.

    Provided for decoupling: do NOT import `main` inside this module to avoid
    circular imports. Instead, `main` should call this setter after it is
    initialized (or register via the ControlServer).
    """
    global _rejected_event_callback
    _rejected_event_callback = cb

def register_rejected_event_callback(signature: str):
    """Invoke the registered rejection callback (if any).

    This function preserves the old exported name so other modules that import
    `register_rejected_event_callback` will still have a callable available,
    but the real callback must be registered via `set_rejected_event_callback`.
    """
    if _rejected_event_callback:
        try:
            _rejected_event_callback(signature)
        except Exception as e:
            logger.error(f"Rejection callback raised an exception: {e}")
    else:
        logger.debug(f"No rejection callback registered for signature: {signature}")

def confirm_and_disable_path(path: str, reason: str = "Suspicious activity detected", event_signature: str = "") -> str:
    """
    Queue a remediation request for user approval via the control server.
    Returns the request ID.
    
    Args:
        path: File path to potentially remediate
        reason: Description of why remediation is needed
    
    Returns:
        Request ID string
    
    Raises:
        RuntimeError: If control server is not available
    """
    control_server = get_control_server()
    
    if not control_server:
        raise RuntimeError("Control server not available")
    
    # Validate path
    if not path:
        raise ValueError("Path cannot be empty")
    
    # Queue the request
    req_id = control_server.queue_request(path, reason, event_signature=event_signature)
    logger.info(f"Remediation request queued: {req_id} for path={path}")
    
    return req_id

def block_ip_address(ip_address: str) -> bool:
    """
    Block an IP address using Windows Firewall.
    Requires Administrator privileges.
    """
    try:
        subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
             f'name=Block IP {ip_address}', 'dir=in', 'action=block',
             f'remoteip={ip_address}'],
            check=True,
            capture_output=True,
            text=True
        )
        logger.info(f"Successfully blocked IP address: {ip_address}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block IP address {ip_address}: {e.stderr.strip()}")
        return False
    except Exception as e:
        logger.error(f"System error during IP blocking: {e}")
        return False

def terminate_process(pid: int) -> bool:
    """Kill a process by its PID."""
    try:
        # Check if process exists
        if not psutil.pid_exists(pid):
            logger.warning(f"PID {pid} does not exist (already dead?).")
            return True

        process = psutil.Process(pid)
        process_name = process.name()
        
        logger.info(f"Attempting to terminate process: {process_name} (PID: {pid})")
        process.kill()  # Force kill
        
        # Wait up to 3 seconds for it to die
        try:
            process.wait(timeout=3)
            logger.info(f"Process {pid} killed successfully.")
            return True
        except psutil.TimeoutExpired:
            logger.error(f"Failed to kill process {pid} within timeout.")
            return False

    except psutil.AccessDenied:
        logger.error(f"Access denied when trying to kill PID {pid}. Agent needs Admin rights.")
        return False
    except Exception as e:
        logger.error(f"Error terminating PID {pid}: {e}")
        return False

def terminate_process_by_path(file_path: Path) -> bool:
    """
    Finds and kills any process running from the specific file path.
    Includes safeguards to prevent the Agent from killing itself.
    """
    killed_something = False
    target_name = file_path.name.lower()  # e.g., "ransomware.exe" or "python.exe"
    
    # 💡 Lấy PID của chính Agent để tránh tự sát
    MY_PID = os.getpid()
    
    try:
        # Method 1: Surgical Kill (via psutil) - SAFE MODE
        # Normalize path for comparison
        target_path = str(file_path.resolve()).lower()
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                # Bỏ qua chính mình
                if proc.info['pid'] == MY_PID:
                    continue

                # Check if it matches the target path
                if proc.info['exe'] and proc.info['exe'].lower() == target_path:
                    logger.warning(f"Found active process {proc.info['name']} (PID: {proc.info['pid']}). Killing...")
                    proc.kill()
                    killed_something = True
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Method 2: The "Nuclear Option" (Taskkill by Name)
        # 💡 FIX: KHÔNG chạy lệnh này nếu mục tiêu là python.exe
        # Vì taskkill /IM python.exe sẽ giết cả Agent!
        if file_path.exists():
            if target_name == "python.exe":
                logger.info("Target is python.exe. Skipping 'taskkill /IM' to prevent Agent suicide.")
            else:
                logger.info(f"Executing forcing cleanup: taskkill /F /IM {target_name}")
                subprocess.run(
                    ["taskkill", "/F", "/IM", target_name], 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL
                )
                killed_something = True

        if killed_something:
            time.sleep(1.5) # Wait for Windows to clean up handles
            return True
            
    except Exception as e:
        logger.error(f"Error cleaning up processes for {file_path}: {e}")
    
    return False

def execute_remediation(path: str, action: str = "quarantine") -> bool:
    """
    Execute the actual remediation action with Retry Logic and Process Killing.
    """
    if path.startswith("IP:"):
        ip_address = path.replace("IP:", "")
        return block_ip_address(ip_address)

    # 1. Handle System Objects (User)
    if path.startswith("USER:"):
        username = path.replace("USER:", "")
        from agent.remediator import delete_user 
        return delete_user(username)

    # 2. Handle Process Objects (NEW FIX) 💡
    if path.startswith("pid_"):
        try:
            pid_str = path.replace("pid_", "")
            pid = int(pid_str)
            return terminate_process(pid)
        except ValueError:
            logger.error(f"Invalid PID format in remediation path: {path}")
            return False

    # 3. Handle File Objects (Existing Logic)
    path_obj = Path(path)
    if not path_obj.exists():
        logger.warning(f"Path does not exist: {path}")
        return False

    # STEP A: Kill the process holding the file (File Locking logic)
    terminate_process_by_path(path_obj)

    # STEP B: Attempt Remediation with Retry Logic
    max_retries = 3
    for attempt in range(max_retries):
        try:
            if action == "disable":
                return disable_file(path_obj)
            elif action == "quarantine":
                return quarantine_file(path_obj)
            elif action == "delete":
                return delete_file(path_obj)
            else:
                logger.error(f"Unknown action: {action}")
                return False
        except PermissionError:
            logger.warning(f"File locked. Retrying remediation ({attempt + 1}/{max_retries})...")
            terminate_process_by_path(path_obj)
            time.sleep(1)
        except Exception as e:
            logger.error(f"Remediation error on attempt {attempt}: {e}")
            return False
            
    logger.error(f"Failed to remediate {path} after {max_retries} attempts.")
    return False


def disable_file(path: Path) -> bool:
    """Disable a file by renaming (Windows) or removing execute permissions (Unix)."""
    try:
        if os.name == 'nt':  # Windows
            disabled_path = path.with_suffix(path.suffix + '.disabled')
            if disabled_path.exists():
                logger.warning(f"Disabled version already exists: {disabled_path}")
                return False
            path.rename(disabled_path)
            logger.info(f"File disabled: {path} -> {disabled_path}")
            return True
        else:
            # Unix-like: remove execute bits
            current_mode = path.stat().st_mode
            new_mode = current_mode & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH
            path.chmod(new_mode)
            logger.info(f"Execute permissions removed: {path}")
            return True
    except Exception as e:
        logger.error(f"Failed to disable file {path}: {e}")
        return False

def quarantine_file(path: Path) -> bool:
    """Move file to quarantine directory and record metadata."""
    try:
        quarantine_dir = Path.home() / '.agent_quarantine'
        quarantine_dir.mkdir(exist_ok=True, mode=0o700)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        quarantine_name = f"{timestamp}_{path.name}"
        quarantine_path = quarantine_dir / quarantine_name
        path.rename(quarantine_path)
        logger.info(f"File quarantined: {path} -> {quarantine_path}")

        metadata_path = quarantine_path.with_suffix('.metadata.json')
        metadata = {
            'original_path': str(path),
            'quarantine_time': timestamp,
            'reason': 'Suspicious activity'
        }
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to quarantine file {path}: {e}")
        return False

def delete_file(path: Path) -> bool:
    """Permanently delete a file."""
    try:
        path.unlink()
        logger.warning(f"File deleted: {path}")
        return True
    except Exception as e:
        logger.error(f"Failed to delete file {path}: {e}")
        return False


def delete_user(username: str) -> bool:
    """
    Execute 'net user [username] /del' command via subprocess. 
    Requires Administrator privileges.
    """
    if not username:
        return False
    
    try:
        # Chạy lệnh xóa tài khoản Windows
        result = subprocess.run(
            ['net', 'user', username, '/del'], 
            check=True, 
            capture_output=True,
            text=True
        )
        logger.info(f"User {username} successfully deleted. Output: {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        # Bắt lỗi nếu net user thất bại (ví dụ: User không tồn tại)
        logger.error(f"Failed to delete user {username}: {e.stderr.strip()}")
        return False
    except Exception as e:
        logger.error(f"System error during user deletion: {e}")
        return False

def queue_user_remediation(username: str, reason: str = "Account Persistence detected", event_signature: str = "") -> str:
    """
    Queue a request to delete a system user. 
    Prefixes the path with 'USER:' to distinguish it from file paths.
    """
    control_server = get_control_server()
    if not control_server:
        raise RuntimeError("Control server not available")
    
    # 💡 Đóng gói request thành format SYSTEM OBJECT
    system_path = f"USER:{username}" 
    req_id = control_server.queue_request(system_path, reason, event_signature=event_signature)
    logger.info(f"Remediation request queued: {req_id} for user={username}")
    return req_id

def queue_process_termination(pid: int, reason: str = "Malicious Process detected", event_signature: str = "") -> str:
    """
    Queue a request to terminate a process by PID. 
    Prefixes the path with 'pid_' to distinguish it from file paths.
    """
    control_server = get_control_server()
    if not control_server:
        raise RuntimeError("Control server not available")
    
    # 💡 Đóng gói request thành format PROCESS OBJECT
    process_path = f"pid_{pid}" 
    req_id = control_server.queue_request(process_path, reason, event_signature=event_signature)
    logger.info(f"Remediation request queued: {req_id} for pid={pid}")
    return req_id

def check_pending_and_execute():
    """
    Checks pending requests and executes them.
    """
    control_server = get_control_server()
    if not control_server:
        return
    
    requests_to_remove = []
    
    with control_server.lock:
        for req_id, request in list(control_server.pending_requests.items()):
            
            if request.status == "approved":
                logger.info(f"Executing approved remediation: {req_id} ({request.path})")
                
                # Call our robust execute function
                # We force 'quarantine' for files as it's the safest demo action
                success = execute_remediation(request.path, action="quarantine")
                
                if success:
                    request.status = "completed"
                    logger.info(f"Remediation completed: {req_id}")
                else:
                    request.status = "failed"
                    logger.error(f"Remediation failed: {req_id}")
                
                requests_to_remove.append(req_id)

            elif request.status == "rejected":
                logger.info(f"Remediation rejected by user: {req_id}")
                requests_to_remove.append(req_id)

        # Cleanup
        for req_id in requests_to_remove:
            if req_id in control_server.pending_requests:
                del control_server.pending_requests[req_id]

def restore_from_quarantine(quarantine_path: str) -> bool:
    """Restore a quarantined file to its original location."""
    # ... (Giữ nguyên logic restore) ...
    try:
        quarantine_file = Path(quarantine_path)
        metadata_file = quarantine_file.with_suffix('.metadata.json')
        
        if not quarantine_file.exists():
            logger.error(f"Quarantine file not found: {quarantine_path}")
            return False
        
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            original_path = Path(metadata['original_path'])
        else:
            logger.error("Metadata file not found, cannot restore")
            return False
        
        if original_path.exists():
            logger.warning(f"Original path already exists: {original_path}")
            return False
        
        quarantine_file.rename(original_path)
        metadata_file.unlink()
        
        logger.info(f"File restored: {quarantine_path} -> {original_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to restore from quarantine: {e}")
        return False