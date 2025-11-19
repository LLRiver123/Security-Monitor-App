import logging
import os
import subprocess
from pathlib import Path
from typing import Optional
from datetime import datetime
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


def execute_remediation(path: str, action: str = "disable") -> bool:
    """
    Execute the actual remediation action on a file path.
    This should only be called after user approval.
    
    Args:
        path: File path to remediate
        action: Type of action ('disable', 'quarantine', 'delete')
    
    Returns:
        True if successful, False otherwise
    """
    try:
        path_obj = Path(path)
        
        if not path_obj.exists():
            logger.warning(f"Path does not exist: {path}")
            return False
        
        if action == "disable":
            return disable_file(path_obj)
        elif action == "quarantine":
            return quarantine_file(path_obj)
        elif action == "delete":
            return delete_file(path_obj)
        else:
            logger.error(f"Unknown remediation action: {action}")
            return False
            
    except Exception as e:
        logger.error(f"Remediation execution failed for {path}: {e}")
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
        # else:  # Unix-like
        #     current_mode = path.stat().st_mode
        #     new_mode = current_mode & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH
        #     path.chmod(new_mode)        
        #     logger.info(f"Execute permissions removed: {path}")
        #     return True                 
    except Exception as e:
        logger.error(f"Failed to disable file {path}: {e}")
        return False

def quarantine_file(path: Path) -> bool:
    """Move file to quarantine directory."""
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


def execute_remediation(path: str, action: str = "disable") -> bool:
    """
    Execute the actual remediation action. Dựa vào prefix để phân loại.
    """
    if path.startswith("USER:"):
        # 💡 XỬ LÝ XÓA TÀI KHOẢN
        username = path.replace("USER:", "")
        logger.warning(f"Executing system remediation: Deleting user {username}")
        return delete_user(username)
        
    else:
        # XỬ LÝ FILE (Giữ nguyên logic cũ)
        try:
            path_obj = Path(path)
            
            if not path_obj.exists():
                logger.warning(f"Path does not exist: {path}")
                return False
            
            if action == "disable":
                return disable_file(path_obj)
            elif action == "quarantine":
                return quarantine_file(path_obj)
            elif action == "delete":
                return delete_file(path_obj)
            else:
                logger.error(f"Unknown remediation action: {action}")
                return False
        except Exception as e:
            logger.error(f"Remediation execution failed for file {path}: {e}")
            return False


def check_pending_and_execute():
    control_server = get_control_server()
    if not control_server:
        return
    
    requests_to_remove = []

    with control_server.lock:
        for req_id, request in list(control_server.pending_requests.items()):
            if request.status == "approved":
                logger.info(f"Executing approved remediation: {req_id} ({request.path})")
                
                # 💡 PHÂN LOẠI ĐỐI TƯỢNG VÀ THỰC THI CHỈ MỘT LẦN
                
                # 1. Trường hợp System Object (User)
                if request.path.startswith("USER:"):
                    username = request.path.replace("USER:", "")
                    logger.warning(f"Executing user deletion for: {username}")
                    success = delete_user(username) # 🛑 GỌI THẲNG HÀM XỬ LÝ USER
                    
                # 2. Trường hợp File Object
                else:
                    # Giao cho execute_remediation xử lý File Remediation
                    # Giả định action là "quarantine" để demo rõ hơn
                    success = execute_remediation(request.path, action="quarantine") 
                
                # Cập nhật trạng thái
                if success:
                    request.status = "completed"
                    logger.info(f"Remediation completed: {req_id}")
                    requests_to_remove.append(req_id)
                else:
                    request.status = "failed"
                    logger.error(f"Remediation failed: {req_id}")
                    requests_to_remove.append(req_id)
            
            elif request.status == "rejected":
                logger.info(f"Remediation rejected by user: {req_id}")
                requests_to_remove.append(req_id)
            # Giữ nguyên logic dọn dẹp (nếu có)
        for req_id in requests_to_remove:
            if req_id in control_server.pending_requests:
                del control_server.pending_requests[req_id]
                logger.debug(f"Removed processed request {req_id} from pending queue.")

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