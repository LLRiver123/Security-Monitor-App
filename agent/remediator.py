import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

from agent.control import get_control_server

logger = logging.getLogger(__name__)


def confirm_and_disable_path(path: str, reason: str = "Suspicious activity detected") -> str:
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
    req_id = control_server.queue_request(path, reason)
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
    """
    Disable a file by removing execute permissions (Unix) or renaming (Windows)
    
    Args:
        path: Path object to disable
    
    Returns:
        True if successful
    """
    try:
        if os.name == 'nt':  # Windows
            # Rename file to .disabled
            disabled_path = path.with_suffix(path.suffix + '.disabled')
            
            if disabled_path.exists():
                logger.warning(f"Disabled version already exists: {disabled_path}")
                return False
            
            path.rename(disabled_path)
            logger.info(f"File disabled: {path} -> {disabled_path}")
            return True
            
        else:  # Unix-like
            # Remove execute permissions
            current_mode = path.stat().st_mode
            new_mode = current_mode & ~0o111  # Remove execute bits
            path.chmod(new_mode)
            logger.info(f"Execute permissions removed: {path}")
            return True
            
    except Exception as e:
        logger.error(f"Failed to disable file {path}: {e}")
        return False


def quarantine_file(path: Path) -> bool:
    """
    Move file to quarantine directory
    
    Args:
        path: Path object to quarantine
    
    Returns:
        True if successful
    """
    try:
        # Create quarantine directory
        quarantine_dir = Path.home() / '.agent_quarantine'
        quarantine_dir.mkdir(exist_ok=True, mode=0o700)
        
        # Generate unique name in quarantine
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        quarantine_name = f"{timestamp}_{path.name}"
        quarantine_path = quarantine_dir / quarantine_name
        
        # Move file
        path.rename(quarantine_path)
        logger.info(f"File quarantined: {path} -> {quarantine_path}")
        
        # Write metadata
        metadata_path = quarantine_path.with_suffix('.metadata.json')
        metadata = {
            'original_path': str(path),
            'quarantine_time': timestamp,
            'reason': 'Suspicious activity'
        }
        
        import json
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to quarantine file {path}: {e}")
        return False


def delete_file(path: Path) -> bool:
    """
    Permanently delete a file (use with extreme caution)
    
    Args:
        path: Path object to delete
    
    Returns:
        True if successful
    """
    try:
        path.unlink()
        logger.warning(f"File deleted: {path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to delete file {path}: {e}")
        return False


def check_pending_and_execute():
    """
    Check for approved remediation requests and execute them.
    This should be called periodically from the main agent loop.
    """
    control_server = get_control_server()
    
    if not control_server:
        return
    
    with control_server.lock:
        for req_id, request in list(control_server.pending_requests.items()):
            if request.status == "approved":
                logger.info(f"Executing approved remediation: {req_id}")
                
                success = execute_remediation(request.path)
                
                if success:
                    request.status = "completed"
                    logger.info(f"Remediation completed: {req_id}")
                else:
                    request.status = "failed"
                    logger.error(f"Remediation failed: {req_id}")
            
            elif request.status == "rejected":
                logger.info(f"Remediation rejected by user: {req_id}")
                # Could remove from dict or keep for audit trail
                
            # Clean up old completed/rejected requests
            # (In production, might want to keep for audit log)


from datetime import datetime

def restore_from_quarantine(quarantine_path: str) -> bool:
    """
    Restore a quarantined file to its original location
    
    Args:
        quarantine_path: Path to quarantined file
    
    Returns:
        True if successful
    """
    try:
        quarantine_file = Path(quarantine_path)
        metadata_file = quarantine_file.with_suffix('.metadata.json')
        
        if not quarantine_file.exists():
            logger.error(f"Quarantine file not found: {quarantine_path}")
            return False
        
        # Read metadata to get original path
        if metadata_file.exists():
            import json
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            original_path = Path(metadata['original_path'])
        else:
            logger.error("Metadata file not found, cannot restore")
            return False
        
        # Restore file
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