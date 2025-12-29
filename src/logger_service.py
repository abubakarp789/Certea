"""Logger service for verification audit trail."""

import json
import os
import threading
from datetime import datetime
from typing import List, Optional
from src.models import LogEntry


class VerificationLogger:
    """Handles logging of signature verification events.
    
    Attributes:
        log_file: Path to the JSON log file
        _lock: Thread lock for concurrent write safety
    """
    
    def __init__(self, log_file: str = "data/verification_logs.json"):
        """Initialize the verification logger.
        
        The verification logger maintains an audit trail of all signature
        verification attempts. This is important for:
        - Security auditing and compliance
        - Debugging verification issues
        - Tracking usage patterns
        - Non-repudiation (proving when verifications occurred)
        
        Args:
            log_file: Path to the log file (default: data/verification_logs.json)
        """
        self.log_file = log_file
        self._lock = threading.Lock()
        
        # Ensure the data directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # Create log file if it doesn't exist
        # Initialize with an empty JSON array
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                json.dump([], f)
    
    def log_verification(
        self,
        message_id: str,
        signature_id: str,
        result: bool,
        timestamp: datetime,
        padding_scheme: str
    ) -> None:
        """Log a verification attempt to the audit trail.
        
        This method appends a new log entry to the verification log file.
        The log is stored in JSON format for easy parsing and analysis.
        
        Note: Only the first 16 characters of message and signature hashes
        are stored to save space while still providing unique identification
        for most practical purposes.
        
        Args:
            message_id: First 16 chars of message hash (for identification)
            signature_id: First 16 chars of signature hash (for identification)
            result: Verification outcome (True for valid, False for invalid)
            timestamp: When the verification occurred
            padding_scheme: 'PSS' or 'PKCS1' (padding used for verification)
        """
        log_entry = LogEntry(
            timestamp=timestamp,
            message_id=message_id,
            signature_id=signature_id,
            result=result,
            padding_scheme=padding_scheme
        )
        
        # Use lock to ensure thread-safe writes
        with self._lock:
            # Read existing logs
            logs = self._read_logs()
            
            # Append new entry
            logs.append(log_entry.to_dict())
            
            # Write back to file
            with open(self.log_file, 'w') as f:
                json.dump(logs, f, indent=2)
    
    def get_logs(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[LogEntry]:
        """Retrieve verification logs with optional date filtering.
        
        This method reads the log file and returns log entries, optionally
        filtered by date range. This is useful for:
        - Auditing verification activity over a specific period
        - Investigating security incidents
        - Generating compliance reports
        
        Args:
            start_date: Optional start date for filtering (inclusive)
            end_date: Optional end date for filtering (inclusive)
            
        Returns:
            List of LogEntry objects in chronological order
        """
        logs = self._read_logs()
        
        # Convert to LogEntry objects
        log_entries = [LogEntry.from_dict(log) for log in logs]
        
        # Apply date filtering if specified
        if start_date is not None:
            log_entries = [
                entry for entry in log_entries
                if entry.timestamp >= start_date
            ]
        
        if end_date is not None:
            log_entries = [
                entry for entry in log_entries
                if entry.timestamp <= end_date
            ]
        
        return log_entries
    
    def clear_logs(self) -> None:
        """Clear all verification logs."""
        with self._lock:
            with open(self.log_file, 'w') as f:
                json.dump([], f)
    
    def _read_logs(self) -> List[dict]:
        """Read logs from the JSON file.
        
        Returns:
            List of log dictionaries
        """
        try:
            with open(self.log_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # If file doesn't exist or is corrupted, return empty list
            return []
