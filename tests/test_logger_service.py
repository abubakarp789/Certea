"""
Unit tests for VerificationLogger component
"""

import os
import tempfile
import json
from datetime import datetime, timedelta
import pytest
from src.logger_service import VerificationLogger
from src.models import LogEntry


class TestVerificationLogger:
    """Test suite for VerificationLogger class"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "test_logs.json")
        self.logger = VerificationLogger(log_file=self.log_file)
    
    def teardown_method(self):
        """Clean up test files"""
        # Remove all files in temp directory
        for filename in os.listdir(self.temp_dir):
            filepath = os.path.join(self.temp_dir, filename)
            try:
                os.remove(filepath)
            except Exception:
                pass
        try:
            os.rmdir(self.temp_dir)
        except Exception:
            pass
    
    def test_log_entry_creation(self):
        """Test creating a log entry"""
        timestamp = datetime.now()
        message_id = "abc123def4567890"
        signature_id = "xyz789uvw1234567"
        
        self.logger.log_verification(
            message_id=message_id,
            signature_id=signature_id,
            result=True,
            timestamp=timestamp,
            padding_scheme="PSS"
        )
        
        # Verify log file exists
        assert os.path.exists(self.log_file)
        
        # Read and verify log content
        with open(self.log_file, 'r') as f:
            logs = json.load(f)
        
        assert len(logs) == 1
        assert logs[0]['message_id'] == message_id
        assert logs[0]['signature_id'] == signature_id
        assert logs[0]['result'] is True
        assert logs[0]['padding_scheme'] == "PSS"
    
    def test_log_multiple_entries(self):
        """Test logging multiple verification attempts"""
        timestamp1 = datetime.now()
        timestamp2 = timestamp1 + timedelta(seconds=10)
        
        self.logger.log_verification(
            message_id="msg001",
            signature_id="sig001",
            result=True,
            timestamp=timestamp1,
            padding_scheme="PSS"
        )
        
        self.logger.log_verification(
            message_id="msg002",
            signature_id="sig002",
            result=False,
            timestamp=timestamp2,
            padding_scheme="PKCS1"
        )
        
        # Verify both entries are logged
        with open(self.log_file, 'r') as f:
            logs = json.load(f)
        
        assert len(logs) == 2
        assert logs[0]['message_id'] == "msg001"
        assert logs[1]['message_id'] == "msg002"
    
    def test_log_retrieval(self):
        """Test retrieving all logs"""
        timestamp1 = datetime.now()
        timestamp2 = timestamp1 + timedelta(seconds=10)
        
        self.logger.log_verification(
            message_id="msg001",
            signature_id="sig001",
            result=True,
            timestamp=timestamp1,
            padding_scheme="PSS"
        )
        
        self.logger.log_verification(
            message_id="msg002",
            signature_id="sig002",
            result=False,
            timestamp=timestamp2,
            padding_scheme="PKCS1"
        )
        
        # Retrieve logs
        logs = self.logger.get_logs()
        
        assert len(logs) == 2
        assert isinstance(logs[0], LogEntry)
        assert isinstance(logs[1], LogEntry)
        assert logs[0].message_id == "msg001"
        assert logs[1].message_id == "msg002"
    
    def test_date_filtering_start_date(self):
        """Test log retrieval with start date filter"""
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        
        # Log entries at different times
        self.logger.log_verification(
            message_id="msg001",
            signature_id="sig001",
            result=True,
            timestamp=base_time,
            padding_scheme="PSS"
        )
        
        self.logger.log_verification(
            message_id="msg002",
            signature_id="sig002",
            result=True,
            timestamp=base_time + timedelta(hours=1),
            padding_scheme="PSS"
        )
        
        self.logger.log_verification(
            message_id="msg003",
            signature_id="sig003",
            result=True,
            timestamp=base_time + timedelta(hours=2),
            padding_scheme="PSS"
        )
        
        # Filter logs starting from 1 hour after base_time
        start_date = base_time + timedelta(hours=1)
        logs = self.logger.get_logs(start_date=start_date)
        
        assert len(logs) == 2
        assert logs[0].message_id == "msg002"
        assert logs[1].message_id == "msg003"
    
    def test_date_filtering_end_date(self):
        """Test log retrieval with end date filter"""
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        
        # Log entries at different times
        self.logger.log_verification(
            message_id="msg001",
            signature_id="sig001",
            result=True,
            timestamp=base_time,
            padding_scheme="PSS"
        )
        
        self.logger.log_verification(
            message_id="msg002",
            signature_id="sig002",
            result=True,
            timestamp=base_time + timedelta(hours=1),
            padding_scheme="PSS"
        )
        
        self.logger.log_verification(
            message_id="msg003",
            signature_id="sig003",
            result=True,
            timestamp=base_time + timedelta(hours=2),
            padding_scheme="PSS"
        )
        
        # Filter logs ending at 1 hour after base_time
        end_date = base_time + timedelta(hours=1)
        logs = self.logger.get_logs(end_date=end_date)
        
        assert len(logs) == 2
        assert logs[0].message_id == "msg001"
        assert logs[1].message_id == "msg002"
    
    def test_date_filtering_range(self):
        """Test log retrieval with both start and end date filters"""
        base_time = datetime(2024, 1, 1, 12, 0, 0)
        
        # Log entries at different times
        for i in range(5):
            self.logger.log_verification(
                message_id=f"msg{i:03d}",
                signature_id=f"sig{i:03d}",
                result=True,
                timestamp=base_time + timedelta(hours=i),
                padding_scheme="PSS"
            )
        
        # Filter logs between 1 and 3 hours after base_time
        start_date = base_time + timedelta(hours=1)
        end_date = base_time + timedelta(hours=3)
        logs = self.logger.get_logs(start_date=start_date, end_date=end_date)
        
        assert len(logs) == 3
        assert logs[0].message_id == "msg001"
        assert logs[1].message_id == "msg002"
        assert logs[2].message_id == "msg003"
    
    def test_log_file_persistence(self):
        """Test that logs persist across logger instances"""
        timestamp = datetime.now()
        
        # Log with first logger instance
        self.logger.log_verification(
            message_id="msg001",
            signature_id="sig001",
            result=True,
            timestamp=timestamp,
            padding_scheme="PSS"
        )
        
        # Create new logger instance with same log file
        new_logger = VerificationLogger(log_file=self.log_file)
        
        # Retrieve logs from new instance
        logs = new_logger.get_logs()
        
        assert len(logs) == 1
        assert logs[0].message_id == "msg001"
    
    def test_clear_logs(self):
        """Test clearing all logs"""
        timestamp = datetime.now()
        
        # Add some log entries
        self.logger.log_verification(
            message_id="msg001",
            signature_id="sig001",
            result=True,
            timestamp=timestamp,
            padding_scheme="PSS"
        )
        
        self.logger.log_verification(
            message_id="msg002",
            signature_id="sig002",
            result=False,
            timestamp=timestamp,
            padding_scheme="PKCS1"
        )
        
        # Verify logs exist
        logs = self.logger.get_logs()
        assert len(logs) == 2
        
        # Clear logs
        self.logger.clear_logs()
        
        # Verify logs are cleared
        logs = self.logger.get_logs()
        assert len(logs) == 0
    
    def test_empty_log_retrieval(self):
        """Test retrieving logs when log file is empty"""
        logs = self.logger.get_logs()
        assert len(logs) == 0
        assert isinstance(logs, list)
    
    def test_log_with_failed_verification(self):
        """Test logging a failed verification"""
        timestamp = datetime.now()
        
        self.logger.log_verification(
            message_id="msg001",
            signature_id="sig001",
            result=False,
            timestamp=timestamp,
            padding_scheme="PSS"
        )
        
        logs = self.logger.get_logs()
        assert len(logs) == 1
        assert logs[0].result is False
    
    def test_log_with_different_padding_schemes(self):
        """Test logging verifications with different padding schemes"""
        timestamp = datetime.now()
        
        self.logger.log_verification(
            message_id="msg001",
            signature_id="sig001",
            result=True,
            timestamp=timestamp,
            padding_scheme="PSS"
        )
        
        self.logger.log_verification(
            message_id="msg002",
            signature_id="sig002",
            result=True,
            timestamp=timestamp,
            padding_scheme="PKCS1"
        )
        
        logs = self.logger.get_logs()
        assert len(logs) == 2
        assert logs[0].padding_scheme == "PSS"
        assert logs[1].padding_scheme == "PKCS1"
