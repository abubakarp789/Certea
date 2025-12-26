"""
Tests for Validation Module

Tests for input validation functions including file paths,
key sizes, certificate dates, and size limits.
"""

import pytest
import os
import tempfile
from datetime import datetime, timedelta

from src.validation import (
    ValidationError,
    validate_file_path,
    validate_directory_path,
    validate_key_size,
    validate_certificate_dates,
    validate_validity_days,
    sanitize_string_input,
    validate_padding_scheme,
    validate_file_size,
    validate_message_length,
    validate_request_size
)


class TestValidateFilePath:
    """Tests for validate_file_path function."""
    
    def test_valid_file_path(self):
        """Should accept valid file path."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.close()  # Close the file handle first
            try:
                result = validate_file_path(f.name, must_exist=True)
                assert result is not None
                assert os.path.isabs(result)
            finally:
                os.unlink(f.name)
    
    def test_relative_path_converted_to_absolute(self):
        """Should convert relative path to absolute."""
        result = validate_file_path("somefile.txt")
        assert os.path.isabs(result)
    
    def test_empty_path_rejected(self):
        """Should reject empty file path."""
        with pytest.raises(ValidationError):
            validate_file_path("")
    
    def test_none_path_rejected(self):
        """Should reject None file path."""
        with pytest.raises(ValidationError):
            validate_file_path(None)
    
    def test_null_byte_rejected(self):
        """Should reject path with null bytes."""
        with pytest.raises(ValidationError):
            validate_file_path("file\x00.txt")
    
    def test_must_exist_fails_for_missing_file(self):
        """Should fail when must_exist=True and file doesn't exist."""
        with pytest.raises(ValidationError):
            validate_file_path("/nonexistent/path/file.txt", must_exist=True)
    
    def test_allow_create_for_new_files(self):
        """Should allow paths for files that don't exist yet."""
        result = validate_file_path("newfile.txt", allow_create=True)
        assert result is not None


class TestValidateDirectoryPath:
    """Tests for validate_directory_path function."""
    
    def test_valid_directory_path(self):
        """Should accept valid directory path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = validate_directory_path(tmpdir, must_exist=True)
            assert result is not None
            assert os.path.isdir(result)
    
    def test_empty_path_rejected(self):
        """Should reject empty directory path."""
        with pytest.raises(ValidationError):
            validate_directory_path("")
    
    def test_none_path_rejected(self):
        """Should reject None directory path."""
        with pytest.raises(ValidationError):
            validate_directory_path(None)
    
    def test_null_byte_rejected(self):
        """Should reject path with null bytes."""
        with pytest.raises(ValidationError):
            validate_directory_path("dir\x00name")
    
    def test_must_exist_fails_for_missing_dir(self):
        """Should fail when must_exist=True and directory doesn't exist."""
        with pytest.raises(ValidationError):
            validate_directory_path("/nonexistent/directory", must_exist=True)
    
    def test_create_if_missing(self):
        """Should create directory when create_if_missing=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = os.path.join(tmpdir, "new_subdir")
            result = validate_directory_path(new_dir, create_if_missing=True)
            assert os.path.isdir(result)


class TestValidateKeySize:
    """Tests for validate_key_size function."""
    
    def test_valid_key_sizes(self):
        """Should accept valid key sizes."""
        assert validate_key_size(2048) == 2048
        assert validate_key_size(3072) == 3072
        assert validate_key_size(4096) == 4096
    
    def test_minimum_key_size(self):
        """Should reject key sizes below 2048."""
        with pytest.raises(ValidationError):
            validate_key_size(1024)
        
        with pytest.raises(ValidationError):
            validate_key_size(512)
    
    def test_maximum_key_size(self):
        """Should reject key sizes above 16384."""
        with pytest.raises(ValidationError):
            validate_key_size(32768)
    
    def test_non_multiple_of_256(self):
        """Should reject key sizes not multiple of 256."""
        with pytest.raises(ValidationError):
            validate_key_size(2000)
        
        with pytest.raises(ValidationError):
            validate_key_size(2049)
    
    def test_non_integer_rejected(self):
        """Should reject non-integer key sizes."""
        with pytest.raises(ValidationError):
            validate_key_size("2048")
        
        with pytest.raises(ValidationError):
            validate_key_size(2048.5)


class TestValidateCertificateDates:
    """Tests for validate_certificate_dates function."""
    
    def test_valid_dates(self):
        """Should accept valid certificate dates."""
        now = datetime.now()
        valid_from = now
        valid_until = now + timedelta(days=365)
        
        result = validate_certificate_dates(valid_from, valid_until)
        assert result == (valid_from, valid_until)
    
    def test_valid_until_before_valid_from(self):
        """Should reject if valid_until is before valid_from."""
        now = datetime.now()
        valid_from = now
        valid_until = now - timedelta(days=1)
        
        with pytest.raises(ValidationError):
            validate_certificate_dates(valid_from, valid_until)
    
    def test_max_validity_days_enforced(self):
        """Should enforce maximum validity days."""
        now = datetime.now()
        valid_from = now
        valid_until = now + timedelta(days=1000)
        
        with pytest.raises(ValidationError):
            validate_certificate_dates(valid_from, valid_until, max_validity_days=365)
    
    def test_non_datetime_rejected(self):
        """Should reject non-datetime objects."""
        with pytest.raises(ValidationError):
            validate_certificate_dates("2025-01-01", datetime.now())
        
        with pytest.raises(ValidationError):
            validate_certificate_dates(datetime.now(), "2026-01-01")
    
    def test_same_dates_rejected(self):
        """Should reject if valid_from equals valid_until."""
        now = datetime.now()
        with pytest.raises(ValidationError):
            validate_certificate_dates(now, now)


class TestValidateValidityDays:
    """Tests for validate_validity_days function."""
    
    def test_valid_days(self):
        """Should accept valid day values."""
        assert validate_validity_days(1) == 1
        assert validate_validity_days(365) == 365
        assert validate_validity_days(36500) == 36500
    
    def test_zero_days_rejected(self):
        """Should reject zero days."""
        with pytest.raises(ValidationError):
            validate_validity_days(0)
    
    def test_negative_days_rejected(self):
        """Should reject negative days."""
        with pytest.raises(ValidationError):
            validate_validity_days(-1)
    
    def test_exceeds_maximum_rejected(self):
        """Should reject days exceeding maximum."""
        with pytest.raises(ValidationError):
            validate_validity_days(36501)
    
    def test_non_integer_rejected(self):
        """Should reject non-integer values."""
        with pytest.raises(ValidationError):
            validate_validity_days("365")


class TestSanitizeStringInput:
    """Tests for sanitize_string_input function."""
    
    def test_normal_string(self):
        """Should pass normal string unchanged."""
        result = sanitize_string_input("Hello World")
        assert result == "Hello World"
    
    def test_max_length_enforced(self):
        """Should enforce maximum length."""
        with pytest.raises(ValidationError):
            sanitize_string_input("x" * 1001, max_length=1000)
    
    def test_null_bytes_rejected(self):
        """Should reject null bytes."""
        with pytest.raises(ValidationError):
            sanitize_string_input("Hello\x00World")
    
    def test_newlines_rejected_by_default(self):
        """Should reject newlines when not allowed."""
        with pytest.raises(ValidationError):
            sanitize_string_input("Hello\nWorld")
    
    def test_newlines_allowed(self):
        """Should allow newlines when specified."""
        result = sanitize_string_input("Hello\nWorld", allow_newlines=True)
        assert "\n" in result
    
    def test_control_chars_removed(self):
        """Should remove control characters."""
        result = sanitize_string_input("Hello\x07World")
        assert "\x07" not in result
    
    def test_non_string_rejected(self):
        """Should reject non-string input."""
        with pytest.raises(ValidationError):
            sanitize_string_input(12345)


class TestValidatePaddingScheme:
    """Tests for validate_padding_scheme function."""
    
    def test_valid_schemes(self):
        """Should accept valid padding schemes."""
        assert validate_padding_scheme("PSS") == "PSS"
        assert validate_padding_scheme("PKCS1") == "PKCS1"
    
    def test_case_insensitive(self):
        """Should be case insensitive."""
        assert validate_padding_scheme("pss") == "PSS"
        assert validate_padding_scheme("pkcs1") == "PKCS1"
        assert validate_padding_scheme("Pss") == "PSS"
    
    def test_invalid_scheme_rejected(self):
        """Should reject invalid schemes."""
        with pytest.raises(ValidationError):
            validate_padding_scheme("INVALID")
        
        with pytest.raises(ValidationError):
            validate_padding_scheme("OAEP")
    
    def test_non_string_rejected(self):
        """Should reject non-string input."""
        with pytest.raises(ValidationError):
            validate_padding_scheme(123)


class TestValidateFileSize:
    """Tests for validate_file_size function."""
    
    def test_valid_size(self):
        """Should accept valid file size."""
        result = validate_file_size(1024)
        assert result == 1024
    
    def test_zero_size_accepted(self):
        """Should accept zero size."""
        result = validate_file_size(0)
        assert result == 0
    
    def test_exceeds_max_size_rejected(self):
        """Should reject size exceeding maximum."""
        # Use a very large size
        huge_size = 2 * 1024 * 1024 * 1024  # 2GB
        with pytest.raises(ValidationError):
            validate_file_size(huge_size, max_size_mb=1)
    
    def test_custom_max_size(self):
        """Should use custom max size when provided."""
        result = validate_file_size(1024 * 1024, max_size_mb=10)
        assert result == 1024 * 1024
    
    def test_negative_size_rejected(self):
        """Should reject negative size."""
        with pytest.raises(ValidationError):
            validate_file_size(-1)
    
    def test_non_integer_rejected(self):
        """Should reject non-integer size."""
        with pytest.raises(ValidationError):
            validate_file_size("1024")


class TestValidateMessageLength:
    """Tests for validate_message_length function."""
    
    def test_valid_message(self):
        """Should accept valid message."""
        result = validate_message_length("Hello World")
        assert result == "Hello World"
    
    def test_empty_message_accepted(self):
        """Should accept empty message."""
        result = validate_message_length("")
        assert result == ""
    
    def test_exceeds_max_length_rejected(self):
        """Should reject message exceeding maximum length."""
        with pytest.raises(ValidationError):
            validate_message_length("x" * 1001, max_length=1000)
    
    def test_custom_max_length(self):
        """Should use custom max length when provided."""
        result = validate_message_length("Hello", max_length=100)
        assert result == "Hello"
    
    def test_non_string_rejected(self):
        """Should reject non-string input."""
        with pytest.raises(ValidationError):
            validate_message_length(12345)


class TestValidateRequestSize:
    """Tests for validate_request_size function."""
    
    def test_valid_content_length(self):
        """Should accept valid content length."""
        result = validate_request_size(1024)
        assert result == 1024
    
    def test_delegates_to_validate_file_size(self):
        """Should use validate_file_size internally."""
        # This should reject since it's too large
        with pytest.raises(ValidationError):
            validate_request_size(-1)
