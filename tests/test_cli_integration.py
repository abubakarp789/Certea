"""
Tests for CLI Module

Tests for command-line interface functionality including
all commands and error handling.
"""

import pytest
import tempfile
import os
import sys
import json
from unittest.mock import patch, MagicMock
from io import StringIO

from src.cli import CLI
from src.exceptions import (
    KeyManagementError,
    SignatureError,
    VerificationError,
    CertificateError
)


class TestCLICreation:
    """Tests for CLI initialization."""
    
    def test_cli_initialization(self):
        """Should create CLI instance with all services."""
        cli = CLI()
        
        assert cli.key_manager is not None
        assert cli.signature_service is not None
        assert cli.logger is not None
        assert cli.parser is not None


class TestCLIArgParsing:
    """Tests for argument parsing."""
    
    def test_generate_keys_command(self):
        """Should parse generate-keys command."""
        cli = CLI()
        args = cli.parser.parse_args([
            'generate-keys',
            '--output-dir', '/tmp'
        ])
        
        assert args.command == 'generate-keys'
        assert args.output_dir == '/tmp'
        assert args.key_size == 2048
    
    def test_sign_command(self):
        """Should parse sign command."""
        cli = CLI()
        args = cli.parser.parse_args([
            'sign',
            '--message', 'test message',
            '--private-key', '/path/to/key',
            '--output', '/path/to/output'
        ])
        
        assert args.command == 'sign'
        assert args.message == 'test message'
        assert args.private_key == '/path/to/key'
        assert args.output == '/path/to/output'
    
    def test_sign_file_command(self):
        """Should parse sign-file command."""
        cli = CLI()
        args = cli.parser.parse_args([
            'sign-file',
            '--file', '/path/to/file',
            '--private-key', '/path/to/key',
            '--output', '/path/to/output'
        ])
        
        assert args.command == 'sign-file'
        assert args.file == '/path/to/file'
    
    def test_verify_command(self):
        """Should parse verify command."""
        cli = CLI()
        args = cli.parser.parse_args([
            'verify',
            '--message', 'test message',
            '--signature', '/path/to/sig',
            '--public-key', '/path/to/pub'
        ])
        
        assert args.command == 'verify'
    
    def test_verify_file_command(self):
        """Should parse verify-file command."""
        cli = CLI()
        args = cli.parser.parse_args([
            'verify-file',
            '--file', '/path/to/file',
            '--signature', '/path/to/sig',
            '--public-key', '/path/to/pub'
        ])
        
        assert args.command == 'verify-file'
    
    def test_show_logs_command(self):
        """Should parse show-logs command."""
        cli = CLI()
        args = cli.parser.parse_args([
            'show-logs'
        ])
        
        assert args.command == 'show-logs'
    
    def test_create_ca_command(self):
        """Should parse create-ca command."""
        cli = CLI()
        args = cli.parser.parse_args([
            'create-ca',
            '--output-dir', '/tmp'
        ])
        
        assert args.command == 'create-ca'
    
    def test_sign_certificate_command(self):
        """Should parse sign-certificate command."""
        cli = CLI()
        args = cli.parser.parse_args([
            'sign-certificate',
            '--public-key', '/path/to/pub',
            '--ca-key', '/path/to/ca',
            '--subject', 'test',
            '--output', '/path/to/out'
        ])
        
        assert args.command == 'sign-certificate'
        assert args.subject == 'test'
    
    def test_verify_certificate_command(self):
        """Should parse verify-certificate command."""
        cli = CLI()
        args = cli.parser.parse_args([
            'verify-certificate',
            '--certificate', '/path/to/cert',
            '--ca-public-key', '/path/to/ca'
        ])
        
        assert args.command == 'verify-certificate'


class TestCLIGenerateKeys:
    """Tests for generate-keys command."""
    
    def test_cmd_generate_keys_success(self, tmp_path):
        """Should generate keys successfully."""
        cli = CLI()
        
        # Mock the key manager to avoid actual key generation
        with patch.object(cli.key_manager, 'generate_key_pair') as mock_gen, \
             patch.object(cli.key_manager, 'save_private_key') as mock_save_priv, \
             patch.object(cli.key_manager, 'save_public_key') as mock_save_pub:
            
            # Mock key generation
            mock_gen.return_value = (MagicMock(), MagicMock())
            
            # Create args
            class Args:
                output_dir = str(tmp_path)
                passphrase = None
                key_size = 2048
            
            args = Args()
            
            result = cli.cmd_generate_keys(args)
            
            assert result == 0
            mock_gen.assert_called_once_with(2048)
            mock_save_priv.assert_called_once()
            mock_save_pub.assert_called_once()
    
    def test_cmd_generate_keys_with_passphrase(self, tmp_path):
        """Should generate keys with passphrase."""
        cli = CLI()
        
        with patch.object(cli.key_manager, 'generate_key_pair') as mock_gen, \
             patch.object(cli.key_manager, 'save_private_key') as mock_save_priv, \
             patch.object(cli.key_manager, 'save_public_key') as mock_save_pub:
            
            mock_gen.return_value = (MagicMock(), MagicMock())
            
            class Args:
                output_dir = str(tmp_path)
                passphrase = "testpass"
                key_size = 2048
            
            args = Args()
            
            result = cli.cmd_generate_keys(args)
            
            assert result == 0
            # Verify that passphrase was passed to save_private_key
            mock_save_priv.assert_called_once()
    
    def test_cmd_generate_keys_validation_error(self):
        """Should handle validation errors."""
        cli = CLI()
        
        class Args:
            output_dir = ""  # Invalid directory
            passphrase = None
            key_size = 2048
        
        args = Args()
        
        # Capture stderr
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        
        try:
            result = cli.cmd_generate_keys(args)
            assert result == 1
        finally:
            sys.stderr = old_stderr
    
    def test_cmd_generate_keys_key_error(self, tmp_path):
        """Should handle key management errors."""
        cli = CLI()
        
        with patch.object(cli.key_manager, 'generate_key_pair') as mock_gen:
            mock_gen.side_effect = KeyManagementError("Key generation failed")
            
            class Args:
                output_dir = str(tmp_path)
                passphrase = None
                key_size = 2048
            
            args = Args()
            
            old_stderr = sys.stderr
            sys.stderr = StringIO()
            
            try:
                result = cli.cmd_generate_keys(args)
                assert result == 1
            finally:
                sys.stderr = old_stderr


class TestCLISign:
    """Tests for sign command."""
    
    def test_cmd_sign_success(self, tmp_path):
        """Should sign message successfully."""
        cli = CLI()
        
        with patch.object(cli.key_manager, 'load_private_key') as mock_load_key, \
             patch.object(cli.signature_service, 'sign_message') as mock_sign:
            
            # Mock key and signature result
            mock_load_key.return_value = MagicMock()
            mock_sign_result = MagicMock()
            mock_sign_result.message_digest = "abc123"
            mock_sign_result.padding_scheme = "PSS"
            mock_sign_result.timestamp.isoformat.return_value = "2025-01-01T00:00:00"
            mock_sign_result.to_file = MagicMock()  # Mock the to_file method
            mock_sign.return_value = mock_sign_result
            
            class Args:
                message = "test message"
                private_key = "/path/to/key"
                output = str(tmp_path / "output.sig")
                passphrase = None
                padding = "PSS"
            
            args = Args()
            
            result = cli.cmd_sign(args)
            
            assert result == 0
            mock_load_key.assert_called_once()
            mock_sign.assert_called_once()
    
    def test_cmd_sign_file_success(self, tmp_path):
        """Should sign file successfully."""
        cli = CLI()
        
        # Create the test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        with patch.object(cli.key_manager, 'load_private_key') as mock_load_key, \
             patch.object(cli.signature_service, 'sign_file') as mock_sign:
            
            mock_load_key.return_value = MagicMock()
            mock_sign_result = MagicMock()
            mock_sign_result.message_digest = "abc123"
            mock_sign_result.padding_scheme = "PSS"
            mock_sign_result.timestamp.isoformat.return_value = "2025-01-01T00:00:00"
            mock_sign_result.to_file = MagicMock()
            mock_sign.return_value = mock_sign_result
            
            class Args:
                file = str(test_file)
                private_key = "/path/to/key"
                output = str(tmp_path / "output.sig")
                passphrase = None
                padding = "PSS"
            
            args = Args()
            
            result = cli.cmd_sign_file(args)
            
            assert result == 0
            mock_load_key.assert_called_once()
            mock_sign.assert_called_once()


class TestCLIVerify:
    """Tests for verify command."""
    
    def test_cmd_verify_success(self, tmp_path):
        """Should verify signature successfully."""
        cli = CLI()
        
        # Create the signature file
        sig_file = tmp_path / "sig.sig"
        sig_file.write_text('{"signature": "test"}')
        
        with patch.object(cli.key_manager, 'load_public_key') as mock_load_pub, \
             patch('src.cli.SignatureResult') as mock_result_class, \
             patch.object(cli.signature_service, 'verify_signature') as mock_verify, \
             patch.object(cli.logger, 'log_verification') as mock_log:
            
            # Mock public key
            mock_load_pub.return_value = MagicMock()
            
            # Mock signature result
            mock_sig_result = MagicMock()
            mock_sig_result.signature = b"test_signature"
            mock_result_class.from_file.return_value = mock_sig_result
            
            # Mock verification result
            mock_verify_result = MagicMock()
            mock_verify_result.is_valid = True
            mock_verify_result.message_digest = "abc123"
            mock_verify_result.timestamp.isoformat.return_value = "2025-01-01T00:00:00"
            mock_verify.return_value = mock_verify_result
            
            class Args:
                message = "test message"
                signature = str(sig_file)
                public_key = "/path/to/pub"
                padding = "PSS"
            
            args = Args()
            
            result = cli.cmd_verify(args)
            
            assert result == 0
            mock_load_pub.assert_called_once()
            mock_verify.assert_called_once()
    
    def test_cmd_verify_invalid_signature(self, tmp_path):
        """Should handle invalid signature."""
        cli = CLI()
        
        with patch.object(cli.key_manager, 'load_public_key') as mock_load_pub, \
             patch('src.cli.SignatureResult') as mock_result_class, \
             patch.object(cli.signature_service, 'verify_signature') as mock_verify:
            
            mock_load_pub.return_value = MagicMock()
            mock_sig_result = MagicMock()
            mock_sig_result.signature = b"test_signature"
            mock_result_class.from_file.return_value = mock_sig_result
            
            mock_verify_result = MagicMock()
            mock_verify_result.is_valid = False
            mock_verify_result.error_message = "Invalid signature"
            mock_verify_result.timestamp.isoformat.return_value = "2025-01-01T00:00:00"
            mock_verify.return_value = mock_verify_result
            
            class Args:
                message = "test message"
                signature = str(tmp_path / "sig.sig")
                public_key = "/path/to/pub"
                padding = "PSS"
            
            args = Args()
            
            result = cli.cmd_verify(args)
            
            assert result == 1  # Should return 1 for invalid signature


class TestCLIShowLogs:
    """Tests for show-logs command."""
    
    def test_cmd_show_logs_success(self):
        """Should show logs successfully."""
        cli = CLI()
        
        with patch.object(cli.logger, 'get_logs') as mock_get_logs:
            # Mock log entries
            mock_log1 = MagicMock()
            mock_log1.timestamp.isoformat.return_value = "2025-01-01T00:00:00"
            mock_log1.result = True
            mock_log1.message_id = "msg123"
            mock_log1.signature_id = "sig123"
            mock_log1.padding_scheme = "PSS"
            
            mock_get_logs.return_value = [mock_log1]
            
            class Args:
                start_date = None
                end_date = None
            
            args = Args()
            
            result = cli.cmd_show_logs(args)
            
            assert result == 0
            mock_get_logs.assert_called_once_with(None, None)
    
    def test_cmd_show_logs_no_entries(self):
        """Should handle case with no logs."""
        cli = CLI()
        
        with patch.object(cli.logger, 'get_logs') as mock_get_logs:
            mock_get_logs.return_value = []
            
            class Args:
                start_date = None
                end_date = None
            
            args = Args()
            
            result = cli.cmd_show_logs(args)
            
            assert result == 0
    
    def test_cmd_show_logs_invalid_date(self):
        """Should handle invalid date format."""
        cli = CLI()
        
        class Args:
            start_date = "invalid-date"
            end_date = None
        
        args = Args()
        
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        
        try:
            result = cli.cmd_show_logs(args)
            assert result == 1
        finally:
            sys.stderr = old_stderr


class TestCLICertificateCommands:
    """Tests for certificate-related commands."""
    
    def test_cmd_create_ca_success(self, tmp_path):
        """Should create CA successfully."""
        cli = CLI()
        
        with patch.object(cli.key_manager, 'generate_key_pair') as mock_gen, \
             patch.object(cli.key_manager, 'save_private_key') as mock_save_priv, \
             patch.object(cli.key_manager, 'save_public_key') as mock_save_pub:
            
            mock_gen.return_value = (MagicMock(), MagicMock())
            
            class Args:
                output_dir = str(tmp_path)
                passphrase = None
            
            args = Args()
            
            result = cli.cmd_create_ca(args)
            
            assert result == 0
            mock_gen.assert_called_once()
            mock_save_priv.assert_called_once()
            mock_save_pub.assert_called_once()
    
    def test_cmd_sign_certificate_success(self, tmp_path):
        """Should sign certificate successfully."""
        cli = CLI()
        
        # Create the required files
        pub_file = tmp_path / "pub.pem"
        pub_file.write_text("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----")
        ca_file = tmp_path / "ca.pem"
        ca_file.write_text("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----")
        
        with patch.object(cli.key_manager, 'load_private_key') as mock_load_ca, \
             patch.object(cli.key_manager, 'load_public_key') as mock_load_pub, \
             patch('src.cli.CertificateAuthority') as mock_ca_class, \
             patch('builtins.open', create=True) as mock_open:
            
            mock_ca_instance = MagicMock()
            mock_cert = MagicMock()
            mock_cert.to_dict.return_value = {"subject": "test"}
            mock_cert.subject = "Test Subject"
            mock_cert.issuer = "CA"
            mock_cert.valid_from = MagicMock()
            mock_cert.valid_from.isoformat.return_value = "2025-01-01T00:00:00"
            mock_cert.valid_until = MagicMock()
            mock_cert.valid_until.isoformat.return_value = "2026-01-01T00:00:00"
            mock_ca_instance.sign_public_key.return_value = mock_cert
            mock_ca_class.return_value = mock_ca_instance
            
            mock_priv_key = MagicMock()
            mock_priv_key.public_key.return_value = MagicMock()
            mock_load_ca.return_value = mock_priv_key
            mock_load_pub.return_value = MagicMock()
            
            class Args:
                public_key = str(pub_file)
                ca_key = str(ca_file)
                subject = "Test Subject"
                output = str(tmp_path / "cert.json")
                days = 365
                passphrase = None
            
            args = Args()
            
            result = cli.cmd_sign_certificate(args)
            
            assert result == 0
            mock_ca_instance.sign_public_key.assert_called_once()
    
    def test_cmd_verify_certificate_success(self, tmp_path):
        """Should verify certificate successfully."""
        cli = CLI()
        
        # Create the required files
        cert_file = tmp_path / "cert.json"
        cert_file.write_text('{"subject": "test"}')
        ca_pub_file = tmp_path / "ca.pub"
        ca_pub_file.write_text("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----")
        
        with patch.object(cli.key_manager, 'load_public_key') as mock_load_pub, \
             patch('src.cli.Certificate') as mock_cert_class, \
             patch('src.cli.CertificateAuthority') as mock_ca_class:
            
            # Mock certificate
            mock_cert = MagicMock()
            mock_cert.subject = "test"
            mock_cert.issuer = "CA"
            mock_cert.valid_from = MagicMock()
            mock_cert.valid_from.isoformat.return_value = "2025-01-01T00:00:00"
            mock_cert.valid_until = MagicMock()
            mock_cert.valid_until.isoformat.return_value = "2026-01-01T00:00:00"
            mock_cert_class.from_dict.return_value = mock_cert
            
            # Mock CA
            mock_ca_instance = MagicMock()
            mock_ca_instance.verify_certificate.return_value = True
            mock_ca_class.return_value = mock_ca_instance
            
            mock_load_pub.return_value = MagicMock()
            
            class Args:
                certificate = str(cert_file)
                ca_public_key = str(ca_pub_file)
            
            args = Args()
            
            result = cli.cmd_verify_certificate(args)
            
            assert result == 0
            mock_ca_instance.verify_certificate.assert_called_once()


class TestCLIRunMethod:
    """Tests for CLI run method."""
    
    def test_run_with_no_command(self):
        """Should show help when no command provided."""
        cli = CLI()
        
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        
        try:
            result = cli.run([])  # No command provided
            assert result == 1
        finally:
            sys.stderr = old_stderr
    
    def test_run_with_invalid_command(self):
        """Should show help for invalid command."""
        cli = CLI()
        
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        
        try:
            result = cli.run(['invalid-command'])
            assert result == 1
        finally:
            sys.stderr = old_stderr


class TestCLIPassphraseHandling:
    """Tests for passphrase handling."""
    
    def test_get_passphrase_with_provided(self):
        """Should return provided passphrase."""
        cli = CLI()
        
        result = cli._get_passphrase("provided_pass")
        assert result == "provided_pass"
    
    def test_get_passphrase_none_provided(self):
        """Should handle None passphrase."""
        cli = CLI()
        
        # Patch input and getpass to avoid actual prompts
        with patch('src.cli.input', return_value='n'), \
             patch('src.cli.getpass.getpass', return_value=None):
            result = cli._get_passphrase(None)
            assert result is None
    
    def test_prompt_passphrase_if_needed_with_provided(self):
        """Should return provided passphrase."""
        cli = CLI()
        
        result = cli._prompt_passphrase_if_needed("provided_pass")
        assert result == "provided_pass"
    
    def test_prompt_passphrase_if_needed_none_provided(self):
        """Should handle None passphrase."""
        cli = CLI()
        
        with patch('src.cli.getpass.getpass', return_value=""):
            result = cli._prompt_passphrase_if_needed(None)
            assert result is None