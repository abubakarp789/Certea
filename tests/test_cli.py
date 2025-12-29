"""Integration tests for CLI interface."""

import os
import json
import tempfile
import shutil
from pathlib import Path

import pytest

from src.cli import CLI


class TestCLIIntegration:
    """Integration tests for CLI commands."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test files."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def cli(self):
        """Create a CLI instance."""
        return CLI()
    
    def test_generate_keys_without_passphrase(self, cli, temp_dir, monkeypatch):
        """Test key generation without passphrase."""
        # Mock user input to decline passphrase
        monkeypatch.setattr('builtins.input', lambda _: 'n')
        
        # Run generate-keys command
        exit_code = cli.run([
            'generate-keys',
            '--output-dir', temp_dir,
            '--key-size', '2048'
        ])
        
        assert exit_code == 0
        
        # Verify keys were created
        private_key_path = os.path.join(temp_dir, 'private_key.pem')
        public_key_path = os.path.join(temp_dir, 'public_key.pem')
        
        assert os.path.exists(private_key_path)
        assert os.path.exists(public_key_path)
        
        # Verify key files have content
        with open(private_key_path, 'r') as f:
            private_key_content = f.read()
            assert '-----BEGIN PRIVATE KEY-----' in private_key_content
        
        with open(public_key_path, 'r') as f:
            public_key_content = f.read()
            assert '-----BEGIN PUBLIC KEY-----' in public_key_content
    
    def test_end_to_end_message_signing_and_verification(self, cli, temp_dir, monkeypatch):
        """Test complete workflow: generate keys, sign message, verify signature."""
        # Mock user input to decline passphrase
        monkeypatch.setattr('builtins.input', lambda _: 'n')
        monkeypatch.setattr('getpass.getpass', lambda _: '')
        
        # Step 1: Generate keys
        exit_code = cli.run([
            'generate-keys',
            '--output-dir', temp_dir
        ])
        assert exit_code == 0
        
        private_key_path = os.path.join(temp_dir, 'private_key.pem')
        public_key_path = os.path.join(temp_dir, 'public_key.pem')
        signature_path = os.path.join(temp_dir, 'signature.json')
        
        # Step 2: Sign a message
        test_message = "This is a test message for signing"
        exit_code = cli.run([
            'sign',
            '--message', test_message,
            '--private-key', private_key_path,
            '--output', signature_path,
            '--padding', 'PSS'
        ])
        assert exit_code == 0
        assert os.path.exists(signature_path)
        
        # Step 3: Verify the signature
        exit_code = cli.run([
            'verify',
            '--message', test_message,
            '--signature', signature_path,
            '--public-key', public_key_path,
            '--padding', 'PSS'
        ])
        assert exit_code == 0
        
        # Step 4: Verify with wrong message (should fail)
        exit_code = cli.run([
            'verify',
            '--message', 'Wrong message',
            '--signature', signature_path,
            '--public-key', public_key_path,
            '--padding', 'PSS'
        ])
        assert exit_code == 1
    
    def test_end_to_end_file_signing_and_verification(self, cli, temp_dir, monkeypatch):
        """Test complete workflow: generate keys, sign file, verify signature."""
        # Mock user input to decline passphrase
        monkeypatch.setattr('builtins.input', lambda _: 'n')
        monkeypatch.setattr('getpass.getpass', lambda _: '')
        
        # Step 1: Generate keys
        exit_code = cli.run([
            'generate-keys',
            '--output-dir', temp_dir
        ])
        assert exit_code == 0
        
        private_key_path = os.path.join(temp_dir, 'private_key.pem')
        public_key_path = os.path.join(temp_dir, 'public_key.pem')
        
        # Step 2: Create a test file
        test_file_path = os.path.join(temp_dir, 'test_file.txt')
        with open(test_file_path, 'w') as f:
            f.write("This is test file content for signing")
        
        signature_path = os.path.join(temp_dir, 'file_signature.json')
        
        # Step 3: Sign the file
        exit_code = cli.run([
            'sign-file',
            '--file', test_file_path,
            '--private-key', private_key_path,
            '--output', signature_path,
            '--padding', 'PKCS1'
        ])
        assert exit_code == 0
        assert os.path.exists(signature_path)
        
        # Step 4: Verify the file signature
        exit_code = cli.run([
            'verify-file',
            '--file', test_file_path,
            '--signature', signature_path,
            '--public-key', public_key_path,
            '--padding', 'PKCS1'
        ])
        assert exit_code == 0
        
        # Step 5: Modify the file and verify (should fail)
        with open(test_file_path, 'a') as f:
            f.write(" - modified")
        
        exit_code = cli.run([
            'verify-file',
            '--file', test_file_path,
            '--signature', signature_path,
            '--public-key', public_key_path,
            '--padding', 'PKCS1'
        ])
        assert exit_code == 1
    
    def test_ca_certificate_workflow(self, cli, temp_dir, monkeypatch):
        """Test CA certificate issuance and verification."""
        # Mock user input to decline passphrase
        monkeypatch.setattr('builtins.input', lambda _: 'n')
        monkeypatch.setattr('getpass.getpass', lambda _: '')
        
        # Step 1: Create CA
        ca_dir = os.path.join(temp_dir, 'ca')
        exit_code = cli.run([
            'create-ca',
            '--output-dir', ca_dir
        ])
        assert exit_code == 0
        
        ca_private_key_path = os.path.join(ca_dir, 'ca_private_key.pem')
        ca_public_key_path = os.path.join(ca_dir, 'ca_public_key.pem')
        
        assert os.path.exists(ca_private_key_path)
        assert os.path.exists(ca_public_key_path)
        
        # Step 2: Generate user keys
        user_dir = os.path.join(temp_dir, 'user')
        exit_code = cli.run([
            'generate-keys',
            '--output-dir', user_dir
        ])
        assert exit_code == 0
        
        user_public_key_path = os.path.join(user_dir, 'public_key.pem')
        
        # Step 3: Sign user's public key to create certificate
        cert_path = os.path.join(temp_dir, 'user_cert.json')
        exit_code = cli.run([
            'sign-certificate',
            '--public-key', user_public_key_path,
            '--ca-key', ca_private_key_path,
            '--subject', 'Test User',
            '--output', cert_path,
            '--days', '30'
        ])
        assert exit_code == 0
        assert os.path.exists(cert_path)
        
        # Verify certificate structure
        with open(cert_path, 'r') as f:
            cert_data = json.load(f)
            assert 'subject' in cert_data
            assert cert_data['subject'] == 'Test User'
            assert 'issuer' in cert_data
            assert 'valid_from' in cert_data
            assert 'valid_until' in cert_data
            assert 'signature' in cert_data
        
        # Step 4: Verify the certificate
        exit_code = cli.run([
            'verify-certificate',
            '--certificate', cert_path,
            '--ca-public-key', ca_public_key_path
        ])
        assert exit_code == 0
    
    def test_verification_logs(self, cli, temp_dir, monkeypatch):
        """Test verification logging functionality."""
        # Mock user input to decline passphrase
        monkeypatch.setattr('builtins.input', lambda _: 'n')
        monkeypatch.setattr('getpass.getpass', lambda _: '')
        
        # Generate keys
        exit_code = cli.run([
            'generate-keys',
            '--output-dir', temp_dir
        ])
        assert exit_code == 0
        
        private_key_path = os.path.join(temp_dir, 'private_key.pem')
        public_key_path = os.path.join(temp_dir, 'public_key.pem')
        signature_path = os.path.join(temp_dir, 'signature.json')
        
        # Sign a message
        test_message = "Test message for logging"
        exit_code = cli.run([
            'sign',
            '--message', test_message,
            '--private-key', private_key_path,
            '--output', signature_path
        ])
        assert exit_code == 0
        
        # Verify the signature (creates log entry)
        exit_code = cli.run([
            'verify',
            '--message', test_message,
            '--signature', signature_path,
            '--public-key', public_key_path
        ])
        assert exit_code == 0
        
        # Show logs
        exit_code = cli.run(['show-logs'])
        assert exit_code == 0
    
    def test_padding_schemes(self, cli, temp_dir, monkeypatch):
        """Test both PSS and PKCS1 padding schemes."""
        # Mock user input to decline passphrase
        monkeypatch.setattr('builtins.input', lambda _: 'n')
        monkeypatch.setattr('getpass.getpass', lambda _: '')
        
        # Generate keys
        exit_code = cli.run([
            'generate-keys',
            '--output-dir', temp_dir
        ])
        assert exit_code == 0
        
        private_key_path = os.path.join(temp_dir, 'private_key.pem')
        public_key_path = os.path.join(temp_dir, 'public_key.pem')
        
        test_message = "Test message"
        
        # Test PSS padding
        pss_signature_path = os.path.join(temp_dir, 'pss_signature.json')
        exit_code = cli.run([
            'sign',
            '--message', test_message,
            '--private-key', private_key_path,
            '--output', pss_signature_path,
            '--padding', 'PSS'
        ])
        assert exit_code == 0
        
        exit_code = cli.run([
            'verify',
            '--message', test_message,
            '--signature', pss_signature_path,
            '--public-key', public_key_path,
            '--padding', 'PSS'
        ])
        assert exit_code == 0
        
        # Test PKCS1 padding
        pkcs1_signature_path = os.path.join(temp_dir, 'pkcs1_signature.json')
        exit_code = cli.run([
            'sign',
            '--message', test_message,
            '--private-key', private_key_path,
            '--output', pkcs1_signature_path,
            '--padding', 'PKCS1'
        ])
        assert exit_code == 0
        
        exit_code = cli.run([
            'verify',
            '--message', test_message,
            '--signature', pkcs1_signature_path,
            '--public-key', public_key_path,
            '--padding', 'PKCS1'
        ])
        assert exit_code == 0
    
    def test_invalid_command(self, cli):
        """Test handling of invalid command."""
        # CLI now catches SystemExit and returns 1
        exit_code = cli.run(['invalid-command'])
        assert exit_code == 1
    
    def test_missing_required_arguments(self, cli):
        """Test handling of missing required arguments."""
        # CLI now catches SystemExit and returns 1
        exit_code = cli.run(['sign'])
        assert exit_code == 1
