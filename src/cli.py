"""
Command-Line Interface for Digital Signature Validator

Provides CLI commands for key generation, signing, verification, logging,
and certificate authority operations.
"""

import argparse
import sys
import os
import hashlib
import getpass
from datetime import datetime
from typing import Optional

from src.key_manager import KeyManager
from src.signature_service import SignatureService
from src.logger_service import VerificationLogger
from src.certificate_service import CertificateAuthority
from src.models import SignatureResult, Certificate
from src.exceptions import (
    DigitalSignatureError,
    KeyManagementError,
    SignatureError,
    VerificationError,
    CertificateError
)
from src.validation import (
    validate_directory_path,
    validate_file_path,
    validate_validity_days,
    validate_padding_scheme,
    sanitize_string_input,
    ValidationError
)


class CLI:
    """Command-line interface for the Digital Signature Validator."""
    
    def __init__(self):
        """Initialize the CLI with service instances.
        
        Creates instances of all required services:
        - KeyManager: For RSA key generation and management
        - SignatureService: For signing and verification operations
        - VerificationLogger: For audit trail logging
        - ArgumentParser: For command-line argument parsing
        """
        self.key_manager = KeyManager()
        self.signature_service = SignatureService()
        self.logger = VerificationLogger()
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser with all subcommands.
        
        Returns:
            Configured ArgumentParser instance
        """
        parser = argparse.ArgumentParser(
            prog='digital-signature-validator',
            description='Digital Signature Validator - Create and verify digital signatures using RSA and SHA-256'
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # generate-keys command
        gen_keys_parser = subparsers.add_parser(
            'generate-keys',
            help='Generate a new RSA key pair'
        )
        gen_keys_parser.add_argument(
            '--output-dir',
            required=True,
            help='Directory to save the key pair'
        )
        gen_keys_parser.add_argument(
            '--passphrase',
            help='Passphrase to encrypt the private key (will prompt if not provided)'
        )
        gen_keys_parser.add_argument(
            '--key-size',
            type=int,
            default=2048,
            help='Key size in bits (default: 2048, minimum: 2048)'
        )
        
        # sign command
        sign_parser = subparsers.add_parser(
            'sign',
            help='Sign a text message'
        )
        sign_parser.add_argument(
            '--message',
            required=True,
            help='Text message to sign'
        )
        sign_parser.add_argument(
            '--private-key',
            required=True,
            help='Path to private key file'
        )
        sign_parser.add_argument(
            '--output',
            required=True,
            help='Path to save the signature'
        )
        sign_parser.add_argument(
            '--passphrase',
            help='Passphrase for encrypted private key (will prompt if needed)'
        )
        sign_parser.add_argument(
            '--padding',
            choices=['PSS', 'PKCS1'],
            default='PSS',
            help='Padding scheme (default: PSS)'
        )
        
        # sign-file command
        sign_file_parser = subparsers.add_parser(
            'sign-file',
            help='Sign a file'
        )
        sign_file_parser.add_argument(
            '--file',
            required=True,
            help='Path to file to sign'
        )
        sign_file_parser.add_argument(
            '--private-key',
            required=True,
            help='Path to private key file'
        )
        sign_file_parser.add_argument(
            '--output',
            required=True,
            help='Path to save the signature'
        )
        sign_file_parser.add_argument(
            '--passphrase',
            help='Passphrase for encrypted private key (will prompt if needed)'
        )
        sign_file_parser.add_argument(
            '--padding',
            choices=['PSS', 'PKCS1'],
            default='PSS',
            help='Padding scheme (default: PSS)'
        )
        
        # verify command
        verify_parser = subparsers.add_parser(
            'verify',
            help='Verify a signature for a text message'
        )
        verify_parser.add_argument(
            '--message',
            required=True,
            help='Original text message'
        )
        verify_parser.add_argument(
            '--signature',
            required=True,
            help='Path to signature file'
        )
        verify_parser.add_argument(
            '--public-key',
            required=True,
            help='Path to public key file'
        )
        verify_parser.add_argument(
            '--padding',
            choices=['PSS', 'PKCS1'],
            default='PSS',
            help='Padding scheme (default: PSS)'
        )
        
        # verify-file command
        verify_file_parser = subparsers.add_parser(
            'verify-file',
            help='Verify a signature for a file'
        )
        verify_file_parser.add_argument(
            '--file',
            required=True,
            help='Path to file to verify'
        )
        verify_file_parser.add_argument(
            '--signature',
            required=True,
            help='Path to signature file'
        )
        verify_file_parser.add_argument(
            '--public-key',
            required=True,
            help='Path to public key file'
        )
        verify_file_parser.add_argument(
            '--padding',
            choices=['PSS', 'PKCS1'],
            default='PSS',
            help='Padding scheme (default: PSS)'
        )
        
        # show-logs command
        logs_parser = subparsers.add_parser(
            'show-logs',
            help='Display verification logs'
        )
        logs_parser.add_argument(
            '--start-date',
            help='Start date for filtering (ISO format: YYYY-MM-DD)'
        )
        logs_parser.add_argument(
            '--end-date',
            help='End date for filtering (ISO format: YYYY-MM-DD)'
        )
        
        # create-ca command
        create_ca_parser = subparsers.add_parser(
            'create-ca',
            help='Create a Certificate Authority key pair'
        )
        create_ca_parser.add_argument(
            '--output-dir',
            required=True,
            help='Directory to save the CA key pair'
        )
        create_ca_parser.add_argument(
            '--passphrase',
            help='Passphrase to encrypt the CA private key (will prompt if not provided)'
        )
        
        # sign-certificate command
        sign_cert_parser = subparsers.add_parser(
            'sign-certificate',
            help='Sign a public key to create a certificate'
        )
        sign_cert_parser.add_argument(
            '--public-key',
            required=True,
            help='Path to public key file to sign'
        )
        sign_cert_parser.add_argument(
            '--ca-key',
            required=True,
            help='Path to CA private key file'
        )
        sign_cert_parser.add_argument(
            '--subject',
            required=True,
            help='Certificate subject name'
        )
        sign_cert_parser.add_argument(
            '--output',
            required=True,
            help='Path to save the certificate'
        )
        sign_cert_parser.add_argument(
            '--days',
            type=int,
            default=365,
            help='Certificate validity in days (default: 365)'
        )
        sign_cert_parser.add_argument(
            '--passphrase',
            help='Passphrase for encrypted CA private key (will prompt if needed)'
        )
        
        # verify-certificate command
        verify_cert_parser = subparsers.add_parser(
            'verify-certificate',
            help='Verify a certificate'
        )
        verify_cert_parser.add_argument(
            '--certificate',
            required=True,
            help='Path to certificate file'
        )
        verify_cert_parser.add_argument(
            '--ca-public-key',
            required=True,
            help='Path to CA public key file'
        )
        
        return parser
    
    def _get_passphrase(self, provided_passphrase: Optional[str], prompt: str = "Enter passphrase: ") -> Optional[str]:
        """Get passphrase from argument or prompt user.
        
        Args:
            provided_passphrase: Passphrase from command line argument
            prompt: Prompt message for user input
            
        Returns:
            Passphrase string or None
        """
        if provided_passphrase is not None:
            return provided_passphrase
        
        # Prompt user
        response = input("Use passphrase protection? (y/n): ").strip().lower()
        if response == 'y':
            return getpass.getpass(prompt)
        return None
    
    def _prompt_passphrase_if_needed(self, provided_passphrase: Optional[str]) -> Optional[str]:
        """Prompt for passphrase if not provided and key is encrypted.
        
        Args:
            provided_passphrase: Passphrase from command line argument
            
        Returns:
            Passphrase string or None
        """
        if provided_passphrase is not None:
            return provided_passphrase
        
        # Try without passphrase first, will prompt if needed
        return getpass.getpass("Enter passphrase (or press Enter if none): ") or None
    
    def cmd_generate_keys(self, args) -> int:
        """Handle generate-keys command.
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            # Validate and create output directory
            try:
                output_dir = validate_directory_path(args.output_dir, create_if_missing=True)
            except ValidationError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            
            # Get passphrase
            passphrase = self._get_passphrase(
                args.passphrase,
                "Enter passphrase to encrypt private key: "
            )
            
            # Generate key pair
            print(f"Generating {args.key_size}-bit RSA key pair...")
            private_key, public_key = self.key_manager.generate_key_pair(args.key_size)
            
            # Save keys
            private_key_path = os.path.join(output_dir, 'private_key.pem')
            public_key_path = os.path.join(output_dir, 'public_key.pem')
            
            self.key_manager.save_private_key(private_key, private_key_path, passphrase)
            self.key_manager.save_public_key(public_key, public_key_path)
            
            print(f"✓ Key pair generated successfully!")
            print(f"  Private key: {private_key_path}")
            print(f"  Public key: {public_key_path}")
            
            if passphrase:
                print("  Private key is encrypted with passphrase")
            
            return 0
            
        except KeyManagementError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            return 1
    
    def cmd_sign(self, args) -> int:
        """Handle sign command.
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            # Validate inputs
            try:
                message = sanitize_string_input(args.message, max_length=1000000, allow_newlines=True)
                padding = validate_padding_scheme(args.padding)
            except ValidationError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            
            # Get passphrase if needed
            passphrase = self._prompt_passphrase_if_needed(args.passphrase)
            
            # Load private key
            print("Loading private key...")
            try:
                private_key = self.key_manager.load_private_key(args.private_key, passphrase)
            except KeyManagementError as e:
                if "passphrase" in str(e).lower():
                    # Try prompting for passphrase
                    passphrase = getpass.getpass("Enter passphrase: ")
                    private_key = self.key_manager.load_private_key(args.private_key, passphrase)
                else:
                    raise
            
            # Sign message
            print(f"Signing message with {padding} padding...")
            result = self.signature_service.sign_message(
                message,
                private_key,
                padding
            )
            
            # Save signature
            result.to_file(args.output)
            
            print(f"✓ Message signed successfully!")
            print(f"  Signature: {args.output}")
            print(f"  Message digest: {result.message_digest}")
            print(f"  Padding: {result.padding_scheme}")
            print(f"  Timestamp: {result.timestamp.isoformat()}")
            
            return 0
            
        except (KeyManagementError, SignatureError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            return 1
    
    def cmd_sign_file(self, args) -> int:
        """Handle sign-file command.
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            # Validate inputs
            try:
                validate_file_path(args.file, must_exist=True)
                padding = validate_padding_scheme(args.padding)
            except ValidationError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            
            # Get passphrase if needed
            passphrase = self._prompt_passphrase_if_needed(args.passphrase)
            
            # Load private key
            print("Loading private key...")
            try:
                private_key = self.key_manager.load_private_key(args.private_key, passphrase)
            except KeyManagementError as e:
                if "passphrase" in str(e).lower():
                    # Try prompting for passphrase
                    passphrase = getpass.getpass("Enter passphrase: ")
                    private_key = self.key_manager.load_private_key(args.private_key, passphrase)
                else:
                    raise
            
            # Sign file
            print(f"Signing file with {padding} padding...")
            result = self.signature_service.sign_file(
                args.file,
                private_key,
                padding
            )
            
            # Save signature
            result.to_file(args.output)
            
            print(f"✓ File signed successfully!")
            print(f"  File: {args.file}")
            print(f"  Signature: {args.output}")
            print(f"  File digest: {result.message_digest}")
            print(f"  Padding: {result.padding_scheme}")
            print(f"  Timestamp: {result.timestamp.isoformat()}")
            
            return 0
            
        except (KeyManagementError, SignatureError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            return 1
    
    def cmd_verify(self, args) -> int:
        """Handle verify command.
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            # Validate inputs
            try:
                message = sanitize_string_input(args.message, max_length=1000000, allow_newlines=True)
                validate_file_path(args.signature, must_exist=True)
                padding = validate_padding_scheme(args.padding)
            except ValidationError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            
            # Load public key
            print("Loading public key...")
            public_key = self.key_manager.load_public_key(args.public_key)
            
            # Load signature
            print("Loading signature...")
            sig_result = SignatureResult.from_file(args.signature)
            
            # Verify signature
            print(f"Verifying signature with {padding} padding...")
            result = self.signature_service.verify_signature(
                message,
                sig_result.signature,
                public_key,
                padding
            )
            
            # Log verification
            message_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
            sig_hash = hashlib.sha256(sig_result.signature).hexdigest()
            self.logger.log_verification(
                message_id=message_hash[:16],
                signature_id=sig_hash[:16],
                result=result.is_valid,
                timestamp=result.timestamp,
                padding_scheme=padding
            )
            
            # Display result
            if result.is_valid:
                print(f"✓ Signature is VALID")
                print(f"  Message digest: {result.message_digest}")
                print(f"  Verification timestamp: {result.timestamp.isoformat()}")
                return 0
            else:
                print(f"✗ Signature is INVALID")
                print(f"  Error: {result.error_message}")
                print(f"  Verification timestamp: {result.timestamp.isoformat()}")
                return 1
            
        except (KeyManagementError, VerificationError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            return 1
    
    def cmd_verify_file(self, args) -> int:
        """Handle verify-file command.
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            # Validate inputs
            try:
                validate_file_path(args.file, must_exist=True)
                validate_file_path(args.signature, must_exist=True)
                padding = validate_padding_scheme(args.padding)
            except ValidationError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            
            # Load public key
            print("Loading public key...")
            public_key = self.key_manager.load_public_key(args.public_key)
            
            # Load signature
            print("Loading signature...")
            sig_result = SignatureResult.from_file(args.signature)
            
            # Verify signature
            print(f"Verifying file signature with {padding} padding...")
            result = self.signature_service.verify_file_signature(
                args.file,
                sig_result.signature,
                public_key,
                padding
            )
            
            # Log verification
            with open(args.file, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            sig_hash = hashlib.sha256(sig_result.signature).hexdigest()
            self.logger.log_verification(
                message_id=file_hash[:16],
                signature_id=sig_hash[:16],
                result=result.is_valid,
                timestamp=result.timestamp,
                padding_scheme=padding
            )
            
            # Display result
            if result.is_valid:
                print(f"✓ File signature is VALID")
                print(f"  File: {args.file}")
                print(f"  File digest: {result.message_digest}")
                print(f"  Verification timestamp: {result.timestamp.isoformat()}")
                return 0
            else:
                print(f"✗ File signature is INVALID")
                print(f"  File: {args.file}")
                print(f"  Error: {result.error_message}")
                print(f"  Verification timestamp: {result.timestamp.isoformat()}")
                return 1
            
        except (KeyManagementError, VerificationError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            return 1
    
    def cmd_show_logs(self, args) -> int:
        """Handle show-logs command.
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            # Parse dates if provided
            start_date = None
            end_date = None
            
            if args.start_date:
                start_date = datetime.fromisoformat(args.start_date)
            
            if args.end_date:
                end_date = datetime.fromisoformat(args.end_date)
            
            # Get logs
            logs = self.logger.get_logs(start_date, end_date)
            
            if not logs:
                print("No verification logs found.")
                return 0
            
            # Display logs
            print(f"\nVerification Logs ({len(logs)} entries):")
            print("-" * 80)
            
            for log in logs:
                status = "✓ VALID" if log.result else "✗ INVALID"
                print(f"{log.timestamp.isoformat()} | {status}")
                print(f"  Message ID: {log.message_id}")
                print(f"  Signature ID: {log.signature_id}")
                print(f"  Padding: {log.padding_scheme}")
                print()
            
            return 0
            
        except ValueError as e:
            print(f"Error: Invalid date format. Use ISO format (YYYY-MM-DD): {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            return 1
    
    def cmd_create_ca(self, args) -> int:
        """Handle create-ca command.
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            # Validate and create output directory
            try:
                output_dir = validate_directory_path(args.output_dir, create_if_missing=True)
            except ValidationError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            
            # Get passphrase
            passphrase = self._get_passphrase(
                args.passphrase,
                "Enter passphrase to encrypt CA private key: "
            )
            
            # Generate CA key pair
            print("Generating CA key pair...")
            private_key, public_key = self.key_manager.generate_key_pair(2048)
            
            # Save keys
            ca_private_key_path = os.path.join(output_dir, 'ca_private_key.pem')
            ca_public_key_path = os.path.join(output_dir, 'ca_public_key.pem')
            
            self.key_manager.save_private_key(private_key, ca_private_key_path, passphrase)
            self.key_manager.save_public_key(public_key, ca_public_key_path)
            
            print(f"✓ CA key pair created successfully!")
            print(f"  CA Private key: {ca_private_key_path}")
            print(f"  CA Public key: {ca_public_key_path}")
            
            if passphrase:
                print("  CA private key is encrypted with passphrase")
            
            return 0
            
        except KeyManagementError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            return 1
    
    def cmd_sign_certificate(self, args) -> int:
        """Handle sign-certificate command.
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            # Validate inputs
            try:
                validate_file_path(args.public_key, must_exist=True)
                validate_file_path(args.ca_key, must_exist=True)
                subject = sanitize_string_input(args.subject, max_length=256)
                days = validate_validity_days(args.days)
            except ValidationError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            
            # Get passphrase if needed
            passphrase = self._prompt_passphrase_if_needed(args.passphrase)
            
            # Load CA private key
            print("Loading CA private key...")
            try:
                ca_private_key = self.key_manager.load_private_key(args.ca_key, passphrase)
            except KeyManagementError as e:
                if "passphrase" in str(e).lower():
                    # Try prompting for passphrase
                    passphrase = getpass.getpass("Enter CA passphrase: ")
                    ca_private_key = self.key_manager.load_private_key(args.ca_key, passphrase)
                else:
                    raise
            
            ca_public_key = ca_private_key.public_key()
            
            # Load public key to sign
            print("Loading public key to sign...")
            public_key = self.key_manager.load_public_key(args.public_key)
            
            # Create CA and sign certificate
            print(f"Creating certificate for '{subject}'...")
            ca = CertificateAuthority(ca_private_key, ca_public_key)
            certificate = ca.sign_public_key(public_key, subject, days)
            
            # Save certificate
            import json
            with open(args.output, 'w') as f:
                json.dump(certificate.to_dict(), f, indent=2)
            
            print(f"✓ Certificate created successfully!")
            print(f"  Certificate: {args.output}")
            print(f"  Subject: {certificate.subject}")
            print(f"  Issuer: {certificate.issuer}")
            print(f"  Valid from: {certificate.valid_from.isoformat()}")
            print(f"  Valid until: {certificate.valid_until.isoformat()}")
            
            return 0
            
        except (KeyManagementError, CertificateError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            return 1
    
    def cmd_verify_certificate(self, args) -> int:
        """Handle verify-certificate command.
        
        Args:
            args: Parsed command-line arguments
            
        Returns:
            Exit code (0 for success, 1 for error)
        """
        try:
            # Validate inputs
            try:
                validate_file_path(args.certificate, must_exist=True)
                validate_file_path(args.ca_public_key, must_exist=True)
            except ValidationError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
            
            # Load certificate
            print("Loading certificate...")
            import json
            with open(args.certificate, 'r') as f:
                cert_data = json.load(f)
            certificate = Certificate.from_dict(cert_data)
            
            # Load CA public key
            print("Loading CA public key...")
            ca_public_key = self.key_manager.load_public_key(args.ca_public_key)
            
            # Create CA and verify certificate
            print("Verifying certificate...")
            # We need a dummy CA private key for initialization, but won't use it
            ca = CertificateAuthority(None, ca_public_key)
            
            try:
                is_valid = ca.verify_certificate(certificate)
                
                if is_valid:
                    print(f"✓ Certificate is VALID")
                    print(f"  Subject: {certificate.subject}")
                    print(f"  Issuer: {certificate.issuer}")
                    print(f"  Valid from: {certificate.valid_from.isoformat()}")
                    print(f"  Valid until: {certificate.valid_until.isoformat()}")
                    return 0
                else:
                    print(f"✗ Certificate is INVALID")
                    return 1
                    
            except CertificateError as e:
                print(f"✗ Certificate verification failed: {e}")
                return 1
            
        except (KeyManagementError, CertificateError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Unexpected error: {e}", file=sys.stderr)
            return 1
    
    def run(self, argv=None) -> int:
        """Run the CLI with the provided arguments.
        
        This is the main entry point for the CLI. It parses command-line
        arguments and dispatches to the appropriate command handler.
        
        Args:
            argv: Command-line arguments (defaults to sys.argv[1:])
            
        Returns:
            Exit code:
                0 - Success
                1 - Error (invalid arguments, operation failed, etc.)
        """
        if argv is None:
            argv = sys.argv[1:]
        
        # Parse arguments
        args = self.parser.parse_args(argv)
        
        # Check if a command was provided
        if not args.command:
            self.parser.print_help()
            return 1
        
        # Dispatch to appropriate command handler
        command_handlers = {
            'generate-keys': self.cmd_generate_keys,
            'sign': self.cmd_sign,
            'sign-file': self.cmd_sign_file,
            'verify': self.cmd_verify,
            'verify-file': self.cmd_verify_file,
            'show-logs': self.cmd_show_logs,
            'create-ca': self.cmd_create_ca,
            'sign-certificate': self.cmd_sign_certificate,
            'verify-certificate': self.cmd_verify_certificate,
        }
        
        handler = command_handlers.get(args.command)
        if handler:
            return handler(args)
        else:
            print(f"Error: Unknown command '{args.command}'", file=sys.stderr)
            self.parser.print_help()
            return 1


def main():
    """Main entry point for the CLI."""
    cli = CLI()
    sys.exit(cli.run())


if __name__ == '__main__':
    main()
