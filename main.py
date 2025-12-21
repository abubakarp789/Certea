"""
Digital Signature Validator - Main Entry Point

This module serves as the entry point for the Digital Signature Validator application.
"""

import sys
from src.cli import CLI
from src.exceptions import DigitalSignatureError


def main() -> int:
    """Main entry point for the application.
    
    This function initializes the CLI and handles top-level exceptions.
    It ensures that all errors are properly caught and reported to the user
    with appropriate exit codes.
    
    Returns:
        Exit code:
            0 - Success
            1 - Error (general error or DigitalSignatureError)
            130 - User cancelled operation (Ctrl+C)
    """
    try:
        cli = CLI()
        return cli.run()
    except DigitalSignatureError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
