"""Utility functions for Floresta integration tests.

This module provides helper functions for TLS certificate generation,
command-line argument parsing, and test configuration.
"""

# pylint: disable=duplicate-code
import os
from typing import Optional
from test_framework.crypto.pkcs8 import (
    create_pkcs8_private_key,
    create_pkcs8_self_signed_certificate,
)


def create_tls_key_cert(temp_dir: str, log_func) -> tuple[str, str]:
    """Create TLS private key and self-signed certificate.

    Args:
        temp_dir: Base temporary directory path.
        log_func: Logging function to call with status messages.

    Returns:
        Tuple of (private_key_path, certificate_path).
    """
    tls_rel_path = os.path.join(temp_dir, "data", "tls")
    tls_path = os.path.normpath(os.path.abspath(tls_rel_path))
    os.makedirs(tls_path, exist_ok=True)

    pk_path, private_key = create_pkcs8_private_key(tls_path)
    log_func(f"Created PKCS#8 key at {pk_path}")

    cert_path = create_pkcs8_self_signed_certificate(
        tls_path, private_key, common_name="florestad", validity_days=365
    )
    log_func(f"Created self-signed certificate at {cert_path}")
    return (pk_path, cert_path)


def is_option_set(extra_args: list[str], option: str) -> bool:
    """Check if an option is present in the arguments list.

    Args:
        extra_args: List of command-line arguments.
        option: Option prefix to search for.

    Returns:
        True if option is found, False otherwise.
    """
    return any(arg.startswith(option) for arg in extra_args)


def extract_port_from_args(extra_args: list[str], option: str) -> Optional[int]:
    """Extract port number from command-line arguments.

    Args:
        extra_args: List of command-line arguments.
        option: Option prefix containing the port.

    Returns:
        Port number if found, None otherwise.
    """
    for arg in extra_args:
        if arg.startswith(f"{option}="):
            address = arg.split("=", 1)[1]
            if ":" in address:
                return int(address.split(":")[-1])
    return None


def get_integration_test_dir() -> str:
    """Get the temporary directory for integration tests.

    Returns:
        Path to the integration test directory.

    Raises:
        RuntimeError: If FLORESTA_TEMP_DIR environment variable is not set.
    """
    temp_dir = os.getenv("FLORESTA_TEMP_DIR")
    if temp_dir is None:
        raise RuntimeError("FLORESTA_TEMP_DIR not set")
    return temp_dir


def should_enable_electrum_for_utreexod(extra_args: list[str]) -> bool:
    """Determine if Electrum should be enabled for utreexod.

    Reads `extra_args` to find flags that disable Electrum or enable
    Electrum listeners for utreexod.

    Args:
        extra_args: List of command-line arguments.

    Returns:
        False if disable flags are present, True if listener options are present,
        False otherwise.
    """
    electrum_disabled_options = [
        "--noelectrum",
        "--disable-electrum",
        "--electrum=false",
        "--electrum=0",
    ]
    if any(
        arg.startswith(opt) for arg in extra_args for opt in electrum_disabled_options
    ):
        return False

    electrum_listener_options = ["--electrumlisteners", "--tlselectrumlisteners"]
    if any(
        arg.startswith(opt) for arg in extra_args for opt in electrum_listener_options
    ):
        return True

    return False
