# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT

"""
Mass Market Relay Client Package

A modular Python client for interacting with Mass Market relay services.
Provides shop management, order processing, and blockchain integration.
"""

from .client import RelayClient
from .utils import RelayException, EnrollException

# Package version using setuptools_scm
try:
    from importlib.metadata import version

    __version__ = version("massmarket-client")
except ImportError:
    # Fallback for older Python versions
    from pkg_resources import get_distribution

    __version__ = get_distribution("massmarket-client").version
except Exception:
    # Fallback version
    __version__ = "unknown"

# Public API - only include what we know exists
__all__ = [
    "RelayClient",  # Main modern client (refactored)
    "RelayException",  # Main relay exception
    "EnrollException",  # Key card enrollment exception
]
