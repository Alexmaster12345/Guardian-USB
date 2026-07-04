"""Custom exceptions for Guardian USB."""
from __future__ import annotations


class GuardianError(Exception):
    """Base class for all Guardian errors."""


class ConfigurationError(GuardianError):
    """Raised when configuration is invalid or missing."""


class DiscoveryError(GuardianError):
    """Raised when asset discovery fails."""


class ScanError(GuardianError):
    """Raised when a scan cannot be completed."""


class FingerprintError(GuardianError):
    """Raised when fingerprinting fails."""


class VulnerabilityDBError(GuardianError):
    """Raised on vulnerability database sync/import errors."""


class NotFoundError(GuardianError):
    """Raised when a requested entity does not exist."""


class AuthenticationError(GuardianError):
    """Raised on failed API authentication."""


class PluginError(GuardianError):
    """Raised when a plugin fails to load or execute."""


class ComplianceError(GuardianError):
    """Raised when a compliance check fails to run."""
