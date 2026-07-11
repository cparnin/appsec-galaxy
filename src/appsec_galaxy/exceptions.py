"""
Centralized exception handling for AppSec Galaxy.

This module provides custom exception classes to improve error handling
consistency across all scanner modules.
"""

class ScannerError(Exception):
    """Base exception for all scanner-related errors."""

    def __init__(self, message: str, scanner: str = None, details: dict = None):
        self.scanner = scanner
        self.details = details or {}
        super().__init__(message)

class ValidationError(ScannerError):
    """Raised when input validation fails."""
    pass

class ScanExecutionError(ScannerError):
    """Raised when scanner execution fails."""
    pass

class BinaryNotFoundError(ScannerError):
    """Raised when required scanner binary is not found."""
    pass

class DependencyAnalysisError(ScannerError):
    """Raised when dependency code path analysis fails."""
    pass

class RegistryLookupError(ScannerError):
    """Raised when a package registry lookup fails."""
    pass
