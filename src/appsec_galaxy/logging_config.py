"""
Centralized logging configuration for AppSec Galaxy.

Consistent log format across CLI, web, and MCP surfaces.
"""

import logging
import sys

def setup_logging(level: str = "INFO", log_file: str = None) -> None:
    """
    Configure logging for the application.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional file to write logs to
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Create formatter with useful information
    formatter = logging.Formatter(
        fmt='%(asctime)s | %(name)s | %(levelname)s | %(message)s',
        datefmt='%H:%M:%S'
    )

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove any existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler (always present)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Optional file handler
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            logging.info(f"Logging to file: {log_file}")
        except Exception as e:
            logging.warning(f"Could not setup file logging: {e}")

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with consistent naming.

    Args:
        name: Usually __name__ from the calling module

    Returns:
        Configured logger instance
    """
    # Simplify module names for cleaner logs
    if name.startswith('src.'):
        name = name[4:]  # Remove 'src.' prefix
    elif name.startswith('appsec_galaxy.scanners.'):
        name = name.removeprefix('appsec_galaxy.scanners.')

    return logging.getLogger(name)

def set_debug_mode(enabled: bool = True) -> None:
    """
    Enable/disable debug mode for troubleshooting.

    Args:
        enabled: Whether to enable debug logging
    """
    level = logging.DEBUG if enabled else logging.INFO
    logging.getLogger().setLevel(level)

    if enabled:
        logging.debug("Debug mode enabled - verbose logging active")
    else:
        logging.info("Debug mode disabled - normal logging level")
