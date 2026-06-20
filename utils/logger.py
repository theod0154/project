"""
Centralized logging.

Replaces the scattered print() calls in the original script with a proper
logging system: timestamped, level-filtered, written to both the console
and a rotating file. Every module obtains its logger via get_logger(__name__)
so log lines are traceable to their source.
"""
from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

_CONFIGURED: dict[str, logging.Logger] = {}

_FMT = "%(asctime)s | %(levelname)-8s | %(name)-22s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def get_logger(name: str, log_dir: str = "logs", level: str = "INFO") -> logging.Logger:
    """
    Return a configured logger. Idempotent — calling it twice with the same
    name returns the same logger without adding duplicate handlers.
    """
    if name in _CONFIGURED:
        return _CONFIGURED[name]

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    formatter = logging.Formatter(_FMT, datefmt=_DATEFMT)

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    logger.addHandler(console)

    # Rotating file handler — 5 MB per file, keep 3 backups
    try:
        os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, "ddos_system.log"),
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        # If the filesystem is read-only (rare in containers), console-only is fine.
        logger.warning("Could not create log file; continuing with console only.")

    _CONFIGURED[name] = logger
    return logger
