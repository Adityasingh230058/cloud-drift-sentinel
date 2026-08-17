"""
Reports module initialization.
"""

from .console import ConsoleReporter
from .html_report import HTMLReporter

__all__ = ["ConsoleReporter", "HTMLReporter"]
