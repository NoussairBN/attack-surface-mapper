"""UI module for report generation and CLI."""

from .cli import main, parse_arguments
from .report_generator import ReportGenerator

__all__ = ['main', 'parse_arguments', 'ReportGenerator']