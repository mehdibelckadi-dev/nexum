"""Presentation-layer formatters over already-computed findings (no risk logic)."""

from .sarif import to_sarif

__all__ = ["to_sarif"]
