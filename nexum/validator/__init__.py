"""Nexum Validator — automated quality checks for Nexum Cert drafts."""

from .reports import ValidationResult, validate

__all__ = ["ValidationResult", "validate"]
