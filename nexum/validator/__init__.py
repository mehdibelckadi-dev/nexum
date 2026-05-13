"""Nexum Validator — automated quality checks for Trust Manifest drafts."""

from .reports import ValidationResult, validate

__all__ = ["ValidationResult", "validate"]
