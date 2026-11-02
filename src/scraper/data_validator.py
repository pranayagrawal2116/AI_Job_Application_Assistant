"""Re-export DataValidator for backwards compatibility."""

from src.scraper.extraction.data_validator import DataValidator, ValidationResult

__all__ = ["DataValidator", "ValidationResult"]
