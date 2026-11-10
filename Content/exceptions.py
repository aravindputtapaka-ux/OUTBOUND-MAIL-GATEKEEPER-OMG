class InspectionError(RuntimeError):
    """Raised when a required inspection cannot be completed."""


class RuleConfigurationError(InspectionError):
    """Raised when the runtime rule configuration is invalid."""
