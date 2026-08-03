"""CodeRifts SDK exceptions."""


class CodeRiftsError(Exception):
    """Base exception for all CodeRifts SDK errors."""

    def __init__(self, message: str, code: str = "unknown_error"):
        self.message = message
        self.code = code
        super().__init__(message)


class ApiError(CodeRiftsError):
    """Raised when the API returns an error response (4xx/5xx other than 401/429)."""

    def __init__(self, message: str, status_code: int = 0, code: str = "api_error"):
        self.status_code = status_code
        super().__init__(message, code)


class AuthError(CodeRiftsError):
    """Raised when authentication fails (HTTP 401)."""

    def __init__(self, message: str = "Invalid or missing API key"):
        super().__init__(message, "auth_error")


class RateLimitError(CodeRiftsError):
    """Raised when the API rate limit is exceeded (HTTP 429)."""

    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message, "rate_limit_error")
