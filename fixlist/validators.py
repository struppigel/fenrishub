"""Shared validation utilities for request payloads and form data."""
import json
from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.http import JsonResponse


class BadJsonError(Exception):
    """Raised when JSON payload parsing fails."""
    pass


class PayloadTooLargeError(Exception):
    """Raised when the request body exceeds DATA_UPLOAD_MAX_MEMORY_SIZE."""

    def __init__(self, limit_bytes: int):
        self.limit_bytes = limit_bytes
        limit_mb = limit_bytes / (1024 * 1024)
        message = (
            f'Log is too large for the analyzer. '
            f'The current limit is {limit_mb:.1f} MB — try uploading the log as a file '
            f'or trimming it before pasting.'
        )
        super().__init__(message)


class PayloadValidator:
    """Utilities for validating HTTP request payloads."""

    @staticmethod
    def json_payload(request) -> dict:
        """Safely parse request body as JSON.

        Raises BadJsonError if the payload is not valid JSON, or
        PayloadTooLargeError if the body exceeds DATA_UPLOAD_MAX_MEMORY_SIZE.
        """
        try:
            body = request.body
        except RequestDataTooBig:
            raise PayloadTooLargeError(settings.DATA_UPLOAD_MAX_MEMORY_SIZE)
        try:
            return json.loads(body.decode('utf-8') or '{}')
        except json.JSONDecodeError:
            raise BadJsonError('Invalid JSON payload.')

    @staticmethod
    def check_field_type(obj: dict, field: str, expected_type) -> bool:
        """Check if field exists in obj and is of expected_type. Return True if valid."""
        if field not in obj:
            return False
        if not isinstance(obj[field], expected_type):
            return False
        return True

    @staticmethod
    def check_field_in(value, allowed: set | list) -> bool:
        """Check if value is in allowed set/list."""
        return value in allowed

    @staticmethod
    def error_response(message: str, status: int = 400) -> JsonResponse:
        """Return standardized error JSON response."""
        return JsonResponse({'error': message}, status=status)
