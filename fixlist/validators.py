"""Shared validation utilities for request payloads and form data."""
import json
from django.http import JsonResponse


class BadJsonError(Exception):
    """Raised when JSON payload parsing fails."""
    pass


class PayloadValidator:
    """Utilities for validating HTTP request payloads."""

    @staticmethod
    def json_payload(request) -> dict:
        """Safely parse request body as JSON; raise BadJsonError on failure."""
        try:
            return json.loads(request.body.decode('utf-8') or '{}')
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
