"""Fixlist tests package with compatibility exports."""

from .test_auth_access import AuthenticationAndAccessTests
from .test_fixlist_views import FixlistCrudViewTests, SharingAndDownloadTests
from .test_log_analyzer_api import LogAnalyzerApiTests
from .test_models import FixlistModelTests
from .test_template_markup import TemplateMarkupTests

__all__ = [
    "FixlistModelTests",
    "AuthenticationAndAccessTests",
    "FixlistCrudViewTests",
    "SharingAndDownloadTests",
    "TemplateMarkupTests",
    "LogAnalyzerApiTests",
]

