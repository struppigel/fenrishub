"""Fixlist tests package with compatibility exports."""

from .test_auth_access import AuthenticationAndAccessTests
from .test_fixlist_crud_cases import FixlistCrudViewTests
from .test_fixlist_sharing_cases import SharingAndDownloadTests
from .test_log_analyzer_access_cases import UploadedLogAccessTests
from .test_log_analyzer_api_core_cases import LogAnalyzerApiCoreTests
from .test_log_analyzer_api_precedence_cases import LogAnalyzerApiPrecedenceTests
from .test_log_analyzer_api_rule_changes_cases import LogAnalyzerApiRuleChangeTests
from .test_log_analyzer_api_warning_cases import LogAnalyzerApiWarningTests
from .test_log_analyzer_clean_cases import LogAnalyzerCleanSaveTests
from .test_log_analyzer_rule_ownership_cases import RuleOwnershipTests
from .test_models import FixlistModelTests
from .test_template_markup import TemplateMarkupTests
from .test_uploaded_log_analyzer_view_cases import UploadedLogAnalyzerViewTests
from .test_uploaded_log_detail_view_cases import UploadedLogDetailViewTests
from .test_uploaded_log_diff_view_cases import UploadedLogDiffViewTests
from .test_uploaded_log_list_view_cases import UploadedLogListViewTests
from .test_uploaded_log_trash_cases import PurgeOldTrashTests, TrashViewTests
from .test_uploaded_log_uploads_view_cases import UploadedLogUploadsViewTests

__all__ = [
    "FixlistModelTests",
    "AuthenticationAndAccessTests",
    "FixlistCrudViewTests",
    "SharingAndDownloadTests",
    "UploadedLogUploadsViewTests",
    "UploadedLogListViewTests",
    "UploadedLogDetailViewTests",
    "UploadedLogDiffViewTests",
    "UploadedLogAnalyzerViewTests",
    "TrashViewTests",
    "PurgeOldTrashTests",
    "TemplateMarkupTests",
    "LogAnalyzerCleanSaveTests",
    "LogAnalyzerApiCoreTests",
    "LogAnalyzerApiRuleChangeTests",
    "LogAnalyzerApiWarningTests",
    "LogAnalyzerApiPrecedenceTests",
    "UploadedLogAccessTests",
    "RuleOwnershipTests",
]

