import json
from pathlib import Path

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from unittest.mock import patch

from django.http import HttpResponse
from django.test import RequestFactory

from ..models import ClassificationRule, ParsedFilepathExclusion, UploadedLog
from ..views import log_analyzer_view


class LogAnalyzerCleanSaveTests(TestCase):
    """Tests for the superuser-only 'remaining = C' feature in the log analyzer."""

    def test_superuser_context_is_true(self):
        superuser = User.objects.create_superuser(username="admin", password="password123")
        request = RequestFactory().get(reverse("log_analyzer"))
        request.user = superuser

        with patch("fixlist.views.analyzer.render", return_value=HttpResponse("ok")) as mock_render:
            log_analyzer_view(request)

        rendered_context = mock_render.call_args.args[2]
        self.assertTrue(rendered_context.get("is_superuser"))

    def test_regular_user_context_is_false(self):
        user = User.objects.create_user(username="regular", password="password123")
        request = RequestFactory().get(reverse("log_analyzer"))
        request.user = user

        with patch("fixlist.views.analyzer.render", return_value=HttpResponse("ok")) as mock_render:
            log_analyzer_view(request)

        rendered_context = mock_render.call_args.args[2]
        self.assertFalse(rendered_context.get("is_superuser"))

    def test_template_contains_superuser_button_conditionally(self):
        project_root = Path(__file__).resolve().parent.parent.parent
        content = (project_root / "templates" / "log_analyzer.html").read_text(encoding="utf-8")

        self.assertIn('id="addRemainingCleanButton"', content)
        self.assertIn("remaining = C", content)
        self.assertIn("{% if is_superuser %}", content)
        self.assertIn("isSuperuser", content)

    def test_js_contains_add_remaining_as_clean_function(self):
        project_root = Path(__file__).resolve().parent.parent.parent
        js_path = project_root / "static" / "js" / "log_analyzer" / "analysis.js"
        js_content = js_path.read_text(encoding="utf-8")

        self.assertIn("function addRemainingAsClean()", js_content)
        self.assertIn("ATTENTION", js_content)
        self.assertIn("No File", js_content)
        self.assertIn("Access Denied", js_content)
        self.assertIn("entry_type", js_content)


