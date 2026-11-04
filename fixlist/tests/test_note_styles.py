"""Hint and note lines must never fall back to the page's default font size.

Twice a help line showed up huge because its class was only styled in one
context (inside a dropdown option, or on one page) and not where it was used.
Notes now share the `.small-note` class from base.html; these checks keep the
pieces from drifting apart again.
"""

import re
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

BASE_DIR = Path(settings.BASE_DIR)


def read(relative):
    return (BASE_DIR / relative).read_text(encoding='utf-8')


class NoteStyleTests(SimpleTestCase):
    def test_base_defines_the_shared_small_note_class(self):
        self.assertRegex(read('templates/base.html'), r'\.small-note\s*\{[^}]*font-size')

    def test_picker_note_is_styled_on_its_own(self):
        # A rule that applies anywhere, not only nested in an option.
        css = read('static/css/rule_tags.css')
        self.assertRegex(css, r'(?m)^\.tag-picker-option-note\s*\{[^}]*font-size')

    def test_standalone_notes_use_small_note(self):
        picker = read('static/js/rule_tag_picker.js')
        for match in re.finditer(r"'tag-picker-option-note[^']*'", picker):
            if match.group(0) != "'tag-picker-option-note'":
                self.assertIn('small-note', match.group(0))
        self.assertIn("'tag-picker-option-note small-note'", picker)
        self.assertIn("'tag-picker-option-note small-note'", read('templates/rule_tag_editor.html'))
        self.assertIn('small-note', read('templates/partials/speech_triggers.html'))
