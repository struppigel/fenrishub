import re

from charset_normalizer import from_bytes
from django import forms
from .models import Fixlist


class FixlistForm(forms.ModelForm):
    class Meta:
        model = Fixlist
        fields = ['username', 'content', 'internal_note']
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter a username for your fixlist'
            }),
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Paste or type the content here',
                'rows': 15
            }),
            'internal_note': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Only visible to logged in users',
                'rows': 5
            }),
        }


class UploadedLogForm(forms.Form):
    reddit_username = forms.CharField(max_length=20, required=True)
    log_file = forms.FileField(required=False)
    log_text = forms.CharField(required=False, widget=forms.Textarea)
    INVALID_TEXT_CHAR_RE = re.compile(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')
    _LOG_HINTS = (
        'Farbar Recovery Scan Tool',
        'Additional scan result of',
        'Scan result of Farbar Recovery Scan Tool',
        'Fixlog',
        '====================',
    )

    @classmethod
    def _text_has_invalid_controls(cls, text: str) -> bool:
        return '\x00' in text or bool(cls.INVALID_TEXT_CHAR_RE.search(text))

    @classmethod
    def _candidate_score(cls, text: str) -> float:
        if not text:
            return float('-inf')

        total_chars = max(len(text), 1)
        ascii_chars = sum(1 for ch in text if ch == '\n' or ch == '\r' or ch == '\t' or 32 <= ord(ch) <= 126)
        non_ascii_chars = sum(1 for ch in text if ord(ch) > 126)
        log_hints = sum(1 for hint in cls._LOG_HINTS if hint in text)
        replacement_count = text.count('\ufffd')
        high_plane_chars = sum(1 for ch in text if ord(ch) >= 0x2E80)

        ascii_ratio = ascii_chars / total_chars
        non_ascii_ratio = non_ascii_chars / total_chars
        high_plane_ratio = high_plane_chars / total_chars

        score = 0.0
        score += log_hints * 40.0
        score += ascii_ratio * 30.0
        score -= non_ascii_ratio * 10.0
        score -= high_plane_ratio * 25.0
        score -= replacement_count * 2.0
        return score

    @classmethod
    def _iter_candidate_variants(cls, text: str):
        yield text
        try:
            repaired = text.encode('utf-16-le').decode('utf-8')
        except (UnicodeEncodeError, UnicodeDecodeError):
            return
        if repaired and repaired != text:
            yield repaired

    def clean_reddit_username(self):
        username = (self.cleaned_data.get('reddit_username') or '').strip()
        if not username:
            raise forms.ValidationError('Reddit username is required.')
        # Strip leading "u/" or "/u/" that users often include
        username = re.sub(r'^/?u/', '', username)
        if not re.fullmatch(r'[A-Za-z0-9_-]{3,20}', username):
            raise forms.ValidationError(
                'Enter just the username (3-20 letters, numbers, underscores, or hyphens). '
                'No need for the u/ prefix.'
            )
        return username

    def clean_log_file(self):
        uploaded_file = self.cleaned_data.get('log_file')
        if not uploaded_file:
            return None

        filename = (uploaded_file.name or '').strip()
        if not filename.lower().endswith(('.txt', '.log')):
            raise forms.ValidationError('Only .txt or .log files are allowed.')

        raw_bytes = uploaded_file.read()
        if not raw_bytes:
            raise forms.ValidationError('Uploaded file is empty.')

        # Build decode candidates from detector + common FRST encodings,
        # then pick the best readable/log-like text instead of first match.
        candidates = []
        detected = from_bytes(raw_bytes).best()
        if detected is not None:
            detected_text = str(detected)
            if detected_text:
                candidates.append(detected_text)

        for encoding in ('utf-8-sig', 'utf-16', 'utf-16-le', 'utf-16-be', 'windows-1252'):
            try:
                candidates.append(raw_bytes.decode(encoding))
            except (UnicodeDecodeError, UnicodeError):
                continue

        best_content = None
        best_score = float('-inf')
        seen_candidates = set()
        for candidate in candidates:
            if not candidate:
                continue
            for candidate_variant in self._iter_candidate_variants(candidate):
                if not candidate_variant or candidate_variant in seen_candidates:
                    continue
                seen_candidates.add(candidate_variant)
                cleaned = candidate_variant.replace('\x00', '')
                cleaned = self.INVALID_TEXT_CHAR_RE.sub('', cleaned)
                if not cleaned:
                    continue
                score = self._candidate_score(cleaned)
                if score > best_score:
                    best_score = score
                    best_content = cleaned

        if best_content is None:
            raise forms.ValidationError('File must be valid text and cannot contain binary control bytes.')

        if not best_content.strip():
            raise forms.ValidationError('Uploaded file is empty.')

        uploaded_file.seek(0)
        uploaded_file.decoded_content = best_content
        return uploaded_file

    def clean_log_text(self):
        log_text = self.cleaned_data.get('log_text') or ''
        if self.INVALID_TEXT_CHAR_RE.search(log_text):
            raise forms.ValidationError(
                'Pasted log contains invalid control characters. Please remove binary/non-text characters and try again.'
            )
        return log_text

    def clean(self):
        cleaned = super().clean()
        has_file = bool(cleaned.get('log_file'))
        log_text = cleaned.get('log_text') or ''
        has_text = bool(log_text.strip())
        if not has_file and not has_text:
            raise forms.ValidationError('Provide either a .txt/.log file or paste the log content.')
        if has_file and has_text:
            raise forms.ValidationError('Provide a file or pasted text, not both.')
        return cleaned
