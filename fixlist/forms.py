import re

from django import forms
from .models import Fixlist


class FixlistForm(forms.ModelForm):
    class Meta:
        model = Fixlist
        fields = ['title', 'content', 'internal_note']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter a title for your fixlist'
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
        if not filename.lower().endswith('.txt'):
            raise forms.ValidationError('Only .txt files are allowed.')

        raw_bytes = uploaded_file.read()

        # FRST log files are usually UTF-8 but can be ANSI (Windows-1252) or
        # UTF-16 depending on the system locale and FRST version.
        decoded_content = None
        for encoding in ('utf-8-sig', 'utf-16', 'windows-1252'):
            try:
                decoded_content = raw_bytes.decode(encoding)
                break
            except (UnicodeDecodeError, UnicodeError):
                continue
        if decoded_content is None:
            raise forms.ValidationError('File must be valid text (UTF-8, UTF-16, or ANSI encoded).')

        if not decoded_content.strip():
            raise forms.ValidationError('Uploaded file is empty.')

        uploaded_file.seek(0)
        uploaded_file.decoded_content = decoded_content
        return uploaded_file

    def clean(self):
        cleaned = super().clean()
        has_file = bool(cleaned.get('log_file'))
        has_text = bool((cleaned.get('log_text') or '').strip())
        if not has_file and not has_text:
            raise forms.ValidationError('Provide either a .txt file or paste the log content.')
        if has_file and has_text:
            raise forms.ValidationError('Provide a file or pasted text, not both.')
        return cleaned
