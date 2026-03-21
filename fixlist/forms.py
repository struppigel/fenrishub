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
    log_file = forms.FileField(required=True)

    def clean_reddit_username(self):
        username = (self.cleaned_data.get('reddit_username') or '').strip()
        if not username:
            raise forms.ValidationError('Reddit username is required.')
        return username

    def clean_log_file(self):
        uploaded_file = self.cleaned_data.get('log_file')
        if not uploaded_file:
            raise forms.ValidationError('A .txt file is required.')

        filename = (uploaded_file.name or '').strip()
        if not filename.lower().endswith('.txt'):
            raise forms.ValidationError('Only .txt files are allowed.')

        raw_bytes = uploaded_file.read()
        try:
            decoded_content = raw_bytes.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise forms.ValidationError('File must be valid UTF-8 text.') from exc

        if not decoded_content.strip():
            raise forms.ValidationError('Uploaded file is empty.')

        uploaded_file.seek(0)
        uploaded_file.decoded_content = decoded_content
        return uploaded_file
