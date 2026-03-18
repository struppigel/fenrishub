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
