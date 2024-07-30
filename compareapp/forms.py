from django import forms
from .models import Document
from django.utils import timezone

class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['title', 'author', 'creation_date', 'version', 'language', 'doc_type', 'doc_format', 'upload_document', 'comments']
        widgets = {
            'creation_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-input mt-1 rounded w-full mb-3'}),
        }

    def __init__(self, *args, **kwargs):
        super(DocumentForm, self).__init__(*args, **kwargs)
        self.fields['title'].widget.attrs.update({'class': 'form-input mt-1 rounded w-full mb-3'})
        self.fields['author'].widget.attrs.update({'class': 'form-input mt-1 rounded w-full mb-3'})
        # self.fields['creation_date'].widget.attrs.update({'class': 'form-input mt-1 rounded w-full mb-3'})
        self.fields['version'].widget.attrs.update({'class': 'form-input mt-1 rounded w-full mb-3'})
        self.fields['language'].widget.attrs.update({'class': 'form-select mt-1 rounded w-full mb-3'})
        self.fields['doc_type'].widget.attrs.update({'class': 'form-select mt-1 rounded w-full mb-3'})
        self.fields['doc_format'].widget.attrs.update({'class': 'form-input mt-1 rounded w-full mb-3'})
        self.fields['upload_document'].widget.attrs.update({'class': 'form-input mt-1 rounded w-full mb-3'})
        self.fields['comments'].widget.attrs.update({'class': 'form-textarea h-14 mt-1 rounded w-full mb-3'})
