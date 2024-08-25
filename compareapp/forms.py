from django import forms
from .models import Document, Feedback
from django.utils import timezone

from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.models import User
from django.contrib.auth.models import Permission

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
        self.fields['version'].widget.attrs.update({'class': 'form-input mt-1 rounded w-full mb-3'})
        self.fields['language'].widget.attrs.update({'class': 'form-select mt-1 rounded w-full mb-3'})
        self.fields['doc_type'].widget.attrs.update({'class': 'form-select mt-1 rounded w-full mb-3'})
        self.fields['doc_format'].widget.attrs.update({'class': 'form-input mt-1 rounded w-full mb-3'})
        self.fields['upload_document'].widget.attrs.update({'class': 'form-input mt-1 rounded w-full mb-3'})
        self.fields['comments'].widget.attrs.update({'class': 'form-textarea h-14 mt-1 rounded w-full mb-3'})

class CustomPasswordResetForm(PasswordResetForm):
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not User.objects.filter(email=email).exists():
            raise forms.ValidationError("There is no account registered with this email address.")
        return email


class UserForm(forms.ModelForm):
    DOCUMENT_PERMISSIONS = [
        'add_document',
        'change_document',
        'delete_document',
        'view_document',
    ]
    COMPARISON_REPORT_PERMISSIONS = [
        'add_comparisonreport',
        'change_comparisonreport',
        'delete_comparisonreport',
        'view_comparisonreport',
    ]
    USER_MANAGEMENT_PERMISSIONS = [
        'add_user',
        'change_user',
        'delete_user',
        'view_user',
    ]
    FEEDBACK_PERMISSIONS = [
        'add_feedback',
        'change_feedback',
        'delete_feedback',
        'view_feedback',
    ]
    
    PERMISSIONS = (
        DOCUMENT_PERMISSIONS +
        COMPARISON_REPORT_PERMISSIONS +
        USER_MANAGEMENT_PERMISSIONS +
        FEEDBACK_PERMISSIONS
    )

    permissions = forms.ModelMultipleChoiceField(
        queryset=Permission.objects.filter(codename__in=PERMISSIONS),
        widget=forms.CheckboxSelectMultiple,
        required=True
    )

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'is_active', 'permissions']
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-input w-full rounded-lg border-gray-300 focus:ring-blue-500 focus:border-blue-500',
                'required': 'required',
                'placeholder': 'Enter username',
            }),
            'first_name': forms.TextInput(attrs={
                'class': 'form-input w-full rounded-lg border-gray-300 focus:ring-blue-500 focus:border-blue-500',
                'required': 'required',
                'placeholder': 'Enter first name',
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-input w-full rounded-lg border-gray-300 focus:ring-blue-500 focus:border-blue-500',
                'required': 'required',
                'placeholder': 'Enter last name',
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-input w-full rounded-lg border-gray-300 focus:ring-blue-500 focus:border-blue-500',
                'required': 'required',
                'placeholder': 'Enter email address',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox text-blue-600 focus:ring-blue-500 border-gray-300 rounded',
            }),
        }

class FeedbackForm(forms.ModelForm):
    class Meta:
        model = Feedback
        fields = ['feedback', 'email']
        widgets = {
            'feedback': forms.Textarea(attrs={'rows': 3}),
            'email': forms.EmailInput(attrs={'placeholder': 'Optional'}),
        }