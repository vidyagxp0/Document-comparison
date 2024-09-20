from django import forms
from .models import Document, Feedback

from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib.auth.models import User
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError

class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['title', 'author', 'creation_date', 'version', 'language', 'doc_type', 'doc_format', 'upload_document', 'comments']
        widgets = {
            'creation_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-input mb-3 rounded w-full text-slate-700 border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500'}),
        }

    def __init__(self, *args, **kwargs):
        super(DocumentForm, self).__init__(*args, **kwargs)
        self.fields['title'].widget.attrs.update({'class': 'form-input mb-3 rounded w-full text-slate-700 border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500', 'placeholder': 'Enter document title'})
        self.fields['author'].widget.attrs.update({'class': 'form-input mb-3 rounded w-full text-slate-700 border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500', 'placeholder': 'Enter document author'})
        self.fields['version'].widget.attrs.update({'class': 'form-input mb-3 rounded w-full text-slate-700 border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500', 'placeholder': 'Enter document version'})
        self.fields['language'].widget.attrs.update({'class': 'form-select mb-3 rounded w-full text-slate-700 border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500'})
        self.fields['doc_type'].widget.attrs.update({'class': 'form-select mb-3 rounded w-full text-slate-700 border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500'})
        self.fields['doc_format'].widget.attrs.update({'class': 'form-input mb-3 rounded w-full text-slate-700 border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500', 'readonly': 'readonly', 'title': 'This field is read-only.'})
        self.fields['upload_document'].widget.attrs.update({'class': 'form-input mb-3 rounded w-full text-slate-700 border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500'})
        self.fields['comments'].widget.attrs.update({'class': 'form-input mb-4 rounded w-full text-slate-700 border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500', 'maxlength': '200', 'placeholder': 'Enter comments here...'})

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

    PASSWORD_TYPE_CHOICES = [
        ('manual', 'Manual'),
        ('bymail', 'By Mail'),
    ]

    password_type = forms.ChoiceField(
        choices=PASSWORD_TYPE_CHOICES,
        widget=forms.RadioSelect,
        required=False,
    )

    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-input w-full text-slate-700 rounded-lg border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500',
            'placeholder': 'Enter user password',
        }),
        required=False,
    )

    class Meta:
        model = User
        fields = ['username', 'password', 'first_name', 'last_name', 'email', 'date_joined', 'is_superuser', 'is_active', 'permissions']
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-input w-full text-slate-700 rounded-lg border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500',
                'required': 'required',
                'placeholder': 'Enter username',
            }),
            'first_name': forms.TextInput(attrs={
                'class': 'form-input w-full text-slate-700 rounded-lg border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500',
                'required': 'required',
                'placeholder': 'Enter first name',
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-input w-full text-slate-700 rounded-lg border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500',
                'required': 'required',
                'placeholder': 'Enter last name',
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-input w-full text-slate-700 rounded-lg border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500',
                'required': 'required',
                'placeholder': 'Enter email address',
            }),
            'date_joined': forms.DateInput(attrs={
                'type': 'date',
                'class': 'form-input w-full text-slate-700 rounded-lg border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500',
                'required': 'required',
                'readonly': 'readonly',
                'title': 'This field is set as read-only.'
            }),
            'is_superuser': forms.CheckboxInput(attrs={
                'class': 'form-checkbox text-cyan-600 focus:ring-cyan-500 border-cyan-300 rounded',
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-checkbox text-cyan-600 focus:ring-cyan-500 border-cyan-300 rounded',
            }),
        }

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)

        if self.instance.pk:                  # User is being edited
            self.fields.pop('password_type', None)
            self.fields.pop('password', None)

    def clean(self):
        cleaned_data = super().clean()
        password_type = cleaned_data.get('password_type')
        password = cleaned_data.get('password')

        if not self.instance.pk:
            if password_type == 'manual':
                if not password:
                    self.add_error('password', "Password is required when selecting 'Manual' password type.")
                elif len(password) < 8:
                    self.add_error('password', "Password must be at least 8 characters long.")

        return cleaned_data
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            if User.objects.filter(email=email).exclude(id=self.instance.id).exists():
                raise ValidationError("A user with that email already exists.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)

        if not self.instance.pk:
            password = self.cleaned_data.get('password')
            password_type = self.cleaned_data.get('password_type')

            if password_type == 'manual' and password:
                user.set_password(password)

        if commit:
            user.save()
            self.save_m2m()

        return user

class CustomSetPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(
        label="New Password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-input w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-cyan-500 focus:border-cyan-500',
            'placeholder': 'Enter your new password',
        }),
    )
    new_password2 = forms.CharField(
        label="Confirm New Password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-input w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-cyan-500 focus:border-cyan-500',
            'placeholder': 'Confirm your new password',
        }),
    )
        
class FeedbackForm(forms.ModelForm):
    class Meta:
        model = Feedback
        fields = ['feedback', 'email']
        widgets = {
            'feedback': forms.Textarea(attrs={'rows': 3}),
            'email': forms.EmailInput(attrs={'placeholder': 'Optional'}),
        }