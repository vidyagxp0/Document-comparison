import os, re
from django import forms
from .models import Document, Feedback, UserProfile

from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib.auth.models import User
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError

# Handling multiple files -------------------------------
class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True

class MultipleFileField(forms.FileField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("widget", MultipleFileInput())
        super().__init__(*args, **kwargs)

    def clean(self, data, initial=None):
        single_file_clean = super().clean
        if isinstance(data, (list, tuple)):
            result = [single_file_clean(d, initial) for d in data]
        else:
            result = [single_file_clean(data, initial)]
        return result

# end - Handling multiple files -------------------------------

class DocumentForm(forms.ModelForm):
    upload_documents = MultipleFileField()
    class Meta:
        model = Document
        fields = ['upload_documents']

    def clean_upload_documents(self):
        files = self.files.getlist('upload_documents')
        if not files:
            raise forms.ValidationError('Please upload at least one document.')

        if len(files) < 2:
            raise forms.ValidationError('Please upload minimum two documents.')

        return files

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
        # 'add_user',
        'change_user',
        # 'delete_user',
        # 'view_user',
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

    phone_number = forms.CharField(
        max_length=15,
        widget=forms.TextInput(attrs={
            'class': 'form-input w-full text-slate-700 rounded-lg border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500',
            'placeholder': '9876543210',
        }),
        required=True,
    )

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')

        if not re.match(r'\d{10}$', phone_number):
            raise ValidationError("Enter a valid phone number in the format: 9876543210")

        return phone_number

    address = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-input w-full text-slate-700 rounded-lg border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500',
            'placeholder': 'Enter address',
            'rows': 3,
        }),
        required=True,
    )

    department = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-input w-full text-slate-700 rounded-lg border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500',
            'placeholder': 'Enter your department'
        }),
        required=True,
    )

    blood_group = forms.ChoiceField(
        choices=[
            ('A+', 'A+'), ('A-', 'A-'), 
            ('B+', 'B+'), ('B-', 'B-'), 
            ('AB+', 'AB+'), ('AB-', 'AB-'), 
            ('O+', 'O+'), ('O-', 'O-')
        ],
        widget=forms.Select(attrs={
            'class': 'form-select w-full text-slate-700 rounded-lg border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500',
        }),
        required=False,
    )

    image = forms.ImageField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-input w-full text-slate-700 rounded-lg border-cyan-300 focus:ring-cyan-500 focus:border-cyan-500',
        }),
    )

    class Meta:
        model = User
        fields = ['username', 'password', 'first_name', 'last_name', 'email', 'date_joined', 'is_superuser', 'is_active', 'permissions', 'phone_number', 'address', 'department', 'blood_group', 'image']
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

            profile = self.instance.profile
            self.fields['phone_number'].initial = profile.phone_number
            self.fields['address'].initial = profile.address
            self.fields['department'].initial = profile.department
            self.fields['blood_group'].initial = profile.blood_group
            self.fields['image'].initial = profile.image

    def clean(self):
        cleaned_data = super().clean()

        if not self.instance.pk:
            password_type = cleaned_data.get('password_type')
            password = cleaned_data.get('password')
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


        profile, created = UserProfile.objects.get_or_create(user=user)
        
        profile.phone_number = self.cleaned_data.get('phone_number', profile.phone_number)
        profile.address = self.cleaned_data.get('address', profile.address)
        profile.department = self.cleaned_data.get('department', profile.department)
        profile.blood_group = self.cleaned_data.get('blood_group', profile.blood_group)

        new_image = self.cleaned_data.get('image')
        if new_image:
            if profile.pk and profile.image and profile.image != new_image:
                old_image = profile.image
                if old_image and os.path.isfile(old_image.path):
                    os.remove(old_image.path)

            profile.image = new_image  # Update with the new image

        profile.save()

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

