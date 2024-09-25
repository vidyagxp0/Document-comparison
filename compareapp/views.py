from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404, HttpResponse
from django.urls import reverse
from django.db.models import Q
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import user_passes_test

from django.views.decorators.csrf import csrf_exempt
from django.templatetags.static import static
from django.contrib import messages

from .forms import DocumentForm, CustomPasswordResetForm, UserForm, FeedbackForm, CustomSetPasswordForm
from .models import Document as Form, ComparisonReport, Feedback, UserProfile

from docx import Document
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from docx.shared import RGBColor
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.shared import Pt, Inches

import fitz     # PDF reader
from PyPDF2 import PdfReader

import pandas as pd
from pathlib import Path
import convertapi
import difflib
from django.http import JsonResponse
import json

import os
import openai
import requests
import logging
from datetime import datetime as date
import datetime

# mail configuration  
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.http import urlsafe_base64_decode
from django.core.mail import EmailMultiAlternatives
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.auth.models import User

def index(request):
    return render(request, "index.html")

def logoutUser(request):
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('index')

def loginUser(request):
    if request.method == "POST":
        username = request.POST.get('userid')
        password = request.POST.get('password')

        if not username or not password:
            messages.warning(request, "Please provide the login credentials.")
        else:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                
                request.session.set_expiry(settings.SESSION_COOKIE_AGE)
                request.session['expiry_time'] = settings.SESSION_COOKIE_AGE

                messages.success(request, "You have successfully logged in.")
                return redirect('dashboard')
            else:
                messages.error(request, "Please provide valid login credentials.")
            
    return render(request, "login.html")

def submitFeedback(request):
    previous_url = request.META.get('HTTP_REFERER', 'dashboard')

    if request.method == 'POST':
        form = FeedbackForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Thank you for your valuable feedback!')
        else:
            messages.warning(request, 'Please provide valid feedback!')

    return redirect(previous_url)
    
# User Management Section -------------------------------------------------------------
@login_required
@user_passes_test(lambda user: user.is_superuser)
def userManagement(request):
    # Custom logic for superuser validation
    # if not request.user.is_superuser:
    #     messages.warning(request, "You are restricted to access the user management!")
    #     return redirect(request.META.get('HTTP_REFERER', reverse('dashboard')))    
    
    query = request.GET.get('q')
    filter_by = request.GET.get('status')

    users = User.objects.all()

    if query:
        users = users.filter(
            Q(id__icontains=query) |
            Q(username__icontains=query) |
            Q(email__icontains=query)
        ).distinct()
    
    if filter_by:
        if filter_by == 'active':
            users = users.filter(is_active=True)
        elif filter_by == 'inactive':
            users = users.filter(is_active=False)

    return render(request, 'user-management/users.html', {'users': users})

@login_required
@user_passes_test(lambda user: user.is_superuser)
def add_edit_user(request, user_id=None):
    if user_id:
        user = get_object_or_404(User, id=user_id)
        form = UserForm(request.POST or None, request.FILES or None , instance=user)
        user_permissions = user.user_permissions.all()
    else:
        user = None
        form = UserForm(request.POST or None, request.FILES or None , request=request)
        user_permissions = []

    if request.method == 'POST':
        if form.is_valid():
            user = form.save()
            user.user_permissions.set(form.cleaned_data['permissions'])

            if not user_id:
                passwd_type = form.cleaned_data.get('password_type')
                if passwd_type == "bymail":
                    # Send email for password creation
                    subject = "Create Your Password"
                    email_template_name = "password-base/password_creation_email.html"
                    context = {
                        "email": user.email,
                        "domain": request.META['HTTP_HOST'],
                        "site_name": "Doc Comparison Pro",
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        "token": default_token_generator.make_token(user),
                        "protocol": "http",
                    }
                    email_message = render_to_string(email_template_name, context)
                    email = EmailMultiAlternatives(
                        subject=subject,
                        body=email_message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        to=[user.email]
                    )
                    email.attach_alternative(email_message, "text/html")
                    email.send(fail_silently=False)

                    messages.success(request, 'User created successfully.')
                    messages.info(request, 'Password creation request has been sent to the user.')
                else:
                    messages.success(request, 'User created successfully.')
            else:
                messages.success(request, 'User updated successfully.')

            return redirect('user-management')

    return render(request, 'user-management/user_form.html', {
        'form': form,
        'user': user,
        'user_permissions': user_permissions,
    })
    
@login_required
@user_passes_test(lambda user: user.is_superuser)
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        user.delete()
        messages.success(request, f'User {user.username} was successfully deleted.')
        return redirect(reverse('user-management'))
    return render(request, 'user-management/user_management.html', {'users': User.objects.all()})

# User Profile View
@login_required
def user_profile(request, user_id):
    exists = User.objects.filter(id=user_id)

    if not exists:
        messages.warning(request, "The requested profile is not available!")
        return redirect(request.META.get('HTTP_REFERER', 'dashboard'))
    
    if request.user.is_superuser:
        user = User.objects.get(id=user_id)
    else:
        user = User.objects.get(id=request.user.id)

    total_comparison = len(ComparisonReport.objects.filter(user=request.user))
    total_documents = len(Form.objects.filter(user=request.user))

    specific_permissions = [
        "auth.add_user",
        "auth.change_user",
        "auth.delete_user",
        "auth.view_user",
        "compareapp.add_comparisonreport",
        "compareapp.change_comparisonreport",
        "compareapp.delete_comparisonreport",
        "compareapp.view_comparisonreport",
        "compareapp.add_document",
        "compareapp.change_document",
        "compareapp.delete_document",
        "compareapp.view_document",
        "compareapp.add_feedback",
        "compareapp.change_feedback",
        "compareapp.delete_feedback",
        "compareapp.view_feedback",
    ]
    
    return render(request, 'user-management/user_profile.html', {
        'user': user,
        'total_comparison': total_comparison,
        'total_documents': total_documents,
        'specific_permissions': specific_permissions,
    })

# Comparison analytics ------------------------------------
def analytics(request):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')

    files_format = ['pdf', 'docx', 'xlsx', 'pptx', 'vsd', 'wav', 'mp4', 'png', 'txt', 'other']
    file_labels = ['PDFs', 'Documents', 'Spreadsheets', 'Prasentations', 'Visios', 'Audios', 'Videos', 'Images', 'Text', 'Others']

    # Handling users
    if request.user.is_superuser:
        total_files_data = [ len(Form.objects.filter(comparison_between = doc)) for doc in files_format ]
        all_comparison_data = [ len(ComparisonReport.objects.filter(comparison_between = doc)) for doc in files_format ]

        total_comparisons = len(ComparisonReport.objects.all())
        failed_reports = len(ComparisonReport.objects.filter(comparison_status=False))
    else:
        total_files_data = [ len(Form.objects.filter(user=request.user, comparison_between = doc)) for doc in files_format ]
        all_comparison_data = [ len(ComparisonReport.objects.filter(user=request.user, comparison_between = doc)) for doc in files_format ]

        total_comparisons = len(ComparisonReport.objects.filter(user=request.user))
        failed_reports = len(ComparisonReport.objects.filter(user=request.user, comparison_status=False))
    
    total_users = len(User.objects.all())
    user_feedbacks = len(Feedback.objects.all())

    total_files = {
        'labels': file_labels,
        'values': total_files_data
    }

    all_comparisons = {
        'labels': file_labels,
        'values': all_comparison_data
    }
    
    report_data={
        'labels': file_labels,
        'values': total_files_data
    }

    return render(request, 'analytics.html', { 'failed_reports':failed_reports, 'total_users': total_users, 'total_files': total_files, 'report_data':report_data , 'user_feedbacks': user_feedbacks, 'total_comparisons':total_comparisons , 'all_comparisons':all_comparisons})

def password_reset_request(request):
    if request.method == "POST":
        form = CustomPasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            users = User.objects.filter(email=email)
            if users.exists():
                for user in users:
                    subject = "Password Reset Requested"
                    email_template_name = "password-base/password_reset_email.html"
                    context = {
                        "email": user.email,
                        "domain": request.META['HTTP_HOST'],
                        "site_name": "Doc Comparison Pro",
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        "token": default_token_generator.make_token(user),
                        "protocol": "http",
                    }
                    email_message = render_to_string(email_template_name, context)
                    email = EmailMultiAlternatives(
                        subject=subject,
                        body=email_message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        to=[user.email]
                    )
                    email.attach_alternative(email_message, "text/html")
                    email.send(fail_silently=False)
                messages.success(request, "Password reset request has been sent.")
            else:
                messages.error(request, "The provided email is not registered.")
            form = CustomPasswordResetForm()
    else:
        form = CustomPasswordResetForm()

    return render(request, "password-base/password_reset_form.html", {"form": form})

def password_creation_view(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = get_object_or_404(User, pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = CustomSetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                return redirect('password_create_done')
        else:
            form = CustomSetPasswordForm(user)
    else:
        form = None

    return render(request, 'password-base/password_creation_confirm.html', {'form': form})

def dashboard(request):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')
    
    query = request.GET.get('q', '')
    filter_by = request.GET.get('filter')

    if request.user.is_superuser:
        reports = ComparisonReport.objects.all()
    else:
        reports = ComparisonReport.objects.filter(user=request.user)
    
    if filter_by:
        valid_filters = ['docx', 'pdf', 'xlsx', 'pptx', 'vsd', 'wav', 'mp4', 'png', 'txt', 'other']
        if filter_by in valid_filters:
            reports = reports.filter(comparison_between__icontains=filter_by)

    if query:
        reports = reports.filter(
            Q(report_number__icontains=query) |
            Q(short_description__icontains=query) |
            Q(department_type__icontains=query) |
            Q(comparison_date__icontains=query) |
            Q(compared_by__icontains=query)
        ).distinct()
    
    return render(request, 'dashboard.html', { "reports": reports[::-1] })

def viewComparison(request, report_id):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')
    
    try:
        if request.user.is_superuser:
            report = ComparisonReport.objects.filter(report_number=report_id).first()
            compared_documents = report.compared_documents
            document_ids = list(compared_documents.values())
            documents = Form.objects.filter(document_id__in=document_ids)
        else:
            report = ComparisonReport.objects.filter(user=request.user, report_number=report_id).first()
            compared_documents = report.compared_documents
            document_ids = list(compared_documents.values())
            documents = Form.objects.filter(user=request.user, document_id__in=document_ids)

    except:
        messages.warning(request, "The requested report is not available!")
        return redirect('dashboard')

    comparison_details = report.comparison_summary

    return render(request, "view-comparisons/view-comparison.html", {
        "documents": documents,
        "comparison_details": comparison_details,
        "report": report_id,
        "report_summary": report.ai_summary
    })

def formView(request):   
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')

    report_number = request.GET.get('report_number')
    success = request.GET.get('success')
    last_report = ComparisonReport.objects.last()
    current_date = datetime.date.today()

    if last_report:
        new_report_number = f"DC{ request.user.id }R{int(last_report.report_number.split('R')[1]) + 1}"
    else:
        new_report_number = f"DC{ request.user.id }R1001"

    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        comparison_between = request.POST.get("documents_format")
        comparison_date = request.POST.get("comparison_date")
        short_description = request.POST.get("short_description")
        description = request.POST.get("description")
        department_type = request.POST.get("department_type")

        if form.is_valid():
            documents = request.FILES.getlist('upload_documents')

            if not comparison_between:
                messages.warning(request, f"Please select the files type to intialise the upload process, otherwise reset the process!")
                return render(request, "form.html", {
                    'form': form,
                    'success': success,
                    'new_report_number': new_report_number,
                    'current_date': current_date,
                    'report_number': report_number
                })

            for doc in documents:
                file_extension = os.path.splitext(doc.name)[1].lstrip('.').lower()

                if file_extension != comparison_between:
                    messages.warning(request, f"Please upload '{comparison_between}' files only for the comparison!")
                    return render(request, "form.html", {
                        'form': form,
                        'success': success,
                        'new_report_number': new_report_number,
                        'current_date': current_date,
                        'report_number': report_number
                    })
            
            try:
                for doc in documents:
                    document_instance = Form()
                    document_instance.comparison_between = comparison_between
                    document_instance.upload_documents = doc
                    document_instance.user = request.user
                    document_instance.save()

                comparison_instance = ComparisonReport()
                comparison_instance.report_number = new_report_number
                comparison_instance.department_type = department_type
                comparison_instance.description = description
                comparison_instance.short_description = short_description
                comparison_instance.comparison_date = comparison_date
                comparison_instance.comparison_between = comparison_between
                comparison_instance.user = request.user
                comparison_instance.save()
            except:
                messages.warning(request, "Error occured while saving the files or comparison!")
                messages.info(request, "Please reset the upload process!")
                return redirect("form")

            url = reverse('compare')
            redirect_url = f"{url}?report_number={new_report_number}"
            
            return redirect(redirect_url)
        else:
            messages.warning(request, "All fields are required to be filled!")
    else:
        form = DocumentForm()

    return render(request, "form.html", {
        'form': form,
        'success': success,
        'report_number': report_number,
        'current_date': current_date,
        'new_report_number': new_report_number
    })
    

# Import data view
def importData(request):
    if request.method == 'POST' and request.FILES.get('excelFile'):
        try:
            excel_file = request.FILES['excelFile']
            df = pd.read_excel(excel_file)

            description = df['description'].iloc[0]
            short_description = df['short_description'].iloc[0]
            department_type = df['department_type'].iloc[0]

            return JsonResponse({
                'success': True,
                'data': {
                    'description': description,
                    'short_description': short_description,
                    'department_type': department_type,
                }
            })

        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    return JsonResponse({'success': False, 'error': 'Invalid request'})


# Resetting upload process
@login_required
def uploadReset(request):
    documents = Form.objects.filter(new=True, user=request.user)
    if documents:
        documents.delete()

    messages.success(request, "The upload process was successfully reset.")
    return redirect('form')

def documentDetail(request, doc_id):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')
    
    try: 
        if request.user.is_superuser:
            document = get_object_or_404(Form, document_id=doc_id)
        else:
            document = get_object_or_404(Form, document_id=doc_id, user=request.user)
    except:
        messages.warning(request, "Invalid document ID, please provide valid ID.")
        return redirect('dashboard')
    
    return render(request, 'document-details.html', { 'document': document })

def comparedDocument(request, id):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')

    query = request.GET.get('q', '')
    filter_type = request.GET.get('filter', '')

    try:
        documents = Form.objects.filter(report_number=id, user=request.user)
    except:
        messages.warning(request, "Document ID is not available or invalid!")
        return redirect('dashboard')

    if query:
        documents = documents.filter(
            Q(document_id__icontains=query) |
            Q(comparison_between__icontains=query) |
            Q(report_number__icontains=query) |
            Q(summary__icontains=query)
        ).distinct()

    if filter_type and filter_type != '':
        documents = documents.filter(comparison_between=filter_type)
    
    return render(request, 'view-comparisons/compared-documents.html', { 'documents': documents })

@login_required
def removeDocument(request, doc_id):
    previous_url = request.META.get('HTTP_REFERER', 'dashboard')

    try:
        document = get_object_or_404(Form, document_id=doc_id)
        document.delete()
        remove_file = document.upload_document.path
        os.remove(remove_file)
        messages.success(request, "Document deleted successfully.")
    except:
        messages.warning(request, "Invalid document ID, please provide valid ID")
        
    return redirect(previous_url)

def comparison(request: HttpRequest):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')

    old_report_number = request.GET.get('report_number', '')
    documents = Form.objects.filter(new=True, user=request.user)

    if not documents or len(documents) < 2:
        messages.warning(request, "Minimum two documents are required to perform the comparison!")
        return redirect('form') 
    
    comparison_between = documents[0].comparison_between
    user_full_name = request.user.get_full_name().title()
    
    try:
        short_description = get_object_or_404(ComparisonReport, report_number=old_report_number).short_description
    except:
        messages.error(request, "Invalid comparison ID, can't perform the comparison!")
        return redirect("form")
    
    if not user_full_name:
        comparedBy = request.user.username.title()
    else:
        comparedBy = user_full_name  
    
    data = {}
    ai_summary = {}
    for doc in documents:
        file_path = doc.upload_documents.path
        if comparison_between == 'docx':
            sections = read_docx(file_path)
            data[doc.document_id] = sections
            
            # Getting AI Summary
            content = read_file(file_path)
            ai_summary[doc.document_id] = getSummary(content)
            
        elif comparison_between == 'pdf':
            sections = read_pdf(file_path)
            data[doc.document_id] = sections
            
            # Getting AI Summary
            content = read_file(file_path)
            ai_summary[doc.document_id] = getSummary(content)

        else:
            messages.error(request, "Can't perform comparison due to invalid file format.")
            return redirect('form')


    result_dir = os.path.join(settings.MEDIA_ROOT, 'comparison-reports')
    os.makedirs(result_dir, exist_ok=True)

    result_path = os.path.join(result_dir, f"{old_report_number}.docx")
    logo_path = "compareapp" + static('images/logo.png')

    create_merged_docx(data, old_report_number, result_path, logo_path, comparedBy, short_description)

    # Prepare comparison details
    comparison_details = {}
    overall_similarity_scores = {}
    headers = set()
    for sections in data.values():
        headers.update(sections.keys())

    headers = sorted(headers, key=lambda x: (int(x.split('.')[0]), x))  # Sort headers

    primary_doc_id = list(data.keys())[0]  # Assume the first document is the primary document
    for header in headers:
        comparison_details[header] = {
            'primary': data[primary_doc_id].get(header, ""),
            'documents': {}
        }
        ref_section_content = data[primary_doc_id].get(header, "")
        for doc_id, sections in data.items():
            if doc_id != primary_doc_id:
                section_content = sections.get(header, "")
                if section_content:
                    similarity, is_different, tag ,added_text, removed_text, modified_text  = compare_sections(ref_section_content, section_content)
                    if is_different:  # Only include if different
                        comparison_details[header]['documents'][doc_id] = {
                            'content': section_content or 'Removed',
                            'tag': tag,
                            'added_text': added_text,
                            'removed_text': removed_text,
                            'modified_text': modified_text
                        }
                    else:
                        comparison_details[header]['documents'][doc_id] = {
                            'content': 'Same as Primary Document',
                            'tag': 'S'
                        }

    # Calculate overall similarity score for each document
    ref_doc_content = "\n".join(list(data.values())[0].values())
    for doc_id, sections in data.items():
        doc_content = "\n".join(sections.values())
        overall_similarity_score, _, _, _, _, _ = compare_sections(ref_doc_content, doc_content )
        overall_similarity_scores[doc_id] = int(overall_similarity_score * 100)


    # Now Saving the Comparison Result
    for doc in documents:
        doc.new = False
        doc.summary = "Same" if overall_similarity_scores[doc.document_id] == 100 else "Different"
        doc.similarity_score = overall_similarity_scores[doc.document_id]
        doc.comparison_status = 'Compared'
        doc.ai_summary = ai_summary[doc.document_id]
        doc.report_number = old_report_number
        doc.save()

    compared_documents = {}
    for index, doc in zip(range(1, len(documents) + 1), documents):
        compared_documents[f'doc{index}'] = doc.document_id

    prepare_data = read_file(result_path)
    comparison_ai_summary = getSummary(prepare_data, ind=False)

    try:
        comparison_instance = ComparisonReport.objects.get(report_number=old_report_number, user=request.user)
        comparison_instance.compared_documents = compared_documents
        comparison_instance.comparison_summary = comparison_details
        comparison_instance.ai_summary = comparison_ai_summary
        comparison_instance.compared_by = comparedBy
        comparison_instance.report_path = result_path
        comparison_instance.save()

        return redirect(f'{reverse("form")}?success=True&report_number={old_report_number}')

    except Exception as e:
        # messages.error(request, "Error occured while saving the comparison data.")
        return HttpResponse(f"Error: {e}")

def compare_sections(section1, section2):      
    words1 = section1.strip().split()
    words2 = section2.strip().split()

    seq_matcher = difflib.SequenceMatcher(None, words1, words2)
    similarity = seq_matcher.ratio()
    is_different = similarity < 1.0

    added_words = []
    removed_words = []
    modified_words = []

    for tag, i1, i2, j1, j2 in seq_matcher.get_opcodes():
        if tag == 'replace':
            removed_words.append(' '.join(words1[i1:i2]))
            added_words.append(' '.join(words2[j1:j2]))
        elif tag == 'delete':
            removed_words.append(' '.join(words1[i1:i2]))
        elif tag == 'insert':
            added_words.append(' '.join(words2[j1:j2]))

    if similarity <= 0.4:
        modified_words.append(section2)

    if similarity == 1.0:
        tag = "S"  # Same
    elif added_words and not removed_words:
        tag = "A"  # Added
    elif removed_words and not added_words:
        tag = "R"  # Removed
    else:
        tag = "M"  # Modified       

    return similarity, is_different, tag, ' '.join(added_words), ' '.join(removed_words), ' '.join(modified_words) 

def read_docx(file_path):
    doc = Document(file_path)
    sections = {}
    current_section = None
    current_content = []

    for para in doc.paragraphs:
        text = para.text.strip()
        if text:
            if text[0].isdigit() and (text[1] == '.' or (text[1].isdigit() and text[2] == '.')):
                if current_section:
                    sections[current_section] = '\n'.join(current_content)
                current_section = text
                current_content = []
            else:
                current_content.append(text)

    if current_section:
        sections[current_section] = '\n'.join(current_content)

    return sections

def read_pdf(file_path):
    doc = fitz.open(file_path)
    sections = {}
    current_section = None
    current_content = []

    for page_num in range(len(doc)):
        page = doc[page_num]
        text = page.get_text("text").strip()
        lines = text.splitlines()

        for line in lines:
            line = line.strip()
            if line:
                if line[0].isdigit() and (line[1] == '.' or (line[1].isdigit() and line[2] == '.')):
                    if current_section:
                        sections[current_section] = '\n'.join(current_content)
                    current_section = line
                    current_content = []
                else:
                    current_content.append(line)

    if current_section:
        sections[current_section] = '\n'.join(current_content)

    return sections

def create_merged_docx(data, reportNo, output_path, logo_path, comparedBy, short_description):
    new_doc = Document()

    # Set headers and footers for the entire document
    section = new_doc.sections[0]

    # Header with logo image
    header = section.header
    header_table = header.add_table(rows=3, cols=2, width=Inches(6))

    header_table.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

    # Set table borders for header
    set_table_borders(header_table)

    # Set vertical alignment for all cells
    for row in header_table.rows:
        for cell in row.cells:
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER

    header_table.cell(0, 0).paragraphs[0].add_run().add_picture(logo_path, width=Inches(1.5))  # Adjust width as needed

    header_right_cell = header_table.cell(0, 1)
    header_right_para = header_right_cell.paragraphs[0]
    header_right_para.add_run("Documents Comparison Report").font.size = Pt(15)
    header_right_para.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

    header_left_cell = header_table.cell(1, 0)
    header_left_para = header_left_cell.paragraphs[0]
    header_left_para.add_run("Compared By: " + comparedBy).font.size = Pt(12)
    header_left_para.alignment = WD_PARAGRAPH_ALIGNMENT.LEFT

    header_right1_cell = header_table.cell(1, 1)
    header_right1_para = header_right1_cell.paragraphs[0]
    header_right1_para.add_run(f"Report Number: {reportNo}").font.size = Pt(12)
    header_right1_para.alignment = WD_PARAGRAPH_ALIGNMENT.RIGHT

    header_table.cell(2, 0).merge(header_table.cell(2, 1))

    header_right2_cell = header_table.cell(2, 0)
    header_right2_para = header_right2_cell.paragraphs[0]
    header_right2_para.add_run("Comparison short description: " + short_description).font.size = Pt(12)
    header_right2_para.alignment = WD_PARAGRAPH_ALIGNMENT.LEFT

    footer = section.footer
    footer_table = footer.add_table(rows=1, cols=2, width=Inches(6))

    footer_table.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

    set_table_borders(footer_table)

    for row in footer_table.rows:
        for cell in row.cells:
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER

    footer_left_cell = footer_table.cell(0, 0)
    footer_left_para = footer_left_cell.paragraphs[0]
    cdate = date.now()
    footer_left_para.add_run(f"Comparison Date: {str(cdate).split(' ')[0]}").font.size = Pt(12)
    footer_left_para.alignment = WD_PARAGRAPH_ALIGNMENT.LEFT

    footer_right_cell = footer_table.cell(0, 1)
    footer_right_para = footer_right_cell.paragraphs[0]
    footer_right_para.add_run("Page ").font.size = Pt(12)
    footer_right_para.alignment = WD_PARAGRAPH_ALIGNMENT.RIGHT

    run = footer_right_para.add_run()
    fldChar = OxmlElement('w:fldChar')
    fldChar.set(qn('w:fldCharType'), 'begin')
    run._r.append(fldChar)

    instrText = OxmlElement('w:instrText')
    instrText.set(qn('xml:space'), 'preserve')
    instrText.text = 'PAGE'
    run._r.append(instrText)

    fldChar = OxmlElement('w:fldChar')
    fldChar.set(qn('w:fldCharType'), 'separate')
    run._r.append(fldChar)

    run._r.append(OxmlElement('w:t'))

    fldChar = OxmlElement('w:fldChar')
    fldChar.set(qn('w:fldCharType'), 'end')
    run._r.append(fldChar)

    run = footer_right_para.add_run(" of ")

    run = footer_right_para.add_run()
    fldChar = OxmlElement('w:fldChar')
    fldChar.set(qn('w:fldCharType'), 'begin')
    run._r.append(fldChar)

    instrText = OxmlElement('w:instrText')
    instrText.set(qn('xml:space'), 'preserve')
    instrText.text = 'NUMPAGES'
    run._r.append(instrText)

    fldChar = OxmlElement('w:fldChar')
    fldChar.set(qn('w:fldCharType'), 'separate')
    run._r.append(fldChar)

    run._r.append(OxmlElement('w:t'))

    fldChar = OxmlElement('w:fldChar')
    fldChar.set(qn('w:fldCharType'), 'end')
    run._r.append(fldChar)

    headers = set()
    for sections in data.values():
        headers.update(sections.keys())

    headers = sorted(headers, key=lambda x: (int(x.split('.')[0]), x))  # Sort headers

    for header in headers:
        new_doc.add_heading(header, level=1)
        for doc_id, sections in data.items():
            section_content = sections.get(header, "")
            if section_content:
                ref_section_content = list(data.values())[0].get(header, "")
                similarity, is_different, tag , added_text, removed_text, modified_text = compare_sections(ref_section_content, section_content)
                summary = "Same" if not is_different else "Different"
                comparison_status = "Compared" if ref_section_content else "Not Compared"

                if tag == 'A':
                    tag = 'Added'
                elif tag == 'R':
                    tag = 'Removed'
                elif tag == 'S':
                    tag = 'Similar'
                else:
                    tag = 'Modified'

                new_doc.add_heading(f"Document {doc_id}", level=2)

                css = new_doc.add_paragraph()
                run = css.add_run("Content Similarity Score: ")
                run.bold = True
                css.add_run(f"{int(similarity*100)}%")

                s = new_doc.add_paragraph()
                run = s.add_run("Summary: ")
                run.bold = True
                s.add_run(summary)
                
                t = new_doc.add_paragraph()
                run = t.add_run("Tag: ")
                run.bold = True
                t.add_run(tag)

                if modified_text:
                    new_doc.add_heading("Modified Text:", level=3)
                    new_doc.add_paragraph(modified_text)
                else:
                    if added_text:
                        new_doc.add_heading("Added Text:", level=3)
                        new_doc.add_paragraph(added_text)
                    if removed_text:
                        new_doc.add_heading("Removed Text:", level=3)
                        new_doc.add_paragraph(removed_text)

                new_doc.add_heading("Content:", level=3)
                highlight_differences(new_doc, header, section_content, is_different)

    new_doc.save(output_path)

def set_table_borders(table):
    tbl = table._element
    tbl_pr = tbl.tblPr if tbl.tblPr is not None else OxmlElement('w:tblPr')
    tbl_borders = OxmlElement('w:tblBorders')
    for border_name in ["top", "left", "bottom", "right", "insideH", "insideV"]:
        border = OxmlElement(f'w:{border_name}')
        border.set(qn('w:val'), 'single')
        border.set(qn('w:sz'), '4')
        border.set(qn('w:space'), '0')
        border.set(qn('w:color'), '000000')
        tbl_borders.append(border)
    tbl_pr.append(tbl_borders)
    tbl.append(tbl_pr)

def highlight_differences(doc, title, text, is_different):
    paragraphs = text.split('\n')
    for para_text in paragraphs:
        para = doc.add_paragraph()
        for part in para_text.split(' '):
            run = para.add_run(part + ' ')
            if is_different:
                run.font.color.rgb = RGBColor(255, 0, 0)  # Red color for differences

logger = logging.getLogger(__name__)

def docx_to_pdf(docx_path, pdf_path):
    try:
        # Set your ConvertAPI secret
        convertapi.api_secret = settings.CONVERT_API_SECRET

        # Convert the file paths to strings
        docx_path = str(docx_path)
        pdf_path = str(pdf_path)

        # Convert the DOCX to PDF
        result = convertapi.convert('pdf', {
            'File': docx_path
        })

        # Save the result to the specified path
        result.file.save(pdf_path)
        
    except Exception as e:
        logger.error(f"Error converting DOCX to PDF: {e}")
        raise

def preview(request, report):
    comparison_report = Path(settings.MEDIA_ROOT) / f'comparison-reports/{report}.docx'
    pdf_path = comparison_report.with_suffix('.pdf')
    pdf_url = str(pdf_path.relative_to(settings.MEDIA_ROOT)).replace("\\", "/")

    if not pdf_path.exists():
        try:
            docx_to_pdf(comparison_report, pdf_path)
        except :
            messages.info(request, 'Error occured while rendering the file!')
            return redirect('view-comparison', report)
    
    return render(request, 'report-preview.html', {'pdf_path': f'/media/{pdf_url}', 'report': report})


# Chatting with document -----------------------------------------------------------------------
@csrf_exempt
def uploadPDF(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            relative_pdf_path = data.get('file_url')

            absolute_pdf_path = os.path.join(settings.MEDIA_ROOT, relative_pdf_path)

            if not os.path.exists(absolute_pdf_path):
                return JsonResponse({'error': 'File not found or invalid file path'}, status=400)

            with open(absolute_pdf_path, 'rb') as pdf_file:
                files = [
                    ('file', ('file', pdf_file, 'application/pdf'))
                ]
                headers = {
                    'x-api-key': settings.CHATPDF_API_KEY
                }

                response = requests.post('https://api.chatpdf.com/v1/sources/add-file', headers=headers, files=files)

                if response.status_code == 200:
                    return JsonResponse(response.json())
                else:
                    return JsonResponse({'error': response.text}, status=response.status_code)
        except Exception as e:
            print(f"Exception: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)
    
logger = logging.getLogger(__name__)

@csrf_exempt
def proxy_chat_pdf(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            question = data.get('question')
            source_id = data.get('source_id')
            headers = {
                'x-api-key': settings.CHATPDF_API_KEY,
                'Content-Type': 'application/json'
            }
            payload = {
                'sourceId': source_id,
                'messages': [
                    {'role': 'user', 'content': question}
                ]
            }
            response = requests.post('https://api.chatpdf.com/v1/chats/message', json=payload, headers=headers)
            
            if response.ok:
                return JsonResponse(response.json())
            else:
                logger.error(f"ChatPDF API Error: {response.status_code} - {response.text}")
                return JsonResponse(response.json(), status=response.status_code)
        except Exception as e:
            logger.exception("An error occurred while processing the request")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

        
# Handling an environment for generating comparison summary --------------------------------------
def read_word_data(file):
    doc = Document(file)
    return "\n".join([para.text for para in doc.paragraphs])

def read_pdf_data(file):
    pdf = PdfReader(file)
    content = ""
    for page in pdf.pages:
        content += page.extract_text()
    return content

def read_file(file):
    file_type = os.path.splitext(file)[1].lower()
    if file_type == ".docx":
        return read_word_data(file)
    elif file_type == ".pdf":
        return read_pdf_data(file)
    else:
        return None

def getSummary(data, ind=True):
    openai.api_key = settings.OPENAI_API_KEY

    try:
        if ind:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are an AI that give the summary of document content."},
                    {"role": "user", "content": f"give the summary of the following document content:\n{data}"}
                ],
                max_tokens=2000
            )

            summary = response['choices'][0]['message']['content'].strip()
            return summary
        else:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                {"role": "system", "content": "You are an AI that compares documents and highlights revisions/changes."},
                {"role": "user", "content": f"Compare the following documents and highlight the revisions/changes:\n{data}"}
            ],
                max_tokens=2000
            )

            summary = response['choices'][0]['message']['content'].strip()

            return summary
    except Exception as e:
        print("Error occured while fetching the summary response!\n", e)

        return None