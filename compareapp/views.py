import os
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.core.files.storage import FileSystemStorage
from django.contrib import messages
from docx import Document
from .forms import DocumentForm
from .models import Document as Form
from docx.shared import RGBColor
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
import difflib
import PyPDF2   
import fitz
import docx


def index(request):
    return render(request, "index.html")

def logoutUser(request):
    logout(request)
    messages.info(request, "You have logged out.")
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
                messages.success(request, "You have successfully logged in.")
                return redirect('form')
            else:
                messages.error(request, "Please provide valid login credentials.")
            
    return render(request, "login.html")

def form(request):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')
    
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, "Document added successfully.")
            return redirect('document-list')
        else:
            messages.warning(request, "All the fields are required to fill!")
    else:
        form = DocumentForm()
    document_count = Form.objects.count()
    formData = Form.objects.last()
    if not formData:
        doc_id = 1
    else:
        doc_id = formData.document_id + 1
        
    return render(request, "form.html", {'form': form, 'doc_id': doc_id, 'document_count': document_count})

def documentList(request):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')
    
    documents = Form.objects.all()
    
    if not documents:
        messages.info(request, "Please upload documents first.")
    
    return render(request, 'document-list.html', { 'documents': documents })

def removeDocument(request, doc_id):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')
    
    document = get_object_or_404(Form, document_id=doc_id)

    if not document:
        messages.warning(request, "Invalid document ID, please provide valid ID")
        return redirect('document-list')
    
    try:
        document.delete()
        messages.success(request, "Document deleted successfully.")
        return redirect('document-list')
    except:
        messages.error(request, "Error occured while performing the action.")

    return redirect('document-list')

def comparison(request):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')

    documents = Form.objects.all()
    
    if not documents:
        messages.info(request, "Please upload documents first.")
        return redirect('form')
    
    data = {}
    for doc in documents:
        file_path = doc.upload_document.path  # Ensure this is the correct path
        sections = read_docx(file_path)
        data[doc.document_id] = sections  # Use doc.id to uniquely identify documents

    output_path = os.path.join(settings.MEDIA_ROOT, "data.docx")
    create_merged_docx(data, output_path)
    
    return render(request, 'result.html', { 'documents': documents, 'output_path': output_path })
    


def read_docx(file_path):
    doc = Document(file_path)
    sections = {}
    current_section = None
    current_content = []
    
    for para in doc.paragraphs:
        text = para.text.strip()
        if text:
            if text[0].isdigit() and text[1] == '.':
                if current_section:
                    sections[current_section] = ' '.join(current_content)
                current_section = text
                current_content = []
            else:
                current_content.append(text)
    
    if current_section:
        sections[current_section] = ' '.join(current_content)
    
    return sections

def highlight_differences(doc, title, text, is_different):
    doc.add_heading(title, level=2)
    para = doc.add_paragraph()
    for part in text.split(' '):
        run = para.add_run(part + ' ')
        if is_different:
            run.font.color.rgb = RGBColor(255, 0, 0)  # Red color for differences

def compare_sections(section1, section2):
    return section1 != section2

def create_merged_docx(data, output_path):
    new_doc = Document()
    headers = [
        "1. Introduction",
        "2. Responsibilities",
        "3. OOS Identification and Notification",
        "4. OOS Investigation",
        "5. OOS Communication",
        "6. Corrective and Preventive Actions (CAPA)",
        "7. Backorder Management",
        "8. Product Recall (if applicable)",
        "9. Recordkeeping",
        "10. Training",
        "11. Review and Update"
    ]
    
    for header in headers:
        new_doc.add_heading(header, level=1)
        for doc_id, sections in data.items():
            section_content = sections.get(header, "")
            if section_content:
                is_different = compare_sections(section_content, list(data.values())[0].get(header, ""))
                highlight_differences(new_doc, header, section_content, is_different)
    
    new_doc.save(output_path)