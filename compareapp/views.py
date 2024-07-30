import os
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.core.files.storage import FileSystemStorage
from django.contrib import messages
from docx import Document
from docx.shared import RGBColor
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
import difflib
import PyPDF2   
import fitz


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

    return render(request, "form.html")

def read_docx(file_path):
    doc = Document(file_path)
    full_text = []
    for para in doc.paragraphs:
        full_text.append(para.text)
    return '\n'.join(full_text)

def compare_documents_html(content1, content2):
    d = difflib.Differ()
    diff = list(d.compare(content1.splitlines(), content2.splitlines()))
    
    diff_html = []
    for line in diff:
        if line.startswith('+ '):
            diff_html.append(f'<span style="color: green;">{line}</span>')
        elif line.startswith('- '):
            diff_html.append(f'<span style="color: red;">{line}</span>')
        elif line.startswith('  '):
            diff_html.append(line)
    
    return '<br>'.join(diff_html)

def compare_documents_docx(content1, content2):
    d = difflib.Differ()
    diff = list(d.compare(content1.splitlines(), content2.splitlines()))
    return [line for line in diff if not line.startswith('? ')]

def bulkDoc(request):
    if request.method == 'POST':
        attachmentCount = int(request.POST.get('rows', 0))
        main_dir = os.path.join(settings.MEDIA_ROOT, 'documents')
        doc_dir = os.path.join(main_dir, 'docs')
        result_dir = os.path.join(main_dir, 'comparison-data')

        os.makedirs(doc_dir, exist_ok=True)
        os.makedirs(result_dir, exist_ok=True)

        file_paths = []
        document_titles = []

        try:
            for i in range(1, attachmentCount + 1):
                file_object = request.FILES.get(f'attachment_word_{i}')
                if file_object:
                    if not file_object.name.endswith('.docx'):
                        messages.warning(request, 'Please upload only Word (.docx) files.')
                        return redirect('form')

                    file_path = os.path.join(doc_dir, file_object.name)
                    counter = 1

                    while os.path.exists(file_path):
                        base, ext = os.path.splitext(file_path)
                        file_path = f"{base} ({counter}){ext}"
                        counter += 1

                    with open(file_path, 'wb') as temp_file:
                        for chunk in file_object.chunks():
                            temp_file.write(chunk)
                    file_paths.append(file_path)
                    document_titles.append(file_object.name)

            if len(file_paths) > 1:
                comparison_results = []

                for i in range(len(file_paths)):
                    for j in range(i + 1, len(file_paths)):
                        content1 = read_docx(file_paths[i])
                        content2 = read_docx(file_paths[j])
                        comparison_result = compare_documents_docx(content1, content2)

                        summary = 'Same' if 'differences' not in comparison_result else 'Different'

                        comparison_results.append({
                            'doc1_title': document_titles[i],
                            'doc2_title': document_titles[j],
                            'summary': summary,
                            'details': comparison_result
                        })

                result_file_name = 'comparison_results.docx'
                result_file_path = os.path.join(result_dir, result_file_name)
                
                # Create the document with comparison results
                doc = Document()
                doc.add_heading('Comparison Results', 0).alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

                for result in comparison_results:
                    sub_heading = doc.add_heading(f"Comparison between {result['doc1_title']} and {result['doc2_title']}", level=1)
                    sub_heading.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

                    for line in result['details']:
                        para = doc.add_paragraph()
                        run = para.add_run(line)
                        if line.startswith('+ '):
                            run.font.color.rgb = RGBColor(25, 135, 84)
                        elif line.startswith('- '):
                            run.font.color.rgb = RGBColor(255, 0, 0)

                    doc.add_page_break()

                doc.save(result_file_path)

                # Cleanup temporary files
                for file_path in file_paths:
                    try:
                        os.remove(file_path)
                    except OSError as e:
                        print(f"Error removing file {file_path}: {e}")

                # Generate URL for the result file
                result_file_url = os.path.join('documents', 'comparison-data', result_file_name)
                result_url = request.build_absolute_uri(settings.MEDIA_URL + result_file_url)

                return render(request, "result.html", {
                    'url': result_url,
                    'comparison_results': comparison_results
                })
            else:
                messages.warning(request, 'Please upload at least two files to compare.')
                return redirect('form')

        except Exception as e:
            print(f"Error during document comparison: {e}")
            messages.error(request, 'An error occurred during the document comparison process.')
            return redirect('form')

    return redirect('form')

def extract_text_from_pdf(pdf_path):
    """Extract text from a PDF file."""
    doc = fitz.open(pdf_path)
    text = ""
    for page in doc:
        text += page.get_text()
    return text

def compare_pdfs(text1, text2):
    """Compare text content of two PDFs and return a list of differences."""
    differences = []
    lines1 = text1.splitlines()
    lines2 = text2.splitlines()

    for line in lines1:
        if line not in lines2:
            differences.append(f"- {line}")
    
    for line in lines2:
        if line not in lines1:
            differences.append(f"+ {line}")

    return differences

def bulkPDF(request):
    if request.method == 'POST':
        attachmentCount = int(request.POST.get('rows', 0))
        main_dir = os.path.join(settings.MEDIA_ROOT, 'documents')
        pdf_dir = os.path.join(main_dir, 'pdfs')
        result_dir = os.path.join(main_dir, 'comparison-data')

        os.makedirs(pdf_dir, exist_ok=True)
        os.makedirs(result_dir, exist_ok=True)

        file_paths = []
        document_titles = []

        try:
            for i in range(1, attachmentCount + 1):
                file_object = request.FILES.get(f'attachment_pdf_{i}')
                if file_object:
                    if not file_object.name.endswith('.pdf'):
                        messages.warning(request, 'Please upload only PDF files.')
                        return redirect('form')

                    file_path = os.path.join(pdf_dir, file_object.name)
                    counter = 1

                    while os.path.exists(file_path):
                        base, ext = os.path.splitext(file_path)
                        file_path = f"{base} ({counter}){ext}"
                        counter += 1

                    with open(file_path, 'wb') as temp_file:
                        for chunk in file_object.chunks():
                            temp_file.write(chunk)
                    file_paths.append(file_path)
                    document_titles.append(file_object.name)

            if len(file_paths) > 1:
                comparison_results = []

                for i in range(len(file_paths)):
                    for j in range(i + 1, len(file_paths)):
                        text1 = extract_text_from_pdf(file_paths[i])
                        text2 = extract_text_from_pdf(file_paths[j])
                        comparison_result = compare_pdfs(text1, text2)

                        summary = 'Same' if not comparison_result else 'Different'

                        comparison_results.append({
                            'doc1_title': document_titles[i],
                            'doc2_title': document_titles[j],
                            'summary': summary,
                            'details': comparison_result
                        })

                result_file_name = 'pdf_comparison_results.docx'
                result_file_path = os.path.join(result_dir, result_file_name)
                
                doc = Document()
                doc.add_heading('PDF Comparison Results', 0).alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

                for result in comparison_results:
                    sub_heading = doc.add_heading(f"Comparison between {result['doc1_title']} and {result['doc2_title']}", level=1)
                    sub_heading.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

                    for line in result['details']:
                        para = doc.add_paragraph()
                        run = para.add_run(line)
                        if line.startswith('+ '):
                            run.font.color.rgb = RGBColor(25, 135, 84)
                        elif line.startswith('- '):
                            run.font.color.rgb = RGBColor(255, 0, 0)

                    doc.add_page_break()

                doc.save(result_file_path)

                for file_path in file_paths:
                    try:
                        os.remove(file_path)
                    except OSError as e:
                        print(f"Error removing file {file_path}: {e}")

                result_file_url = os.path.join('documents', 'comparison-data', result_file_name)
                result_url = request.build_absolute_uri(settings.MEDIA_URL + result_file_url)

                return render(request, "result.html", {
                    'url': result_url,
                    'comparison_results': comparison_results
                })
            else:
                messages.warning(request, 'Please upload at least two files to compare.')
                return redirect('form')

        except Exception as e:
            print(f"Error during PDF comparison: {e}")
            messages.error(request, 'An error occurred during the PDF comparison process.')
            return redirect('form')

    return redirect('form')
