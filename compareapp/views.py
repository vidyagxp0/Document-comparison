import os
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from docx import Document
from docx.shared import RGBColor
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
import difflib


def index(request):
    return render(request, "index.html")

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
                messages.error(request, "Invalid username or password.")
    return render(request, "login.html")

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

def form(request):
    if request.method == 'POST':
        attachmentCount = int(request.POST.get('rows'))
        doc_dir = os.path.join(settings.MEDIA_ROOT, 'documents')

        if not os.path.exists(doc_dir):
            os.makedirs(doc_dir)

        file_paths = []
        for i in range(1, attachmentCount + 1):
            file_object = request.FILES.get(f'attachment_{i}')
            is_docx = file_object.name.split('.')[-1].lower() == 'docx'

            if not is_docx:
                messages.warning(request, 'Please attach Word documents only to perform the action.')
                return render(request, "form.html")
            
            if file_object:
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

        if len(file_paths) > 1:
            comparison_results = []
            comparison_results_html = []
            
            for i in range(len(file_paths)):
                for j in range(i + 1, len(file_paths)):
                    content1 = read_docx(file_paths[i])
                    content2 = read_docx(file_paths[j])
                    comparison_result = compare_documents_docx(content1, content2)
                    comparison_results.append({
                        'file1': os.path.basename(file_paths[i]),
                        'file2': os.path.basename(file_paths[j]),
                        'result': comparison_result
                    })
                    comparison_results_html.append(compare_documents_html(content1, content2))

            # Create a new Word document with the comparison results
            doc = Document()
            main_heading = doc.add_heading('Comparison Results', 0)
            main_heading.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER
            
            for index, result in enumerate(comparison_results, start=1):
                sub_heading = doc.add_heading(f"Comparison between {result['file1']} and {result['file2']}", level=1)
                sub_heading.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER
                run = sub_heading.runs[0]
                
                for line in result['result']:
                    if line.startswith('+ '):
                        run = doc.add_paragraph().add_run(line)
                        run.font.color.rgb = RGBColor(25, 135, 84)
                    elif line.startswith('- '):
                        run = doc.add_paragraph().add_run(line)
                        run.font.color.rgb = RGBColor(255, 0, 0)
                    elif line.startswith('  '):
                        doc.add_paragraph(line)
                doc.add_page_break()

            result_file_name = 'comparison_results.docx'
            result_file_path = os.path.join(doc_dir, result_file_name)
            doc.save(result_file_path)

            # Cleanup temporary files except for the result file
            for file_path in file_paths:
                try:
                    os.remove(file_path)
                except OSError as e:
                    print(f"Error removing file {file_path}: {e}")

            # Generate URL for the result file
            result_file_url = os.path.join('documents', result_file_name)
            result_url = request.build_absolute_uri(settings.MEDIA_URL + result_file_url)

            return render(request, "result.html", { 'url': result_url })

    return render(request, "form.html")


