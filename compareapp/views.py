import os
from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404, HttpResponse
from django.http import HttpRequest
from django.contrib.auth import authenticate, login, logout
from django.templatetags.static import static
from docx.oxml.ns import qn
from django.contrib import messages
from docx import Document
from .forms import DocumentForm
from .models import Document as Form
from docx.shared import RGBColor
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.shared import Pt, Inches
from docx.oxml import OxmlElement
from datetime import datetime as date
import difflib
from random import randint
from pathlib import Path
import win32com.client
import pythoncom
import logging
import requests
from django.http import JsonResponse
import json
from django.views.decorators.csrf import csrf_exempt

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
            return redirect('form')
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

def comparison(request: HttpRequest):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')

    documents = Form.objects.all()
    
    if not documents:
        messages.info(request, "Please upload documents first.")
        return redirect('form')
    
    data = {}
    for doc in documents:
        file_path = doc.upload_document.path
        sections = read_docx(file_path)
        data[doc.document_id] = sections

    result_dir = os.path.join(settings.MEDIA_ROOT, 'comparison')
    os.makedirs(result_dir, exist_ok=True)

    result_path = os.path.join(result_dir, "comparison-report.docx")
    logo_path = "compareapp" + static('images/logo.png')

    reason = request.GET.get('reason', '')
    comparedBy = request.user.username.upper()
    create_merged_docx(data, result_path, logo_path, comparedBy, reason)

    output_url = request.build_absolute_uri(settings.MEDIA_URL + 'comparison/comparison-report.docx')

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
                    similarity, is_different, tag = compare_sections(section_content, ref_section_content)
                    if is_different:  # Only include if different
                        comparison_details[header]['documents'][doc_id] = {
                            'content': section_content or 'Removed',
                            'tag': tag
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
        overall_similarity_score, _, _ = compare_sections(doc_content, ref_doc_content)
        overall_similarity_scores[doc_id] = int(overall_similarity_score * 100)

    return render(request, 'result.html', { 
        'documents': documents, 
        'output_path': output_url,
        'comparison_details': comparison_details,
        'overall_similarity_scores': overall_similarity_scores
    })

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

def highlight_differences(doc, title, text, is_different):
    paragraphs = text.split('\n')
    for para_text in paragraphs:
        para = doc.add_paragraph()
        for part in para_text.split(' '):
            run = para.add_run(part + ' ')
            if is_different:
                run.font.color.rgb = RGBColor(255, 0, 0)  # Red color for differences

def compare_sections(section1, section2):
    primary_text = section2.strip()
    other_text = section1.strip()
    
    # Calculate similarity ratio
    seq_matcher = difflib.SequenceMatcher(None, primary_text, other_text)
    similarity = seq_matcher.ratio()
    is_different = similarity < 1.0

    # Determine the tag with a more detailed analysis
    diffs = list(seq_matcher.get_opcodes())
    added = any(opcode == 'insert' for opcode, _, _, _, _ in diffs)
    removed = any(opcode == 'delete' for opcode, _, _, _, _ in diffs)
    replaced = any(opcode == 'replace' for opcode, _, _, _, _ in diffs)
    
    if similarity == 1.0:
        tag = "S"  # Same
    else:
        if added and not removed and not replaced:
            tag = "A"  # Added
        elif removed and not added and not replaced:
            tag = "R"  # Removed
        elif replaced or (added and removed):
            tag = "M"  # Modified
        else:
            tag = "M"  # Modified, catch-all for any changes

    return similarity, is_different, tag

def create_merged_docx(data, output_path, logo_path, comparedBy, reason):
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
    header_left_para.add_run("Compared By: " + comparedBy).font.size = Pt(10)
    header_left_para.alignment = WD_PARAGRAPH_ALIGNMENT.LEFT

    header_right1_cell = header_table.cell(1, 1)
    header_right1_para = header_right1_cell.paragraphs[0]
    header_right1_para.add_run(f"Report Number: CR100{randint(100, 999)}").font.size = Pt(10)
    header_right1_para.alignment = WD_PARAGRAPH_ALIGNMENT.RIGHT

    header_table.cell(2, 0).merge(header_table.cell(2, 1))

    header_right2_cell = header_table.cell(2, 0)
    header_right2_para = header_right2_cell.paragraphs[0]
    header_right2_para.add_run("Comparison Reason: " + reason).font.size = Pt(10)
    header_right2_para.alignment = WD_PARAGRAPH_ALIGNMENT.LEFT

    # Footer with text and page number
    footer = section.footer
    footer_table = footer.add_table(rows=1, cols=2, width=Inches(6))  # One row, two columns

    footer_table.alignment = WD_PARAGRAPH_ALIGNMENT.CENTER

    # Set table borders for footer
    set_table_borders(footer_table)

    # Set vertical alignment for all cells in footer
    for row in footer_table.rows:
        for cell in row.cells:
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER

    # Left cell content (compared by text)
    footer_left_cell = footer_table.cell(0, 0)
    footer_left_para = footer_left_cell.paragraphs[0]
    cdate = date.now()
    footer_left_para.add_run(f"Comparison Date: {str(cdate).split(' ')[0]}").font.size = Pt(10)
    footer_left_para.alignment = WD_PARAGRAPH_ALIGNMENT.LEFT

    # Right cell content (page number)
    footer_right_cell = footer_table.cell(0, 1)
    footer_right_para = footer_right_cell.paragraphs[0]
    footer_right_para.add_run("Page ").font.size = Pt(10)
    footer_right_para.alignment = WD_PARAGRAPH_ALIGNMENT.RIGHT

    # Add the page number field
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

    # Add the total page number field
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
                similarity, is_different, tag = compare_sections(section_content, ref_section_content)
                summary = "Same" if not is_different else "Different"
                comparison_status = "Compared" if ref_section_content else "Not Compared"

                new_doc.add_heading(f"Document {doc_id}", level=2)
                new_doc.add_paragraph(f"Similarity Score: {int(similarity*100)}%")
                new_doc.add_paragraph(f"Tag: {tag}")
                new_doc.add_paragraph(f"Summary: {summary}")
                new_doc.add_paragraph(f"Comparison Status: {comparison_status}")

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

logger = logging.getLogger(__name__)

def docx_to_pdf(docx_path, pdf_path):
    try:
        # Initialize the COM library
        pythoncom.CoInitialize()
        
        # Dispatch the Word Application
        word = win32com.client.Dispatch("Word.Application")
        doc = word.Documents.Open(str(docx_path))

        doc.SaveAs(str(pdf_path), FileFormat=17) 
        doc.Close()
        word.Quit()

    except Exception as e:
        logger.error(f"Error converting DOCX to PDF: {e}")
        raise

    finally:
        pythoncom.CoUninitialize()

def preview(request: HttpRequest):
    output_path = request.GET.get('path', '')
    saved_doc = Path(settings.MEDIA_ROOT) / 'comparison/comparison-report.docx'
    pdf_path = saved_doc.with_suffix('.pdf')
    pdf_url = str(pdf_path.relative_to(settings.MEDIA_ROOT)).replace("\\", "/")

    try:
        docx_to_pdf(saved_doc, pdf_path)
    except :
        return HttpResponse("Oops please reload the page.", status=500)
    
    return render(request, 'report-preview.html', {'pdf_path': f'/media/{pdf_url}', 'document_path': output_path})

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