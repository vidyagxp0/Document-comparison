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
from .models import Document as Form, ComparisonReport
from docx.shared import RGBColor
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.shared import Pt, Inches
from docx.oxml import OxmlElement
from datetime import datetime as date
import difflib
from random import randint
from pathlib import Path
import convertapi
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
                return redirect('dashboard')
            else:
                messages.error(request, "Please provide valid login credentials.")
            
    return render(request, "login.html")

def dashboard(request):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')

    return render(request, 'dashboard.html')

def formView(request):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')

    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        documents = Form.objects.filter(new=True)
        document_count = documents.count()
        formData = Form.objects.last()

        if formData:
            doc_id = formData.document_id + 1
        else:
            doc_id = 1

        if form.is_valid():
            doc_format = form.cleaned_data.get('doc_format')
            upload_document = request.FILES.get('upload_document')

            if upload_document and doc_format:
                file_extension = os.path.splitext(upload_document.name)[1].lstrip('.').lower()

                # Check if format is 'other' or the file extension matches the selected format
                if doc_format != 'other' and doc_format != file_extension:
                    messages.warning(request, f"Please upload the file with the selected format '{doc_format}'.")
                    return render(request, "form.html", {'form': form, 'doc_id': doc_id, 'document_count': document_count, 'documents': documents})

            form.save()
            messages.success(request, "Document added successfully.")
            return redirect('form')
        else:
            messages.warning(request, "All the fields are required to fill!")

    else:
        form = DocumentForm()
        documents = Form.objects.filter(new=True)
        document_count = documents.count()
        formData = Form.objects.last()

        if formData:
            doc_id = formData.document_id + 1
        else:
            doc_id = 1

    return render(request, "form.html", {
        'form': form,
        'doc_id': doc_id,
        'document_count': document_count,
        'documents': documents
    })

def documentDetail(request, doc_id):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')
    
    document = get_object_or_404(Form, document_id=doc_id)

    print(document)

    if not document:
        messages.warning(request, "Invalid Document ID.")
    
    return render(request, 'document-details.html', { 'document': document })

def initialDocument(request):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')
    
    documents = Form.objects.filter(new=True)
    
    if not documents:
        messages.info(request, "Please upload documents first.")
    
    return render(request, 'initial-document.html', { 'documents': documents })

def removeDocument(request, doc_id):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')
    
    document = get_object_or_404(Form, document_id=doc_id)

    if not document:
        messages.warning(request, "Invalid document ID, please provide valid ID")
        return redirect('initial-document')
    
    try:
        document.delete()
        messages.success(request, "Document deleted successfully.")
        return redirect('initial-document')
    except:
        messages.error(request, "Error occured while performing the action.")

    return redirect('initial-document')

def comparison(request: HttpRequest):
    if not request.user.is_authenticated:
        messages.warning(request, "Login Required!")
        return redirect('login')

    documents = Form.objects.filter(new=True)
    
    if not documents:
        messages.info(request, "Please upload documents first.")
        return redirect('form')
    
    data = {}
    for doc in documents:
        file_path = doc.upload_document.path
        sections = read_docx(file_path)
        data[doc.document_id] = sections

    result_dir = os.path.join(settings.MEDIA_ROOT, 'temp')
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

    last_report = ComparisonReport.objects.last()
    if last_report:
        new_report_number = f"DCR{int(last_report.report_number[3:]) + 1}"
    else:
        new_report_number = "DCR1001"

    for doc in documents:
        doc.new = False
        doc.summary = "Same" if overall_similarity_scores[doc.document_id] == 100 else "Different"
        doc.similarity_score = overall_similarity_scores[doc.document_id]
        doc.comparison_status = 'Compared'
        doc.report_number = new_report_number
        doc.save()

    compared_documents = {}
    for index, doc in zip(range(1, len(documents) + 1), documents):
        compared_documents[f'doc{index}'] = doc.document_id

    try:
        comparison_report = ComparisonReport.objects.create(
            report_number = new_report_number,
            comparison_reason = reason,
            compared_documents = compared_documents,
            comparison_summary = comparison_details,
            compared_by = comparedBy,
            report_path = result_path
        )
        comparison_report.save()
    
        return HttpResponse(f"Report Saved Successfully as {new_report_number}")

    except Exception as e:
        return HttpResponse(f"Error : {e}")

    return render(request, 'result.html', {    
        'output_path': output_url,
        'comparison_details': comparison_details,
    })

def compare_sections(section1, section2):
    section1 = section1.strip()
    section2 = section2.strip()
    
    seq_matcher = difflib.SequenceMatcher(None, section1, section2)
    similarity = seq_matcher.ratio()
    is_different = similarity < 1.0

    added_text = []
    removed_text = []
    modified_text = []
    
    # Iterate through the differences
    for tag, i1, i2, j1, j2 in seq_matcher.get_opcodes():
        if tag == 'equal':
            pass  # Unchanged parts
        elif tag == 'replace':
            removed_text.append(section1[i1:i2])    # Replaced in section1
            added_text.append(section2[j1:j2])      # Added in section2
        elif tag == 'delete':
            removed_text.append(section1[i1:i2])    # Deleted in section1
        elif tag == 'insert':
            added_text.append(section2[j1:j2])      # Inserted in section2
    
    if similarity < 0.4:
        modified_text.append(section2)
    
    if similarity == 1.0:
        tag = "S"  # Same
    else:
        if added_text and not removed_text:
            tag = "A"  # Added
        elif removed_text and not added_text:
            tag = "R"  # Removed
        else:
            tag = "M"  # Modified

    return similarity, is_different, tag, ' '.join(added_text), ' '.join(removed_text), ' '.join(modified_text) 

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
                similarity, is_different, tag , added_text, removed_text, modified_text = compare_sections(ref_section_content, section_content)
                summary = "Same" if not is_different else "Different"
                comparison_status = "Compared" if ref_section_content else "Not Compared"

                new_doc.add_heading(f"Document {doc_id}", level=2)
                new_doc.add_paragraph(f"Similarity Score: {int(similarity*100)}%")
                new_doc.add_paragraph(f"Tag: {tag}")
                new_doc.add_paragraph(f"Summary: {summary}")
                new_doc.add_paragraph(f"Comparison Status: {comparison_status}")

                if added_text:
                    new_doc.add_paragraph(f"Added Text: {added_text}")
                if removed_text:
                    new_doc.add_paragraph(f"Removed Text: {removed_text}")
                if modified_text:
                    new_doc.add_paragraph(f"Modified Text: {modified_text}")

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
        convertapi.api_secret = 'QdENoLepFl1Z6CwK'

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
    
