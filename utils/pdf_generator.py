"""
PDF Report Generator for IOC Investigation Reports
"""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib import colors
from datetime import datetime
import re


def generate_pdf_report(report_text, ip_address, filename=None):
    """
    Generate PDF from IOC Investigation Report
    
    Args:
        report_text (str): The complete report text
        ip_address (str): IP address being analyzed
        filename (str, optional): Custom filename for PDF
    
    Returns:
        str: Path to generated PDF file
    """
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/IOC_Report_{ip_address.replace('.', '_')}_{timestamp}.pdf"
    
    # Create reports directory if it doesn't exist
    os.makedirs('reports', exist_ok=True)
    
    # Setup PDF
    doc = SimpleDocTemplate(
        filename, 
        pagesize=letter,
        topMargin=0.75*inch, 
        bottomMargin=0.75*inch,
        leftMargin=0.75*inch, 
        rightMargin=0.75*inch
    )
    
    styles = getSampleStyleSheet()
    story = []
    
    # Custom styles
    title_style = ParagraphStyle(
        'IOCTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#4169E1'),
        spaceAfter=12,
        alignment=TA_LEFT
    )
    
    header_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#2C3E50'),
        spaceAfter=8,
        spaceBefore=12
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        leading=14
    )
    
    # Parse report text
    lines = report_text.split('\n')
    
    for line in lines:
        line = line.strip()
        
        if not line:
            story.append(Spacer(1, 0.1*inch))
            continue
        
        # Title
        if '🔵 IOC Investigation Report' in line:
            p = Paragraph(line, title_style)
            story.append(p)
        
        # Section headers with emojis
        elif line.startswith(('🌐', '🏢', '⏱️', '📊', '🎯')):
            p = Paragraph(line, header_style)
            story.append(p)
        
        # Verdict line
        elif 'Verdict:' in line:
            verdict_style = ParagraphStyle(
                'Verdict',
                parent=styles['Normal'],
                fontSize=12,
                textColor=colors.red if '💀' in line else colors.green,
                spaceBefore=6,
                spaceAfter=6
            )
            p = Paragraph(line, verdict_style)
            story.append(p)
        
        # Regular text
        else:
            p = Paragraph(line, normal_style)
            story.append(p)
        
        story.append(Spacer(1, 0.05*inch))
    
    # Build PDF
    doc.build(story)
    print(f"\n📄 PDF Report saved: {filename}")
    return filename