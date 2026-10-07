from src.data.supabase.client import supabase_client
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import Response
from fpdf import FPDF
from datetime import datetime

router = APIRouter(prefix="/export", tags=["Export"])

RULE_TITLES = {
    "SEC-01": "Cifrado Global de Contraseñas (CWE-316)",
    "SEC-02": "Inhabilitación del Protocolo Telnet (CWE-319)",
    "SEC-03": "Timeout de Sesión Inactiva (CWE-613)",
    "SEC-04": "Servidor HTTP de Gestión (CVE-2018-0171)",
    "SEC-05": "Centralización de Logs (CWE-778)",
    "OSINT-01": "Inteligencia de Amenazas y CVEs (Offline)"
}

def safe_str(text: str) -> str:
    if not text:
        return ""
    return str(text).encode('latin-1', 'replace').decode('latin-1')

class PDFReport(FPDF):
    def header(self):
        # Draw a top accent line
        self.set_draw_color(6, 182, 212) # Cyan
        self.set_line_width(1.5)
        self.line(10, 10, 200, 10)
        
        # Header text
        self.set_font('helvetica', 'B', 10)
        self.set_text_color(15, 23, 42) # Slate-900
        self.cell(100, 10, safe_str('NETSHIELD CORE // AUTOMATED SECURITY AUDIT'), new_x="RIGHT", new_y="TOP", align='L')
        
        self.set_font('helvetica', '', 8)
        self.set_text_color(100, 116, 139) # Slate-500
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
        self.cell(0, 10, safe_str(f'GENERATED: {date_str}'), new_x="LMARGIN", new_y="NEXT", align='R')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        # Draw a bottom line
        self.set_draw_color(226, 232, 240) # Slate-200
        self.set_line_width(0.5)
        self.line(10, 282, 200, 282)
        
        self.set_font('helvetica', 'B', 8)
        self.set_text_color(148, 163, 184) # Slate-400
        self.cell(100, 10, safe_str('CONFIDENTIAL - INTERNAL USE ONLY'), new_x="RIGHT", new_y="TOP", align='L')
        self.cell(0, 10, safe_str(f'PAGE {self.page_no()}'), new_x="LMARGIN", new_y="NEXT", align='R')

@router.get("/{report_id}/pdf")
async def export_pdf(report_id: str):
    try:
        response = supabase_client.table('audit_reports').select('*, devices(*)').eq('report_id', report_id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Reporte no encontrado")
            
        report_data = response.data[0]
        
        results_response = supabase_client.table('audit_results').select('*').eq('report_id', report_id).execute()
        results_data = results_response.data
        
        pdf = PDFReport()
        pdf.add_page()
        
        # TITLE
        pdf.set_font("helvetica", "B", 18)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 12, safe_str("SECURITY INTELLIGENCE REPORT"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        
        # TARGET INFO BOX
        pdf.set_fill_color(248, 250, 252) # Slate-50
        pdf.set_draw_color(226, 232, 240) # Slate-200
        pdf.set_line_width(0.2)
        pdf.rect(10, pdf.get_y(), 190, 25, style="FD")
        
        pdf.set_y(pdf.get_y() + 4)
        pdf.set_x(14)
        
        pdf.set_font("helvetica", "B", 9)
        pdf.set_text_color(71, 85, 105) # Slate-600
        pdf.cell(30, 6, safe_str("TARGET HOST:"), new_x="RIGHT", new_y="TOP")
        pdf.set_font("Courier", "B", 10)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(60, 6, safe_str(report_data['devices']['hostname']), new_x="RIGHT", new_y="TOP")
        
        pdf.set_font("helvetica", "B", 9)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(25, 6, safe_str("REPORT ID:"), new_x="RIGHT", new_y="TOP")
        pdf.set_font("Courier", "", 9)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 6, safe_str(report_id[:8].upper()), new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_x(14)
        pdf.set_font("helvetica", "B", 9)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(30, 6, safe_str("IP ADDRESS:"), new_x="RIGHT", new_y="TOP")
        pdf.set_font("Courier", "", 10)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(60, 6, safe_str(report_data['devices']['ip_address']), new_x="RIGHT", new_y="TOP")
        
        pdf.set_font("helvetica", "B", 9)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(25, 6, safe_str("OS SYSTEM:"), new_x="RIGHT", new_y="TOP")
        pdf.set_font("Courier", "", 9)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 6, safe_str(report_data['devices']['os_version']), new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_y(pdf.get_y() + 8)
        
        # SCORE SECTION
        score = report_data['overall_score']
        pdf.set_font("helvetica", "B", 14)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(60, 10, safe_str("OVERALL POSTURE:"), new_x="RIGHT", new_y="TOP")
        
        pdf.set_font("helvetica", "B", 16)
        if score >= 80:
            pdf.set_text_color(16, 185, 129) # Emerald
        elif score >= 50:
            pdf.set_text_color(245, 158, 11) # Amber
        else:
            pdf.set_text_color(244, 63, 94) # Rose
            
        pdf.cell(0, 10, safe_str(f"{score:.2f}%"), new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_draw_color(226, 232, 240)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(8)
        
        # DETAILED DIAGNOSTICS
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 10, safe_str("SECURITY DIAGNOSTICS & TELEMETRY"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)
        
        for res in results_data:
            rule_id = res.get('rule_id', 'UNKNOWN')
            rule_title_raw = RULE_TITLES.get(rule_id, f'Security Rule {rule_id}')
            passed = res.get('passed', False)
            
            # Draw rule header box
            pdf.set_fill_color(241, 245, 249) # Slate-100
            if passed:
                pdf.set_draw_color(16, 185, 129) # Emerald
                status_txt = "PASS"
                status_color = (16, 185, 129)
            else:
                pdf.set_draw_color(244, 63, 94) # Rose
                status_txt = "FAIL"
                status_color = (244, 63, 94)
                
            pdf.set_line_width(0.5)
            # We want a left-border effect. In fpdf2 we can draw a filled rect and a line.
            current_y = pdf.get_y()
            pdf.rect(10, current_y, 190, 8, style="F")
            pdf.line(10, current_y, 10, current_y + 8)
            
            pdf.set_y(current_y + 1.5)
            pdf.set_x(14)
            pdf.set_font("helvetica", "B", 9)
            pdf.set_text_color(*status_color)
            pdf.cell(15, 5, safe_str(f"[{status_txt}]"), new_x="RIGHT", new_y="TOP")
            
            pdf.set_text_color(15, 23, 42)
            pdf.set_font("helvetica", "B", 9)
            pdf.cell(0, 5, safe_str(f"{rule_id} : {rule_title_raw}"), new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_y(current_y + 10)
            
            # Details text
            pdf.set_text_color(71, 85, 105)
            pdf.set_font("helvetica", "", 9)
            # Add small indentation
            pdf.set_x(14)
            # We need to limit the width so it stays indented
            pdf.multi_cell(186, 5, safe_str(res.get('details')), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
            
            # Remediation Box
            if not passed and res.get('remediation'):
                pdf.set_x(14)
                # Terminal-like box
                pdf.set_fill_color(15, 23, 42) # Slate-900
                pdf.set_text_color(248, 250, 252) # Slate-50
                pdf.set_font("Courier", "B", 8)
                
                # Title bar of terminal
                pdf.cell(186, 6, safe_str("> RECOMMENDED REMEDIATION COMMANDS"), fill=True, new_x="LMARGIN", new_y="NEXT")
                
                # Commands body
                pdf.set_x(14)
                pdf.set_fill_color(30, 41, 59) # Slate-800
                pdf.set_text_color(56, 189, 248) # Sky-400 (Syntax highlight feel)
                pdf.set_font("Courier", "", 8)
                pdf.multi_cell(186, 5, safe_str(res.get('remediation')), fill=True, new_x="LMARGIN", new_y="NEXT")
                
            pdf.ln(6)

        pdf_bytes = bytes(pdf.output())
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=NetShield_Report_{report_data['devices']['hostname']}.pdf"
            }
        )
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error PDF: {error_details}")
        raise HTTPException(status_code=500, detail=str(e))
