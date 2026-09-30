from src.data.supabase.client import supabase_client
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import Response
from fpdf import FPDF
from src.data.supabase.repositories.supabase_audit_repo import SupabaseAuditRepository
from src.data.supabase.repositories.supabase_device_repo import SupabaseDeviceRepository

router = APIRouter(prefix="/export", tags=["Export"])

RULE_TITLES = {
    "SEC-01": "Cifrado Global de Contraseñas (CWE-316)",
    "SEC-02": "Inhabilitación del Protocolo Telnet (CWE-319)",
    "SEC-03": "Timeout de Sesión Inactiva (CWE-613)",
    "SEC-04": "Servidor HTTP de Gestión (CVE-2018-0171)",
    "SEC-05": "Centralización de Logs (CWE-778)"
}

def safe_str(text: str) -> str:
    if not text:
        return ""
    return str(text).encode('latin-1', 'replace').decode('latin-1')

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.set_text_color(11, 17, 32)
        self.cell(0, 10, safe_str('NetShield Core - Reporte de Auditoría de Seguridad'), 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Pagina {self.page_no()}', 0, 0, 'C')

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
        
        # Meta info
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, safe_str(f"Hostname: {report_data['devices']['hostname']}"), 0, 1)
        pdf.cell(0, 8, safe_str(f"IP Address: {report_data['devices']['ip_address']}"), 0, 1)
        pdf.cell(0, 8, safe_str(f"OS Version: {report_data['devices']['os_version']}"), 0, 1)
        
        score = report_data['overall_score']
        pdf.set_font("Arial", "B", 14)
        if score >= 80:
            pdf.set_text_color(16, 185, 129) # Emerald
        else:
            pdf.set_text_color(244, 63, 94) # Rose
            
        pdf.cell(0, 10, safe_str(f"Score de Seguridad: {score:.2f}%"), 0, 1)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)
        
        # Rules
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, safe_str("Detalles de Auditoría"), 0, 1)
        
        for res in results_data:
            pdf.set_font("Arial", "B", 10)
            status_text = "[SEGURO]" if res.get('passed') == True else f"[VULNERABLE - ALTA]"
            
            if res.get('passed') == True:
                pdf.set_text_color(16, 185, 129)
            else:
                pdf.set_text_color(244, 63, 94)
            
            rule_title_raw = RULE_TITLES.get(res.get('rule_id'), 'Regla de Seguridad ' + str(res.get('rule_id')))
            pdf.cell(0, 8, safe_str(f"{status_text} {rule_title_raw}"), 0, 1)
            
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", "", 9)
            pdf.multi_cell(0, 5, safe_str(res.get('details')))
            
            if res.get('passed') == False and res.get('remediation'):
                pdf.set_font("Courier", "", 9)
                pdf.set_fill_color(240, 240, 240)
                pdf.multi_cell(0, 5, safe_str(f"Remediación:\n{res.get('remediation')}"), fill=True)
                
            pdf.ln(3)

        pdf_bytes = bytes(pdf.output())
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=NetShield_Report_{report_data['devices']['hostname']}.pdf"
            }
        )
    except Exception as e:
        print(f"Error PDF: {e}")
        raise HTTPException(status_code=500, detail="Error generando PDF")
