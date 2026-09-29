from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import Response
from fpdf import FPDF
from src.data.supabase.repositories.supabase_audit_repo import SupabaseAuditRepository
from src.data.supabase.repositories.supabase_device_repo import SupabaseDeviceRepository

router = APIRouter(prefix="/export", tags=["Export"])

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.set_text_color(11, 17, 32)
        self.cell(0, 10, 'NetShield Core - Reporte de Auditoria de Seguridad', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Pagina {self.page_no()}', 0, 0, 'C')

@router.get("/{report_id}/pdf")
async def export_pdf(report_id: str):
    try:
        audit_repo = SupabaseAuditRepository()
        
        # We need to get the report details directly using supabase client
        response = audit_repo.client.table('audit_reports').select('*, devices(*)').eq('report_id', report_id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Reporte no encontrado")
            
        report_data = response.data[0]
        
        results_response = audit_repo.client.table('audit_results').select('*').eq('report_id', report_id).execute()
        results_data = results_response.data
        
        pdf = PDFReport()
        pdf.add_page()
        
        # Meta info
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, f"Hostname: {report_data['devices']['hostname']}", 0, 1)
        pdf.cell(0, 8, f"IP Address: {report_data['devices']['ip_address']}", 0, 1)
        pdf.cell(0, 8, f"OS Version: {report_data['devices']['os_version']}", 0, 1)
        
        score = report_data['overall_score']
        pdf.set_font("Arial", "B", 14)
        if score >= 80:
            pdf.set_text_color(16, 185, 129) # Emerald
        else:
            pdf.set_text_color(244, 63, 94) # Rose
            
        pdf.cell(0, 10, f"Score de Seguridad: {score:.2f}%", 0, 1)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)
        
        # Rules
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Detalles de Auditoria", 0, 1)
        
        for res in results_data:
            pdf.set_font("Arial", "B", 10)
            status_text = "[SEGURO]" if res['status'] == 'PASSED' else f"[VULNERABLE - {res['severity']}]"
            
            if res['status'] == 'PASSED':
                pdf.set_text_color(16, 185, 129)
            else:
                pdf.set_text_color(244, 63, 94)
                
            pdf.cell(0, 8, f"{status_text} {res['rule_name']}", 0, 1)
            
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", "", 9)
            # Remove unicode characters that might break fpdf
            safe_details = str(res['details']).encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 5, safe_details)
            
            if res['status'] == 'FAILED' and res.get('remediation'):
                pdf.set_font("Courier", "", 9)
                pdf.set_fill_color(240, 240, 240)
                safe_remediation = str(res['remediation']).encode('latin-1', 'replace').decode('latin-1')
                pdf.multi_cell(0, 5, f"Remediacion:
{safe_remediation}", fill=True)
                
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
