import hashlib
from datetime import datetime
from fpdf import FPDF
from typing import Dict, List

def _clean(text: str) -> str:
    if not text:
        return ""
    return str(text).encode("latin-1", "replace").decode("latin-1")

class ForensicPDF(FPDF):
    def header(self):
        self.set_fill_color(18, 25, 43)
        self.rect(0, 0, 210, 28, "F")
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 14)
        self.set_xy(10, 7)
        self.cell(0, 7, _clean("S.A.R.A. | CerberusOps - Dictamen Forense Digital y Cadena de Custodia"), ln=True)
        self.set_font("Helvetica", "", 9)
        self.set_x(10)
        self.cell(0, 6, _clean(f"Sistema Automatizado de Respuesta y Análisis SOAR | Fecha de emisión: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"), ln=True)
        self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(110, 110, 110)
        self.cell(0, 10, _clean(f"Documento Confidencial - CerberusOps Digital Forensics | Página {self.page_no()}"), align="C")

def generate_incident_forensic_pdf(incident: Dict) -> bytes:
    pdf = ForensicPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=18)

    pdf.set_text_color(18, 25, 43)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _clean(f"1. IDENTIFICACIÓN DEL INCIDENTE FORENSE #{incident['id']}"), ln=True)
    pdf.set_draw_color(18, 25, 43)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    ev_hash = incident.get("evidence_hash")
    if not ev_hash or ev_hash == "N/A":
        ev_hash = hashlib.sha256(str(incident.get("raw_log", "")).encode("utf-8")).hexdigest()

    meta_rows = [
        ("Folio de Incidente:", f"SARA-INC-{int(incident['id']):05d}"),
        ("Fecha y Hora de Detección:", incident.get("timestamp", "N/A")),
        ("Dirección IP Origen (Atacante):", incident.get("source_ip", "N/A")),
        ("Reputación AbuseIPDB:", f"{incident.get('abuse_score', 0)}% de confianza de abuso"),
        ("Vector / Tipo de Amenaza:", incident.get("event_type", "N/A")),
        ("Nivel de Severidad:", incident.get("severity", "N/A")),
        ("Estado Operativo Actual:", incident.get("status", "N/A")),
        ("Acción de Contención UFW:", incident.get("action_taken", "N/A")),
    ]

    for label, val in meta_rows:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(62, 6, _clean(label))
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, _clean(val), ln=True)

    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _clean("2. INTEGRIDAD CRIPTOGRÁFICA Y EVIDENCIA DIGITAL (RAW LOG)"), ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 5, _clean("Hash SHA-256 de Integridad de Evidencia:"), ln=True)
    pdf.set_font("Courier", "", 9)
    pdf.set_fill_color(240, 243, 248)
    pdf.cell(0, 7, _clean(ev_hash), ln=True, fill=True)
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(0, 5, _clean("Payload / Log Crudo Capturado:"), ln=True)
    pdf.set_font("Courier", "", 9)
    pdf.multi_cell(0, 6, _clean(incident.get("raw_log", "")), fill=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _clean("3. DICTAMEN TÉCNICO E INTERPRETACIÓN CON IA"), ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(0, 6, _clean(incident.get("ai_analysis", "Sin análisis registrado.")))
    pdf.ln(5)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _clean("4. REGISTRO FORMAL DE CADENA DE CUSTODIA"), ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(220, 226, 235)
    pdf.cell(38, 7, _clean("Timestamp"), border=1, fill=True)
    pdf.cell(45, 7, _clean(" Fase / Custodio"), border=1, fill=True)
    pdf.cell(107, 7, _clean(" Operación Realizada y Verificación"), border=1, ln=True, fill=True)

    pdf.set_font("Helvetica", "", 8)
    ts = incident.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    custody_steps = [
        (ts, "Sensor SOAR / n8n", "Captura del paquete/log y generación de firma SHA-256."),
        (ts, "AbuseIPDB + IA", "Enriquecimiento Threat Intel y clasificación MITRE ATT&CK."),
        (ts, "Módulo UFW Firewall", f"Contención perimetral: {incident.get('action_taken', '')[:55]}"),
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Auditoría Forense", "Exportación firmada en PDF desde Registro Histórico SQL.")
    ]
    for c_ts, actor, desc in custody_steps:
        pdf.cell(38, 7, _clean(c_ts), border=1)
        pdf.cell(45, 7, _clean(" " + actor), border=1)
        pdf.cell(107, 7, _clean(" " + desc), border=1, ln=True)

    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 9)
    pdf.cell(95, 6, _clean("________________________________________"), align="C")
    pdf.cell(95, 6, _clean("________________________________________"), align="C", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(95, 5, _clean("Firma de Analista Responsable (CerberusOps)"), align="C")
    pdf.cell(95, 5, _clean("Sello Digital de Integridad S.A.R.A. SOAR"), align="C", ln=True)

    return bytes(pdf.output())

def generate_executive_summary_pdf(incidents: List[Dict], blocked_ips: List[Dict], audits: List[Dict] = None) -> bytes:
    pdf = ForensicPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=18)

    pdf.set_text_color(18, 25, 43)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _clean("1. RESUMEN EJECUTIVO DE OPERACIONES DE SEGURIDAD (SOC)"), ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    total = len(incidents)
    crit = sum(1 for i in incidents if i["severity"] in ["CRÍTICO", "ALTO"])
    fp = sum(1 for i in incidents if i["status"] == "Falso Positivo")
    active_b = sum(1 for b in blocked_ips if b["is_active"] == 1)
    last_h_idx = audits[0]["hardening_index"] if audits else "N/A"

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, _clean(f"• Total de Incidentes en Registro Histórico SQL: {total}"), ln=True)
    pdf.cell(0, 6, _clean(f"• Incidentes de Severidad Alta / Crítica: {crit}"), ln=True)
    pdf.cell(0, 6, _clean(f"• Direcciones IP Contenidas en Cortafuegos UFW: {active_b}"), ln=True)
    pdf.cell(0, 6, _clean(f"• Falsos Positivos Descartados y en Lista Blanca: {fp}"), ln=True)
    pdf.cell(0, 6, _clean(f"• Último Índice de Endurecimiento (Lynis Hardening Index): {last_h_idx}/100"), ln=True)
    pdf.ln(5)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _clean("2. BITÁCORA HISTÓRICA SQL DE INCIDENTES Y EVIDENCIAS"), ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(220, 226, 235)
    pdf.cell(12, 7, "ID", border=1, fill=True)
    pdf.cell(32, 7, "Fecha/Hora", border=1, fill=True)
    pdf.cell(28, 7, "IP Origen", border=1, fill=True)
    pdf.cell(34, 7, "Vector", border=1, fill=True)
    pdf.cell(18, 7, "AbuseIP", border=1, fill=True)
    pdf.cell(20, 7, "Severidad", border=1, fill=True)
    pdf.cell(46, 7, "Estado / Hash SHA-256", border=1, ln=True, fill=True)

    pdf.set_font("Helvetica", "", 8)
    for inc in incidents[:30]:
        short_hash = (inc.get("evidence_hash") or "N/A")[:10]
        pdf.cell(12, 6, _clean(f"#{inc['id']}"), border=1)
        pdf.cell(32, 6, _clean(inc["timestamp"]), border=1)
        pdf.cell(28, 6, _clean(inc["source_ip"]), border=1)
        pdf.cell(34, 6, _clean(inc["event_type"][:18]), border=1)
        pdf.cell(18, 6, _clean(f"{inc.get('abuse_score', 0)}%"), border=1)
        pdf.cell(20, 6, _clean(inc["severity"]), border=1)
        pdf.cell(46, 6, _clean(f"{inc['status']} ({short_hash})"), border=1, ln=True)

    return bytes(pdf.output())
