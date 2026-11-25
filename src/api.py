from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from apscheduler.schedulers.background import BackgroundScheduler
import random

from src.database import (
    init_db, create_incident, get_incidents, get_incident_by_id,
    update_incident_status, get_blocked_ips, get_setting, set_setting,
    get_lynis_audits
)
from src.ai_service import analyze_incident_with_ai
from src.security import block_ip_ufw, unblock_ip_ufw
from src.notifier import send_telegram_alert
from src.forensics_pdf import generate_incident_forensic_pdf
from src.threat_intel import check_ip_abuseipdb
from src.lynis_auditor import run_lynis_system_audit

app = FastAPI(
    title="S.A.R.A. SOAR API - CerberusOps v4.0",
    description="API SOAR con Orquestación n8n, AbuseIPDB, Auditorías Programadas Lynis, Registro SQL, IA Ollama y UFW",
    version="4.0.0"
)

init_db()

# Programador de Auditorías Automáticas con Lynis (cada 12 horas)
scheduler = BackgroundScheduler()
scheduler.add_job(run_lynis_system_audit, "interval", hours=12, id="lynis_scheduled_audit", replace_existing=True)
scheduler.start()

# Si no hay auditorías previas en la base de datos SQL, genera la primera al arrancar
if not get_lynis_audits(1):
    run_lynis_system_audit()

class LogEvent(BaseModel):
    source_ip: str
    event_type: str
    raw_log: str
    severity: str = "ALTO"

class ManualBlockRequest(BaseModel):
    ip: str
    reason: str = "Bloqueo manual desde SOC Dashboard"

@app.get("/health")
def health_check():
    return {
        "status": "online",
        "system": "S.A.R.A. CerberusOps v4.0",
        "simulation_mode": get_setting("simulation_mode"),
        "scheduled_jobs": len(scheduler.get_jobs())
    }

@app.post("/api/v1/ingest")
def ingest_security_event(event: LogEvent):
    set_setting("traffic_spike", "3")

    # 1. Enriquecimiento con Threat Intelligence (AbuseIPDB)
    intel = check_ip_abuseipdb(event.source_ip)
    abuse_score = intel.get("abuseConfidenceScore", 0)

    # 2. Triage con IA Local (Ollama / Heurística)
    ai_res = analyze_incident_with_ai(event.event_type, event.source_ip, event.raw_log, event.severity, abuse_score)
    ai_analysis = f"[{ai_res['engine']}] {ai_res['analysis']}"
    
    # 3. Mitigación Automática en Cortafuegos UFW
    auto_block = get_setting("auto_block_enabled", "1") == "1"
    action_taken = "Monitoreo / Registro en SQL"
    status = "Activa"
    
    if auto_block and (event.severity.upper() in ["CRÍTICO", "CRITICO", "ALTO"] or abuse_score >= 75):
        ufw_res = block_ip_ufw(event.source_ip, reason=f"Auto-mitigación: {event.event_type} (AbuseIPDB: {abuse_score}%)")
        if ufw_res["success"]:
            action_taken = f"IP Bloqueada ({ufw_res['message']})"
            status = "Mitigada"
        else:
            action_taken = f"Sin bloqueo ({ufw_res['message']})"

    # 4. Registro Histórico en SQL con Hash SHA-256
    incident_id = create_incident(
        source_ip=event.source_ip,
        event_type=event.event_type,
        raw_log=event.raw_log,
        severity=event.severity.upper(),
        abuse_score=abuse_score,
        ai_analysis=ai_analysis,
        status=status,
        action_taken=action_taken
    )

    alert_details = (
        f"• *Tipo:* `{event.event_type}`\n"
        f"• *IP Atacante:* `{event.source_ip}` (AbuseIPDB: {abuse_score}%)\n"
        f"• *Estado:* {status}\n"
        f"• *Acción:* {action_taken}\n"
        f"• *IA:* {ai_res['analysis']}"
    )

    send_telegram_alert(
        title=f"🚨 Incidente #{incident_id} Detectado ({event.severity.upper()})",
        details=alert_details
    )

    return {
        "incident_id": incident_id,
        "status": status,
        "abuse_score": abuse_score,
        "action_taken": action_taken,
        "ai_analysis": ai_analysis
    }

@app.get("/api/v1/threat-intel/{ip}")
def check_threat_intel(ip: str):
    return check_ip_abuseipdb(ip)

@app.post("/api/v1/audit/lynis")
def trigger_lynis_audit():
    res = run_lynis_system_audit()
    send_telegram_alert(
        title="🔍 Auditoría Programada Lynis Completada",
        details=(
            f"• *Hardening Index:* `{res['hardening_index']}/100`\n"
            f"• *Warnings:* {res['warnings_count']} | *Sugerencias:* {res['suggestions_count']}\n"
            f"• *Modo:* {res['execution_mode']}"
        )
    )
    return res

@app.get("/api/v1/audit/history")
def list_lynis_audits():
    return get_lynis_audits()

@app.get("/api/v1/forensics/report/{incident_id}")
def download_forensic_pdf(incident_id: int):
    inc = get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")
    pdf_bytes = generate_incident_forensic_pdf(inc)
    headers = {"Content-Disposition": f"attachment; filename=Dictamen_Forense_SARA_INC_{incident_id}.pdf"}
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)

@app.get("/api/v1/incidents")
def list_incidents(limit: int = 100):
    return get_incidents(limit)

@app.get("/api/v1/blocked-ips")
def list_blocked_ips():
    return get_blocked_ips()

@app.post("/api/v1/mitigate/block")
def manual_block_ip(req: ManualBlockRequest):
    res = block_ip_ufw(req.ip, req.reason)
    if not res["success"]:
        raise HTTPException(status_code=400, detail=res["message"])
    send_telegram_alert("🔒 Bloqueo Manual UFW", f"IP `{req.ip}` bloqueada.\nMotivo: {req.reason}")
    return res

@app.post("/api/v1/mitigate/false-positive/{incident_id}")
def mark_as_false_positive(incident_id: int):
    incident = get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")
        
    ip = incident["source_ip"]
    ufw_res = unblock_ip_ufw(ip, whitelist=True)
    action = f"Falso Positivo confirmado. IP {ip} desbloqueada y en Lista Blanca."
    update_incident_status(incident_id, "Falso Positivo", action)
    
    send_telegram_alert(
        "✅ Falso Positivo Revertido",
        f"Incidente #{incident_id} marcado como Falso Positivo.\nIP `{ip}` liberada en UFW y añadida a Lista Blanca."
    )
    return {"incident_id": incident_id, "status": "Falso Positivo", "ufw": ufw_res}

@app.post("/api/v1/simulate-attack")
def simulate_attack():
    samples = [
        ("185.220.101.45", "SSH Brute Force", "Failed password for root from 185.220.101.45 port 54322 ssh2 (15 attempts in 10s)", "CRÍTICO"),
        ("45.33.32.156", "SQL Injection", "GET /login.php?user=admin'%20OR%20'1'='1'-- HTTP/1.1 200", "ALTO"),
        ("103.145.13.99", "Port Scan", "SYN Stealth Scan detected targeting ports 22, 80, 443, 3306, 8080 from 103.145.13.99", "MEDIO"),
        ("91.240.118.172", "Malware Beacon", "Outbound connection to known CobaltStrike C2 91.240.118.172:4444", "CRÍTICO"),
        ("198.51.100.88", "DDoS SYN Flood", "SYN Flood detected: 18,500 packets/sec targeting TCP/443 from 198.51.100.88", "CRÍTICO")
    ]
    ip, ev_type, log, sev = random.choice(samples)
    octets = ip.split(".")
    octets[-1] = str(random.randint(2, 250))
    dynamic_ip = ".".join(octets)
    return ingest_security_event(LogEvent(source_ip=dynamic_ip, event_type=ev_type, raw_log=log, severity=sev))
