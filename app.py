import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import qrcode
from io import BytesIO

from src.database import (
    init_db, get_incidents, get_blocked_ips, get_setting, set_setting,
    update_incident_status, get_lynis_audits, get_connection
)
from src.security import block_ip_ufw, unblock_ip_ufw
from src.notifier import send_telegram_alert, fetch_latest_telegram_chat_id
from src.api import ingest_security_event, simulate_attack, LogEvent
from src.telemetry import sample_network_telemetry
from src.forensics_pdf import generate_incident_forensic_pdf, generate_executive_summary_pdf
from src.threat_intel import check_ip_abuseipdb
from src.lynis_auditor import run_lynis_system_audit

st.set_page_config(
    page_title="S.A.R.A. v4.0 | CerberusOps SOAR",
    page_icon="🛡️",
    layout="wide"
)

init_db()

if "telemetry_history" not in st.session_state:
    st.session_state.telemetry_history = []
    for _ in range(20):
        st.session_state.telemetry_history.append(sample_network_telemetry())

st.title(" S.A.R.A. — Sistema Automatizado de Respuesta y Análisis")
st.caption("CerberusOps v4.0 | Arquitectura SOAR Contenerizada: FastAPI, n8n, AbuseIPDB, Auditorías Lynis, Registro Histórico SQL, Ollama y UFW")

with st.sidebar:
    st.header("⚡ Panel de Control SOC")
    if st.button(" Simular Ataque en Vivo", use_container_width=True, type="primary"):
        res = simulate_attack()
        st.success(f"Incidente #{res['incident_id']} procesado (AbuseIPDB: {res['abuse_score']}%).")
        st.rerun()

    if st.button(" Simular Ráfaga DDoS en Tráfico", use_container_width=True):
        set_setting("traffic_spike", "5")
        simulate_attack()
        st.warning("¡Ráfaga de tráfico hostil inyectada!")
        st.rerun()

    if st.button(" Ejecutar Auditoría Lynis Ahora", use_container_width=True):
        audit_res = run_lynis_system_audit()
        st.success(f"Auditoría Lynis #{audit_res['audit_id']} registrada (Índice: {audit_res['hardening_index']}/100).")
        st.rerun()

    st.divider()
    st.subheader(" Telemetría y Modo UFW")
    live_stream_active = st.toggle("Activar Gráficas en Tiempo Real (2s)", value=True)

    sim_mode = st.toggle(
        "Modo Simulación UFW (Seguro)",
        value=(get_setting("simulation_mode", "1") == "1"),
        help="Registra comandos UFW sin requerir permisos root reales en la demo."
    )
    set_setting("simulation_mode", "1" if sim_mode else "0")

    auto_block = st.toggle(
        "Auto-Bloqueo UFW (Alto/Crítico o AbuseIPDB >= 75%)",
        value=(get_setting("auto_block_enabled", "1") == "1")
    )
    set_setting("auto_block_enabled", "1" if auto_block else "0")

    st.divider()
    with st.expander("➕ Inyectar Evento Manual"):
        m_ip = st.text_input("IP Origen", "185.220.101.77")
        m_type = st.selectbox("Tipo de Amenaza", ["SSH Brute Force", "SQL Injection", "Port Scan", "Malware Beacon", "DDoS SYN Flood"])
        m_sev = st.selectbox("Severidad", ["CRÍTICO", "ALTO", "MEDIO", "BAJO"])
        m_log = st.text_area("Log Crudo", "Failed password for invalid user admin port 22 ssh2")
        if st.button("Procesar Evento", use_container_width=True):
            ingest_security_event(LogEvent(source_ip=m_ip, event_type=m_type, raw_log=m_log, severity=m_sev))
            st.toast("Evento analizado y guardado en SQL", icon="")
            st.rerun()

incidents = get_incidents(200)
blocked_ips = get_blocked_ips()
lynis_audits = get_lynis_audits(50)

with st.sidebar:
    st.divider()
    st.subheader(" Exportación Forense")
    exec_pdf_bytes = generate_executive_summary_pdf(incidents, blocked_ips, lynis_audits)
    st.download_button(
        label=" Descargar Reporte Ejecutivo SOC (PDF)",
        data=exec_pdf_bytes,
        file_name="Reporte_Ejecutivo_SOC_SARA.pdf",
        mime="application/pdf",
        use_container_width=True
    )

tab_soc, tab_intel, tab_lynis, tab_sql, tab_fp, tab_ufw, tab_tg = st.tabs([
    "📡 Monitor SOC en Vivo",
    "🌐 Threat Intel (AbuseIPDB)",
    "🛡️ Auditorías Lynis y Recomendaciones",
    "🗄️ Registro Histórico SQL",
    "📄 Dictámenes Forenses PDF",
    "🧱 Cortafuegos UFW",
    "📱 n8n, Telegram QR e IA"
])

def render_live_telemetry_panel():
    sample = sample_network_telemetry()
    st.session_state.telemetry_history.append(sample)
    if len(st.session_state.telemetry_history) > 30:
        st.session_state.telemetry_history.pop(0)

    df_t = pd.DataFrame(st.session_state.telemetry_history)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Tráfico Entrante (RX)", f"{sample['rx_kbps']} KB/s", delta=f"{sample['threat_kbps']} KB/s anómalo", delta_color="inverse")
    m2.metric("Paquetes / seg (PPS)", f"{sample['pps_total']} pkt/s", delta=f"{sample['malicious_pps']} hostiles", delta_color="inverse")
    m3.metric("Carga CPU Nodo SOAR", f"{sample['cpu_percent']}%")
    m4.metric("Uso de Memoria RAM", f"{sample['ram_percent']}%")

    col_live1, col_live2 = st.columns(2)
    with col_live1:
        fig_net = go.Figure()
        fig_net.add_trace(go.Scatter(x=df_t["timestamp"], y=df_t["rx_kbps"], mode="lines+markers", name="Entrada Total (KB/s)", line=dict(color="#00d4ff", width=2), fill="tozeroy"))
        fig_net.add_trace(go.Scatter(x=df_t["timestamp"], y=df_t["tx_kbps"], mode="lines", name="Salida (KB/s)", line=dict(color="#00ff88", width=2)))
        fig_net.add_trace(go.Scatter(x=df_t["timestamp"], y=df_t["threat_kbps"], mode="lines+markers", name="Tráfico Hostil (KB/s)", line=dict(color="#ff3366", width=3, dash="dot")))
        fig_net.update_layout(title="🌊 Flujo de Tráfico de Red en Tiempo Real (KB/s)", height=310, margin=dict(l=10, r=10, t=40, b=10), legend=dict(orientation="h", y=1.12))
        st.plotly_chart(fig_net, use_container_width=True)

    with col_live2:
        fig_pps = go.Figure()
        fig_pps.add_trace(go.Bar(x=df_t["timestamp"], y=df_t["pps_total"], name="Paquetes Totales/s", marker_color="#3b82f6"))
        fig_pps.add_trace(go.Scatter(x=df_t["timestamp"], y=df_t["malicious_pps"], mode="lines+markers", name="Paquetes Maliciosos/s", line=dict(color="#f97316", width=3)))
        fig_pps.update_layout(title="⚡ Tasa de Paquetes por Segundo (PPS) vs Eventos Hostiles", height=310, margin=dict(l=10, r=10, t=40, b=10), legend=dict(orientation="h", y=1.12))
        st.plotly_chart(fig_pps, use_container_width=True)

if hasattr(st, "fragment") and live_stream_active:
    live_telemetry_fragment = st.fragment(run_every="2s")(render_live_telemetry_panel)
else:
    live_telemetry_fragment = render_live_telemetry_panel

# TAB 1: MONITOR SOC
with tab_soc:
    st.subheader(" Telemetría de Red e Inspección de Tráfico en Tiempo Real")
    live_telemetry_fragment()

    st.divider()
    total_inc = len(incidents)
    crit_inc = sum(1 for i in incidents if i["severity"] in ["CRÍTICO", "ALTO"])
    active_blocks = sum(1 for b in blocked_ips if b["is_active"] == 1)
    last_lynis = lynis_audits[0]["hardening_index"] if lynis_audits else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Incidentes Históricos (SQL)", total_inc)
    c2.metric("Amenazas Altas / Críticas", crit_inc)
    c3.metric("IPs Bloqueadas en UFW", active_blocks)
    c4.metric("Índice Hardening Lynis", f"{last_lynis}/100")

    if incidents:
        df = pd.DataFrame(incidents)
        col_g1, col_g2 = st.columns(2)
        with col_g1:
            fig_sev = px.pie(df, names="severity", title="Distribución por Severidad", hole=0.4)
            st.plotly_chart(fig_sev, use_container_width=True)
        with col_g2:
            fig_type = px.bar(df["event_type"].value_counts().reset_index(), x="event_type", y="count", title="Incidentes por Vector de Ataque", color="event_type")
            st.plotly_chart(fig_type, use_container_width=True)

        st.subheader("📋 Bitácora Reciente de Incidentes")
        cols_to_show = [c for c in ["id", "timestamp", "source_ip", "abuse_score", "event_type", "severity", "status", "action_taken", "evidence_hash"] if c in df.columns]
        st.dataframe(df[cols_to_show], use_container_width=True, hide_index=True)
    else:
        st.info("No hay incidentes registrados aún. Usa el botón 'Simular Ataque en Vivo' en la barra lateral.")

# TAB 2: ABUSEIPDB THREAT INTEL
with tab_intel:
    st.subheader(" Inteligencia de Amenazas y Reputación de IPs (AbuseIPDB)")
    st.markdown("Cada alerta recibida por S.A.R.A. se enriquece automáticamente consultando **AbuseIPDB** antes de tomar decisiones de bloqueo.")
    col_i1, col_i2 = st.columns([1, 1.5])
    with col_i1:
        ip_query = st.text_input("Consultar dirección IP en AbuseIPDB:", "185.220.101.45")
        if st.button("🔎 Analizar Reputación IP", type="primary", use_container_width=True):
            st.session_state["last_intel"] = check_ip_abuseipdb(ip_query)
    with col_i2:
        if "last_intel" in st.session_state:
            ir = st.session_state["last_intel"]
            score = ir.get("abuseConfidenceScore", 0)
            st.metric("Nivel de Confianza de Abuso (Abuse Score)", f"{score}%", delta="MALICIOSA - BLOQUEO RECOMENDADO" if score >= 75 else "Riesgo Moderado/Bajo", delta_color="inverse")
            st.json(ir)

# TAB 3: AUDITORÍAS PROGRAMADAS LYNIS
with tab_lynis:
    st.subheader(" Auditorías Programadas de Sistema (Lynis) y Recomendaciones Correctivas")
    st.markdown("S.A.R.A. ejecuta auditorías periódicas mediante **Lynis** para evaluar el nivel de endurecimiento (*Hardening Index*) de Ubuntu y almacenar recomendaciones correctivas en SQL.")
    if lynis_audits:
        latest = lynis_audits[0]
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Hardening Index Actual", f"{latest['hardening_index']}/100")
        k2.metric("Warnings Detectados", latest["warnings_count"])
        k3.metric("Sugerencias de Mejora", latest["suggestions_count"])
        k4.metric("Última Ejecución", latest["timestamp"])

        st.markdown(f"**Modo de Ejecución:** `{latest['execution_mode']}`")
        col_l1, col_l2 = st.columns(2)
        with col_l1:
            st.warning(f"**Hallazgos y Advertencias (Lynis Findings):**\n\n{latest['findings_summary']}")
        with col_l2:
            st.success(f"**Recomendaciones Correctivas Generadas:**\n\n{latest['corrective_recommendations']}")

        st.divider()
        st.markdown("####  Historial SQL de Auditorías Lynis")
        st.dataframe(pd.DataFrame(lynis_audits), use_container_width=True, hide_index=True)
    else:
        st.info("Ejecuta tu primera auditoría con el botón 'Ejecutar Auditoría Lynis Ahora' en la barra lateral.")

# TAB 4: REGISTRO HISTÓRICO SQL
with tab_sql:
    st.subheader("🗄️ Explorador del Registro Histórico en Base de Datos SQL (`sara_soar.db`)")
    st.markdown("Consulta directa sobre las tablas relacionales que conforman la persistencia histórica de **S.A.R.A.**")
    table_choice = st.selectbox("Seleccionar tabla SQL a consultar:", ["incidents", "blocked_ips", "lynis_audits"])
    conn = get_connection()
    df_sql = pd.read_sql_query(f"SELECT * FROM {table_choice} ORDER BY 1 DESC", conn)
    conn.close()
    st.dataframe(df_sql, use_container_width=True, hide_index=True)
    csv_bytes = df_sql.to_csv(index=False).encode("utf-8")
    st.download_button(
        label=f"Exportar Tabla '{table_choice}' a CSV",
        data=csv_bytes,
        file_name=f"sara_sql_{table_choice}.csv",
        mime="text/csv"
    )

# TAB 5: DICTÁMENES FORENSES PDF Y FALSOS POSITIVOS
with tab_fp:
    st.subheader(" Dictamen Forense Digital (Cadena de Custodia PDF) y Falsos Positivos")
    if incidents:
        options = {f"#{i['id']} | {i['timestamp']} | {i['source_ip']} ({i['event_type']} - {i['status']})": i for i in incidents}
        selected_label = st.selectbox("Selecciona un incidente del registro histórico SQL:", list(options.keys()))
        inc = options[selected_label]

        col_d1, col_d2 = st.columns([2, 1])
        with col_d1:
            st.markdown(f"**Folio Forense:** `SARA-INC-{int(inc['id']):05d}`")
            st.markdown(f"**IP Origen:** `{inc['source_ip']}` | **AbuseIPDB Score:** `{inc.get('abuse_score', 0)}%` | **Severidad:** `{inc['severity']}`")
            st.markdown(f"**Estado Actual:** `{inc['status']}` | **Acción Aplicada:** `{inc['action_taken']}`")
            st.markdown(f"**Hash SHA-256 de Integridad:** `{inc.get('evidence_hash', 'N/A')}`")
            st.code(inc["raw_log"], language="bash")
            st.info(f"🤖 **Dictamen de Inteligencia Artificial:**\n\n{inc['ai_analysis']}")

        with col_d2:
            st.markdown("###  Evidencia y Respuesta")
            pdf_bytes = generate_incident_forensic_pdf(inc)
            st.download_button(
                label=f" Descargar Dictamen Forense #{inc['id']} (PDF)",
                data=pdf_bytes,
                file_name=f"Dictamen_Forense_SARA_INC_{inc['id']}.pdf",
                mime="application/pdf",
                type="primary",
                use_container_width=True
            )

            st.divider()
            if st.button(" Marcar como Falso Positivo (Desbloquear IP)", use_container_width=True):
                unblock_ip_ufw(inc["source_ip"], whitelist=True)
                update_incident_status(inc["id"], "Falso Positivo", "Revertido: IP en Lista Blanca y liberada en UFW")
                send_telegram_alert("Falso Positivo", f"Incidente #{inc['id']} ({inc['source_ip']}) marcado como Falso Positivo.")
                st.success(f"IP {inc['source_ip']} desbloqueada y agregada a Lista Blanca.")
                st.rerun()

            if st.button(" Forzar Bloqueo en UFW", use_container_width=True):
                res = block_ip_ufw(inc["source_ip"], f"Bloqueo manual por incidente #{inc['id']}")
                if res["success"]:
                    update_incident_status(inc["id"], "Mitigada", res["message"])
                    st.success(res["message"])
                    st.rerun()
                else:
                    st.error(res["message"])
    else:
        st.info("Sin incidentes para inspeccionar.")

# TAB 6: CORTAFUEGOS UFW
with tab_ufw:
    st.subheader(" Control Directo del Cortafuegos (UFW) y Lista Blanca")
    col_u1, col_u2 = st.columns(2)
    with col_u1:
        ip_to_block = st.text_input("Dirección IP a Bloquear", placeholder="Ej. 203.0.113.50")
        reason_block = st.text_input("Motivo de Bloqueo", "Actividad hostil detectada en auditoría")
        if st.button("Bloquear IP en UFW", type="primary"):
            res = block_ip_ufw(ip_to_block, reason_block)
            if res["success"]:
                st.success(res["message"])
                st.rerun()
            else:
                st.error(res["message"])

    with col_u2:
        ip_to_unblock = st.text_input("Dirección IP a Desbloquear / Lista Blanca", placeholder="Ej. 203.0.113.50")
        add_wl = st.checkbox("Añadir permanentemente a Lista Blanca", value=True)
        if st.button("Liberar IP en UFW"):
            res = unblock_ip_ufw(ip_to_unblock, whitelist=add_wl)
            if res["success"]:
                st.success(res["message"])
                st.rerun()
            else:
                st.error(res["message"])

    st.divider()
    if blocked_ips:
        df_b = pd.DataFrame(blocked_ips)
        df_b["Estado UFW"] = df_b["is_active"].apply(lambda x: "🔴 Bloqueada" if x == 1 else "🟢 Liberada")
        df_b["Lista Blanca"] = df_b["whitelisted"].apply(lambda x: " Sí" if x == 1 else "No")
        st.dataframe(df_b[["ip", "Estado UFW", "Lista Blanca", "reason", "blocked_at"]], use_container_width=True, hide_index=True)
    else:
        st.info("No hay direcciones IP registradas en la tabla de control de UFW.")

# TAB 7: N8N, TELEGRAM QR Y OLLAMA
with tab_tg:
    col_t1, col_t2 = st.columns([1.3, 1])
    with col_t1:
        st.subheader("📱 Configuración de Telegram, AbuseIPDB, n8n y Motor IA")
        bot_token = st.text_input("Telegram Bot Token (de @BotFather)", value=get_setting("telegram_bot_token"), type="password")
        bot_user = st.text_input("Username del Bot (sin @)", value=get_setting("telegram_bot_username", "CerberusSARA_bot"))
        chat_id = st.text_input("Telegram Chat ID", value=get_setting("telegram_chat_id"))
        abuse_key = st.text_input("AbuseIPDB API Key (Opcional - usa simulador si está vacío)", value=get_setting("abuseipdb_api_key"), type="password")
        
        st.markdown("####  Parámetros de IA Local (Ollama) y Orquestador n8n")
        ollama_url = st.text_input("URL del Servidor Ollama", value=get_setting("ollama_url", "http://localhost:11434"))
        ollama_model = st.text_input("Modelo LLM en Ollama", value=get_setting("ollama_model", "llama3"))

        if st.button(" Guardar Configuración", type="primary"):
            set_setting("telegram_bot_token", bot_token)
            set_setting("telegram_bot_username", bot_user.replace("@", ""))
            set_setting("telegram_chat_id", chat_id)
            set_setting("abuseipdb_api_key", abuse_key)
            set_setting("ollama_url", ollama_url)
            set_setting("ollama_model", ollama_model)
            st.success("Configuración guardada en SQL correctamente.")

        c_b1, c_b2 = st.columns(2)
        with c_b1:
            if st.button(" Detectar Chat ID Automáticamente", use_container_width=True):
                res = fetch_latest_telegram_chat_id()
                if res["success"]:
                    st.success(f"Vinculado con {res['user']} (Chat ID: {res['chat_id']})")
                    st.rerun()
                else:
                    st.warning(res["message"])
        with c_b2:
            if st.button(" Enviar Alerta de Prueba", use_container_width=True):
                res = send_telegram_alert(" Prueba de Enlace S.A.R.A. v4.0", "Conexión móvil verificada con éxito desde el dashboard.")
                if res["sent"]:
                    st.success(res["reason"])
                else:
                    st.error(res["reason"])

    with col_t2:
        st.subheader(" Vinculación Rápida por QR")
        clean_user = bot_user.replace("@", "").strip() or "CerberusSARA_bot"
        tg_link = f"https://t.me/{clean_user}?start=sara_soc"
        qr = qrcode.QRCode(version=1, box_size=8, border=2)
        qr.add_data(tg_link)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = BytesIO()
        img.save(buf, format="PNG")
        st.image(buf.getvalue(), caption=f"Escanea para abrir @{clean_user}", width=220)
        st.markdown(
            "1. Escanea el código QR con tu celular.\n"
            "2. Presiona **Iniciar (`/start`)** en Telegram.\n"
            "3. Haz clic en **Detectar Chat ID Automáticamente**."
        )
        st.divider()
        st.markdown("####  Servicios Contenerizados")
        st.markdown("- **Orquestador n8n:** `http://localhost:5678`")
        st.markdown("- **Swagger FastAPI:** `http://localhost:8000/docs`")
        st.markdown("- **Motor IA Ollama:** `http://localhost:11434`")
