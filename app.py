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
    layout="wide"
)

init_db()

# ---------------------------------------------------------------------------
# Constantes de tema y traducciones
# ---------------------------------------------------------------------------
COLORS = {
    "text": "#e6ebff",
    "muted": "#8f9bc4",
    "cyan": "#00d4ff",
    "blue": "#2b6bff",
    "purple": "#8b2cff",
    "red": "#ff2e63",
    "orange": "#ff8a1f",
    "green": "#00e08a",
}

SEVERITY_COLORS = {
    "CRÍTICO": "#ff2e63",
    "ALTO": "#ff8a1f",
    "MEDIO": "#2b6bff",
    "BAJO": "#00d4ff",
}

SEVERITY_GRADIENTS = {
    "CRÍTICO": "linear-gradient(90deg, #ff2e63, #ff0055)",
    "ALTO": "linear-gradient(90deg, #ff9f1c, #ff3d00)",
    "MEDIO": "linear-gradient(90deg, #2b3cff, #a020f0)",
    "BAJO": "linear-gradient(90deg, #1e90ff, #00f0ff)",
}

# Los valores originales se conservan en la base de datos; solo se traducen al mostrarlos.
EVENT_LABELS = {
    "SSH Brute Force": "Fuerza bruta SSH",
    "SQL Injection": "Inyección SQL",
    "Port Scan": "Escaneo de puertos",
    "Malware Beacon": "Baliza de malware",
    "DDoS SYN Flood": "Inundación SYN (DDoS)",
}

COLUMN_LABELS = {
    "id": "ID",
    "audit_id": "ID auditoría",
    "timestamp": "Fecha y hora",
    "source_ip": "IP de origen",
    "abuse_score": "Score AbuseIPDB",
    "event_type": "Tipo de amenaza",
    "severity": "Severidad",
    "status": "Estado",
    "action_taken": "Acción tomada",
    "evidence_hash": "Hash de evidencia",
    "raw_log": "Log crudo",
    "ai_analysis": "Análisis de IA",
    "ip": "Dirección IP",
    "is_active": "Bloqueada",
    "whitelisted": "En lista blanca",
    "reason": "Motivo",
    "blocked_at": "Fecha de bloqueo",
    "hardening_index": "Índice de hardening",
    "warnings_count": "Advertencias",
    "suggestions_count": "Sugerencias",
    "execution_mode": "Modo de ejecución",
    "findings_summary": "Hallazgos",
    "corrective_recommendations": "Recomendaciones",
}

COLUMN_WIDTHS = {
    "id": "small", "audit_id": "small", "severity": "small", "abuse_score": "small",
    "is_active": "small", "whitelisted": "small",
    "raw_log": "large", "action_taken": "large", "evidence_hash": "medium",
}

CUSTOM_CSS = """
<style>
:root {
    --text: #e6ebff;
    --muted: #8f9bc4;
    --border: rgba(120, 140, 220, 0.14);
    --cyan: #00d4ff;
}

.stApp {
    background: radial-gradient(1200px 600px at 10% -10%, #17224f 0%, #0b1020 55%) fixed;
    color: var(--text);
}
header[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 1.2rem; padding-bottom: 3rem; max-width: 1500px; }

/* Ocultar elementos en inglés del marco de Streamlit */
[data-testid="stAppDeployButton"], #MainMenu, footer,
[data-testid="stElementToolbar"], [data-testid="stStatusWidget"] { display: none !important; }

h1, h2, h3, h4, h5 { color: var(--text); letter-spacing: 0.2px; }
p, label, span, li { color: var(--text); }
[data-testid="stCaptionContainer"] { color: var(--muted); }

/* Barra lateral */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d1330 0%, #0a0f26 100%);
    border-right: 1px solid var(--border);
}
section[data-testid="stSidebar"] h2, section[data-testid="stSidebar"] h3 {
    font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1.4px;
    color: var(--muted); font-weight: 600; margin-top: 0.4rem;
}

/* Barra superior */
.topbar {
    display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap;
    background: linear-gradient(135deg, #131a3a 0%, #0f1530 100%);
    border: 1px solid var(--border); border-radius: 18px;
    padding: 14px 22px; margin-bottom: 16px;
    box-shadow: 0 12px 30px rgba(0, 0, 0, 0.35);
}
.brand { display: flex; align-items: center; gap: 14px; }
.logo {
    width: 44px; height: 44px; border-radius: 50%;
    background: linear-gradient(135deg, #2b6bff, #8b2cff);
    display: flex; align-items: center; justify-content: center;
    font-weight: 800; font-size: 1.2rem; color: white;
    box-shadow: 0 0 18px rgba(139, 44, 255, 0.55);
}
.brand-title { font-size: 1.25rem; font-weight: 750; color: white; line-height: 1.1; }
.brand-sub { font-size: 0.78rem; color: var(--muted); margin-top: 2px; }
.chips { display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
.chip {
    font-size: 0.74rem; font-weight: 600; padding: 6px 12px; border-radius: 999px;
    background: rgba(43, 107, 255, 0.14); color: #9db9ff; border: 1px solid rgba(43, 107, 255, 0.35);
}
.chip.ok { background: rgba(0, 224, 138, 0.10); color: #4ff0b0; border-color: rgba(0, 224, 138, 0.35); }
.chip.warn { background: rgba(255, 138, 31, 0.10); color: #ffb067; border-color: rgba(255, 138, 31, 0.35); }
.chip.off { background: rgba(255, 46, 99, 0.10); color: #ff8aa8; border-color: rgba(255, 46, 99, 0.35); }

/* Pestañas */
div[data-baseweb="tab-list"] { gap: 8px; border-bottom: none; flex-wrap: wrap; margin-bottom: 6px; }
button[data-baseweb="tab"] {
    background: rgba(30, 48, 100, 0.45); border-radius: 8px; padding: 10px 20px;
    height: auto; color: var(--muted); font-weight: 600; border: 1px solid transparent;
}
button[data-baseweb="tab"]:hover { color: white; border-color: var(--border); }
button[data-baseweb="tab"][aria-selected="true"] {
    background: linear-gradient(90deg, #1e6bff 0%, #00e5ff 100%);
    box-shadow: 0 6px 20px rgba(0, 212, 255, 0.28);
}
button[data-baseweb="tab"][aria-selected="true"] p { color: #04101f; font-weight: 700; }
div[data-baseweb="tab-highlight"], div[data-baseweb="tab-border"] { display: none; }

/* Métricas */
div[data-testid="stMetric"] {
    background: linear-gradient(145deg, #171f42 0%, #121833 100%);
    border: 1px solid var(--border); border-radius: 16px; padding: 16px 18px;
    box-shadow: 0 10px 24px rgba(0, 0, 0, 0.30), inset 0 1px 0 rgba(255, 255, 255, 0.03);
}
div[data-testid="stMetricLabel"] p {
    color: var(--muted); font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.8px;
}
div[data-testid="stMetricValue"] { color: white; font-weight: 750; }

/* Tarjetas */
div[data-testid="stVerticalBlockBorderWrapper"] {
    background: linear-gradient(145deg, #151c3b 0%, #11172f 100%);
    border: 1px solid var(--border) !important; border-radius: 18px !important;
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.30);
}

/* Botones */
.stButton > button, .stDownloadButton > button {
    background: rgba(30, 48, 100, 0.55); color: var(--text);
    border: 1px solid var(--border); border-radius: 10px; font-weight: 600;
    padding: 0.55rem 1rem; transition: all 0.15s ease;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    border-color: var(--cyan); color: white;
    box-shadow: 0 0 0 1px rgba(0, 212, 255, 0.35), 0 8px 20px rgba(0, 212, 255, 0.12);
}
button[data-testid="stBaseButton-primary"], .stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] {
    background: linear-gradient(90deg, #1e6bff 0%, #00d4ff 100%); color: #04101f; border: none;
    box-shadow: 0 8px 22px rgba(0, 212, 255, 0.25);
}
button[data-testid="stBaseButton-primary"] p { color: #04101f; font-weight: 700; }

/* Campos */
.stTextInput input, .stTextArea textarea, div[data-baseweb="select"] > div {
    background: #0e1430 !important; color: var(--text) !important;
    border: 1px solid var(--border) !important; border-radius: 10px !important;
}
.stTextInput input:focus, .stTextArea textarea:focus { border-color: var(--cyan) !important; }

div[data-testid="stExpander"] { background: rgba(20, 26, 53, 0.7); border: 1px solid var(--border); border-radius: 14px; }
div[data-testid="stAlert"] { background: rgba(24, 32, 74, 0.65); border: 1px solid var(--border); border-radius: 14px; }
div[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: 14px; overflow: hidden; }
hr { border-color: var(--border) !important; margin: 1rem 0 !important; }

/* Títulos de sección */
.sec { margin: 26px 0 12px 0; }
.sec-title { font-size: 1.15rem; font-weight: 700; color: white; }
.sec-sub { font-size: 0.85rem; color: var(--muted); margin-top: 2px; }
.sec-first { margin-top: 8px; }
.card-label {
    font-size: 0.74rem; text-transform: uppercase; letter-spacing: 1.2px;
    color: var(--muted); font-weight: 650; margin-bottom: 8px;
}
.hint { color: var(--muted); font-size: 0.85rem; margin-bottom: 8px; }

/* Barras de progreso */
.pbar-row { display: flex; align-items: center; gap: 14px; margin: 14px 0; }
.pbar-label { width: 90px; font-size: 0.78rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.6px; }
.pbar-track { flex: 1; height: 16px; border-radius: 6px; background: rgba(255, 255, 255, 0.06); overflow: hidden; }
.pbar-fill { height: 100%; border-radius: 6px; box-shadow: 0 0 14px rgba(255, 255, 255, 0.12); }
.pbar-value { width: 90px; text-align: right; font-weight: 700; color: white; font-size: 0.92rem; }

/* Ficha de detalle */
.detail-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }
.detail-title { font-size: 1.1rem; font-weight: 700; color: white; margin-right: 6px; }
.badge {
    font-size: 0.72rem; font-weight: 700; padding: 4px 10px; border-radius: 999px;
    border: 1px solid; letter-spacing: 0.4px;
}
.kv-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px 18px; margin-bottom: 14px; }
.kv-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); }
.kv-value { font-size: 0.95rem; font-weight: 600; color: white; word-break: break-word; margin-top: 2px; }
.kv-full { margin-bottom: 14px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.8rem; color: #9db9ff; word-break: break-all; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Funciones de presentación
# ---------------------------------------------------------------------------
def section(title, subtitle=None, first=False):
    cls = "sec sec-first" if first else "sec"
    sub = f'<div class="sec-sub">{subtitle}</div>' if subtitle else ""
    st.markdown(f'<div class="{cls}"><div class="sec-title">{title}</div>{sub}</div>', unsafe_allow_html=True)


def card_label(text):
    st.markdown(f'<div class="card-label">{text}</div>', unsafe_allow_html=True)


def chip(text, kind=""):
    return f'<span class="chip {kind}">{text}</span>'


def badge(text, color):
    return f'<span class="badge" style="color:{color}; border-color:{color}66; background:{color}1f;">{text}</span>'


def status_color(status):
    s = str(status).lower()
    if "mitigad" in s:
        return COLORS["green"]
    if "falso" in s:
        return COLORS["blue"]
    return COLORS["orange"]


def kv(label, value, mono=False):
    cls = "kv-value mono" if mono else "kv-value"
    return f'<div><div class="kv-label">{label}</div><div class="{cls}">{value}</div></div>'


def progress_bar_html(label, pct, gradient, value_text=None):
    pct = max(0, min(100, pct))
    value_text = value_text if value_text is not None else f"{pct:.0f}%"
    return (
        f'<div class="pbar-row"><div class="pbar-label">{label}</div>'
        f'<div class="pbar-track"><div class="pbar-fill" style="width:{pct}%; background:{gradient};"></div></div>'
        f'<div class="pbar-value">{value_text}</div></div>'
    )


def style_fig(fig, height=300, title=None, legend=True):
    fig.update_layout(
        title=dict(text=title, font=dict(size=14, color=COLORS["text"])) if title else None,
        height=height,
        margin=dict(l=10, r=10, t=50 if title else 20, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=COLORS["muted"], size=12),
        showlegend=legend,
        legend=dict(orientation="h", y=1.14, x=0, font=dict(color=COLORS["muted"])),
        hoverlabel=dict(bgcolor="#141a35", font_color="white"),
    )
    fig.update_xaxes(showgrid=False, zeroline=False, linecolor="rgba(255,255,255,0.08)")
    fig.update_yaxes(gridcolor="rgba(255,255,255,0.06)", zeroline=False)
    return fig


def show_chart(fig, key):
    st.plotly_chart(fig, use_container_width=True, key=key, config={"displayModeBar": False})


def ring_chart(value, label, color, height=210):
    value = max(0, min(100, float(value)))
    fig = go.Figure(go.Pie(
        values=[value, 100 - value], hole=0.78, sort=False, direction="clockwise",
        marker=dict(colors=[color, "rgba(255,255,255,0.07)"], line=dict(width=0)),
        textinfo="none", hoverinfo="skip", showlegend=False,
    ))
    fig.update_layout(
        height=height, margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        annotations=[
            dict(text=f"<b>{value:.0f}%</b>", x=0.5, y=0.54, showarrow=False, font=dict(size=28, color="white")),
            dict(text=label, x=0.5, y=0.38, showarrow=False, font=dict(size=11, color=COLORS["muted"])),
        ],
    )
    return fig


def show_table(df, columns=None, height=None, translate_values=True, selectable=False, key=None):
    """Muestra un DataFrame con encabezados en español sin modificar los datos originales."""
    d = df.copy()
    if columns:
        d = d[[c for c in columns if c in d.columns]]
    if translate_values:
        if "event_type" in d.columns:
            d["event_type"] = d["event_type"].map(lambda x: EVENT_LABELS.get(x, x))
        for c in ("is_active", "whitelisted"):
            if c in d.columns:
                d[c] = d[c].map(lambda x: "Sí" if x == 1 else "No")
    cfg = {}
    for c in d.columns:
        label = COLUMN_LABELS.get(c, c)
        width = COLUMN_WIDTHS.get(c)
        if c == "abuse_score":
            cfg[c] = st.column_config.ProgressColumn(label, min_value=0, max_value=100, format="%d%%")
        else:
            cfg[c] = st.column_config.Column(label, width=width) if width else st.column_config.Column(label)
    kwargs = dict(column_config=cfg, use_container_width=True, hide_index=True)
    if height is not None:
        kwargs["height"] = height
    if selectable:
        kwargs.update(on_select="rerun", selection_mode="single-row", key=key)
        return st.dataframe(d, **kwargs)
    st.dataframe(d, **kwargs)


def render_intel(intel, key):
    """Muestra el resultado de una consulta de reputación de IP."""
    data = intel["data"]
    score = data.get("abuseConfidenceScore", 0)
    if score >= 75:
        color, verdict = COLORS["red"], "Maliciosa: se recomienda bloquear"
    elif score >= 40:
        color, verdict = COLORS["orange"], "Sospechosa"
    else:
        color, verdict = COLORS["green"], "Riesgo bajo"
    st.markdown(f'<div class="kv-label">Resultado para {intel["ip"]}</div>', unsafe_allow_html=True)
    show_chart(ring_chart(score, "Score de abuso", color, height=170), f"ring_{key}")
    st.markdown(badge(verdict, color), unsafe_allow_html=True)
    with st.expander("Ver respuesta completa"):
        st.json(data)


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def row_id(row):
    return safe_int(row.get("id", row.get("audit_id", 0)))


# ---------------------------------------------------------------------------
# Datos (la base de datos nunca se modifica al limpiar la vista)
# ---------------------------------------------------------------------------
full_incidents = get_incidents(200)
blocked_ips = get_blocked_ips()
full_lynis = get_lynis_audits(50)

cut_inc = safe_int(get_setting("view_cleared_incident_id", "0"))
cut_aud = safe_int(get_setting("view_cleared_audit_id", "0"))
view_is_cleared = cut_inc > 0 or cut_aud > 0

incidents = [i for i in full_incidents if row_id(i) > cut_inc]
lynis_audits = [a for a in full_lynis if row_id(a) > cut_aud]

# ---------------------------------------------------------------------------
# Estado de sesión
# ---------------------------------------------------------------------------
if "telemetry_history" not in st.session_state:
    st.session_state.telemetry_history = []
    for _ in range(20):
        st.session_state.telemetry_history.append(sample_network_telemetry())

# ---------------------------------------------------------------------------
# Barra lateral
# ---------------------------------------------------------------------------
with st.sidebar:
    st.subheader("Acciones")
    if st.button("Ejecutar auditoría Lynis", use_container_width=True, type="primary"):
        audit_res = run_lynis_system_audit()
        st.success(f"Auditoría Lynis #{audit_res['audit_id']} registrada (índice: {audit_res['hardening_index']}/100).")
        st.rerun()

    with st.expander("Herramientas de demostración"):
        st.caption("Generan datos de prueba. Úsalas solo en entornos de demostración.")
        if st.button("Simular ataque en vivo", use_container_width=True):
            res = simulate_attack()
            st.success(f"Incidente #{res['incident_id']} procesado (AbuseIPDB: {res['abuse_score']}%).")
            st.rerun()

        if st.button("Simular ráfaga DDoS", use_container_width=True):
            set_setting("traffic_spike", "5")
            simulate_attack()
            st.warning("Ráfaga de tráfico hostil inyectada.")
            st.rerun()

        st.divider()
        st.markdown('<div class="card-label">Evento manual</div>', unsafe_allow_html=True)
        m_ip = st.text_input("IP de origen", "185.220.101.77")
        m_type = st.selectbox(
            "Tipo de amenaza",
            list(EVENT_LABELS.keys()),
            format_func=lambda x: EVENT_LABELS.get(x, x),
        )
        m_sev = st.selectbox("Severidad", ["CRÍTICO", "ALTO", "MEDIO", "BAJO"])
        m_log = st.text_area("Log crudo", "Failed password for invalid user admin port 22 ssh2")
        if st.button("Procesar evento", use_container_width=True):
            ingest_security_event(LogEvent(source_ip=m_ip, event_type=m_type, raw_log=m_log, severity=m_sev))
            st.toast("Evento analizado y guardado en la base de datos")
            st.rerun()

    st.divider()
    st.subheader("Vista de datos")
    st.caption("Limpia las tablas en pantalla. Los registros permanecen en la base de datos.")
    if st.button("Limpiar tablas", use_container_width=True):
        set_setting("view_cleared_incident_id", str(max([row_id(i) for i in full_incidents] or [0])))
        set_setting("view_cleared_audit_id", str(max([row_id(a) for a in full_lynis] or [0])))
        st.toast("Vista limpiada. La base de datos no fue modificada.")
        st.rerun()
    if view_is_cleared:
        if st.button("Restaurar vista completa", use_container_width=True):
            set_setting("view_cleared_incident_id", "0")
            set_setting("view_cleared_audit_id", "0")
            st.rerun()

    st.divider()
    st.subheader("Ajustes")
    live_stream_active = st.toggle("Gráficas en vivo (cada 2 s)", value=True)

    sim_mode = st.toggle(
        "Modo simulación UFW",
        value=(get_setting("simulation_mode", "1") == "1"),
        help="Registra los comandos de UFW sin requerir permisos root reales. Recomendado para demostraciones."
    )
    set_setting("simulation_mode", "1" if sim_mode else "0")

    auto_block = st.toggle(
        "Bloqueo automático",
        value=(get_setting("auto_block_enabled", "1") == "1"),
        help="Bloquea la IP de forma automática cuando la severidad es Alta o Crítica, o cuando AbuseIPDB reporta 75% o más."
    )
    set_setting("auto_block_enabled", "1" if auto_block else "0")

    st.divider()
    st.subheader("Reportes")
    # El reporte ejecutivo siempre usa el historial completo, incluso con la vista limpiada.
    exec_pdf_bytes = generate_executive_summary_pdf(full_incidents, blocked_ips, full_lynis)
    st.download_button(
        label="Descargar reporte ejecutivo (PDF)",
        data=exec_pdf_bytes,
        file_name="Reporte_Ejecutivo_SOC_SARA.pdf",
        mime="application/pdf",
        use_container_width=True
    )

# ---------------------------------------------------------------------------
# Encabezado
# ---------------------------------------------------------------------------
crit_count = sum(1 for i in incidents if i["severity"] in ["CRÍTICO", "ALTO"])
header_chips = (
    chip("v4.0")
    + chip("UFW en simulación" if sim_mode else "UFW real", "warn" if sim_mode else "ok")
    + chip("Bloqueo automático activo" if auto_block else "Bloqueo automático inactivo", "ok" if auto_block else "off")
    + chip(f"{crit_count} amenazas altas o críticas", "off" if crit_count else "ok")
    + (chip("Vista limpiada", "warn") if view_is_cleared else "")
)
st.markdown(
    f"""
    <div class="topbar">
        <div class="brand">
            <div class="logo">S</div>
            <div>
                <div class="brand-title">S.A.R.A.</div>
                <div class="brand-sub">Sistema Automatizado de Respuesta y Análisis · CerberusOps SOAR</div>
            </div>
        </div>
        <div class="chips">{header_chips}</div>
    </div>
    """,
    unsafe_allow_html=True,
)

tab_resumen, tab_resp, tab_lynis, tab_db, tab_cfg = st.tabs([
    "Resumen",
    "Respuesta a incidentes",
    "Auditorías",
    "Base de datos",
    "Configuración",
])


# ---------------------------------------------------------------------------
# Telemetría en vivo
# ---------------------------------------------------------------------------
def render_live_telemetry_panel():
    sample = sample_network_telemetry()
    st.session_state.telemetry_history.append(sample)
    if len(st.session_state.telemetry_history) > 30:
        st.session_state.telemetry_history.pop(0)

    df_t = pd.DataFrame(st.session_state.telemetry_history)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Tráfico entrante", f"{sample['rx_kbps']} KB/s",
              delta=f"{sample['threat_kbps']} KB/s anómalo", delta_color="inverse")
    m2.metric("Paquetes por segundo", f"{sample['pps_total']} pkt/s",
              delta=f"{sample['malicious_pps']} hostiles", delta_color="inverse")
    m3.metric("CPU del nodo", f"{sample['cpu_percent']}%")
    m4.metric("Memoria RAM", f"{sample['ram_percent']}%")

    col_a, col_b = st.columns(2)
    with col_a:
        with st.container(border=True):
            fig_net = go.Figure()
            fig_net.add_trace(go.Scatter(
                x=df_t["timestamp"], y=df_t["rx_kbps"], mode="lines", name="Entrada",
                line=dict(color=COLORS["cyan"], width=2.5, shape="spline"),
                fill="tozeroy", fillcolor="rgba(0, 212, 255, 0.10)"))
            fig_net.add_trace(go.Scatter(
                x=df_t["timestamp"], y=df_t["tx_kbps"], mode="lines", name="Salida",
                line=dict(color=COLORS["green"], width=2, shape="spline")))
            fig_net.add_trace(go.Scatter(
                x=df_t["timestamp"], y=df_t["threat_kbps"], mode="lines", name="Tráfico hostil",
                line=dict(color=COLORS["red"], width=3, shape="spline"),
                fill="tozeroy", fillcolor="rgba(255, 46, 99, 0.12)"))
            style_fig(fig_net, height=300, title="Tráfico de red (KB/s)")
            show_chart(fig_net, "live_net_chart")

    with col_b:
        with st.container(border=True):
            fig_pps = go.Figure()
            fig_pps.add_trace(go.Bar(
                x=df_t["timestamp"], y=df_t["pps_total"], name="Paquetes totales",
                marker=dict(color="rgba(43, 107, 255, 0.75)")))
            fig_pps.add_trace(go.Scatter(
                x=df_t["timestamp"], y=df_t["malicious_pps"], mode="lines+markers", name="Paquetes hostiles",
                line=dict(color=COLORS["orange"], width=3, shape="spline"),
                marker=dict(size=6, color=COLORS["orange"])))
            style_fig(fig_pps, height=300, title="Paquetes por segundo")
            show_chart(fig_pps, "live_pps_chart")


if hasattr(st, "fragment") and live_stream_active:
    live_telemetry_fragment = st.fragment(run_every="2s")(render_live_telemetry_panel)
else:
    live_telemetry_fragment = render_live_telemetry_panel


# ---------------------------------------------------------------------------
# Pestaña: Resumen
# ---------------------------------------------------------------------------
with tab_resumen:
    total_inc = len(incidents)
    crit_inc = sum(1 for i in incidents if i["severity"] in ["CRÍTICO", "ALTO"])
    active_blocks = sum(1 for b in blocked_ips if b["is_active"] == 1)
    # El hardening refleja el estado real del sistema: siempre usa la auditoría más reciente.
    last_lynis = full_lynis[0]["hardening_index"] if full_lynis else 0

    section("Estado general", "Indicadores principales del sistema.", first=True)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Incidentes en vista", total_inc)
    c2.metric("Amenazas altas o críticas", crit_inc)
    c3.metric("IPs bloqueadas", active_blocks)
    c4.metric("Índice de hardening", f"{last_lynis}/100")

    if incidents:
        df = pd.DataFrame(incidents)

        section("Distribución de amenazas", "Severidad de los incidentes y postura de seguridad del sistema.")
        col_s1, col_s2 = st.columns([1.6, 1])
        with col_s1:
            with st.container(border=True):
                card_label("Incidentes por severidad")
                counts = df["severity"].value_counts()
                bars_html = ""
                for sev in ["CRÍTICO", "ALTO", "MEDIO", "BAJO"]:
                    n = int(counts.get(sev, 0))
                    pct = (n / total_inc * 100) if total_inc else 0
                    bars_html += progress_bar_html(sev, pct, SEVERITY_GRADIENTS[sev], f"{pct:.0f}%  ({n})")
                st.markdown(bars_html, unsafe_allow_html=True)
        with col_s2:
            with st.container(border=True):
                card_label("Hardening del sistema (Lynis)")
                ring_color = COLORS["green"] if last_lynis >= 70 else (COLORS["orange"] if last_lynis >= 50 else COLORS["red"])
                show_chart(ring_chart(last_lynis, "Índice de hardening", ring_color), "ring_hardening")
    else:
        if view_is_cleared:
            st.info("La vista está limpia. Los nuevos incidentes aparecerán aquí; usa 'Restaurar vista completa' en la barra lateral para ver el historial.")
        else:
            st.info("No hay incidentes registrados. Abre 'Herramientas de demostración' en la barra lateral para generar datos de prueba.")

    section("Tráfico de red en tiempo real", "Se actualiza automáticamente cada 2 segundos.")
    live_telemetry_fragment()

    if incidents:
        section("Análisis de incidentes", "Vectores de ataque más frecuentes y últimos eventos.")
        col_g1, col_g2 = st.columns([1, 1.3])
        with col_g1:
            with st.container(border=True):
                vec = df["event_type"].map(lambda x: EVENT_LABELS.get(x, x)).value_counts()
                df_vec = pd.DataFrame({"Tipo de amenaza": vec.index, "Incidentes": vec.values})
                fig_type = px.bar(
                    df_vec, x="Incidentes", y="Tipo de amenaza", orientation="h",
                    color="Tipo de amenaza",
                    color_discrete_sequence=[COLORS["cyan"], COLORS["blue"], COLORS["purple"], COLORS["red"], COLORS["orange"]],
                )
                fig_type.update_traces(marker_line_width=0)
                style_fig(fig_type, height=330, title="Incidentes por vector de ataque", legend=False)
                fig_type.update_layout(xaxis_title=None, yaxis_title=None)
                fig_type.update_yaxes(autorange="reversed")
                show_chart(fig_type, "chart_vectors")
        with col_g2:
            with st.container(border=True):
                card_label("Últimos incidentes")
                show_table(
                    df.head(8),
                    columns=["timestamp", "source_ip", "event_type", "severity", "status"],
                    height=330,
                )

# ---------------------------------------------------------------------------
# Pestaña: Respuesta a incidentes (incidentes + cortafuegos + inteligencia de IP)
# ---------------------------------------------------------------------------
with tab_resp:
    # ---- 1. Bitácora ----
    section("Bitácora de incidentes", "Filtra la lista y selecciona un incidente para revisarlo y responder.", first=True)

    inc = None
    if not incidents:
        if view_is_cleared:
            st.info("La vista está limpia. Los nuevos incidentes aparecerán aquí.")
        else:
            st.info("Sin incidentes para mostrar.")
    else:
        df_all = pd.DataFrame(incidents)

        f1, f2, f3 = st.columns([1.2, 1.2, 1])
        sev_opts = [s for s in ["CRÍTICO", "ALTO", "MEDIO", "BAJO"] if s in set(df_all["severity"])]
        status_opts = sorted(set(df_all["status"].astype(str)))
        sev_filter = f1.multiselect("Severidad", sev_opts, default=sev_opts)
        status_filter = f2.multiselect("Estado", status_opts, default=status_opts)
        ip_search = f3.text_input("Buscar por IP", placeholder="Ej. 185.220")

        mask = df_all["severity"].isin(sev_filter) & df_all["status"].astype(str).isin(status_filter)
        if ip_search.strip():
            mask &= df_all["source_ip"].astype(str).str.contains(ip_search.strip(), regex=False)
        df_view = df_all[mask]

        st.caption(f"{len(df_view)} de {len(df_all)} incidentes")
        show_table(
            df_view,
            columns=["id", "timestamp", "source_ip", "abuse_score", "event_type", "severity", "status", "action_taken"],
            height=280,
        )

        # ---- 2. Detalle y respuesta ----
        section("Detalle y respuesta", "Evidencia, dictamen de IA y acciones disponibles para el incidente seleccionado.")
        if df_view.empty:
            st.info("Ningún incidente coincide con los filtros seleccionados.")
        else:
            records = df_view.to_dict("records")
            options = {
                f"#{r['id']}  |  {r['timestamp']}  |  {r['source_ip']}  |  {EVENT_LABELS.get(r['event_type'], r['event_type'])}": r
                for r in records
            }
            selected_label = st.selectbox("Incidente", list(options.keys()))
            inc = options[selected_label]

            sev_col = SEVERITY_COLORS.get(inc["severity"], COLORS["blue"])
            col_d1, col_d2 = st.columns([2.1, 1])

            with col_d1:
                with st.container(border=True):
                    head = (
                        f'<div class="detail-head"><span class="detail-title">Incidente #{inc["id"]}</span>'
                        f'{badge(inc["severity"], sev_col)}{badge(str(inc["status"]), status_color(inc["status"]))}</div>'
                    )
                    grid = (
                        '<div class="kv-grid">'
                        + kv("Folio forense", f"SARA-INC-{int(inc['id']):05d}")
                        + kv("IP de origen", inc["source_ip"])
                        + kv("Reputación AbuseIPDB", f"{inc.get('abuse_score', 0)}%")
                        + kv("Tipo de amenaza", EVENT_LABELS.get(inc["event_type"], inc["event_type"]))
                        + kv("Fecha y hora", inc["timestamp"])
                        + kv("Estado", inc["status"])
                        + "</div>"
                    )
                    action = f'<div class="kv-full">{kv("Acción aplicada", inc["action_taken"])}</div>'
                    hash_html = f'<div class="kv-full">{kv("Hash SHA-256 de integridad", inc.get("evidence_hash", "N/D"), mono=True)}</div>'
                    st.markdown(head + grid + action + hash_html, unsafe_allow_html=True)

                    card_label("Log crudo")
                    st.code(inc["raw_log"], language="bash")
                    card_label("Dictamen de inteligencia artificial")
                    st.info(inc["ai_analysis"])

            with col_d2:
                with st.container(border=True):
                    card_label("Acciones")
                    pdf_bytes = generate_incident_forensic_pdf(inc)
                    st.download_button(
                        label="Descargar dictamen (PDF)",
                        data=pdf_bytes,
                        file_name=f"Dictamen_Forense_SARA_INC_{inc['id']}.pdf",
                        mime="application/pdf",
                        type="primary",
                        use_container_width=True
                    )

                    st.caption("Bloquea la IP de origen en el cortafuegos.")
                    if st.button("Forzar bloqueo en UFW", use_container_width=True):
                        res = block_ip_ufw(inc["source_ip"], f"Bloqueo manual por incidente #{inc['id']}")
                        if res["success"]:
                            update_incident_status(inc["id"], "Mitigada", res["message"])
                            st.success(res["message"])
                            st.rerun()
                        else:
                            st.error(res["message"])

                    st.caption("Desbloquea la IP y la agrega a la lista blanca.")
                    if st.button("Marcar como falso positivo", use_container_width=True):
                        unblock_ip_ufw(inc["source_ip"], whitelist=True)
                        update_incident_status(inc["id"], "Falso Positivo", "Revertido: IP en Lista Blanca y liberada en UFW")
                        send_telegram_alert("Falso Positivo", f"Incidente #{inc['id']} ({inc['source_ip']}) marcado como Falso Positivo.")
                        st.success(f"IP {inc['source_ip']} desbloqueada y agregada a la lista blanca.")
                        st.rerun()

                with st.container(border=True):
                    card_label("Reputación de la IP")
                    if st.button("Consultar AbuseIPDB", use_container_width=True, key=f"rep_inc_{inc['id']}"):
                        st.session_state["last_intel"] = {
                            "ip": inc["source_ip"],
                            "data": check_ip_abuseipdb(inc["source_ip"]),
                        }
                    intel = st.session_state.get("last_intel")
                    if intel and intel["ip"] == inc["source_ip"]:
                        render_intel(intel, f"inc_{inc['id']}")
                    else:
                        st.caption(f"Consulta la reputación de {inc['source_ip']}.")

    # ---- 3. Cortafuegos e inteligencia de IP ----
    section("Cortafuegos e inteligencia de IP", "Estado de las direcciones en UFW y herramientas para consultar, bloquear o liberar una IP.")
    col_f1, col_f2 = st.columns([1.3, 1])

    with col_f1:
        with st.container(border=True):
            card_label("Direcciones registradas en el cortafuegos")
            if blocked_ips:
                df_fw = pd.DataFrame(blocked_ips)
                event = show_table(
                    df_fw,
                    columns=["ip", "is_active", "whitelisted", "reason", "blocked_at"],
                    height=290,
                    selectable=True,
                    key="fw_table",
                )
                rows = event.selection.rows if event is not None else []
                if rows:
                    sel_ip = str(df_fw.iloc[rows[0]]["ip"])
                    if sel_ip != st.session_state.get("fw_last_sel"):
                        st.session_state["fw_last_sel"] = sel_ip
                        st.session_state["tool_ip"] = sel_ip
                    st.caption("IP seleccionada: usa el ícono de la derecha para copiarla. También se cargó en las herramientas de IP.")
                    st.code(sel_ip, language=None)
                else:
                    st.session_state["fw_last_sel"] = None
                    st.caption("Selecciona una fila para copiar la IP o cargarla en las herramientas de IP.")
            else:
                st.info("No hay direcciones IP registradas en el cortafuegos.")

    with col_f2:
        with st.container(border=True):
            card_label("Herramientas de IP")
            tool_ip = st.text_input("Dirección IP", key="tool_ip", placeholder="Ej. 203.0.113.50")
            tool_reason = st.text_input("Motivo del bloqueo", "Actividad hostil detectada", key="tool_reason")
            tool_wl = st.checkbox("Al liberar, añadir a la lista blanca", value=True, key="tool_wl")

            b1, b2, b3 = st.columns(3)
            ip_clean = tool_ip.strip()
            if b1.button("Consultar", type="primary", use_container_width=True, key="tool_lookup"):
                if not ip_clean:
                    st.error("Ingresa una dirección IP.")
                else:
                    st.session_state["last_intel"] = {"ip": ip_clean, "data": check_ip_abuseipdb(ip_clean)}
            if b2.button("Bloquear", use_container_width=True, key="tool_block"):
                if not ip_clean:
                    st.error("Ingresa una dirección IP.")
                else:
                    res = block_ip_ufw(ip_clean, tool_reason)
                    if res["success"]:
                        st.success(res["message"])
                        st.rerun()
                    else:
                        st.error(res["message"])
            if b3.button("Liberar", use_container_width=True, key="tool_unblock"):
                if not ip_clean:
                    st.error("Ingresa una dirección IP.")
                else:
                    res = unblock_ip_ufw(ip_clean, whitelist=tool_wl)
                    if res["success"]:
                        st.success(res["message"])
                        st.rerun()
                    else:
                        st.error(res["message"])

            intel = st.session_state.get("last_intel")
            if intel and ip_clean and intel["ip"] == ip_clean:
                render_intel(intel, "tool")

# ---------------------------------------------------------------------------
# Pestaña: Auditorías
# ---------------------------------------------------------------------------
with tab_lynis:
    section("Auditorías de sistema (Lynis)", "Evaluación periódica del nivel de endurecimiento del sistema y recomendaciones correctivas.", first=True)
    if lynis_audits:
        latest = lynis_audits[0]
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Índice de hardening", f"{latest['hardening_index']}/100")
        k2.metric("Advertencias", latest["warnings_count"])
        k3.metric("Sugerencias", latest["suggestions_count"])
        k4.metric("Última ejecución", latest["timestamp"])
        st.caption(f"Modo de ejecución: {latest['execution_mode']}")

        col_l1, col_l2 = st.columns(2)
        with col_l1:
            with st.container(border=True):
                card_label("Hallazgos y advertencias")
                st.warning(latest["findings_summary"])
        with col_l2:
            with st.container(border=True):
                card_label("Recomendaciones correctivas")
                st.success(latest["corrective_recommendations"])

        section("Historial de auditorías")
        show_table(
            pd.DataFrame(lynis_audits),
            columns=["id", "audit_id", "timestamp", "hardening_index", "warnings_count", "suggestions_count", "execution_mode"],
        )
    else:
        if view_is_cleared:
            st.info("La vista está limpia. Ejecuta una auditoría o usa 'Restaurar vista completa' en la barra lateral.")
        else:
            st.info("Ejecuta tu primera auditoría con el botón 'Ejecutar auditoría Lynis' de la barra lateral.")

# ---------------------------------------------------------------------------
# Pestaña: Base de datos
# ---------------------------------------------------------------------------
with tab_db:
    section("Explorador de la base de datos (sara_soar.db)", "Muestra todos los registros reales, incluso los que ocultaste al limpiar las tablas.", first=True)
    table_names = {"incidents": "Incidentes", "blocked_ips": "IPs bloqueadas", "lynis_audits": "Auditorías Lynis"}
    table_choice = st.selectbox("Tabla", list(table_names.keys()), format_func=lambda x: table_names[x])
    conn = get_connection()
    df_sql = pd.read_sql_query(f"SELECT * FROM {table_choice} ORDER BY 1 DESC", conn)
    conn.close()
    st.caption(f"{len(df_sql)} registros")
    show_table(df_sql, translate_values=False)
    st.download_button(
        label=f"Exportar '{table_names[table_choice]}' a CSV",
        data=df_sql.to_csv(index=False).encode("utf-8"),
        file_name=f"sara_sql_{table_choice}.csv",
        mime="text/csv"
    )

# ---------------------------------------------------------------------------
# Pestaña: Configuración
# ---------------------------------------------------------------------------
with tab_cfg:
    section("Configuración e integraciones", "Notificaciones por Telegram, reputación de IPs, motor de IA local y servicios.", first=True)
    col_t1, col_t2 = st.columns([1.3, 1])

    with col_t1:
        with st.container(border=True):
            card_label("Notificaciones por Telegram")
            bot_token = st.text_input("Token del bot (de @BotFather)", value=get_setting("telegram_bot_token"), type="password")
            bot_user = st.text_input("Usuario del bot (sin @)", value=get_setting("telegram_bot_username", "CerberusSARA_bot"))
            chat_id = st.text_input("ID del chat", value=get_setting("telegram_chat_id"))

            c_b1, c_b2 = st.columns(2)
            with c_b1:
                if st.button("Detectar ID de chat", use_container_width=True):
                    res = fetch_latest_telegram_chat_id()
                    if res["success"]:
                        st.success(f"Vinculado con {res['user']} (ID de chat: {res['chat_id']})")
                        st.rerun()
                    else:
                        st.warning(res["message"])
            with c_b2:
                if st.button("Enviar alerta de prueba", use_container_width=True):
                    res = send_telegram_alert(
                        "Prueba de enlace S.A.R.A. v4.0",
                        "Conexión móvil verificada con éxito desde el panel."
                    )
                    if res["sent"]:
                        st.success(res["reason"])
                    else:
                        st.error(res["reason"])

        with st.container(border=True):
            card_label("Reputación de IPs")
            abuse_key = st.text_input(
                "Clave de API de AbuseIPDB",
                value=get_setting("abuseipdb_api_key"), type="password",
                help="Opcional. Si se deja vacía, se usa el simulador."
            )

        with st.container(border=True):
            card_label("Inteligencia artificial local (Ollama)")
            ollama_url = st.text_input("URL del servidor", value=get_setting("ollama_url", "http://localhost:11434"))
            ollama_model = st.text_input("Modelo", value=get_setting("ollama_model", "llama3"))

        if st.button("Guardar configuración", type="primary", use_container_width=True):
            set_setting("telegram_bot_token", bot_token)
            set_setting("telegram_bot_username", bot_user.replace("@", ""))
            set_setting("telegram_chat_id", chat_id)
            set_setting("abuseipdb_api_key", abuse_key)
            set_setting("ollama_url", ollama_url)
            set_setting("ollama_model", ollama_model)
            st.success("Configuración guardada correctamente.")

    with col_t2:
        with st.container(border=True):
            card_label("Vinculación rápida por QR")
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
                "2. Presiona **Iniciar (/start)** en Telegram.\n"
                "3. Regresa aquí y usa **Detectar ID de chat**."
            )

        with st.container(border=True):
            card_label("Servicios")
            st.markdown("- **Orquestador n8n:** `http://localhost:5678`")
            st.markdown("- **Documentación de la API (Swagger):** `http://localhost:8000/docs`")
            st.markdown("- **Motor de IA (Ollama):** `http://localhost:11434`")
