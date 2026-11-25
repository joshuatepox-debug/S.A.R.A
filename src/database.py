import sqlite3
import os
import hashlib
from datetime import datetime
from typing import List, Dict, Optional

DB_PATH = os.getenv("SARA_DB_PATH", "sara_soar.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Tabla histórica de incidentes y evidencias SHA-256
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            event_type TEXT NOT NULL,
            raw_log TEXT NOT NULL,
            evidence_hash TEXT NOT NULL,
            severity TEXT NOT NULL,
            abuse_score INTEGER DEFAULT 0,
            ai_analysis TEXT,
            status TEXT DEFAULT 'Activa',
            action_taken TEXT DEFAULT 'Ninguna'
        )
    ''')
    
    for col_sql in [
        "ALTER TABLE incidents ADD COLUMN evidence_hash TEXT DEFAULT 'N/A'",
        "ALTER TABLE incidents ADD COLUMN abuse_score INTEGER DEFAULT 0"
    ]:
        try:
            cursor.execute(col_sql)
        except Exception:
            pass

    # 2. Tabla histórica de IPs bloqueadas y Lista Blanca en UFW
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            blocked_at TEXT,
            is_active INTEGER DEFAULT 1,
            whitelisted INTEGER DEFAULT 0
        )
    ''')

    # 3. Tabla histórica SQL de Auditorías de Sistema (Lynis)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS lynis_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            hardening_index INTEGER NOT NULL,
            warnings_count INTEGER NOT NULL,
            suggestions_count INTEGER NOT NULL,
            findings_summary TEXT NOT NULL,
            corrective_recommendations TEXT NOT NULL,
            execution_mode TEXT NOT NULL
        )
    ''')
    
    # 4. Tabla de configuración persistente
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    
    default_settings = {
        "telegram_bot_token": "",
        "telegram_bot_username": "CerberusSARA_bot",
        "telegram_chat_id": "",
        "ollama_url": os.getenv("OLLAMA_URL", "http://localhost:11434"),
        "ollama_model": "llama3",
        "abuseipdb_api_key": "",
        "n8n_webhook_url": "http://localhost:5678/webhook/sara-alert",
        "auto_block_enabled": "1",
        "simulation_mode": "1",
        "traffic_spike": "0"
    }
    
    for k, v in default_settings.items():
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
        
    conn.commit()
    conn.close()

def get_setting(key: str, default: str = "") -> str:
    conn = get_connection()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default

def set_setting(key: str, value: str):
    conn = get_connection()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()

def create_incident(source_ip: str, event_type: str, raw_log: str, severity: str, abuse_score: int, ai_analysis: str, status: str, action_taken: str) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    evidence_payload = f"{now}|{source_ip}|{event_type}|{raw_log}".encode("utf-8")
    ev_hash = hashlib.sha256(evidence_payload).hexdigest()

    cursor.execute('''
        INSERT INTO incidents (timestamp, source_ip, event_type, raw_log, evidence_hash, severity, abuse_score, ai_analysis, status, action_taken)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (now, source_ip, event_type, raw_log, ev_hash, severity, abuse_score, ai_analysis, status, action_taken))
    incident_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return incident_id

def get_incidents(limit: int = 100) -> List[Dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_incident_by_id(incident_id: int) -> Optional[Dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def update_incident_status(incident_id: int, status: str, action_taken: str):
    conn = get_connection()
    conn.execute(
        "UPDATE incidents SET status = ?, action_taken = ? WHERE id = ?",
        (status, action_taken, incident_id)
    )
    conn.commit()
    conn.close()

def set_ip_block_state(ip: str, reason: str, is_active: int = 1, whitelisted: int = 0):
    conn = get_connection()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute('''
        INSERT INTO blocked_ips (ip, reason, blocked_at, is_active, whitelisted)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            reason = excluded.reason,
            blocked_at = excluded.blocked_at,
            is_active = excluded.is_active,
            whitelisted = excluded.whitelisted
    ''', (ip, reason, now, is_active, whitelisted))
    conn.commit()
    conn.close()

def is_ip_whitelisted(ip: str) -> bool:
    conn = get_connection()
    row = conn.execute("SELECT whitelisted FROM blocked_ips WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    return bool(row and row["whitelisted"] == 1)

def get_blocked_ips() -> List[Dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def record_lynis_audit(hardening_index: int, warnings_count: int, suggestions_count: int, findings_summary: str, corrective_recommendations: str, execution_mode: str) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO lynis_audits (timestamp, hardening_index, warnings_count, suggestions_count, findings_summary, corrective_recommendations, execution_mode)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (now, hardening_index, warnings_count, suggestions_count, findings_summary, corrective_recommendations, execution_mode))
    audit_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return audit_id

def get_lynis_audits(limit: int = 50) -> List[Dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM lynis_audits ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
