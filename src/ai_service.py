import re
import requests
from src.database import get_setting

DEFAULT_MODEL = "qwen2.5:3b"
CONNECT_TIMEOUT = 5     # segundos para conectar (una URL incorrecta falla rápido)
READ_TIMEOUT = 60       # segundos para esperar la respuesta del modelo

# Referencia fija de técnicas MITRE ATT&CK. El modelo no decide el código: se le entrega
# y, además, se corrige en la respuesta si llegara a escribir otro.
MITRE_REFERENCE = {
    "SSH Brute Force": ("T1110", "Brute Force"),
    "SQL Injection": ("T1190", "Exploit Public-Facing Application"),
    "Port Scan": ("T1046", "Network Service Discovery"),
    "Malware Beacon": ("T1071", "Application Layer Protocol"),
    "DDoS SYN Flood": ("T1498", "Network Denial of Service"),
}

MITRE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _clean_ai_text(text: str, event_type: str) -> str:
    """Limpia la respuesta del modelo: quita razonamiento, datos repetidos y corrige el ID MITRE."""
    text = text.replace("\\n", "\n")
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    text = re.sub(r"<think>.*", "", text, flags=re.DOTALL).strip()

    # Elimina líneas donde el modelo repite los datos del incidente
    kept = []
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^(Amenaza|Datos del incidente)\s*:", stripped, flags=re.IGNORECASE):
            continue
        if "Severidad:" in stripped and "IP:" in stripped:
            continue
        kept.append(line)
    text = "\n".join(kept).strip()

    # Fuerza el ID MITRE correcto
    reference = MITRE_REFERENCE.get(event_type)
    if reference and text:
        mitre_id, mitre_name = reference
        text = MITRE_ID_PATTERN.sub(mitre_id, text)
        if mitre_id not in text:
            text = f"Vector MITRE ATT&CK: {mitre_id} ({mitre_name}).\n{text}"
    return text


def analyze_incident_with_ai(event_type: str, source_ip: str, raw_log: str, initial_severity: str, abuse_score: int = 0) -> dict:
    ollama_url = get_setting("ollama_url", "http://ollama:11434").strip()
    model = get_setting("ollama_model", DEFAULT_MODEL).strip()
    if not model or model == "llama3":
        model = DEFAULT_MODEL

    reference = MITRE_REFERENCE.get(event_type)
    if reference:
        mitre_line = (
            f"Vector MITRE ATT&CK ya determinado: {reference[0]} ({reference[1]}). "
            "Úsalo tal cual en el punto 1, no inventes otro código.\n"
        )
    else:
        mitre_line = (
            "Si no estás seguro del código MITRE ATT&CK, indica solo el nombre de la técnica, "
            "no inventes códigos.\n"
        )

    log_text = raw_log.strip() if raw_log and raw_log.strip() else "(sin log disponible)"

    prompt = (
        "Eres S.A.R.A., analista SOC de InnovaHosting Solutions. "
        "Responde únicamente en español, en exactamente 3 puntos numerados y en máximo 3 líneas técnicas. "
        "No repitas los datos del incidente ni agregues introducción.\n\n"
        "Datos del incidente:\n"
        f"- Tipo de amenaza: {event_type}\n"
        f"- IP de origen: {source_ip} (reputación AbuseIPDB: {abuse_score}%)\n"
        f"- Severidad: {initial_severity}\n"
        f"- Log: {log_text}\n\n"
        f"{mitre_line}"
        "Formato de respuesta:\n"
        "1. Vector MITRE ATT&CK.\n"
        "2. Impacto.\n"
        "3. Contención recomendada."
    )

    urls = []
    for u in [ollama_url, "http://ollama:11434", "http://localhost:11434", "http://172.17.0.1:11434"]:
        if u and u not in urls:
            urls.append(u)

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "keep_alive": "2h",  # mantiene el modelo cargado en memoria entre ataques
        "options": {"temperature": 0.2, "num_predict": 250},
    }
    # El parámetro "think" solo lo entienden los modelos con razonamiento (qwen3, deepseek-r1, etc.)
    if "qwen3" in model or "deepseek-r1" in model:
        payload["think"] = False

    for url_candidate in urls:
        try:
            response = requests.post(
                f"{url_candidate.rstrip('/')}/api/generate",
                json=payload,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            if response.status_code == 200:
                data = response.json()
                ai_text = _clean_ai_text(data.get("response", "").strip(), event_type)
                if ai_text:
                    return {"analysis": ai_text, "engine": f"Ollama ({model})"}
                print(f"[S.A.R.A. IA] {url_candidate} devolvió una respuesta vacía con el modelo {model}", flush=True)
            else:
                print(
                    f"[S.A.R.A. IA] {url_candidate} respondió {response.status_code}: {response.text[:200]}",
                    flush=True,
                )
        except requests.exceptions.ReadTimeout:
            # El servidor existe pero el modelo tardó demasiado; otras URLs apuntarían al mismo Ollama.
            print(f"[S.A.R.A. IA] Tiempo de espera agotado ({READ_TIMEOUT}s) con el modelo {model} en {url_candidate}", flush=True)
            break
        except Exception as e:
            print(f"[S.A.R.A. IA] Error con {url_candidate}: {e}", flush=True)
            continue

    heuristics = {
        "SSH Brute Force": "Vector MITRE T1110 (Brute Force). Múltiples intentos fallidos en puerto 22. Riesgo de intrusión por diccionario. Bloqueo inmediato en UFW y deshabilitar login root.",
        "SQL Injection": "Vector MITRE T1190 (Exploit Public-Facing Application). Carga útil SQL detectada en URI. Riesgo de exfiltración de base de datos SQL. Aislar IP en UFW y parametrizar consultas.",
        "Port Scan": "Vector MITRE T1046 (Network Service Discovery). Escaneo SYN furtivo sobre puertos críticos. Fase de reconocimiento activo. Bloquear IP preventivamente en UFW.",
        "Malware Beacon": "Vector MITRE T1071 (Application Layer Protocol). Tráfico saliente hacia servidor C2. Aislar host de inmediato y preservar evidencia forense.",
        "DDoS SYN Flood": "Vector MITRE T1498 (Network Denial of Service). Inundación de paquetes SYN. Mitigación aplicando rate-limiting y drop en UFW.",
    }
    base_msg = heuristics.get(
        event_type,
        f"Detección heurística para '{event_type}' desde {source_ip}. Severidad {initial_severity}.",
    )
    return {
        "analysis": f"{base_msg} [Reputación AbuseIPDB: {abuse_score}%]",
        "engine": "Motor Heurístico Local S.A.R.A.",
    }
