import requests
from src.database import get_setting, set_setting

def send_telegram_alert(title: str, details: str) -> dict:
    token = get_setting("telegram_bot_token", "").strip()
    chat_id = get_setting("telegram_chat_id", "").strip()
    
    if not token or not chat_id:
        return {"sent": False, "reason": "Token o Chat ID de Telegram no configurados."}

    message = (
        "🛡️ *S.A.R.A. | CerberusOps SOAR*\n"
        f"*{title}*\n\n"
        f"{details}"
    )
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    
    try:
        resp = requests.post(
            url,
            json={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"},
            timeout=5
        )
        if resp.status_code == 200:
            return {"sent": True, "reason": "Notificación enviada a Telegram."}
        return {"sent": False, "reason": f"Error API Telegram: {resp.text}"}
    except Exception as e:
        return {"sent": False, "reason": str(e)}

def fetch_latest_telegram_chat_id() -> dict:
    token = get_setting("telegram_bot_token", "").strip()
    if not token:
        return {"success": False, "message": "Primero guarda el Bot Token."}
        
    url = f"https://api.telegram.org/bot{token}/getUpdates"
    try:
        resp = requests.get(url, timeout=5).json()
        if not resp.get("ok"):
            return {"success": False, "message": "Token inválido o rechazado por Telegram."}
        results = resp.get("result", [])
        if not results:
            return {"success": False, "message": "No hay mensajes recientes. Escanea el QR y envía /start al bot."}
        last_msg = results[-1].get("message", {})
        chat = last_msg.get("chat", {})
        chat_id = str(chat.get("id", ""))
        user_name = chat.get("first_name", "Operador")
        if chat_id:
            set_setting("telegram_chat_id", chat_id)
            return {"success": True, "chat_id": chat_id, "user": user_name}
        return {"success": False, "message": "No se pudo extraer el Chat ID."}
    except Exception as e:
        return {"success": False, "message": str(e)}
