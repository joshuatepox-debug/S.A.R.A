import subprocess
import ipaddress
from src.database import get_setting, set_ip_block_state, is_ip_whitelisted

def validate_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return False
        return True
    except ValueError:
        return False

def block_ip_ufw(ip: str, reason: str = "Bloqueo automático S.A.R.A.") -> dict:
    if not validate_ip(ip):
        return {"success": False, "message": f"IP inválida o loopback protegida: {ip}"}
        
    if is_ip_whitelisted(ip):
        return {"success": False, "message": f"La IP {ip} está en la Lista Blanca (Falso Positivo previo)."}

    sim_mode = get_setting("simulation_mode", "1") == "1"
    
    if sim_mode:
        set_ip_block_state(ip, reason, is_active=1, whitelisted=0)
        return {
            "success": True,
            "message": f"[SIMULACIÓN UFW] sudo ufw insert 1 deny from {ip} to any"
        }

    try:
        cmd = ["sudo", "ufw", "insert", "1", "deny", "from", ip, "to", "any"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            set_ip_block_state(ip, reason, is_active=1, whitelisted=0)
            return {"success": True, "message": f"UFW bloqueó exitosamente a {ip}: {result.stdout.strip()}"}
        return {"success": False, "message": f"Error en UFW: {result.stderr.strip()}"}
    except Exception as e:
        return {"success": False, "message": f"Excepción ejecutando UFW: {str(e)}"}

def unblock_ip_ufw(ip: str, whitelist: bool = False) -> dict:
    if not validate_ip(ip):
        return {"success": False, "message": f"IP inválida: {ip}"}

    sim_mode = get_setting("simulation_mode", "1") == "1"
    reason = "Marcado como Falso Positivo / Lista Blanca" if whitelist else "Desbloqueo manual"

    if sim_mode:
        set_ip_block_state(ip, reason, is_active=0, whitelisted=1 if whitelist else 0)
        return {
            "success": True,
            "message": f"[SIMULACIÓN UFW] sudo ufw delete deny from {ip} to any"
        }

    try:
        cmd = ["sudo", "ufw", "delete", "deny", "from", ip, "to", "any"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        set_ip_block_state(ip, reason, is_active=0, whitelisted=1 if whitelist else 0)
        return {"success": True, "message": f"IP {ip} desbloqueada en UFW: {result.stdout.strip()}"}
    except Exception as e:
        return {"success": False, "message": f"Excepción al desbloquear en UFW: {str(e)}"}
