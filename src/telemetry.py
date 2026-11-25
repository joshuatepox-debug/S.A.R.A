import psutil
import time
import random
from datetime import datetime
from src.database import get_setting, set_setting

_last_net = psutil.net_io_counters()
_last_time = time.time()

def sample_network_telemetry() -> dict:
    global _last_net, _last_time
    now = time.time()
    current_net = psutil.net_io_counters()
    dt = max(now - _last_time, 0.5)

    rx_kbps = (current_net.bytes_recv - _last_net.bytes_recv) / 1024.0 / dt
    tx_kbps = (current_net.bytes_sent - _last_net.bytes_sent) / 1024.0 / dt
    pps_in = (current_net.packets_recv - _last_net.packets_recv) / dt
    pps_out = (current_net.packets_sent - _last_net.packets_sent) / dt

    _last_net = current_net
    _last_time = now

    spike = int(get_setting("traffic_spike", "0") or "0")
    if spike > 0:
        threat_kbps = random.uniform(380.0, 920.0) * spike
        malicious_pps = random.randint(450, 1400) * spike
        rx_kbps += threat_kbps
        pps_in += malicious_pps
        set_setting("traffic_spike", str(max(0, spike - 1)))
    else:
        threat_kbps = random.uniform(1.5, 18.0)
        malicious_pps = random.randint(2, 25)
        rx_kbps = max(rx_kbps, random.uniform(25.0, 95.0))
        tx_kbps = max(tx_kbps, random.uniform(15.0, 60.0))
        pps_in = max(pps_in, random.uniform(40, 130))

    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "rx_kbps": round(rx_kbps, 2),
        "tx_kbps": round(tx_kbps, 2),
        "threat_kbps": round(threat_kbps, 2),
        "pps_total": int(pps_in + pps_out),
        "malicious_pps": int(malicious_pps),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "ram_percent": psutil.virtual_memory().percent
    }
