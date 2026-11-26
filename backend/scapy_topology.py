from datetime import datetime
from scapy.all import ARP, Ether, IP, ICMP, srp, sr1, conf
from router_auditor import detect_network_context
from whitelist_manager import is_authorized

# Prefijos MAC frecuentes de respaldo (100% offline para la defensa sin internet)
LOCAL_OUI_FALLBACK = {
    "C0:25:E9": "TP-Link", "50:C7:BF": "TP-Link", "F4:F2:6D": "TP-Link", "B0:BE:76": "TP-Link",
    "C8:3A:35": "Tenda", "CC:2D:21": "Tenda", "D8:32:14": "Tenda",
    "E8:65:D4": "Mercusys / TP-Link", "98:DA:C4": "TP-Link",
    "00:1A:11": "Google", "3C:5A:B4": "Google",
    "AC:BC:32": "Apple", "F0:18:98": "Apple", "A4:83:E7": "Apple",
    "24:4B:81": "Samsung", "8C:F5:A3": "Samsung", "BC:14:85": "Samsung",
    "64:CC:2E": "Xiaomi", "7C:1D:D9": "Xiaomi", "50:EC:50": "Xiaomi",
    "B4:2E:99": "Intel", "D4:3B:04": "Intel", "A4:4C:C8": "Dell",
}


def resolve_mac_vendor(mac: str) -> str:
    """Resuelve el fabricante por prefijo MAC (OUI) sin depender de internet."""
    if not mac:
        return "Desconocido"
    norm = mac.upper().replace("-", ":")
    prefix = norm[:8]

    if prefix in LOCAL_OUI_FALLBACK:
        return LOCAL_OUI_FALLBACK[prefix]

    try:
        if getattr(conf, "manufdb", None):
            resolved = conf.manufdb._get_manuf(norm)
            if resolved and resolved != norm:
                return resolved
    except Exception:
        pass

    return "Fabricante desconocido"


def _classify_device(ip: str, gateway_ip: str, vendor: str) -> str:
    if ip == gateway_ip:
        return "router"
    v = vendor.lower()
    if any(k in v for k in ["samsung", "apple", "xiaomi", "huawei", "motorola", "oppo", "realme"]):
        return "mobile"
    if any(k in v for k in ["tp-link", "tenda", "mercusys", "cisco", "mikrotik", "d-link", "asus", "netgear"]):
        return "router"
    if any(k in v for k in ["intel", "dell", "hp", "lenovo", "acer", "realtek", "microsoft"]):
        return "laptop"
    return "device"


def scapy_arp_topology(target_subnet: str | None = None, timeout: int = 3) -> dict:
    """Ejecuta un barrido ARP con Scapy y arma el grafo de topología centrado en el router."""
    ctx = detect_network_context()
    subnet = target_subnet or ctx["subnet"]
    gateway_ip = ctx["gateway_ip"]

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(packet, timeout=timeout, verbose=0)

    hosts = []
    links = []
    unauthorized_count = 0
    seen_ips = set()

    for _, received in answered:
        ip = received.psrc
        mac = received.hwsrc.upper()
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        vendor = resolve_mac_vendor(mac)
        is_router = ip == gateway_ip
        is_local = ip == ctx["local_ip"]
        authorized = True if (is_local or is_authorized(mac)) else False
        if not authorized:
            unauthorized_count += 1

        device_type = _classify_device(ip, gateway_ip, vendor)
        hosts.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": "Router Wi-Fi" if is_router else f"dispositivo-{ip.split('.')[-1]}",
            "os": "Detectado vía ARP (ejecutar Nmap -O para huella de SO)",
            "device_type": device_type,
            "is_router": is_router,
            "authorized": authorized,
            "alert_reason": None if authorized else "MAC no registrada en whitelist.json",
            "ports": [],
            "nse_scripts": [],
        })

        if not is_router:
            links.append({"source": gateway_ip, "target": ip, "hops": 1, "protocol": "ARP"})

    # Garantizar que el nodo central del router exista aunque no haya respondido al broadcast
    if gateway_ip not in seen_ips:
        hosts.insert(0, {
            "ip": gateway_ip,
            "mac": "NO_DETECTADA",
            "vendor": "Gateway Wi-Fi",
            "hostname": "Router Wi-Fi",
            "os": "Router / Gateway",
            "device_type": "router",
            "is_router": True,
            "authorized": True,
            "alert_reason": None,
            "ports": [],
            "nse_scripts": [],
        })

    return {
        "report_metadata": {
            "project": "Proyecto 4 - Mapeo de Topología con Scapy (ARP)",
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "target_network": subnet,
            "gateway_ip": gateway_ip,
            "method": "Scapy ARP Scan",
        },
        "summary": {
            "hosts_found": len(hosts),
            "open_ports": 0,
            "unauthorized_devices": unauthorized_count,
        },
        "topology": {
            "center_node": {"id": gateway_ip, "label": f"Router Wi-Fi ({gateway_ip})", "type": "router"},
            "nodes": [
                {
                    "id": h["ip"],
                    "label": f"{h['hostname']}\n{h['ip']}",
                    "mac": h["mac"],
                    "vendor": h["vendor"],
                    "device_type": h["device_type"],
                    "authorized": h["authorized"],
                    "open_ports_count": 0,
                }
                for h in hosts
            ],
            "links": links,
        },
        "hosts": hosts,
    }


def run_scapy_traceroute(target_ip: str, max_hops: int = 8, timeout: float = 1.5) -> dict:
    """Traza los saltos de red (TTL incremental ICMP) hacia una IP usando Scapy."""
    hops = []
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target_ip, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=timeout)

        if reply is None:
            hops.append({"hop": ttl, "ip": "*", "status": "timeout"})
            continue

        hop_ip = reply.src
        hops.append({"hop": ttl, "ip": hop_ip, "status": "reached" if hop_ip == target_ip else "intermediate"})
        if hop_ip == target_ip:
            break

    return {
        "target_ip": target_ip,
        "total_hops": len([h for h in hops if h["ip"] != "*"]),
        "hops": hops,
    }