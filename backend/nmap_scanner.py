import nmap
from datetime import datetime
from whitelist_manager import is_authorized
from router_auditor import detect_network_context

SCAN_PROFILES = {
    "arp": "-sn -PR -T4",                                      # Descubrimiento ARP (LAN)
    "icmp": "-sn -PE -T4",                                     # Descubrimiento ICMP Ping
    "tcp_discovery": "-sn -PS22,80,443 -PA80,443 -T4",         # Descubrimiento TCP SYN/ACK
    "rapido": "-sS --top-ports 50 -T4",                        # Puertos TCP Stealth rápido
    "normal": "-sS -sV -O --top-ports 100 -T4",                # Stealth + Versiones + SO
    "udp": "-sU --top-ports 20 -T4",                           # Puertos UDP comunes
    "completo": "-sS -sV --version-intensity 2 -O --osscan-limit --top-ports 100 --script default --script-timeout 10s --host-timeout 60s --traceroute -T4",
}


def _guess_device_icon(ip: str, gateway_ip: str, os_name: str, vendor: str) -> str:
    if ip == gateway_ip:
        return "router"
    text = f"{os_name} {vendor}".lower()
    if any(k in text for k in ["android", "iphone", "ios", "apple", "xiaomi", "samsung", "huawei", "motorola"]):
        return "mobile"
    if "windows" in text:
        return "windows"
    if any(k in text for k in ["linux", "ubuntu", "debian", "kali"]):
        return "linux"
    return "device"


def run_network_scan(target: str | None = None, profile: str = "normal", custom_args: str | None = None) -> dict:
    ctx = detect_network_context()
    target_network = target or ctx["subnet"]
    gateway_ip = ctx["gateway_ip"]
    arguments = custom_args.strip() if custom_args else SCAN_PROFILES.get(profile, SCAN_PROFILES["normal"])

    scanner = nmap.PortScanner()
    scanner.scan(hosts=target_network, arguments=arguments)

    hosts_list = []
    total_open_ports = 0
    unauthorized_count = 0
    links = []

    for ip in scanner.all_hosts():
        host = scanner[ip]
        if host.state() != "up":
            continue

        addresses = host.get("addresses", {})
        mac = addresses.get("mac")
        vendor = host.get("vendor", {}).get(mac, "Desconocido") if mac else "Host local / No disponible"
        hostname = host.hostname() or ("Router Wi-Fi" if ip == gateway_ip else f"host-{ip.split('.')[-1]}")

        os_matches = host.get("osmatch", [])
        os_name = os_matches[0]["name"] if os_matches else "No determinado"

        ports_info = []
        nse_results = []

        for proto in host.all_protocols():
            for port in sorted(host[proto].keys()):
                pdata = host[proto][port]
                if pdata.get("state") == "open":
                    total_open_ports += 1
                    ports_info.append({
                        "port": port,
                        "protocol": proto,
                        "service": pdata.get("name", ""),
                        "version": f"{pdata.get('product', '')} {pdata.get('version', '')}".strip(),
                    })
                    for sid, sout in pdata.get("script", {}).items():
                        nse_results.append({"port": port, "id": sid, "output": sout.strip()})

        # El router y la laptop auditora se marcan autorizados si están en whitelist o son infraestructura local
        is_router = ip == gateway_ip
        is_local = ip == ctx["local_ip"]
        authorized = True if (is_local or is_authorized(mac)) else False
        if not authorized:
            unauthorized_count += 1

        hosts_list.append({
            "ip": ip,
            "mac": mac or "LOCAL",
            "vendor": vendor,
            "hostname": hostname,
            "os": os_name,
            "device_type": _guess_device_icon(ip, gateway_ip, os_name, vendor),
            "is_router": is_router,
            "authorized": authorized,
            "alert_reason": None if authorized else "MAC no registrada en whitelist.json",
            "ports": ports_info,
            "nse_scripts": nse_results,
        })

        if not is_router:
            links.append({"source": gateway_ip, "target": ip, "hops": 1})

    return {
        "report_metadata": {
            "project": "Proyecto 4 - Escaneo de Red y Auditoría Wi-Fi con Nmap",
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "target_network": target_network,
            "gateway_ip": gateway_ip,
            "profile": profile,
            "nmap_arguments": arguments,
        },
        "summary": {
            "hosts_found": len(hosts_list),
            "open_ports": total_open_ports,
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
                    "open_ports_count": len(h["ports"]),
                }
                for h in hosts_list
            ],
            "links": links,
        },
        "hosts": hosts_list,
    }