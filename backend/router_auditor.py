import platform
import re
import socket
import subprocess
import nmap

# Puertos típicos de routers Wi-Fi y su nivel de riesgo base
ROUTER_PORT_RULES = {
    23: ("Crítico", "Telnet expuesto (puerto 23): transmite credenciales en texto plano. Desactivar inmediatamente."),
    21: ("Alto", "FTP expuesto (puerto 21): servicio inseguro en el router. Deshabilitar si no se usa."),
    1900: ("Alto", "UPnP activo (puerto 1900): permite abrir puertos automáticamente sin consentimiento. Se recomienda desactivar UPnP."),
    80: ("Medio", "Panel web por HTTP sin cifrado (puerto 80): usar HTTPS para administrar el router y cambiar contraseña por defecto."),
    8080: ("Medio", "Administración web alternativa expuesta (puerto 8080): verificar que no sea accesible desde WAN."),
    22: ("Bajo", "SSH habilitado (puerto 22): restringir acceso solo a IPs administrativas y desactivar root por contraseña."),
    53: ("Informativo", "DNS local activo (puerto 53): normal en routers LAN; verificar que no permita recursión externa."),
    443: ("Informativo", "Panel web HTTPS activo (puerto 443): verificar validez del certificado y clave fuerte."),
}


def detect_network_context() -> dict:
    """Detecta automáticamente IP local, Gateway (router Wi-Fi) y subred /24."""
    local_ip = "127.0.0.1"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except Exception:
        pass

    gateway_ip = None
    system = platform.system().lower()

    try:
        if system == "linux":
            out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            if match:
                gateway_ip = match.group(1)
        elif system == "windows":
            out = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
            match = re.search(r"(?:Puerta de enlace predeterminada|Default Gateway)[\s.:]+(\d+\.\d+\.\d+\.\d+)", out)
            if match:
                gateway_ip = match.group(1)
    except Exception:
        pass

    # Respaldo si el router no tiene salida a internet y falla el socket
    if not gateway_ip and local_ip != "127.0.0.1":
        parts = local_ip.split(".")
        gateway_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"

    base_ip = gateway_ip or local_ip
    parts = base_ip.split(".")
    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else "192.168.1.0/24"

    return {
        "local_ip": local_ip,
        "gateway_ip": gateway_ip or "192.168.1.1",
        "subnet": subnet,
        "os_host": platform.system(),
    }


def audit_wifi_router(router_ip: str | None = None) -> dict:
    """Audita el router Wi-Fi detectado: puertos críticos, versiones, SO y scripts NSE."""
    ctx = detect_network_context()
    target_ip = router_ip or ctx["gateway_ip"]

    scanner = nmap.PortScanner()
    # Escaneo dirigido al router: TCP stealth, versiones, SO y scripts NSE seguros/auditoría
    args = "-sS -sV --version-intensity 2 -O --osscan-limit --max-os-tries 1 -Pn -p 21,22,23,53,80,443,1900,8080,8443 --script http-title,http-headers,upnp-info,dns-recursion --script-timeout 10s --host-timeout 45s -T4"
    scanner.scan(hosts=target_ip, arguments=args)

    if target_ip not in scanner.all_hosts():
        return {
            "router_ip": target_ip,
            "reachable": False,
            "risk_level": "Desconocido",
            "findings": [{"severity": "Alto", "detail": "No se pudo contactar al router en la IP indicada."}],
        }

    host_data = scanner[target_ip]
    addresses = host_data.get("addresses", {})
    mac = addresses.get("mac", "No detectada")
    vendor = host_data.get("vendor", {}).get(mac, "Fabricante desconocido")
    os_matches = host_data.get("osmatch", [])
    os_guess = os_matches[0]["name"] if os_matches else "Firmware embebido / No determinado"

    ports_found = []
    findings = []
    severity_rank = {"Informativo": 0, "Bajo": 1, "Medio": 2, "Alto": 3, "Crítico": 4}
    max_risk = "Bajo"

    for proto in host_data.all_protocols():
        for port in sorted(host_data[proto].keys()):
            pdata = host_data[proto][port]
            if pdata.get("state") != "open":
                continue

            scripts = pdata.get("script", {})
            ports_found.append({
                "port": port,
                "protocol": proto,
                "service": pdata.get("name", ""),
                "product": pdata.get("product", ""),
                "version": pdata.get("version", ""),
                "nse_scripts": [{"id": k, "output": v.strip()} for k, v in scripts.items()],
            })

            if port in ROUTER_PORT_RULES:
                sev, detail = ROUTER_PORT_RULES[port]
                findings.append({"port": port, "severity": sev, "detail": detail})
                if severity_rank[sev] > severity_rank[max_risk]:
                    max_risk = sev

            # Detectar si algún script NSE reportó VULNERABLE
            for script_id, output in scripts.items():
                if "VULNERABLE" in output.upper():
                    findings.append({
                        "port": port,
                        "severity": "Crítico",
                        "detail": f"Script NSE '{script_id}' detectó posible vulnerabilidad en puerto {port}.",
                    })
                    max_risk = "Crítico"

    if not findings:
        findings.append({
            "port": None,
            "severity": "Informativo",
            "detail": "No se detectaron puertos de administración inseguros expuestos en el router.",
        })

    return {
        "router_ip": target_ip,
        "reachable": True,
        "mac": mac,
        "vendor": vendor,
        "os_firmware": os_guess,
        "risk_level": max_risk,
        "open_ports": ports_found,
        "findings": findings,
        "nmap_arguments": args,
    }