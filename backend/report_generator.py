import csv
import io
import json
from fpdf import FPDF


def _safe_pdf_text(text: object) -> str:
    """Evita errores de codificación en fuentes estándar de PDF."""
    raw = str(text if text is not None else "")
    return raw.encode("latin-1", "replace").decode("latin-1")


def export_to_json(payload: dict) -> bytes:
    return json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")


def export_to_csv(payload: dict) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)

    # Caso 1: Auditoría específica del router Wi-Fi
    if "audit" in payload:
        audit = payload["audit"]
        writer.writerow(["Router IP", "MAC", "Fabricante", "Firmware/SO", "Riesgo Global", "Puerto", "Servicio", "Severidad", "Hallazgo"])
        findings = audit.get("findings", [])
        if not findings:
            writer.writerow([audit.get("router_ip"), audit.get("mac"), audit.get("vendor"), audit.get("os_firmware"), audit.get("risk_level"), "", "", "Informativo", "Sin hallazgos"])
        for f in findings:
            writer.writerow([
                audit.get("router_ip", ""),
                audit.get("mac", ""),
                audit.get("vendor", ""),
                audit.get("os_firmware", ""),
                audit.get("risk_level", ""),
                f.get("port", ""),
                "",
                f.get("severity", ""),
                f.get("detail", ""),
            ])
        return output.getvalue().encode("utf-8-sig")

    # Caso 2: Escaneo de red (Nmap o Scapy)
    writer.writerow(["IP", "MAC", "Fabricante", "Hostname", "Sistema Operativo", "Tipo", "Autorizado", "Puertos Abiertos", "Alerta"])
    for h in payload.get("hosts", []):
        ports_str = "; ".join(f"{p['port']}/{p.get('protocol', 'tcp')} ({p.get('service', '')})" for p in h.get("ports", []))
        writer.writerow([
            h.get("ip", ""),
            h.get("mac", ""),
            h.get("vendor", ""),
            h.get("hostname", ""),
            h.get("os", ""),
            h.get("device_type", ""),
            "SI" if h.get("authorized") else "NO",
            ports_str or "Ninguno",
            h.get("alert_reason") or "OK",
        ])
    return output.getvalue().encode("utf-8-sig")


def _write_line(pdf: FPDF, text: str, h: float = 6, bold: bool = False, size: int = 10) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B" if bold else "", size)
    usable_w = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.multi_cell(usable_w, h, _safe_pdf_text(text))


def export_to_pdf(payload: dict, scan_id: int) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    _write_line(pdf, "Reporte de Auditoria de Red - Proyecto 4 (Redes II)", h=9, bold=True, size=14)
    _write_line(pdf, f"ID de Escaneo: #{scan_id}", h=6, size=10)
    pdf.ln(3)

    # Caso 1: Reporte de auditoría de Router Wi-Fi
    if "audit" in payload:
        audit = payload.get("audit", {})
        _write_line(pdf, "1. Identidad del Router Wi-Fi Auditado", h=8, bold=True, size=12)
        for label, val in [
            ("IP Gateway", audit.get("router_ip", "N/A")),
            ("Direccion MAC", audit.get("mac", "N/A")),
            ("Fabricante", audit.get("vendor", "N/A")),
            ("SO / Firmware", audit.get("os_firmware", "N/A")),
            ("Nivel de Riesgo Global", audit.get("risk_level", "N/A")),
        ]:
            _write_line(pdf, f"- {label}: {val}")

        pdf.ln(3)
        _write_line(pdf, "2. Puertos Abiertos en el Router", h=8, bold=True, size=12)
        open_ports = audit.get("open_ports", [])
        if not open_ports:
            _write_line(pdf, "- No se detectaron puertos abiertos.")
        for p in open_ports:
            line = f"- Puerto {p.get('port', '')}/{p.get('protocol', 'tcp')} | {p.get('service', '')} {p.get('product', '')} {p.get('version', '')}"
            _write_line(pdf, line)

        pdf.ln(3)
        _write_line(pdf, "3. Hallazgos y Recomendaciones", h=8, bold=True, size=12)
        for f in audit.get("findings", []):
            _write_line(pdf, f"[{f.get('severity', 'Info')}] {f.get('detail', '')}")

    # Caso 2: Reporte de escaneo general de red y topología
    else:
        meta = payload.get("report_metadata", {})
        summary = payload.get("summary", {})

        _write_line(pdf, "1. Resumen del Escaneo", h=8, bold=True, size=12)
        for label, val in [
            ("Fecha y Hora", meta.get("timestamp", "N/A")),
            ("Subred Analizada", meta.get("target_network", "N/A")),
            ("Router Central (Gateway)", meta.get("gateway_ip", "N/A")),
            ("Metodo / Argumentos", meta.get("nmap_arguments") or meta.get("method") or "N/A"),
            ("Dispositivos Conectados", summary.get("hosts_found", 0)),
            ("Puertos Abiertos Totales", summary.get("open_ports", 0)),
            ("Dispositivos No Autorizados", summary.get("unauthorized_devices", 0)),
        ]:
            _write_line(pdf, f"- {label}: {val}")

        pdf.ln(3)
        _write_line(pdf, "2. Detalle de Dispositivos Conectados", h=8, bold=True, size=12)
        hosts = payload.get("hosts", [])
        if not hosts:
            _write_line(pdf, "- No se registraron dispositivos en este escaneo.")
        for h in hosts:
            estado = "AUTORIZADO" if h.get("authorized") else "NO AUTORIZADO (INTRUSO)"
            ports_txt = ", ".join(
                f"{p.get('port', '')}/{p.get('service', '')}" for p in h.get("ports", [])
            ) or "Sin puertos escaneados/abiertos"
            _write_line(pdf, f"{h.get('ip', 'N/A')} - {h.get('hostname', 'N/A')} [{estado}]", h=6, bold=True, size=10)
            _write_line(
                pdf,
                f"   MAC: {h.get('mac', 'N/A')} | Fabricante: {h.get('vendor', 'N/A')}\n"
                f"   SO: {h.get('os', 'N/A')}\n"
                f"   Puertos: {ports_txt}",
                h=5,
                size=9,
            )
            pdf.ln(2)

    raw_out = pdf.output()
    if isinstance(raw_out, (bytes, bytearray)):
        return bytes(raw_out)
    return str(raw_out).encode("latin-1", "replace")