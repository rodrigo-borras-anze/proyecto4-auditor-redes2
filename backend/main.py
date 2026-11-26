from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.responses import Response
from scapy_topology import scapy_arp_topology, run_scapy_traceroute
from report_generator import export_to_json, export_to_csv, export_to_pdf

from history_db import init_db, save_scan, list_scans, get_scan, count_scans
from whitelist_manager import load_whitelist, add_device, remove_device
from nmap_scanner import run_network_scan, SCAN_PROFILES
from router_auditor import detect_network_context, audit_wifi_router

app = FastAPI(title="Proyecto 4 - Auditor de Red y Router Wi-Fi")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()


class ScanRequest(BaseModel):
    target: str | None = None
    profile: str = "normal"
    custom_args: str | None = None


class RouterAuditRequest(BaseModel):
    router_ip: str | None = None


class WhitelistItem(BaseModel):
    mac: str
    label: str
    device_type: str = "laptop"


@app.get("/api/status")
def get_status():
    ctx = detect_network_context()
    return {
        "status": "online",
        "network": ctx,
        "available_profiles": list(SCAN_PROFILES.keys()),
        "saved_scans": count_scans(),
    }


@app.post("/api/scan")
def start_scan(req: ScanRequest):
    try:
        result = run_network_scan(target=req.target, profile=req.profile, custom_args=req.custom_args)
        scan_id = save_scan("network_scan", result["report_metadata"]["target_network"], result)
        result["report_metadata"]["scan_id"] = scan_id
        result["summary"]["saved_scans"] = count_scans()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error ejecutando Nmap: {str(e)}")


@app.post("/api/audit-router")
def start_router_audit(req: RouterAuditRequest):
    try:
        result = audit_wifi_router(router_ip=req.router_ip)
        save_scan("router_audit", result["router_ip"], {"summary": {"hosts_found": 1, "open_ports": len(result.get("open_ports", []))}, "audit": result})
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error auditando router: {str(e)}")


@app.get("/api/whitelist")
def get_whitelist():
    return {"devices": load_whitelist()}


@app.post("/api/whitelist")
def create_whitelist_item(item: WhitelistItem):
    return add_device(item.mac, item.label, item.device_type)


@app.delete("/api/whitelist/{mac}")
def delete_whitelist_item(mac: str):
    if not remove_device(mac):
        raise HTTPException(status_code=404, detail="MAC no encontrada en la lista blanca")
    return {"deleted": mac}


@app.get("/api/history")
def get_history():
    return {"scans": list_scans()}


@app.get("/api/history/{scan_id}")
def get_history_detail(scan_id: int):
    data = get_scan(scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return data

class ScapyTopologyRequest(BaseModel):
    target_subnet: str | None = None
    timeout: int = 3


@app.post("/api/topology/scapy")
def get_scapy_topology(req: ScapyTopologyRequest):
    try:
        result = scapy_arp_topology(target_subnet=req.target_subnet, timeout=req.timeout)
        scan_id = save_scan("scapy_arp", result["report_metadata"]["target_network"], result)
        result["report_metadata"]["scan_id"] = scan_id
        result["summary"]["saved_scans"] = count_scans()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error ejecutando Scapy ARP: {str(e)}")


@app.get("/api/topology/traceroute/{target_ip}")
def get_traceroute(target_ip: str):
    try:
        return run_scapy_traceroute(target_ip=target_ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error ejecutando traceroute: {str(e)}")


@app.get("/api/export/{scan_id}/{fmt}")
def export_report(scan_id: int, fmt: str):
    payload = get_scan(scan_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")

    fmt = fmt.lower()
    if fmt == "json":
        return Response(
            content=export_to_json(payload),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=reporte_scan_{scan_id}.json"},
        )
    if fmt == "csv":
        return Response(
            content=export_to_csv(payload),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename=reporte_scan_{scan_id}.csv"},
        )
    if fmt == "pdf":
        return Response(
            content=export_to_pdf(payload, scan_id),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=reporte_scan_{scan_id}.pdf"},
        )

    raise HTTPException(status_code=400, detail="Formato no soportado. Usa: json, csv o pdf")
@app.get("/api/export/{scan_id}/{fmt}")
def export_report(scan_id: int, fmt: str):
    payload = get_scan(scan_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")

    fmt = fmt.lower()
    try:
        if fmt == "json":
            return Response(
                content=export_to_json(payload),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=reporte_scan_{scan_id}.json"},
            )
        if fmt == "csv":
            return Response(
                content=export_to_csv(payload),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f"attachment; filename=reporte_scan_{scan_id}.csv"},
            )
        if fmt == "pdf":
            return Response(
                content=export_to_pdf(payload, scan_id),
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=reporte_scan_{scan_id}.pdf"},
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando reporte {fmt}: {str(e)}")

    raise HTTPException(status_code=400, detail="Formato no soportado. Usa: json, csv o pdf")