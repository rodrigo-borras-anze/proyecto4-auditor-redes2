import TopologyGraph from "./TopologyGraph";

export default function TopologyView({
  scanData,
  selectedHost,
  onSelectHost,
  onAuthorize,
  onTraceroute,
  traceResult,
  loading,
}) {
  if (!scanData) {
    return (
      <div className="empty-state">
        Presiona <strong>Escanear Nmap</strong> o <strong>Topología Scapy ARP</strong> para detectar los dispositivos
        conectados al router Wi-Fi y dibujar la topología en vivo.
      </div>
    );
  }

  return (
    <div className="topology-layout">
      <TopologyGraph scanData={scanData} selectedIp={selectedHost?.ip} onSelect={onSelectHost} />

      <aside className="inspector-card">
        {selectedHost ? (
          <>
            <h3>
              <span>{selectedHost.hostname || selectedHost.ip}</span>
              <span className={selectedHost.authorized ? "badge badge-ok" : "badge badge-bad"}>
                {selectedHost.authorized ? "Autorizado" : "Intruso"}
              </span>
            </h3>

            <div className="kv-list">
              <div className="kv-row">
                <span>Dirección IP</span>
                <code>{selectedHost.ip}</code>
              </div>
              <div className="kv-row">
                <span>Dirección MAC</span>
                <code>{selectedHost.mac}</code>
              </div>
              <div className="kv-row">
                <span>Fabricante (OUI)</span>
                <span>{selectedHost.vendor}</span>
              </div>
              <div className="kv-row">
                <span>Sistema Operativo</span>
                <span>{selectedHost.os}</span>
              </div>
            </div>

            <div style={{ marginBottom: 14 }}>
              <div className="kpi-label" style={{ marginBottom: 6 }}>
                Puertos y Servicios Abiertos ({selectedHost.ports?.length || 0})
              </div>
              {selectedHost.ports?.length ? (
                selectedHost.ports.map((p) => (
                  <span key={`${p.protocol}-${p.port}`} className="port-chip">
                    {p.port}/{p.protocol} {p.service} {p.version}
                  </span>
                ))
              ) : (
                <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>
                  Sin puertos abiertos (usa perfil Top 20, Top 50 o Servicios -sV).
                </span>
              )}
            </div>

            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {!selectedHost.authorized && selectedHost.mac !== "LOCAL" && (
                <button
                  className="btn btn-success"
                  onClick={() => onAuthorize(selectedHost.mac, selectedHost.hostname, selectedHost.device_type)}
                >
                  Autorizar en Lista Blanca
                </button>
              )}
              <button
                className="btn btn-scapy"
                onClick={() => onTraceroute(selectedHost.ip)}
                disabled={loading === "trace"}
              >
                {loading === "trace" ? "Trazando..." : "Traceroute (Scapy)"}
              </button>
            </div>

            {traceResult && traceResult.target_ip === selectedHost.ip && (
              <div style={{ marginTop: 14 }}>
                <div className="kpi-label">Ruta detectada ({traceResult.total_hops} saltos)</div>
                <div className="hop-chain">
                  {traceResult.hops.map((h) => (
                    <span key={h.hop} className="hop-pill">
                      #{h.hop} → {h.ip}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="empty-state">Selecciona un nodo del mapa para ver sus detalles.</div>
        )}
      </aside>
    </div>
  );
}