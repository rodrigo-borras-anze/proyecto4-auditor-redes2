import { riskBadgeClass } from "../utils/formatters";

export default function RouterAuditView({ routerAudit, gatewayIp }) {
  if (!routerAudit) {
    return (
      <div className="empty-state">
        Haz clic en <strong>Auditar Router Wi-Fi</strong> para analizar el Gateway detectado (
        <code>{gatewayIp || "—"}</code>), sus puertos de gestión, scripts NSE y nivel de riesgo.
      </div>
    );
  }

  return (
    <div className="router-grid">
      <div className="subcard">
        <h3>1. Identidad del Router Wi-Fi</h3>
        <div className="kv-list">
          <div className="kv-row">
            <span>IP Gateway</span>
            <code>{routerAudit.router_ip}</code>
          </div>
          <div className="kv-row">
            <span>Dirección MAC</span>
            <code>{routerAudit.mac || "No detectada"}</code>
          </div>
          <div className="kv-row">
            <span>Fabricante</span>
            <span>{routerAudit.vendor || "Desconocido"}</span>
          </div>
          <div className="kv-row">
            <span>SO / Firmware</span>
            <span>{routerAudit.os_firmware || "No determinado"}</span>
          </div>
          <div className="kv-row">
            <span>Nivel de Riesgo</span>
            <span className={riskBadgeClass(routerAudit.risk_level)}>{routerAudit.risk_level}</span>
          </div>
        </div>
      </div>

      <div className="subcard">
        <h3>2. Puertos y Scripts NSE ({routerAudit.open_ports?.length || 0})</h3>
        {routerAudit.open_ports?.length ? (
          routerAudit.open_ports.map((p) => (
            <div key={`${p.protocol}-${p.port}`} className="finding-item">
              <div>
                <span className="port-chip">
                  {p.port}/{p.protocol}
                </span>
                <strong>{p.service}</strong> {p.product} {p.version}
              </div>
              {p.nse_scripts?.map((s) => (
                <div
                  key={s.id}
                  style={{ marginTop: 6, fontSize: "0.75rem", color: "#94a3b8", fontFamily: "var(--mono)" }}
                >
                  <strong>[{s.id}]</strong> {s.output}
                </div>
              ))}
            </div>
          ))
        ) : (
          <p style={{ color: "var(--muted)", fontSize: "0.84rem" }}>No se detectaron puertos de gestión abiertos.</p>
        )}
      </div>

      <div className="subcard">
        <h3>3. Hallazgos y Recomendaciones</h3>
        {(routerAudit.findings || []).map((f, i) => (
          <div key={i} className="finding-item">
            <div style={{ marginBottom: 5 }}>
              <span className={riskBadgeClass(f.severity)}>{f.severity}</span>
              {f.port && (
                <span style={{ marginLeft: 8, fontFamily: "var(--mono)", fontSize: "0.75rem", color: "var(--cyan)" }}>
                  Puerto {f.port}
                </span>
              )}
            </div>
            <div>{f.detail}</div>
          </div>
        ))}
      </div>
    </div>
  );
}