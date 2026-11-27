export default function KpiCards({ scanData, routerAudit, savedScans }) {
  const unauthCount = scanData?.summary?.unauthorized_devices || 0;

  return (
    <section className="kpi-grid">
      <div className="kpi-card">
        <div className="kpi-label">Dispositivos Conectados</div>
        <div className="kpi-value cyan">{scanData?.summary?.hosts_found ?? 0}</div>
      </div>
      <div className="kpi-card">
        <div className="kpi-label">Puertos Abiertos</div>
        <div className="kpi-value emerald">{scanData?.summary?.open_ports ?? 0}</div>
      </div>
      <div className="kpi-card">
        <div className="kpi-label">No Autorizados (Intrusos)</div>
        <div className={`kpi-value ${unauthCount > 0 ? "rose" : "emerald"}`}>{unauthCount}</div>
      </div>
      <div className="kpi-card">
        <div className="kpi-label">Riesgo del Router / Escaneos</div>
        <div className="kpi-value amber">
          {routerAudit ? routerAudit.risk_level : `${savedScans} guard.`}
        </div>
      </div>
    </section>
  );
}