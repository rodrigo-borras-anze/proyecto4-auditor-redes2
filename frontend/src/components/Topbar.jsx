export default function Topbar({ status, backendOnline }) {
  return (
    <header className="topbar">
      <div className="brand">
        <div className="brand-icon">N4</div>
        <div>
          <h1>NetLab Auditor — Proyecto 4 (Redes II)</h1>
          <div className="net-meta">
            Host: <strong>{status?.network?.local_ip || "—"}</strong> · Gateway Wi-Fi:{" "}
            <strong>{status?.network?.gateway_ip || "—"}</strong> · Subred:{" "}
            <strong>{status?.network?.subnet || "—"}</strong>
          </div>
        </div>
      </div>
      <div className={`status-pill ${backendOnline ? "online" : "offline"}`}>
        <span className="dot" />
        {backendOnline ? "Backend Online · FastAPI" : "Backend Desconectado (puerto 8000)"}
      </div>
    </header>
  );
}