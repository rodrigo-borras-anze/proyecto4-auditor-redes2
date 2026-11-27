import { getExportUrl } from "../services/api";

export default function HistoryView({ history, onLoadScan }) {
  if (history.length === 0) {
    return <div className="empty-state">Aún no hay escaneos guardados en SQLite.</div>;
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Tipo</th>
            <th>Objetivo</th>
            <th>Fecha</th>
            <th>Hosts / Puertos / Intrusos</th>
            <th>Acciones</th>
          </tr>
        </thead>
        <tbody>
          {history.map((s) => (
            <tr key={s.id}>
              <td style={{ fontFamily: "var(--mono)" }}>#{s.id}</td>
              <td>
                <span className="badge badge-info">{s.scan_type}</span>
              </td>
              <td style={{ fontFamily: "var(--mono)" }}>{s.target}</td>
              <td style={{ color: "var(--muted)" }}>{s.timestamp}</td>
              <td>
                {s.hosts_found} hosts · {s.open_ports} puertos ·{" "}
                <strong style={{ color: s.unauthorized_devices > 0 ? "var(--rose)" : "var(--emerald)" }}>
                  {s.unauthorized_devices} intrusos
                </strong>
              </td>
              <td style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                <button className="btn btn-ghost" onClick={() => onLoadScan(s.id)}>
                  Ver
                </button>
                <a className="btn btn-ghost" href={getExportUrl(s.id, "csv")} target="_blank" rel="noreferrer">
                  CSV
                </a>
                <a className="btn btn-primary" href={getExportUrl(s.id, "pdf")} target="_blank" rel="noreferrer">
                  PDF
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}