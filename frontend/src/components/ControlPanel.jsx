import { SCAN_PRESETS } from "../utils/scanPresets";

export default function ControlPanel({
  target,
  setTarget,
  presetKey,
  setPresetKey,
  customArgs,
  setCustomArgs,
  effectiveArgs,
  status,
  loading,
  backendOnline,
  onNmapScan,
  onScapyTopology,
  onAuditRouter,
}) {
  return (
    <section className="control-card">
      <div className="control-grid">
        <div className="field">
          <label>Subred o IP Objetivo</label>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Ej: 192.168.0.0/24 o 192.168.0.1"
          />
        </div>

        <div className="field">
          <label>Perfil de Escaneo Nmap</label>
          <select value={presetKey} onChange={(e) => setPresetKey(e.target.value)}>
            {SCAN_PRESETS.map((p) => (
              <option key={p.key} value={p.key}>
                {p.label}
              </option>
            ))}
          </select>
        </div>

        <div className="field">
          <label>Argumentos Nmap Personalizados (Opcional)</label>
          <input
            value={customArgs}
            onChange={(e) => setCustomArgs(e.target.value)}
            placeholder="Sobrescribe el perfil (ej: -sS -sV -p 22,80,443)"
          />
        </div>

        <div className="action-stack">
          <button className="btn btn-primary" onClick={onNmapScan} disabled={!!loading || !backendOnline}>
            {loading === "nmap" ? "Escaneando..." : "Escanear Nmap"}
          </button>
          <button className="btn btn-scapy" onClick={onScapyTopology} disabled={!!loading || !backendOnline}>
            {loading === "scapy" ? "Mapeando..." : "Topología Scapy ARP"}
          </button>
          <button className="btn btn-router" onClick={onAuditRouter} disabled={!!loading || !backendOnline}>
            {loading === "router" ? "Auditando..." : "Auditar Router Wi-Fi"}
          </button>
        </div>
      </div>

      <div className="cmd-preview">
        <div>
          <span className="label">Comando Nmap activo: </span>
          <code>
            nmap {effectiveArgs} {target || status?.network?.subnet || "192.168.0.0/24"}
          </code>
        </div>
        {customArgs && (
          <button className="btn btn-ghost" onClick={() => setCustomArgs("")}>
            Limpiar args manuales
          </button>
        )}
      </div>
    </section>
  );
}