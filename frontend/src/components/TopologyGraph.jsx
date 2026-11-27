import { deviceShortTag } from "../utils/formatters";

export default function TopologyGraph({ scanData, selectedIp, onSelect }) {
  const hosts = scanData?.hosts || [];
  const gatewayIp =
    scanData?.topology?.center_node?.id || scanData?.report_metadata?.gateway_ip || "Router";

  const centerHost = hosts.find((h) => h.is_router || h.ip === gatewayIp) || {
    ip: gatewayIp,
    hostname: "Router Wi-Fi",
    mac: "Gateway",
    vendor: "Router Central",
    device_type: "router",
    is_router: true,
    authorized: true,
    ports: [],
  };

  const peripheralHosts = hosts.filter((h) => h.ip !== centerHost.ip);
  const width = 660;
  const height = 430;
  const cx = width / 2;
  const cy = height / 2;
  const radius = peripheralHosts.length > 8 ? 158 : 145;

  const positioned = peripheralHosts.map((host, idx) => {
    const angle = (2 * Math.PI * idx) / Math.max(peripheralHosts.length, 1) - Math.PI / 2;
    const r = peripheralHosts.length > 10 && idx % 2 === 1 ? radius - 26 : radius;
    return {
      ...host,
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
    };
  });

  return (
    <div className="svg-stage">
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" height="430">
        <defs>
          <radialGradient id="routerGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.35" />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
          </radialGradient>
        </defs>

        <circle cx={cx} cy={cy} r={radius} fill="none" stroke="#1e293b" strokeDasharray="4 6" />
        <circle cx={cx} cy={cy} r={78} fill="url(#routerGlow)" />

        {positioned.map((node) => {
          const stroke = node.authorized ? "#10b981" : "#f43f5e";
          return (
            <line
              key={`link-${node.ip}`}
              x1={cx}
              y1={cy}
              x2={node.x}
              y2={node.y}
              stroke={stroke}
              strokeOpacity="0.45"
              strokeWidth={selectedIp === node.ip ? 2.6 : 1.6}
              strokeDasharray={node.authorized ? "none" : "6 4"}
            />
          );
        })}

        {positioned.map((node) => {
          const isSelected = selectedIp === node.ip;
          const color = node.authorized ? "#10b981" : "#f43f5e";
          const portCount = node.ports?.length || 0;
          return (
            <g
              key={node.ip}
              transform={`translate(${node.x}, ${node.y})`}
              onClick={() => onSelect(node.ip)}
              style={{ cursor: "pointer" }}
            >
              {isSelected && <circle r={30} fill="none" stroke="#38bdf8" strokeWidth="2" strokeDasharray="4 3" />}
              <circle r={23} fill="#0f172a" stroke={color} strokeWidth="2.8" />
              <text textAnchor="middle" dy="4" fill="#f8fafc" fontSize="11" fontWeight="700" fontFamily="monospace">
                {deviceShortTag(node.device_type)}
              </text>
              {portCount > 0 && (
                <g transform="translate(17, -17)">
                  <circle r="9" fill="#0284c7" stroke="#080d1a" strokeWidth="1.5" />
                  <text textAnchor="middle" dy="3.5" fill="#fff" fontSize="9" fontWeight="700">
                    {portCount}
                  </text>
                </g>
              )}
              <text textAnchor="middle" y="38" fill="#e2e8f0" fontSize="11" fontWeight="600" fontFamily="monospace">
                {node.ip}
              </text>
              <text textAnchor="middle" y="51" fill="#94a3b8" fontSize="9.5">
                {(node.vendor || "").slice(0, 18)}
              </text>
            </g>
          );
        })}

        <g transform={`translate(${cx}, ${cy})`} onClick={() => onSelect(centerHost.ip)} style={{ cursor: "pointer" }}>
          {selectedIp === centerHost.ip && (
            <circle r={42} fill="none" stroke="#f59e0b" strokeWidth="2" strokeDasharray="4 3" />
          )}
          <circle r={33} fill="#0c2542" stroke="#38bdf8" strokeWidth="3.2" />
          <text textAnchor="middle" dy="-2" fill="#7dd3fc" fontSize="11" fontWeight="800">
            ROUTER
          </text>
          <text textAnchor="middle" dy="12" fill="#e0f2fe" fontSize="9.5" fontFamily="monospace">
            Wi-Fi
          </text>
          <text textAnchor="middle" y="48" fill="#38bdf8" fontSize="11.5" fontWeight="700" fontFamily="monospace">
            {centerHost.ip}
          </text>
        </g>
      </svg>

      <div className="legend">
        <span className="legend-item">
          <span className="dot" style={{ background: "#38bdf8" }} /> Router Wi-Fi (Gateway)
        </span>
        <span className="legend-item">
          <span className="dot" style={{ background: "#10b981" }} /> Autorizado (Lista Blanca)
        </span>
        <span className="legend-item">
          <span className="dot" style={{ background: "#f43f5e" }} /> No Autorizado (Intruso)
        </span>
        <span className="legend-item" style={{ marginLeft: "auto" }}>
          Haz clic en cualquier nodo para inspeccionar
        </span>
      </div>
    </div>
  );
}