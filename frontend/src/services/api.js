export const API_BASE = "http://127.0.0.1:8000";

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, options);
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || `Error HTTP ${res.status}`);
  }
  return data;
}

export const getStatus = () => request("/api/status");
export const getWhitelist = () => request("/api/whitelist");
export const getHistory = () => request("/api/history");
export const getHistoryDetail = (scanId) => request(`/api/history/${scanId}`);

export const runNmapScan = ({ target, profile, customArgs }) =>
  request("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target: target || null,
      profile,
      custom_args: customArgs,
    }),
  });

export const runScapyTopology = (targetSubnet, timeout = 3) =>
  request("/api/topology/scapy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_subnet: targetSubnet || null, timeout }),
  });

export const runRouterAudit = (routerIp) =>
  request("/api/audit-router", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ router_ip: routerIp || null }),
  });

export const runTraceroute = (ip) =>
  request(`/api/topology/traceroute/${encodeURIComponent(ip)}`);

export const addWhitelistDevice = ({ mac, label, deviceType = "laptop" }) =>
  request("/api/whitelist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mac, label, device_type: deviceType }),
  });

export const deleteWhitelistDevice = (mac) =>
  request(`/api/whitelist/${encodeURIComponent(mac)}`, { method: "DELETE" });

export const getExportUrl = (scanId, fmt) =>
  `${API_BASE}/api/export/${scanId}/${fmt}`;