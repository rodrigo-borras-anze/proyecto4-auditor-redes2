import { useEffect, useMemo, useState } from "react";
import { SCAN_PRESETS } from "./utils/scanPresets";
import {
  getStatus,
  getWhitelist,
  getHistory,
  getHistoryDetail,
  runNmapScan,
  runScapyTopology,
  runRouterAudit,
  runTraceroute,
  addWhitelistDevice,
  deleteWhitelistDevice,
  getExportUrl,
} from "./services/api";

import Topbar from "./components/Topbar";
import ControlPanel from "./components/ControlPanel";
import KpiCards from "./components/KpiCards";
import TopologyView from "./components/TopologyView";
import HostsTable from "./components/HostsTable";
import RouterAuditView from "./components/RouterAuditView";
import WhitelistView from "./components/WhitelistView";
import HistoryView from "./components/HistoryView";

export default function App() {
  const [status, setStatus] = useState(null);
  const [backendOnline, setBackendOnline] = useState(false);

  const [target, setTarget] = useState("");
  const [presetKey, setPresetKey] = useState("top50");
  const [customArgs, setCustomArgs] = useState("");

  const [activeTab, setActiveTab] = useState("topology");
  const [scanData, setScanData] = useState(null);
  const [routerAudit, setRouterAudit] = useState(null);
  const [whitelist, setWhitelist] = useState([]);
  const [history, setHistory] = useState([]);

  const [selectedHostIp, setSelectedHostIp] = useState(null);
  const [traceResult, setTraceResult] = useState(null);
  const [loading, setLoading] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");

  const currentPreset = useMemo(
    () => SCAN_PRESETS.find((p) => p.key === presetKey) || SCAN_PRESETS[0],
    [presetKey]
  );
  const effectiveArgs = customArgs.trim() || currentPreset.args;

  async function refreshMeta() {
    try {
      const [st, wl, hist] = await Promise.all([getStatus(), getWhitelist(), getHistory()]);
      setStatus(st);
      setBackendOnline(true);
      if (!target && st.network?.subnet) setTarget(st.network.subnet);
      setWhitelist(wl.devices || []);
      setHistory(hist.scans || []);
    } catch {
      setBackendOnline(false);
    }
  }

  useEffect(() => {
    refreshMeta();
  }, []);

  async function handleNmapScan() {
    setLoading("nmap");
    setErrorMsg("");
    setTraceResult(null);
    try {
      const data = await runNmapScan({
        target: target.trim(),
        profile: currentPreset.profile,
        customArgs: effectiveArgs,
      });
      setScanData(data);
      setSelectedHostIp(data.report_metadata?.gateway_ip || data.hosts?.[0]?.ip || null);
      if (activeTab === "router" || activeTab === "history") setActiveTab("topology");
      await refreshMeta();
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setLoading(null);
    }
  }

  async function handleScapyTopology() {
    setLoading("scapy");
    setErrorMsg("");
    setTraceResult(null);
    try {
      const data = await runScapyTopology(target.trim(), 3);
      setScanData(data);
      setSelectedHostIp(data.report_metadata?.gateway_ip || data.hosts?.[0]?.ip || null);
      setActiveTab("topology");
      await refreshMeta();
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setLoading(null);
    }
  }

  async function handleAuditRouter() {
    setLoading("router");
    setErrorMsg("");
    try {
      const data = await runRouterAudit(status?.network?.gateway_ip);
      setRouterAudit(data);
      setActiveTab("router");
      await refreshMeta();
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setLoading(null);
    }
  }

  async function handleTraceroute(ip) {
    setLoading("trace");
    setErrorMsg("");
    try {
      const data = await runTraceroute(ip);
      setTraceResult(data);
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setLoading(null);
    }
  }

  async function authorizeMac(mac, label, deviceType = "laptop") {
    if (!mac || mac === "LOCAL" || mac === "NO_DETECTADA") return;
    setErrorMsg("");
    try {
      await addWhitelistDevice({ mac, label: label || "Dispositivo autorizado", deviceType });
      await refreshMeta();

      if (scanData?.hosts) {
        const norm = mac.trim().toUpperCase();
        const updatedHosts = scanData.hosts.map((h) =>
          h.mac?.toUpperCase() === norm ? { ...h, authorized: true, alert_reason: null } : h
        );
        const unauth = updatedHosts.filter((h) => !h.authorized).length;
        setScanData({
          ...scanData,
          hosts: updatedHosts,
          summary: { ...scanData.summary, unauthorized_devices: unauth },
        });
      }
    } catch (err) {
      setErrorMsg(err.message);
    }
  }

  async function handleDeleteWhitelist(mac) {
    try {
      await deleteWhitelistDevice(mac);
      await refreshMeta();
    } catch (err) {
      setErrorMsg(err.message);
    }
  }

  async function handleLoadHistoryScan(scanId) {
    setErrorMsg("");
    try {
      const data = await getHistoryDetail(scanId);
      if (data.audit) {
        setRouterAudit(data.audit);
        setActiveTab("router");
      } else {
        setScanData({ ...data, report_metadata: { ...data.report_metadata, scan_id: scanId } });
        setSelectedHostIp(data.report_metadata?.gateway_ip || data.hosts?.[0]?.ip || null);
        setActiveTab("topology");
      }
    } catch (err) {
      setErrorMsg(err.message);
    }
  }

  const selectedHost = useMemo(() => {
    if (!scanData?.hosts) return null;
    return scanData.hosts.find((h) => h.ip === selectedHostIp) || scanData.hosts[0] || null;
  }, [scanData, selectedHostIp]);

  const activeScanId = scanData?.report_metadata?.scan_id;
  const unauthCount = scanData?.summary?.unauthorized_devices || 0;

  return (
    <div className="app-shell">
      <Topbar status={status} backendOnline={backendOnline} />

      <ControlPanel
        target={target}
        setTarget={setTarget}
        presetKey={presetKey}
        setPresetKey={setPresetKey}
        customArgs={customArgs}
        setCustomArgs={setCustomArgs}
        effectiveArgs={effectiveArgs}
        status={status}
        loading={loading}
        backendOnline={backendOnline}
        onNmapScan={handleNmapScan}
        onScapyTopology={handleScapyTopology}
        onAuditRouter={handleAuditRouter}
      />

      {errorMsg && (
        <div className="alert-banner alert-error">
          <span>Error: {errorMsg}</span>
          <button className="btn btn-ghost" onClick={() => setErrorMsg("")}>
            Cerrar
          </button>
        </div>
      )}

      {unauthCount > 0 && (
        <div className="alert-banner alert-warn">
          <span>
            Alerta de seguridad: se detectaron <strong>{unauthCount}</strong> dispositivo(s) conectados fuera de la lista
            blanca (<code>whitelist.json</code>).
          </span>
          <button className="btn btn-ghost" onClick={() => setActiveTab("hosts")}>
            Revisar dispositivos
          </button>
        </div>
      )}

      <KpiCards
        scanData={scanData}
        routerAudit={routerAudit}
        savedScans={status?.saved_scans ?? history.length}
      />

      <div className="toolbar-row">
        <nav className="tabs">
          <button className={`tab-btn ${activeTab === "topology" ? "active" : ""}`} onClick={() => setActiveTab("topology")}>
            Mapa de Topología
          </button>
          <button className={`tab-btn ${activeTab === "hosts" ? "active" : ""}`} onClick={() => setActiveTab("hosts")}>
            Hosts y Servicios ({scanData?.hosts?.length ?? 0})
          </button>
          <button className={`tab-btn ${activeTab === "router" ? "active" : ""}`} onClick={() => setActiveTab("router")}>
            Auditoría Router Wi-Fi
          </button>
          <button className={`tab-btn ${activeTab === "whitelist" ? "active" : ""}`} onClick={() => setActiveTab("whitelist")}>
            Lista Blanca ({whitelist.length})
          </button>
          <button className={`tab-btn ${activeTab === "history" ? "active" : ""}`} onClick={() => setActiveTab("history")}>
            Historial ({history.length})
          </button>
        </nav>

        {activeScanId && (
          <div className="export-bar">
            <span>Exportar escaneo #{activeScanId}:</span>
            <a className="btn btn-ghost" href={getExportUrl(activeScanId, "json")} target="_blank" rel="noreferrer">
              JSON
            </a>
            <a className="btn btn-ghost" href={getExportUrl(activeScanId, "csv")} target="_blank" rel="noreferrer">
              CSV
            </a>
            <a className="btn btn-primary" href={getExportUrl(activeScanId, "pdf")} target="_blank" rel="noreferrer">
              PDF
            </a>
          </div>
        )}
      </div>

      <main className="panel">
        {activeTab === "topology" && (
          <TopologyView
            scanData={scanData}
            selectedHost={selectedHost}
            onSelectHost={setSelectedHostIp}
            onAuthorize={authorizeMac}
            onTraceroute={handleTraceroute}
            traceResult={traceResult}
            loading={loading}
          />
        )}
        {activeTab === "hosts" && <HostsTable scanData={scanData} onAuthorize={authorizeMac} />}
        {activeTab === "router" && (
          <RouterAuditView routerAudit={routerAudit} gatewayIp={status?.network?.gateway_ip} />
        )}
        {activeTab === "whitelist" && (
          <WhitelistView whitelist={whitelist} onAdd={authorizeMac} onDelete={handleDeleteWhitelist} />
        )}
        {activeTab === "history" && <HistoryView history={history} onLoadScan={handleLoadHistoryScan} />}
      </main>
    </div>
  );
}