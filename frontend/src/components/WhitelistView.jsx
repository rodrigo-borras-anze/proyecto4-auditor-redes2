import { useState } from "react";

export default function WhitelistView({ whitelist, onAdd, onDelete }) {
  const [form, setForm] = useState({ mac: "", label: "", device_type: "laptop" });

  async function handleSubmit(e) {
    e.preventDefault();
    if (!form.mac.trim() || !form.label.trim()) return;
    await onAdd(form.mac, form.label, form.device_type);
    setForm({ mac: "", label: "", device_type: "laptop" });
  }

  return (
    <>
      <form className="wl-form" onSubmit={handleSubmit}>
        <div className="field">
          <label>Dirección MAC</label>
          <input
            value={form.mac}
            onChange={(e) => setForm({ ...form, mac: e.target.value })}
            placeholder="AA:BB:CC:DD:EE:FF"
            required
          />
        </div>
        <div className="field">
          <label>Nombre / Etiqueta</label>
          <input
            value={form.label}
            onChange={(e) => setForm({ ...form, label: e.target.value })}
            placeholder="Ej: Laptop Rodrigo / Router TP-Link"
            required
          />
        </div>
        <div className="field">
          <label>Tipo</label>
          <select value={form.device_type} onChange={(e) => setForm({ ...form, device_type: e.target.value })}>
            <option value="laptop">Laptop / PC</option>
            <option value="router">Router Wi-Fi</option>
            <option value="mobile">Celular</option>
            <option value="device">Otro</option>
          </select>
        </div>
        <button className="btn btn-primary" type="submit">
          Agregar MAC
        </button>
      </form>

      {whitelist.length === 0 ? (
        <div className="empty-state">No hay dispositivos registrados aún en la lista blanca.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>MAC</th>
                <th>Etiqueta</th>
                <th>Tipo</th>
                <th>Registrado</th>
                <th>Acción</th>
              </tr>
            </thead>
            <tbody>
              {whitelist.map((d) => (
                <tr key={d.mac}>
                  <td style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{d.mac}</td>
                  <td>{d.label}</td>
                  <td>{d.device_type}</td>
                  <td style={{ color: "var(--muted)" }}>{d.added_at}</td>
                  <td>
                    <button className="btn btn-danger" onClick={() => onDelete(d.mac)}>
                      Eliminar
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}