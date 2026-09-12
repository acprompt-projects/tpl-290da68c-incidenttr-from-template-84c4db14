import React, { useState, useEffect, useCallback } from "react";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLORS = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#ca8a04",
  low: "#16a34a",
  info: "#0ea5e9",
};
const STATUS_LABELS = {
  new: "New",
  investigating: "Investigating",
  resolved: "Resolved",
  escalated: "Escalated",
  muted: "Muted",
};
const API_BASE = window.__API_BASE__ || "http://localhost:8000";

export default function App() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [severityFilter, setSeverityFilter] = useState(null);
  const [statusFilter, setStatusFilter] = useState(null);
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 25;

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE) });
      if (severityFilter) params.set("severity", severityFilter);
      if (statusFilter) params.set("status", statusFilter);
      const res = await fetch(`${API_BASE}/api/incidents?${params}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setIncidents(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [severityFilter, statusFilter, page]);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);

  const patchIncident = async (id, body) => {
    const res = await fetch(`${API_BASE}/api/incidents/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  };

  const handleStatusChange = async (id, status) => {
    try {
      await patchIncident(id, { status });
      setIncidents((prev) => prev.map((inc) => (inc.id === id ? { ...inc, status } : inc)));
    } catch (e) { setError(e.message); }
  };

  const selected = incidents.find((i) => i.id === selectedId) || null;

  const filtered = incidents;
  const countBySev = (sev) => incidents.filter((i) => i.severity === sev).length;

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", maxWidth: 1200, margin: "0 auto", padding: 20 }}>
      <header style={{ marginBottom: 24 }}>
        <h1 style={{ margin: 0, fontSize: 24 }}>Incident Triage Dashboard</h1>
        <p style={{ margin: "4px 0 0", color: "#6b7280", fontSize: 13 }}>
          {incidents.length} incidents loaded
        </p>
      </header>

      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap", alignItems: "center" }}>
        <span style={{ fontSize: 13, fontWeight: 600, marginRight: 4 }}>Severity:</span>
        <FilterBtn active={!severityFilter} onClick={() => setSeverityFilter(null)}>All</FilterBtn>
        {SEVERITY_ORDER.map((s) => (
          <FilterBtn key={s} active={severityFilter === s} onClick={() => setSeverityFilter(severityFilter === s ? null : s)} color={SEVERITY_COLORS[s]}>
            {s} ({countBySev(s)})
          </FilterBtn>
        ))}
        <span style={{ fontSize: 13, fontWeight: 600, marginLeft: 12, marginRight: 4 }}>Status:</span>
        <FilterBtn active={!statusFilter} onClick={() => setStatusFilter(null)}>All</FilterBtn>
        {Object.keys(STATUS_LABELS).map((s) => (
          <FilterBtn key={s} active={statusFilter === s} onClick={() => setStatusFilter(statusFilter === s ? null : s)}>
            {STATUS_LABELS[s]}
          </FilterBtn>
        ))}
        <button onClick={fetchIncidents} style={{ marginLeft: "auto", fontSize: 12, padding: "4px 10px", cursor: "pointer" }}>↻ Refresh</button>
      </div>

      {error && <div style={{ background: "#fef2f2", color: "#dc2626", padding: 8, borderRadius: 4, fontSize: 13, marginBottom: 12 }}>{error}</div>}

      <div style={{ display: "flex", gap: 20 }}>
        <div style={{ flex: 1, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: "2px solid #e5e7eb", textAlign: "left" }}>
                <th style={thStyle}>ID</th><th style={thStyle}>Severity</th><th style={thStyle}>Title</th>
                <th style={thStyle}>Status</th><th style={thStyle}>Alerts</th><th style={thStyle}>Created</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6} style={{ padding: 20, textAlign: "center", color: "#9ca3af" }}>Loading…</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={6} style={{ padding: 20, textAlign: "center", color: "#9ca3af" }}>No incidents</td></tr>
              ) : filtered.map((inc) => (
                <tr key={inc.id} onClick={() => setSelectedId(inc.id)} style={{
                  background: selectedId === inc.id ? "#f0f9ff" : "transparent",
                  cursor: "pointer", borderBottom: "1px solid #f3f4f6",
                }}>
                  <td style={tdStyle}><code style={{ fontSize: 11 }}>{inc.id.slice(0, 8)}</code></td>
                  <td style={tdStyle}><SevBadge severity={inc.severity} /></td>
                  <td style={{ ...tdStyle, maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{inc.title}</td>
                  <td style={tdStyle}><StatusBadge status={inc.status} /></td>
                  <td style={{ ...tdStyle, textAlign: "center" }}>{inc.alert_count ?? inc.alert_ids?.length ?? 0}</td>
                  <td style={tdStyle}>{new Date(inc.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ display: "flex", gap: 8, marginTop: 12, justifyContent: "center" }}>
            <button disabled={page === 0} onClick={() => setPage((p) => p - 1)} style={pageBtnStyle}>← Prev</button>
            <span style={{ fontSize: 13, lineHeight: "28px" }}>Page {page + 1}</span>
            <button disabled={filtered.length < PAGE_SIZE} onClick={() => setPage((p) => p + 1)} style={pageBtnStyle}>Next →</button>
          </div>
        </div>

        {selected && (
          <div style={{ width: 360, flexShrink: 0, background: "#f9fafb", borderRadius: 8, padding: 16, border: "1px solid #e5e7eb", alignSelf: "flex-start" }}>
            <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>Incident Detail</h3>
            <DetailRow label="ID" value={selected.id} />
            <DetailRow label="Title" value={selected.title} />
            <DetailRow label="Severity" value={<SevBadge severity={selected.severity} />} />
            <DetailRow label="Status" value={<StatusBadge status={selected.status} />} />
            <DetailRow label="Created" value={new Date(selected.created_at).toLocaleString()} />
            {selected.updated_at && <DetailRow label="Updated" value={new Date(selected.updated_at).toLocaleString()} />}
            <DetailRow label="Alerts" value={selected.alert_count ?? selected.alert_ids?.length ?? 0} />
            {selected.correlation_key && <DetailRow label="Correlation" value={selected.correlation_key} />}
            {selected.description && <DetailRow label="Description" value={selected.description} />}
            <div style={{ marginTop: 16 }}>
              <span style={{ fontSize: 12, fontWeight: 600 }}>Set Status:</span>
              <div style={{ display: "flex", gap: 4, marginTop: 6, flexWrap: "wrap" }}>
                {Object.entries(STATUS_LABELS).map(([key, label]) => (
                  <button key={key} onClick={() => handleStatusChange(selected.id, key)} disabled={selected.status === key} style={{
                    fontSize: 11, padding: "3px 8px", borderRadius: 4, border: "1px solid #d1d5db", cursor: selected.status === key ? "default" : "pointer",
                    opacity: selected.status === key ? 0.5 : 1, background: selected.status === key ? "#e5e7eb" : "#fff",
                  }}>{label}</button>
                ))}
              </div>
            </div>
            <button onClick={() => setSelectedId(null)} style={{ marginTop: 12, fontSize: 11, padding: "4px 10px", border: "1px solid #d1d5db", borderRadius: 4, cursor: "pointer", background: "#fff" }}>Close</button>
          </div>
        )}
      </div>
    </div>
  );
}

function FilterBtn({ active, onClick, color, children }) {
  return (
    <button onClick={onClick} style={{
      fontSize: 12, padding: "3px 8px", borderRadius: 4, border: `1px solid ${active ? (color || "#3b82f6") : "#d1d5db"}`,
      background: active ? (color || "#3b82f6") : "#fff", color: active ? "#fff" : "#374151",
      cursor: "pointer", fontWeight: active ? 600 : 400,
    }}>{children}</button>
  );
}

function SevBadge({ severity }) {
  const c = SEVERITY_COLORS[severity] || "#6b7280";
  return <span style={{ display: "inline-block", padding: "1px 7px", borderRadius: 9999, fontSize: 11, fontWeight: 600, color: "#fff", background: c, textTransform: "uppercase" }}>{severity}</span>;
}

function StatusBadge({ status }) {
  const map = { new: "#3b82f6", investigating: "#f59e0b", resolved: "#16a34a", escalated: "#dc2626", muted: "#6b7280" };
  return <span style={{ display: "inline-block", padding: "1px 7px", borderRadius: 4, fontSize: 11, fontWeight: 500, border: `1px solid ${map[status] || "#d1d5db"}`, color: map[status] || "#374151" }}>{STATUS_LABELS[status] || status}</span>;
}

function DetailRow({ label, value }) {
  return <div style={{ display: "flex", gap: 8, marginTop: 6, fontSize: 13 }}><span style={{ fontWeight: 600, minWidth: 80, color: "#6b7280" }}>{label}</span><span style={{ flex: 1 }}>{value}</span></div>;
}

const thStyle = { padding: "8px 6px", fontWeight: 600, fontSize: 12, color: "#6b7280", textTransform: "uppercase", letterSpacing: 0.5 };
const tdStyle = { padding: "8px 6px" };
const pageBtnStyle = { fontSize: 12, padding: "4px 10px", border: "1px solid #d1d5db", borderRadius: 4, cursor: "pointer", background: "#fff" };