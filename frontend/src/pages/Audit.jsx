import { useState } from "react";
import { api, post } from "../api.js";
import { eventLabel, fmtTime, shortFpr, usePoll } from "../util.js";
import { ListView, useAction } from "../components/ui.jsx";

const subjectText = (s) => s.cred_name || s.peer_name || s.group_name || s.node || s.addr || s.source || "";
const detailText = (d) => Object.entries(d).filter(([, v]) => v !== "" && v !== null && typeof v !== "object")
  .map(([k, v]) => `${k.replace(/_/g, " ")}: ${k === "expires_at" ? fmtTime(v) : v}`).join("; ");

export function AuditLog() {
  const [type, setType] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);
  const size = 50;
  const [d] = usePoll(`/audit?event_type=${encodeURIComponent(type)}&q=${encodeURIComponent(q)}&limit=${size}&offset=${page * size}`, 6000);
  return (
    <div className="page">
      <h1 className="page-title">Event log</h1>
      <div className="filters">
        <select value={type} onChange={(e) => { setType(e.target.value); setPage(0); }} aria-label="Event type">
          <option value="">All events</option>
          {d?.event_types.map((t) => <option key={t} value={t}>{eventLabel(t)}</option>)}
        </select>
        <input type="search" placeholder="Search credential, person or detail" value={q}
               onChange={(e) => { setQ(e.target.value); setPage(0); }} aria-label="Search events" />
        <a className="btn" href="#/verify">Verify integrity</a>
      </div>
      <ListView title={`${d?.total ?? ""} events, newest first`} filterable={false} rows={d?.rows}
                columns={[
                  { key: "seq", label: "#", width: "4rem" },
                  { key: "ts", label: "When", render: (r) => fmtTime(r.ts) },
                  { key: "event_type", label: "Event", render: (r) => eventLabel(r.event_type) },
                  { key: "subject", label: "About", render: (r) => subjectText(r.subject) },
                  { key: "details", label: "Details", render: (r) => <span className="details">{detailText(r.details)}</span> },
                  { key: "hash", label: "Entry hash", render: (r) => <code className="hash" title={r.hash}>{r.hash.slice(0, 12)}</code> },
                ]} />
      {d && d.total > size && (
        <div className="pager">
          <button className="btn" disabled={page === 0} onClick={() => setPage(page - 1)}>Newer</button>
          <span>Page {page + 1} of {Math.ceil(d.total / size)}</span>
          <button className="btn" disabled={(page + 1) * size >= d.total} onClick={() => setPage(page + 1)}>Older</button>
        </div>
      )}
    </div>
  );
}

export function Verify() {
  const [r, setR] = useState(null);
  const act = useAction();
  const run = async () => setR(await act(() => api("/audit/verify")));
  return (
    <div className="page">
      <h1 className="page-title">Log integrity</h1>
      <section className="card">
        <p>Every event on this node is chained to the one before it by hash and signed with this node's key. Peers you talk
          to remember how far your log reached, so a rewritten or shortened log is caught by them even if it verifies here.</p>
        <button className="btn btn-primary" onClick={run}>Verify the log now</button>
        {r && (
          <div className={`verify ${r.ok ? "verify-ok" : "verify-bad"}`}>
            {r.ok ? <h2>All {r.entries} entries verify</h2>
              : <h2>The chain breaks at entry #{r.first_bad_seq}</h2>}
            <p>Current head <code className="hash">{r.head}</code></p>
          </div>
        )}
      </section>
      {r && (
        <ListView title="Peer log anchors: how far each peer's log had reached when you last talked" filterable={false}
                  rows={r.anchors.map((a) => ({ ...a, id: a.peer_fpr }))}
                  empty="No peer anchors yet. They appear after your node talks to a peer."
                  columns={[
                    { key: "peer_name", label: "Peer" },
                    { key: "peer_fpr", label: "Fingerprint", render: (a) => <code>{shortFpr(a.peer_fpr)}</code> },
                    { key: "seq", label: "Their log length" },
                    { key: "hash", label: "Their head", render: (a) => <code className="hash">{a.hash.slice(0, 16)}</code> },
                    { key: "ts", label: "Seen", render: (a) => fmtTime(a.ts) },
                  ]} />
      )}
    </div>
  );
}

export function Alerts() {
  const [rows, reload] = usePoll("/alerts", 6000);
  const act = useAction();
  return (
    <div className="page">
      <ListView title="Security alerts" rows={rows} empty="No alerts. Forked group histories and rewritten peer logs show up here."
                columns={[
                  { key: "ts", label: "When", render: (r) => fmtTime(r.ts) },
                  { key: "kind", label: "Kind", render: (r) => eventLabel(r.kind) },
                  { key: "message", label: "What happened" },
                  { key: "act", label: "", render: (r) => (r.ack ? <span className="muted">Acknowledged</span> : (
                    <button className="btn" onClick={async () => { if (await act(() => post(`/alerts/${r.id}/ack`))) reload(); }}>Acknowledge</button>)) },
                ]} />
    </div>
  );
}
