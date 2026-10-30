import { useMemo, useState } from "react";
import { post } from "../api.js";
import { ago, eventLabel, fmtTime, go, minutesLabel, recNo, usePoll } from "../util.js";
import { Badge, Countdown, Dot, Field, ListView, useAction } from "../components/ui.jsx";

export function Dashboard() {
  const [d] = usePoll("/dashboard", 5000);
  if (!d) return <div className="loading">Loading dashboard…</div>;
  const tiles = [
    { n: d.pending_approvals, label: "Requests waiting for your approval", to: "/approvals", tone: d.pending_approvals ? "warn" : "" },
    { n: d.checked_out_to_me, label: "Credentials checked out to you", to: "/checkouts" },
    { n: d.checked_out_by_me, label: "Checkouts you or your groups granted", to: "/access" },
    { n: d.expiring_soon, label: "Checkouts ending within an hour", to: "/access" },
    { n: d.rotations_due, label: "Credentials due for rotation", to: "/rotations", tone: d.rotations_due ? "bad" : "" },
    { n: `${d.peers_online}/${d.peers_total}`, label: "Paired peers online now", to: "/peers" },
  ];
  return (
    <div className="page">
      <h1 className="page-title">Dashboard</h1>
      {d.alerts > 0 && (
        <a className="alert-strip" href="#/alerts">{d.alerts} security alert{d.alerts > 1 ? "s" : ""} need your attention.</a>
      )}
      <div className="tiles">
        {tiles.map((t) => (
          <a key={t.label} href={`#${t.to}`} className={`tile ${t.tone ? `tile-${t.tone}` : ""}`}>
            <span className="tile-n">{t.n}</span><span className="tile-label">{t.label}</span>
          </a>
        ))}
      </div>
      <div className="split">
        <ListView title="Active checkouts" filterable={false} rows={d.active_leases}
                  empty="Nothing is checked out right now."
                  onRow={(r) => go(r.direction === "in" ? "/checkouts" : "/access")}
                  columns={[
                    { key: "cred_name", label: "Credential" },
                    { key: "criticality", label: "Criticality", render: (r) => <Badge value={r.criticality} /> },
                    { key: "who", label: "Held by", text: (r) => (r.direction === "in" ? "You" : r.holder_name),
                      render: (r) => (r.direction === "in" ? <strong>You</strong> : r.holder_name) },
                    { key: "expires_at", label: "Time left", render: (r) => <Countdown until={r.expires_at} /> },
                  ]} />
        <section className="list">
          <header className="list-head"><h2>Recent activity on this node</h2></header>
          <ol className="activity">
            {d.recent.map((e) => (
              <li key={e.seq}>
                <span className="activity-what">{eventLabel(e.event_type)}</span>
                <span className="activity-subject">{e.subject.cred_name || e.subject.peer_name || e.subject.group_name || ""}</span>
                <time title={fmtTime(e.ts)}>{ago(e.ts)}</time>
              </li>
            ))}
          </ol>
          <a className="list-foot" href="#/audit">Open the full event log</a>
        </section>
      </div>
    </div>
  );
}

function approvalNote(c, minutes) {
  if (c.criticality === "Critical") return "Critical account: a custodian approves every checkout by hand.";
  if (!c.is_member) return c.policy.allow_non_member_requests
    ? "You are not in this group, so a custodian has to approve."
    : "Members only. This request will be denied by group policy.";
  if (!c.policy.auto_approve_members) return "A custodian approves each request.";
  if (minutes > c.policy.max_lease_minutes)
    return `Over the ${minutesLabel(c.policy.max_lease_minutes)} limit, so a custodian has to approve.`;
  return "You are a member: this is approved automatically when a custodian's node is reachable.";
}

const DURATIONS = [15, 30, 60, 120, 240, 480];

export function Catalog() {
  const [cat, reload] = usePoll("/catalog", 10000);
  const [mode, setMode] = useState("group");
  const [pick, setPick] = useState(null);
  const [q, setQ] = useState("");
  const [form, setForm] = useState({ ticket: "", reason: "", minutes: 30, owner_fpr: "", description: "" });
  const act = useAction();
  const items = useMemo(() => (cat?.credentials || []).filter((c) => !c.is_custodian &&
    (!q || `${c.name} ${c.group_name} ${c.username}`.toLowerCase().includes(q.toLowerCase()))), [cat, q]);
  const grouped = useMemo(() => items.reduce((m, c) => ((m[c.group_name] ||= []).push(c), m), {}), [items]);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const choose = (c) => { setPick(c); setForm((f) => ({ ...f, minutes: c.policy.default_lease_minutes })); };
  const submit = async (e) => {
    e.preventDefault();
    const body = mode === "group"
      ? { group_id: pick.group_id, cred_id: pick.cred_id, ticket: form.ticket, reason: form.reason, minutes: +form.minutes }
      : { owner_fpr: form.owner_fpr, description: form.description, ticket: form.ticket, reason: form.reason, minutes: +form.minutes };
    if (await act(() => post("/requests", body), "Request sent")) {
      setForm({ ticket: "", reason: "", minutes: 30, owner_fpr: "", description: "" });
      setPick(null);
      reload();
      go("/requests");
    }
  };

  return (
    <div className="page">
      <h1 className="page-title">Request a credential</h1>
      <div className="tabs tabs-page" role="tablist">
        <button role="tab" aria-selected={mode === "group"} className={mode === "group" ? "tab tab-on" : "tab"}
                onClick={() => setMode("group")}>From a group</button>
        <button role="tab" aria-selected={mode === "person"} className={mode === "person" ? "tab tab-on" : "tab"}
                onClick={() => setMode("person")}>From a person</button>
      </div>
      <div className="catalog">
        {mode === "group" ? (
          <div className="catalog-list">
            <input type="search" className="list-search" placeholder="Search credentials" value={q}
                   onChange={(e) => setQ(e.target.value)} aria-label="Search credentials" />
            {!cat && <p className="loading">Loading…</p>}
            {cat && !items.length && (
              <p className="empty-note">No group credentials to request. You see a group's credentials once a custodian
                adds you to it and your nodes are paired.</p>
            )}
            {Object.entries(grouped).map(([g, cs]) => (
              <div key={g} className="catalog-group">
                <h3>{g}</h3>
                {cs.map((c) => (
                  <button key={c.cred_id} className={`catalog-item ${pick?.cred_id === c.cred_id ? "catalog-on" : ""}`}
                          onClick={() => choose(c)}>
                    <span className="catalog-name">{c.name}<Badge value={c.criticality} /></span>
                    <span className="catalog-meta">{c.account_type} · {c.username}</span>
                    <span className="catalog-cust">
                      {c.custodians.map((p) => <span key={p.fpr}><Dot on={p.online} /> {p.name}</span>)}
                    </span>
                  </button>
                ))}
              </div>
            ))}
          </div>
        ) : (
          <div className="catalog-list">
            <p className="empty-note">Ask a paired teammate for one of their personal credentials. Describe what you
              need; they choose which credential to share.</p>
          </div>
        )}

        <form className="card form-card" onSubmit={submit}>
          {mode === "group" && !pick ? (
            <p className="empty-note">Choose a credential on the left to request it.</p>
          ) : (
            <>
              {mode === "group" ? (
                <div className="form-intro">
                  <h2>{pick.name}</h2>
                  <p>{pick.group_name} · {pick.account_type} · <code>{pick.username}</code></p>
                </div>
              ) : (
                <>
                  <Field label="Teammate">
                    <select value={form.owner_fpr} onChange={set("owner_fpr")} required>
                      <option value="">Choose a paired teammate</option>
                      {cat?.people.map((p) => <option key={p.fpr} value={p.fpr}>{p.name}{p.online ? "" : " (offline)"}</option>)}
                    </select>
                  </Field>
                  <Field label="What you need"><input value={form.description} onChange={set("description")}
                         placeholder="e.g. your Grafana login for the on-call dashboards" required /></Field>
                </>
              )}
              <Field label="Ticket reference" hint="Incident, change or request number that justifies access.">
                <input value={form.ticket} onChange={set("ticket")} placeholder="INC0012345" required />
              </Field>
              <Field label="Justification">
                <textarea value={form.reason} onChange={set("reason")} rows={3} required
                          placeholder="What you will do with this access" />
              </Field>
              <Field label="Checkout duration">
                <select value={form.minutes} onChange={set("minutes")}>
                  {DURATIONS.map((m) => <option key={m} value={m}>{minutesLabel(m)}</option>)}
                </select>
              </Field>
              {mode === "group" && <p className="policy-note">{approvalNote(pick, +form.minutes)}</p>}
              <div className="form-actions"><button className="btn btn-primary">Submit request</button></div>
            </>
          )}
        </form>
      </div>
    </div>
  );
}

export function MyRequests() {
  const [rows] = usePoll("/requests", 4000);
  return (
    <div className="page">
      <ListView title="My requests" rows={rows} empty="You have not requested anything yet."
                actions={<a className="btn btn-primary" href="#/catalog">New request</a>}
                columns={[
                  { key: "id", label: "Number", text: (r) => recNo("REQ", r.id) },
                  { key: "cred_name", label: "Credential" },
                  { key: "target_name", label: "Asked" },
                  { key: "ticket", label: "Ticket" },
                  { key: "minutes", label: "Duration", render: (r) => minutesLabel(r.minutes) },
                  { key: "status", label: "State", render: (r) => <Badge value={r.status} /> },
                  { key: "decided_by", label: "Decided by", render: (r) => r.decided_by || (r.status === "pending" ? "Waiting" : "") },
                  { key: "comment", label: "Comment" },
                  { key: "created_at", label: "Opened", sortValue: (r) => r.created_at, render: (r) => fmtTime(r.created_at) },
                ]} />
    </div>
  );
}
