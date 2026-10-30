import { useState } from "react";
import { post, put } from "../api.js";
import { fmtTime, go, minutesLabel, usePoll } from "../util.js";
import { Badge, Countdown, Dot, Field, ListView, Modal, ReadField, Tabs, useAction } from "../components/ui.jsx";
import { CredentialForm } from "./Vault.jsx";

export function Groups() {
  const [rows, reload] = usePoll("/groups", 8000);
  const [creating, setCreating] = useState(false);
  return (
    <div className="page">
      <ListView title="Groups" rows={rows} onRow={(r) => go(`/groups/${r.group_id}`)}
                empty="You are not in any group yet. Create one, or ask a custodian to add you."
                actions={<button className="btn btn-primary" onClick={() => setCreating(true)}>New group</button>}
                columns={[
                  { key: "name", label: "Name", render: (r) => <a href={`#/groups/${r.group_id}`}>{r.name}</a> },
                  { key: "role", label: "Your role", text: (r) => (r.is_custodian ? "Custodian" : "Member") },
                  { key: "custodians", label: "Custodians", text: (r) => r.custodians.map((c) => c.name).join(", "),
                    render: (r) => r.custodians.map((c) => <span key={c.fpr} className="person"><Dot on={c.online || c.me} /> {c.name}</span>) },
                  { key: "members", label: "Members", text: (r) => String(r.members.length) },
                  { key: "credentials", label: "Credentials", text: (r) => String(r.credentials.length) },
                  { key: "policy", label: "Auto-approval", text: (r) => (r.policy.auto_approve_members
                      ? `Members, up to ${minutesLabel(r.policy.max_lease_minutes)}` : "Off") },
                  { key: "version", label: "Version" },
                ]} />
      {creating && <NewGroup onClose={() => setCreating(false)} onDone={(id) => { setCreating(false); reload(); go(`/groups/${id}`); }} />}
    </div>
  );
}

function NewGroup({ onClose, onDone }) {
  const [peers] = usePoll("/peers", 0);
  const [f, setF] = useState({ name: "", description: "", max_lease_minutes: 60, default_lease_minutes: 30,
                               auto_approve_members: true, allow_non_member_requests: true, members: [], custodians: [] });
  const act = useAction();
  const toggle = (k, fpr) => setF({ ...f, [k]: f[k].includes(fpr) ? f[k].filter((x) => x !== fpr) : [...f[k], fpr] });
  return (
    <Modal title="New group" onClose={onClose}
           footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary" form="ng">Create group</button></>}>
      <form id="ng" className="grid2" onSubmit={async (e) => {
        e.preventDefault();
        const r = await act(() => post("/groups", f), "Group created and sent to its members");
        if (r) onDone(r.group_id);
      }}>
        <Field label="Name" wide><input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required autoFocus /></Field>
        <Field label="Description" wide><input value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <Field label="Longest checkout members get automatically (minutes)">
          <input type="number" min="5" max="1440" value={f.max_lease_minutes} onChange={(e) => setF({ ...f, max_lease_minutes: +e.target.value })} />
        </Field>
        <Field label="Default checkout (minutes)">
          <input type="number" min="5" max="1440" value={f.default_lease_minutes} onChange={(e) => setF({ ...f, default_lease_minutes: +e.target.value })} />
        </Field>
        <label className="check"><input type="checkbox" checked={f.auto_approve_members}
               onChange={(e) => setF({ ...f, auto_approve_members: e.target.checked })} /> Approve members automatically (never for Critical accounts)</label>
        <label className="check"><input type="checkbox" checked={f.allow_non_member_requests}
               onChange={(e) => setF({ ...f, allow_non_member_requests: e.target.checked })} /> Let non-members ask for manual approval</label>
        <fieldset className="field-wide people-pick">
          <legend>People (only paired teammates can be added)</legend>
          {(peers || []).map((p) => (
            <div key={p.fpr} className="people-row">
              <span>{p.name}</span>
              <label className="check"><input type="checkbox" checked={f.members.includes(p.fpr)} onChange={() => toggle("members", p.fpr)} /> Member</label>
              <label className="check"><input type="checkbox" checked={f.custodians.includes(p.fpr)} onChange={() => toggle("custodians", p.fpr)} /> Co-custodian</label>
            </div>
          ))}
          {peers && !peers.length && <p className="muted">Pair with teammates first.</p>}
        </fieldset>
      </form>
    </Modal>
  );
}

export function GroupRecord({ id }) {
  const [g, reload] = usePoll(`/groups/${id}`, 6000);
  const [peers] = usePoll("/peers", 0);
  const [s] = usePoll("/status", 0);
  const [modal, setModal] = useState(null);
  const [addFpr, setAddFpr] = useState("");
  const act = useAction();
  if (!g) return <div className="loading">Loading…</div>;
  const change = async (body, msg) => { if (await act(() => put(`/groups/${id}`, body), msg)) { setModal(null); reload(); } };
  const inGroup = new Set([...g.members, ...g.custodians].map((p) => p.fpr));
  const candidates = (peers || []).filter((p) => !inGroup.has(p.fpr));

  return (
    <div className="page">
      <div className="record-head">
        <div>
          <a href="#/groups" className="crumb">Groups</a>
          <h1 className="page-title">{g.name}</h1>
        </div>
        {g.is_custodian && (
          <div className="record-actions">
            <button className="btn btn-primary" onClick={() => setModal("cred")}>Add credential</button>
            <button className="btn" onClick={() => setModal("member")}>Add member</button>
            <button className="btn" onClick={() => setModal("policy")}>Edit policy</button>
          </div>
        )}
      </div>
      <section className="card form-grid">
        <ReadField label="Description" wide>{g.description}</ReadField>
        <ReadField label="Your role">{g.is_custodian ? "Custodian" : "Member"}</ReadField>
        <ReadField label="Version">v{g.version} <code className="hash" title={g.hash}>{g.hash.slice(0, 16)}</code></ReadField>
        <ReadField label="Automatic approval">{g.policy.auto_approve_members
          ? `Members, up to ${minutesLabel(g.policy.max_lease_minutes)}. Critical accounts always need a custodian.` : "Off. Custodians approve every request."}</ReadField>
        <ReadField label="Non-members">{g.policy.allow_non_member_requests ? "May ask; a custodian decides" : "Requests are denied"}</ReadField>
        <ReadField label="Default checkout">{minutesLabel(g.policy.default_lease_minutes)}</ReadField>
      </section>
      <Tabs tabs={[
        { label: "Credentials", count: g.credentials.length, body: (
          <ListView title="Credentials" filterable={false} rows={g.credentials.map((c) => ({ ...c, id: c.cred_id }))}
                    onRow={g.is_custodian ? (r) => go(`/credentials/${encodeURIComponent(r.cred_id)}`) : undefined}
                    columns={[
                      { key: "name", label: "Name" },
                      { key: "account_type", label: "Account type" },
                      { key: "criticality", label: "Criticality", render: (r) => <Badge value={r.criticality} /> },
                      { key: "username", label: "Username", render: (r) => <code>{r.username}</code> },
                      { key: "url", label: "URL or host" },
                      ...(g.is_custodian ? [{ key: "rm", label: "", render: (r) => (
                        <button className="btn btn-quiet" onClick={(e) => { e.stopPropagation();
                          if (confirm(`Remove ${r.name} from ${g.name}?`)) change({ credentials_remove: [r.cred_id] }, "Credential removed"); }}>Remove</button>) }] : []),
                    ]} />) },
        { label: "People", count: g.members.length + g.custodians.length, body: (
          <ListView title="Custodians and members" filterable={false}
                    rows={[...g.custodians.map((p) => ({ ...p, role: "Custodian" })), ...g.members.map((p) => ({ ...p, role: "Member" }))]}
                    columns={[
                      { key: "name", label: "Name", render: (r) => <><Dot on={r.online || r.me} /> {r.name}{r.me ? " (you)" : ""}</> },
                      { key: "title", label: "Title" },
                      { key: "role", label: "Role" },
                      { key: "fpr", label: "Fingerprint", render: (r) => <code className="fpr">{r.fpr}</code> },
                      ...(g.is_custodian ? [{ key: "rm", label: "", render: (r) => r.role === "Member" && (
                        <button className="btn btn-quiet" onClick={() => {
                          if (confirm(`Remove ${r.name}? Credentials they checked out in the last 30 days will be flagged for rotation.`))
                            change({ members_remove: [r.fpr] }, "Member removed");
                        }}>Remove</button>) }] : []),
                    ]} />) },
        { label: "Checkouts", count: g.checkouts.length, body: (
          <ListView title="Checkouts" filterable={false} rows={g.checkouts} empty={g.is_custodian ? "None yet." : "Only custodians see checkout history."}
                    columns={[
                      { key: "cred_name", label: "Credential" },
                      { key: "holder_name", label: "Held by" },
                      { key: "grantor_name", label: "Granted by" },
                      { key: "status", label: "State", render: (r) => <Badge value={r.status} /> },
                      { key: "expires_at", label: "Ends", render: (r) => (r.status === "active" ? <Countdown until={r.expires_at} /> : fmtTime(r.expires_at)) },
                    ]} />) },
        { label: "Version history", count: g.history.length, body: (
          <ListView title="Signed versions" filterable={false} rows={g.history.map((h) => ({ ...h, id: h.hash }))}
                    columns={[
                      { key: "version", label: "Version" },
                      { key: "hash", label: "Hash", render: (r) => <code className="hash">{r.hash}</code> },
                      { key: "signed_by", label: "Signed by", text: (r) => r.signed_by.join(", ") },
                    ]} />) },
      ]} />

      {modal === "cred" && s && (
        <CredentialForm title={`Add credential to ${g.name}`} types={s.account_types} crits={s.criticalities}
                        onClose={() => setModal(null)}
                        onSave={(f) => change({ credentials_add: [f] }, "Credential added and shared with co-custodians")} />
      )}
      {modal === "member" && (
        <Modal title={`Add member to ${g.name}`} onClose={() => setModal(null)}
               footer={<><button className="btn" onClick={() => setModal(null)}>Cancel</button>
                 <button className="btn btn-primary" disabled={!addFpr} onClick={() => change({ members_add: [addFpr] }, "Member added")}>Add member</button></>}>
          {candidates.length ? (
            <Field label="Paired teammate">
              <select value={addFpr} onChange={(e) => setAddFpr(e.target.value)}>
                <option value="">Choose</option>
                {candidates.map((p) => <option key={p.fpr} value={p.fpr}>{p.name}, {p.title}</option>)}
              </select>
            </Field>
          ) : <p>Everyone you are paired with is already in this group. Pair with a teammate first.</p>}
        </Modal>
      )}
      {modal === "policy" && <PolicyForm policy={g.policy} onClose={() => setModal(null)} onSave={(p) => change({ policy: p }, "Policy updated")} />}
    </div>
  );
}

function PolicyForm({ policy, onClose, onSave }) {
  const [p, setP] = useState(policy);
  return (
    <Modal title="Edit policy" onClose={onClose}
           footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn btn-primary" onClick={() => onSave(p)}>Save policy</button></>}>
      <div className="grid2">
        <Field label="Longest automatic checkout (minutes)">
          <input type="number" min="5" max="1440" value={p.max_lease_minutes} onChange={(e) => setP({ ...p, max_lease_minutes: +e.target.value })} />
        </Field>
        <Field label="Default checkout (minutes)">
          <input type="number" min="5" max="1440" value={p.default_lease_minutes} onChange={(e) => setP({ ...p, default_lease_minutes: +e.target.value })} />
        </Field>
        <label className="check"><input type="checkbox" checked={p.auto_approve_members}
               onChange={(e) => setP({ ...p, auto_approve_members: e.target.checked })} /> Approve members automatically</label>
        <label className="check"><input type="checkbox" checked={p.allow_non_member_requests}
               onChange={(e) => setP({ ...p, allow_non_member_requests: e.target.checked })} /> Let non-members ask</label>
      </div>
    </Modal>
  );
}
