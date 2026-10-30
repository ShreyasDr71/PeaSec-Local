import { useState } from "react";
import { api, del, post, put } from "../api.js";
import { eventLabel, fmtTime, generatePassword, go, recNo, usePoll } from "../util.js";
import { Badge, Countdown, Field, ListView, Modal, ReadField, Secret, Tabs, revealer, useAction } from "../components/ui.jsx";

const blank = { name: "", url: "", username: "", account_type: "Application", criticality: "Medium", notes: "", secret: "" };

export function CredentialForm({ initial = blank, onSave, onClose, title, requireSecret = true, types, crits }) {
  const [f, setF] = useState(initial);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  return (
    <Modal title={title} onClose={onClose}
           footer={<><button className="btn" onClick={onClose}>Cancel</button>
             <button className="btn btn-primary" form="cred-form">Save</button></>}>
      <form id="cred-form" className="grid2" onSubmit={(e) => { e.preventDefault(); onSave(f); }}>
        <Field label="Name"><input value={f.name} onChange={set("name")} required autoFocus /></Field>
        <Field label="Username"><input value={f.username} onChange={set("username")} /></Field>
        <Field label="Account type">
          <select value={f.account_type} onChange={set("account_type")}>{types.map((t) => <option key={t}>{t}</option>)}</select>
        </Field>
        <Field label="Criticality">
          <select value={f.criticality} onChange={set("criticality")}>{crits.map((t) => <option key={t}>{t}</option>)}</select>
        </Field>
        <Field label="URL or host" wide><input value={f.url} onChange={set("url")} /></Field>
        <Field label={requireSecret ? "Secret" : "New secret (leave blank to keep)"} wide>
          <div className="input-row">
            <input type="text" value={f.secret} onChange={set("secret")} required={requireSecret} autoComplete="off"
                   spellCheck={false} className="mono" />
            <button type="button" className="btn btn-quiet" onClick={() => setF({ ...f, secret: generatePassword() })}>Generate</button>
          </div>
        </Field>
        <Field label="Notes" wide><textarea rows={2} value={f.notes} onChange={set("notes")} /></Field>
      </form>
    </Modal>
  );
}

function useEnums() {
  const [s] = usePoll("/status", 0);
  return { types: s?.account_types || ["Application"], crits: s?.criticalities || ["Medium"] };
}

export function Credentials() {
  const [rows, reload] = usePoll("/credentials", 8000);
  const [adding, setAdding] = useState(false);
  const act = useAction();
  const enums = useEnums();
  return (
    <div className="page">
      <ListView title="My credentials" rows={rows} onRow={(r) => go(`/credentials/${encodeURIComponent(r.id)}`)}
                empty="No credentials yet. Add one, or become a custodian of a group."
                actions={<button className="btn btn-primary" onClick={() => setAdding(true)}>New</button>}
                columns={[
                  { key: "name", label: "Name", render: (r) => <a href={`#/credentials/${encodeURIComponent(r.id)}`}>{r.name}</a> },
                  { key: "scope", label: "Held as", text: (r) => (r.scope === "group" ? `Custodian: ${r.group_name}` : "Personal") },
                  { key: "account_type", label: "Account type" },
                  { key: "criticality", label: "Criticality", render: (r) => <Badge value={r.criticality} /> },
                  { key: "username", label: "Username", render: (r) => <code>{r.username}</code> },
                  { key: "active_checkouts", label: "Checked out", render: (r) => r.active_checkouts || "" },
                  { key: "open_rotation", label: "Rotation", text: (r) => (r.open_rotation ? "Due" : ""),
                    render: (r) => (r.open_rotation ? <Badge value="open" /> : "") },
                  { key: "rotated_at", label: "Last rotated", sortValue: (r) => r.rotated_at, render: (r) => fmtTime(r.rotated_at) },
                ]} />
      {adding && (
        <CredentialForm title="New personal credential" {...enums} onClose={() => setAdding(false)}
                        onSave={async (f) => { if (await act(() => post("/credentials", f), "Credential saved")) { setAdding(false); reload(); } }} />
      )}
    </div>
  );
}

export function CredentialRecord({ id }) {
  const [d, reload] = usePoll(`/credentials/${encodeURIComponent(id)}`, 8000);
  const [editing, setEditing] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [newSecret, setNewSecret] = useState("");
  const act = useAction();
  const enums = useEnums();
  if (!d) return <div className="loading">Loading…</div>;
  const c = d.record;
  const personal = c.scope === "personal";

  const rotate = async (e) => {
    e.preventDefault();
    if (await act(() => post(`/credentials/${encodeURIComponent(id)}/rotate`, { secret: newSecret }),
      personal ? "Secret rotated" : "Secret rotated and sent to the other custodians")) {
      setRotating(false); setNewSecret(""); reload();
    }
  };

  return (
    <div className="page">
      <div className="record-head">
        <div>
          <a href="#/credentials" className="crumb">My credentials</a>
          <h1 className="page-title">{c.name} <Badge value={c.criticality} /></h1>
        </div>
        <div className="record-actions">
          <button className={`btn ${c.open_rotation ? "btn-primary" : ""}`} onClick={() => setRotating(true)}>Rotate secret</button>
          {personal && <button className="btn" onClick={() => setEditing(true)}>Edit</button>}
          {personal && (
            <button className="btn btn-danger" onClick={async () => {
              if (confirm(`Delete "${c.name}" from this vault?`) &&
                  await act(() => del(`/credentials/${encodeURIComponent(id)}`), "Credential deleted")) go("/credentials");
            }}>Delete</button>
          )}
        </div>
      </div>
      {c.open_rotation && (
        <p className="alert-strip alert-strip-static">Rotation due: someone held this credential and the checkout has ended. Change the
          password on the target system, then record the new secret here.</p>
      )}
      <section className="card form-grid">
        <ReadField label="Held as">{personal ? "Personal" : `Custodian of ${c.group_name}`}</ReadField>
        <ReadField label="Account type">{c.account_type}</ReadField>
        <ReadField label="Username"><code>{c.username}</code></ReadField>
        <ReadField label="URL or host">{c.url}</ReadField>
        <ReadField label="Secret" wide><Secret reveal={revealer(`/credentials/${encodeURIComponent(id)}/reveal`)} /></ReadField>
        <ReadField label="Last rotated">{fmtTime(c.rotated_at)}</ReadField>
        <ReadField label="Created">{fmtTime(c.created_at)}</ReadField>
        {c.notes && <ReadField label="Notes" wide>{c.notes}</ReadField>}
      </section>
      <Tabs tabs={[
        { label: "Access history", count: d.access.length, body: (
          <ListView title="Checkouts of this credential" filterable={false} rows={d.access}
                    empty={personal ? "Never shared." : "No one has checked this out."}
                    columns={[
                      { key: "holder_name", label: "Held by" },
                      { key: "grantor_name", label: "Granted by" },
                      { key: "ticket", label: "Ticket" },
                      { key: "granted_at", label: "Checked out", render: (r) => fmtTime(r.granted_at) },
                      { key: "status", label: "State", render: (r) => <Badge value={r.status} /> },
                      { key: "expires_at", label: "Ends", render: (r) => r.status === "active"
                          ? <Countdown until={r.expires_at} /> : fmtTime(r.ended_at || r.expires_at) },
                    ]} />) },
        { label: "Requests", count: d.requests.length, body: (
          <ListView title="Requests for this credential" filterable={false} rows={d.requests}
                    columns={[
                      { key: "id", label: "Number", text: (r) => recNo("REQ", r.id) },
                      { key: "requester_name", label: "Requested by" },
                      { key: "ticket", label: "Ticket" },
                      { key: "reason", label: "Justification" },
                      { key: "status", label: "State", render: (r) => <Badge value={r.status} /> },
                      { key: "created_at", label: "Opened", render: (r) => fmtTime(r.created_at) },
                    ]} />) },
        { label: "Rotation tasks", count: d.rotations.length, body: (
          <ListView title="Rotation tasks" filterable={false} rows={d.rotations}
                    columns={[
                      { key: "reason", label: "Why" },
                      { key: "status", label: "State", render: (r) => <Badge value={r.status} /> },
                      { key: "created_at", label: "Raised", render: (r) => fmtTime(r.created_at) },
                      { key: "closed_by", label: "Closed by" },
                    ]} />) },
        { label: "Audit events", count: d.events.length, body: (
          <ListView title="Audit events" filterable={false} rows={d.events}
                    columns={[
                      { key: "seq", label: "#" },
                      { key: "event_type", label: "Event", render: (r) => eventLabel(r.event_type) },
                      { key: "details", label: "Details", render: (r) => Object.entries(r.details).map(([k, v]) => `${k}: ${v}`).join(", ") },
                      { key: "ts", label: "When", render: (r) => fmtTime(r.ts) },
                    ]} />) },
      ]} />

      {editing && (
        <CredentialForm title="Edit credential" {...enums} requireSecret={false} initial={{ ...c, secret: "" }}
                        onClose={() => setEditing(false)}
                        onSave={async (f) => {
                          if (await act(() => put(`/credentials/${encodeURIComponent(id)}`, f), "Changes saved")) { setEditing(false); reload(); }
                        }} />
      )}
      {rotating && (
        <Modal title={`Rotate ${c.name}`} onClose={() => setRotating(false)}
               footer={<><button className="btn" onClick={() => setRotating(false)}>Cancel</button>
                 <button className="btn btn-primary" form="rot-form">Save new secret</button></>}>
          <form id="rot-form" onSubmit={rotate}>
            <p>Change the password on <strong>{c.url || "the target system"}</strong> first, then store the new value here.
              {!personal && " The other custodians of this group receive it over an encrypted channel."}</p>
            <Field label="New secret">
              <div className="input-row">
                <input className="mono" value={newSecret} onChange={(e) => setNewSecret(e.target.value)} required autoFocus spellCheck={false} />
                <button type="button" className="btn btn-quiet" onClick={() => setNewSecret(generatePassword())}>Generate</button>
              </div>
            </Field>
          </form>
        </Modal>
      )}
    </div>
  );
}

export function CheckedOut() {
  const [rows, reload] = usePoll("/leases/in", 4000);
  const act = useAction();
  return (
    <div className="page">
      <ListView title="Checked out to me" rows={rows}
                empty="Nothing is checked out to you. Request a credential when you need one."
                actions={<a className="btn btn-primary" href="#/catalog">Request a credential</a>}
                columns={[
                  { key: "cred_name", label: "Credential", render: (r) => <><strong>{r.cred_name}</strong> <Badge value={r.criticality} /></> },
                  { key: "username", label: "Username", render: (r) => <code>{r.username}</code> },
                  { key: "grantor_name", label: "Granted by" },
                  { key: "ticket", label: "Ticket" },
                  { key: "status", label: "State", render: (r) => <Badge value={r.status} /> },
                  { key: "expires_at", label: "Time left", sortValue: (r) => r.expires_at,
                    render: (r) => (r.status === "active" ? <Countdown until={r.expires_at} /> : fmtTime(r.ended_at)) },
                  { key: "secret", label: "Secret", render: (r) => r.status === "active"
                      ? <Secret reveal={revealer(`/leases/in/${r.id}/reveal`)} /> : <span className="muted">Deleted from this machine</span> },
                  { key: "act", label: "", render: (r) => r.status === "active" && (
                      <button className="btn" onClick={async () => {
                        if (await act(() => post(`/leases/in/${r.id}/checkin`), "Checked in. The secret was deleted from this machine.")) reload();
                      }}>Check in</button>) },
                ]} />
      <p className="page-note">When a checkout ends, the secret is deleted from this machine and the owner is asked to rotate it.
        Viewing or copying a secret sends a signed receipt to whoever granted it.</p>
    </div>
  );
}
