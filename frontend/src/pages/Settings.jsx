import { useState } from "react";
import { post, put } from "../api.js";
import { Field, ReadField, useAction } from "../components/ui.jsx";

export function Settings({ status }) {
  const [p, setP] = useState(status.profile);
  const [pw, setPw] = useState({ old: "", new: "", confirm: "" });
  const [login, setLogin] = useState("");
  const act = useAction();
  return (
    <div className="page">
      <h1 className="page-title">Node settings</h1>
      <div className="split">
        <section className="card">
          <h2>About this node</h2>
          <div className="form-grid">
            <ReadField label="Node">{status.node_id}</ReadField>
            <ReadField label="Peer address"><code>{status.peer_addr}</code></ReadField>
            <ReadField label="Fingerprint" wide><code className="fpr">{status.fpr}</code></ReadField>
            <ReadField label="Auto-lock">After {Math.round(status.idle_lock_seconds / 60)} minutes idle</ReadField>
            <ReadField label="Keys">{status.demo ? "Demo: derived from a public seed. Do not store real secrets." : "Generated on this machine"}</ReadField>
          </div>
          <h3 className="sub">Lock and go offline</h3>
          <p className="muted">The normal lock keeps this node serving teammates (group checkouts, receipts, expiry).
            Going offline wipes every key from memory; nobody can reach this node until you unlock it again.</p>
          <button className="btn btn-danger" onClick={async () => {
            if (confirm("Wipe all keys from memory and go offline?")) { await act(() => post("/lock-full")); window.location.reload(); }
          }}>Lock and go offline</button>
        </section>
        <section className="card">
          <h2>Profile</h2>
          <p className="muted">Teammates see this when you pair. Changes reach them the next time you pair.</p>
          <form onSubmit={(e) => { e.preventDefault(); act(() => put("/settings/profile", p), "Profile saved"); }}>
            <Field label="Name"><input value={p.name} onChange={(e) => setP({ ...p, name: e.target.value })} required /></Field>
            <Field label="Job title"><input value={p.title} onChange={(e) => setP({ ...p, title: e.target.value })} /></Field>
            <Field label="Department"><input value={p.dept} onChange={(e) => setP({ ...p, dept: e.target.value })} /></Field>
            <div className="form-actions"><button className="btn btn-primary">Save profile</button></div>
          </form>
          <h2>Username</h2>
          <form onSubmit={async (e) => {
            e.preventDefault();
            if (await act(() => put("/settings/login", { username: login }), "Username changed")) setLogin("");
          }}>
            <Field label="New username" hint="Used only to sign in to this node.">
              <input value={login} onChange={(e) => setLogin(e.target.value)} required maxLength={64} autoComplete="username" />
            </Field>
            <div className="form-actions"><button className="btn btn-primary">Change username</button></div>
          </form>
          <h2>Master password</h2>
          {status.default_password && <p className="form-error">You are using the default password "user". Change it now.</p>}
          <form onSubmit={async (e) => {
            e.preventDefault();
            if (pw.new !== pw.confirm) return act(async () => { throw new Error("The new passwords do not match."); });
            if (await act(() => post("/settings/password", { old: pw.old, new: pw.new }), "Master password changed")) {
              setPw({ old: "", new: "", confirm: "" });
              window.location.reload();
            }
          }}>
            <Field label="Current"><input type="password" value={pw.old} onChange={(e) => setPw({ ...pw, old: e.target.value })} required autoComplete="current-password" /></Field>
            <Field label="New"><input type="password" value={pw.new} onChange={(e) => setPw({ ...pw, new: e.target.value })} required minLength={12} autoComplete="new-password" /></Field>
            <Field label="Confirm new"><input type="password" value={pw.confirm} onChange={(e) => setPw({ ...pw, confirm: e.target.value })} required autoComplete="new-password" /></Field>
            <div className="form-actions"><button className="btn btn-primary">Change master password</button></div>
          </form>
        </section>
      </div>
    </div>
  );
}
