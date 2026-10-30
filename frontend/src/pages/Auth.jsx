import { useState } from "react";
import { BASE, post, setCsrf } from "../api.js";
import { go } from "../util.js";
import { PeaPod } from "../components/Logo.jsx";
import { Field } from "../components/ui.jsx";

function Frame({ children }) {
  return (
    <div className="gate">
      <div className="gate-card">
        <div className="gate-mark"><PeaPod size={300} /></div>
        <h1 className="gate-title">P2PSec</h1>
        <p className="gate-sub">Privileged credentials, shared peer to peer. Nothing leaves this machine unless you approve it.</p>
        {children}
      </div>
    </div>
  );
}

export function Unlock({ status, onDone }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await post("/unlock", { username, password });
      setCsrf(r.csrf);
      await onDone();
    } catch (err) {
      setError(err.status === 401 ? "Wrong username or password. Failed attempts are logged." : err.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Frame>
      <form onSubmit={submit} className="gate-form">
        <div className="gate-who">
          <strong>{status.profile.name}</strong>
          <span>{status.profile.title}</span>
          <code className="fpr">{status.fpr}</code>
        </div>
        <Field label="Username">
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username"
                 autoCapitalize="none" spellCheck={false} required />
        </Field>
        <Field label="Master password">
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
                 autoComplete="current-password" required />
        </Field>
        {error && <p className="form-error" role="alert">{error}</p>}
        <button className="btn btn-primary btn-block" disabled={busy}>{busy ? "Unlocking…" : "Unlock vault"}</button>
        {status.service_ready && (
          <p className="gate-note">This node is still serving teammates while locked: group checkouts and receipts keep working.</p>
        )}
        {status.login_hint && (
          <p className="gate-demo">
            {status.demo ? "Demo user. " : "First sign-in. "}Username and password: <code>{status.login_hint}</code>
            {!status.demo && ". Change them in Node settings after you sign in."}
          </p>
        )}
        {status.demo_available && (
          <button type="button" className="btn btn-block" onClick={() => go("/demo-mode")}>Demo mode: try a seeded six-person team</button>
        )}
        {BASE !== "/" && <a className="gate-back" href="/">Back to my own node</a>}
      </form>
    </Frame>
  );
}

export function Setup({ onDone }) {
  const [f, setF] = useState({ name: "", title: "", dept: "", password: "", confirm: "" });
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const submit = async (e) => {
    e.preventDefault();
    if (f.password !== f.confirm) return setError("The two passwords do not match.");
    if (f.password.length < 12) return setError("Use at least 12 characters for the master password.");
    setBusy(true);
    try {
      const r = await post("/setup", f);
      setCsrf(r.csrf);
      await onDone();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Frame>
      <form onSubmit={submit} className="gate-form">
        <p className="gate-note">Set up this node. Your keys are generated here and never leave this computer.</p>
        <Field label="Your name"><input value={f.name} onChange={set("name")} required autoFocus /></Field>
        <Field label="Job title"><input value={f.title} onChange={set("title")} /></Field>
        <Field label="Department"><input value={f.dept} onChange={set("dept")} /></Field>
        <Field label="Master password" hint="It cannot be recovered. Losing it means losing this vault.">
          <input type="password" value={f.password} onChange={set("password")} autoComplete="new-password" required />
        </Field>
        <Field label="Confirm master password">
          <input type="password" value={f.confirm} onChange={set("confirm")} autoComplete="new-password" required />
        </Field>
        {error && <p className="form-error" role="alert">{error}</p>}
        <button className="btn btn-primary btn-block" disabled={busy}>{busy ? "Creating keys…" : "Create vault"}</button>
      </form>
    </Frame>
  );
}
