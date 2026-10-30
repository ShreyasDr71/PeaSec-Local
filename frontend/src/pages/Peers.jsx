import { useState } from "react";
import { del, post } from "../api.js";
import { ago, fmtTime, go, usePoll } from "../util.js";
import { PeaPod } from "../components/Logo.jsx";
import { Dot, Field, ListView, useAction } from "../components/ui.jsx";

// The default peer port is implied when pairing, so show it as a bare IP.
const shortAddr = (a) => (a || "").replace(/:7600$/, "");

export function Peers() {
  const [rows, reload] = usePoll("/peers", 5000);
  const act = useAction();
  return (
    <div className="page">
      <ListView title="Paired devices" rows={rows}
                empty="Not paired with anyone yet. Pair with a teammate to share credentials."
                actions={<a className="btn btn-primary" href="#/pair">Pair a device</a>}
                columns={[
                  { key: "name", label: "Person", render: (r) => <><Dot on={r.online} /> <strong>{r.name}</strong>
                      {r.demo ? <span className="badge badge-warn">Demo keys</span> : null}</> },
                  { key: "title", label: "Title" },
                  { key: "dept", label: "Department" },
                  { key: "fpr", label: "Fingerprint", render: (r) => <code className="fpr">{r.fpr}</code> },
                  { key: "addr", label: "Last address", render: (r) => <code>{r.addr}</code> },
                  { key: "last_seen", label: "Last seen", sortValue: (r) => r.last_seen, render: (r) => (r.last_seen ? ago(r.last_seen) : "Never") },
                  { key: "paired_at", label: "Paired", render: (r) => fmtTime(r.paired_at) },
                  { key: "act", label: "", render: (r) => (
                    <button className="btn btn-quiet" onClick={async () => {
                      if (confirm(`Unpair ${r.name}? Their node will no longer be able to talk to yours until you pair again.`)
                          && await act(() => del(`/peers/${encodeURIComponent(r.fpr)}`), "Unpaired")) reload();
                    }}>Unpair</button>) },
                ]} />
    </div>
  );
}

export function IncomingPairBanner() {
  const [sessions] = usePoll("/pair", 2500);
  const act = useAction();
  const incoming = (sessions || []).filter((s) => s.role === "responder" && s.state === "incoming");
  if (!incoming.length || window.location.hash.startsWith("#/pair")) return null;
  return incoming.map((s) => (
    <div key={s.id} className="pair-banner" role="alert">
      <span>A device at <code>{s.addr}</code> wants to pair with you.</span>
      <span className="row-actions">
        <button className="btn btn-primary" onClick={async () => {
          if (await act(() => post(`/pair/${s.id}/accept`, { ok: true }))) go(`/pair?s=${s.id}`);
        }}>Review</button>
        <button className="btn" onClick={() => act(() => post(`/pair/${s.id}/accept`, { ok: false }), "Declined")}>Decline</button>
      </span>
    </div>
  ));
}

export function Pair({ status }) {
  const [addr, setAddr] = useState("");
  const [sessions, reload] = usePoll("/pair", 1200);
  const [nearby] = usePoll("/peers/nearby", 5000);
  const [focus, setFocus] = useState(() => new URLSearchParams(window.location.hash.split("?")[1] || "").get("s"));
  const act = useAction();

  const start = async (a) => {
    const s = await act(() => post("/pair", { addr: a }));
    if (s) { setFocus(s.id); reload(); }
  };
  const live = (sessions || []).filter((s) => !["paired", "failed"].includes(s.state));
  const current = (sessions || []).find((s) => s.id === focus) || live.find((s) => s.state === "compare_codes") || null;

  return (
    <div className="page">
      <h1 className="page-title">Pair a device</h1>
      <div className="pair-layout">
        <section className="card">
          <h2>This device</h2>
          <dl className="facts">
            <dt>Person</dt><dd>{status.profile.name}</dd>
            <dt>Address</dt><dd><code>{shortAddr(status.peer_addr)}</code></dd>
            <dt>Fingerprint</dt><dd><code className="fpr">{status.fpr}</code></dd>
          </dl>
          <p className="muted">Give your teammate this address, or enter theirs below. Just the IP address is
            enough; add <code>:port</code> only for a different port, such as <code>:7606</code> for demo Tom.</p>
          <form className="input-row" onSubmit={(e) => { e.preventDefault(); start(addr.trim()); }}>
            <Field label="Teammate's IP address">
              <input value={addr} onChange={(e) => setAddr(e.target.value)} placeholder="192.168.1.20" required />
            </Field>
            <button className="btn btn-primary">Start pairing</button>
          </form>
          <h3 className="sub">Nearby on this network</h3>
          {nearby && nearby.length ? (
            <ul className="nearby">
              {nearby.map((n) => (
                <li key={n.fpr}>
                  <span><strong>{n.name}</strong> <code>{n.addr}</code> {n.demo && <span className="badge badge-warn">Demo keys</span>}</span>
                  {n.paired ? <span className="muted">Paired</span>
                    : <button className="btn" onClick={() => start(n.addr)}>Pair</button>}
                </li>
              ))}
            </ul>
          ) : <p className="muted">No broadcasts heard. Broadcast discovery does not cross Docker Desktop; enter an address instead.</p>}
        </section>

        <section className="card pair-stage">
          {current ? <PairSession s={current} act={act} reload={reload} />
            : (
              <div className="pair-idle">
                <PeaPod size={220} />
                <p>Pairing shows the same six-digit code on both screens. Read it aloud to each other, in person or by
                  phone, and confirm only if it matches. A mismatch means someone is in the middle.</p>
              </div>
            )}
        </section>
      </div>
      {sessions && sessions.some((s) => ["paired", "failed"].includes(s.state)) && (
        <ListView title="Recent pairing attempts" filterable={false} rows={sessions.filter((s) => ["paired", "failed"].includes(s.state))}
                  columns={[
                    { key: "addr", label: "Address", render: (r) => <code>{r.addr}</code> },
                    { key: "peer", label: "Person", text: (r) => r.peer?.name || "" },
                    { key: "state", label: "Result", text: (r) => (r.state === "paired" ? "Paired" : `Failed: ${r.error}`) },
                  ]} />
      )}
    </div>
  );
}

function PairSession({ s, act, reload }) {
  const [demoAck, setDemoAck] = useState(false);
  const confirm = (ok) => act(() => post(`/pair/${s.id}/confirm`, { ok, demo_ack: demoAck }),
    ok ? "Waiting for your teammate to confirm" : "Pairing cancelled").then(reload);

  if (s.state === "incoming") {
    return (
      <div className="pair-step">
        <h2>Incoming pairing request</h2>
        <p>A device at <code>{s.addr}</code> wants to pair. Accept only if you are expecting this.</p>
        <div className="row-actions">
          <button className="btn btn-primary" onClick={() => act(() => post(`/pair/${s.id}/accept`, { ok: true })).then(reload)}>Accept and show code</button>
          <button className="btn" onClick={() => act(() => post(`/pair/${s.id}/accept`, { ok: false }), "Declined").then(reload)}>Decline</button>
        </div>
      </div>
    );
  }
  if (["connecting", "waiting_for_peer"].includes(s.state)) {
    return <div className="pair-step"><h2>Waiting for {s.addr}</h2><p>Your teammate needs to accept the request on their screen.</p></div>;
  }
  if (s.state === "failed") {
    return <div className="pair-step"><h2>Pairing failed</h2><p className="form-error">{s.error}</p><p>Nothing was saved. You can try again.</p></div>;
  }
  if (s.state === "paired") {
    return <div className="pair-step"><h2>Paired with {s.peer.name}</h2><p>Their key is pinned on this device. Every future
      connection is checked against it.</p><a className="btn btn-primary" href="#/peers">View paired devices</a></div>;
  }
  const code = s.sas || "";
  return (
    <div className="pair-step">
      <p className="sas-intro">Read this code to <strong>{s.peer.name || "your teammate"}</strong>. Their screen must show exactly the same digits.</p>
      <div className="sas" aria-label={`Pairing code ${code.split("").join(" ")}`}>
        <span>{code.slice(0, 3)}</span><span>{code.slice(3)}</span>
      </div>
      <dl className="facts">
        <dt>Person</dt><dd>{s.peer.name}, {s.peer.title}</dd>
        <dt>Fingerprint</dt><dd><code className="fpr">{s.peer.fpr}</code></dd>
      </dl>
      {s.demo_warning && (
        <div className="warn-box">
          <strong>This peer uses publicly computable demo keys.</strong> Anyone on this network can impersonate it.
          <label className="check"><input type="checkbox" checked={demoAck} onChange={(e) => setDemoAck(e.target.checked)} /> I understand, this is a test</label>
        </div>
      )}
      {s.state === "waiting_for_peer_confirm" ? <p className="muted">Waiting for {s.peer.name} to confirm…</p> : (
        <div className="row-actions">
          <button className="btn btn-primary" disabled={s.demo_warning && !demoAck} onClick={() => confirm(true)}>The codes match</button>
          <button className="btn btn-danger" onClick={() => confirm(false)}>They don't match</button>
        </div>
      )}
    </div>
  );
}
