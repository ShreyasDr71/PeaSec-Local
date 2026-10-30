import { useState } from "react";
import { post } from "../api.js";
import { usePoll } from "../util.js";
import { PeaPod } from "../components/Logo.jsx";
import { useAction } from "../components/ui.jsx";

// Demo mode lives on your own node's page. It starts six seeded teammates inside this container;
// each opens in its own tab and signs in separately.
export function DemoMode({ status }) {
  const [d, reload] = usePoll("/demo", 0);
  const [busy, setBusy] = useState(null);
  const act = useAction();
  const run = async (what, label) => {
    setBusy(what);
    await act(() => post(`/demo/${what}`), label);
    await reload();
    setBusy(null);
  };
  if (!status.demo_available) return <div className="page"><p>Demo mode is only available on your own node.</p></div>;

  return (
    <div className="page demo-page">
      <div className="demo-head">
        <PeaPod size={150} />
        <div>
          <h1 className="page-title">Demo mode</h1>
          <p className="page-note">Starts a fictional six-person IT team inside this container, already paired, with
            groups, requests, checkouts and audit history. Their keys come from a public seed, so never put real
            secrets in them. Your own node stays exactly as it is.</p>
        </div>
      </div>

      {!d ? <p className="loading">Loading…</p> : !d.running ? (
        <section className="card">
          <p>Demo mode is off.</p>
          <div><button className="btn btn-primary" disabled={!!busy} onClick={() => run("start", "Demo team started")}>
            {busy === "start" ? "Starting six nodes…" : "Start demo mode"}</button></div>
        </section>
      ) : (
        <>
          <section className="list">
            <header className="list-head"><h2>Demo users</h2>
              <span className="muted">Each opens in a new tab. Password for all: <code>{d.password}</code></span></header>
            <div className="table-wrap">
              <table>
                <thead><tr><th><span className="th-sort">Person</span></th><th><span className="th-sort">Role</span></th>
                  <th><span className="th-sort">Username</span></th><th></th></tr></thead>
                <tbody>
                  {d.users.map((u) => (
                    <tr key={u.id}>
                      <td><strong>{u.name}</strong></td>
                      <td>{u.title}</td>
                      <td><code>{u.login}</code></td>
                      <td><a className="btn btn-primary" href={u.url} target="_blank" rel="noopener">Open as {u.name.split(" ")[0]}</a></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <section className="card">
            <h2>Pair from another device</h2>
            <p className="muted">Tom Becker is paired with nobody. From a node on another device on this Wi-Fi, pair with
              {d.tom_addr ? <> <code>{d.tom_addr}</code>.</> : <> this computer's Wi-Fi address on port <code>7606</code> (the start script prints it).</>}
              {" "}You can also pair your own node with Tom from <a href="#/pair">Pair a device</a> using <code>127.0.0.1:7606</code>.</p>
          </section>
          <section className="card">
            <h2>Reset or stop</h2>
            <p className="muted">Reset puts every demo user back to the original seed: requests, checkouts, pairings and logs.
              Stop shuts the team down; starting again keeps their data.</p>
            <div className="row-actions">
              <button className="btn" disabled={!!busy} onClick={() => confirm("Reset all six demo users to the original seed?") && run("reset", "Demo team reset")}>
                {busy === "reset" ? "Resetting…" : "Reset demo data"}</button>
              <button className="btn btn-danger" disabled={!!busy} onClick={() => run("stop", "Demo mode stopped")}>
                {busy === "stop" ? "Stopping…" : "Stop demo mode"}</button>
            </div>
          </section>
        </>
      )}
      {!status.unlocked && <p><a href="#/dashboard">Back to sign in</a></p>}
    </div>
  );
}
