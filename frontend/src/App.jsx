import { useEffect, useState } from "react";
import { api, post, setCsrf, setOnLocked } from "./api.js";
import { go, shortFpr, useHashRoute, usePoll } from "./util.js";
import { Wordmark } from "./components/Logo.jsx";
import { ToastHost, useAction } from "./components/ui.jsx";
import { Setup, Unlock } from "./pages/Auth.jsx";
import { Dashboard, Catalog, MyRequests } from "./pages/SelfService.jsx";
import { Credentials, CredentialRecord, CheckedOut } from "./pages/Vault.jsx";
import { Approvals } from "./pages/Approvals.jsx";
import { Groups, GroupRecord } from "./pages/Groups.jsx";
import { Access, Rotations } from "./pages/Access.jsx";
import { Peers, Pair, IncomingPairBanner } from "./pages/Peers.jsx";
import { AuditLog, Verify, Alerts } from "./pages/Audit.jsx";
import { Settings } from "./pages/Settings.jsx";
import { DemoMode } from "./pages/Demo.jsx";
import { BASE } from "./api.js";

const NAV = [
  { section: "Self-service", items: [
    { path: "/dashboard", label: "Dashboard" },
    { path: "/catalog", label: "Request a credential" },
    { path: "/requests", label: "My requests" },
  ] },
  { section: "Vault", items: [
    { path: "/credentials", label: "My credentials" },
    { path: "/checkouts", label: "Checked out to me", count: "checked_out_to_me" },
  ] },
  { section: "Approvals", items: [
    { path: "/approvals", label: "Waiting for me", count: "pending_approvals" },
    { path: "/approvals/history", label: "Approval history" },
  ] },
  { section: "Privileged access", items: [
    { path: "/groups", label: "Groups" },
    { path: "/access", label: "Who has access", count: "checked_out_by_me" },
    { path: "/rotations", label: "Rotation tasks", count: "rotations_due" },
  ] },
  { section: "Peers", items: [
    { path: "/peers", label: "Paired devices" },
    { path: "/pair", label: "Pair a device" },
  ] },
  { section: "Audit", items: [
    { path: "/audit", label: "Event log" },
    { path: "/verify", label: "Log integrity" },
    { path: "/alerts", label: "Security alerts", count: "alerts" },
  ] },
  { section: "Settings", items: [{ path: "/settings", label: "Node settings" }, { path: "/demo-mode", label: "Demo mode", demo: true }] },
];

export function route(path, status) {
  const [, a, b] = path.split("?")[0].split("/");
  switch (a) {
    case "dashboard": return <Dashboard />;
    case "catalog": return <Catalog />;
    case "requests": return <MyRequests />;
    case "credentials": return b ? <CredentialRecord id={decodeURIComponent(b)} /> : <Credentials />;
    case "checkouts": return <CheckedOut />;
    case "approvals": return <Approvals history={b === "history"} />;
    case "groups": return b ? <GroupRecord id={decodeURIComponent(b)} /> : <Groups />;
    case "access": return <Access />;
    case "rotations": return <Rotations />;
    case "peers": return <Peers />;
    case "pair": return <Pair status={status} />;
    case "audit": return <AuditLog />;
    case "verify": return <Verify />;
    case "alerts": return <Alerts />;
    case "settings": return <Settings status={status} />;
    case "demo-mode": return <DemoMode status={status} />;
    default: return <Dashboard />;
  }
}

function Shell({ status, onLock }) {
  const path = useHashRoute();
  const [filter, setFilter] = useState("");
  const [counts] = usePoll("/dashboard", 5000);
  const [navOpen, setNavOpen] = useState(false);
  const act = useAction();
  useEffect(() => setNavOpen(false), [path]);
  const lock = async () => { await act(() => post("/lock")); onLock(); };
  const f = filter.toLowerCase();

  return (
    <div className="app">
      <header className="banner">
        <button className="icon-btn nav-toggle" aria-label="Menu" onClick={() => setNavOpen((x) => !x)}>☰</button>
        <a href="#/dashboard" className="banner-brand" aria-label="P2PSec home"><Wordmark /></a>
        {status.demo && <span className="demo-flag" title="Keys on this node are derived from a public seed">Demo user: keys are not secret</span>}
        {BASE !== "/" && <a className="banner-back" href="/">My own node</a>}
        <div className="banner-right">
          <span className="banner-user">
            <strong>{status.profile.name}</strong>
            <span className="banner-fpr" title={status.fpr}>{shortFpr(status.fpr)}</span>
          </span>
          <button className="btn btn-banner" onClick={lock}>Lock</button>
        </div>
      </header>
      <div className="body">
        <nav className={`nav ${navOpen ? "nav-open" : ""}`} aria-label="Application navigator">
          <input className="nav-filter" type="search" placeholder="Filter navigator" value={filter}
                 onChange={(e) => setFilter(e.target.value)} aria-label="Filter navigator" />
          {NAV.map((s) => {
            const items = s.items.filter((i) => (!i.demo || status.demo_available) &&
              (!f || i.label.toLowerCase().includes(f) || s.section.toLowerCase().includes(f)));
            if (!items.length) return null;
            return (
              <div className="nav-section" key={s.section}>
                <div className="nav-heading">{s.section}</div>
                {items.map((i) => {
                  const n = i.count && counts ? counts[i.count] : 0;
                  const on = path === i.path || (i.path !== "/approvals" && path.startsWith(i.path + "/"));
                  return (
                    <a key={i.path} href={`#${i.path}`} className={`nav-item ${on ? "nav-on" : ""}`}
                       aria-current={on ? "page" : undefined}>
                      <span>{i.label}</span>{n > 0 && <span className="nav-count">{n}</span>}
                    </a>
                  );
                })}
              </div>
            );
          })}
        </nav>
        <main className="main">
          {status.default_password && (
            <a className="alert-strip default-pw" href="#/settings">You are still using the default sign-in (user / user).
              Anyone with access to this computer can open your vault. Change it in Node settings.</a>
          )}
          <IncomingPairBanner />
          {route(path, status)}
        </main>
      </div>
    </div>
  );
}

export default function App() {
  const hash = useHashRoute();      // re-render on navigation so the public demo page can open from sign-in
  const [status, setStatus] = useState(null);
  const refresh = async () => {
    try {
      const s = await api("/status");
      setCsrf(s.csrf);
      setStatus(s);
    } catch (e) {
      setStatus({ error: e.message });
    }
  };
  useEffect(() => {
    setOnLocked(() => setStatus((s) => (s ? { ...s, unlocked: false } : s)));
    refresh();
  }, []);

  if (!status) return <div className="splash">Starting…</div>;
  if (status.error) return <div className="splash">This node is not answering: {status.error}</div>;
  const publicDemo = !status.unlocked && status.demo_available && hash.startsWith("/demo-mode");
  return (
    <ToastHost>
      {publicDemo ? <DemoGate status={status} />
        : !status.initialized ? <Setup onDone={refresh} />
        : !status.unlocked ? <Unlock status={status} onDone={refresh} />
        : <Shell status={status} onLock={() => { setCsrf(null); refresh(); go("/dashboard"); }} />}
    </ToastHost>
  );
}

function DemoGate({ status }) {
  return <div className="gate-page"><DemoMode status={status} /></div>;
}
