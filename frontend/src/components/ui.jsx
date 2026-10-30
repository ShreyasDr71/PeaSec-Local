import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { post } from "../api.js";
import { duration, useNow } from "../util.js";

// --- toasts -----------------------------------------------------------------
const ToastCtx = createContext(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastHost({ children }) {
  const [items, setItems] = useState([]);
  const push = (text, kind = "ok") => {
    const id = Math.random();
    setItems((xs) => [...xs, { id, text, kind }]);
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), 4500);
  };
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => <div key={t.id} className={`toast toast-${t.kind}`}>{t.text}</div>)}
      </div>
    </ToastCtx.Provider>
  );
}

/** Run an async action, toast its result. */
export function useAction() {
  const toast = useToast();
  return async (fn, okText) => {
    try {
      const r = await fn();
      if (okText) toast(okText);
      return r ?? true;
    } catch (e) {
      toast(e.message || "Something went wrong", "err");
      return null;
    }
  };
}

// --- badges -------------------------------------------------------------------
const STATE_CLASS = {
  pending: "warn", approved: "ok", auto_approved: "ok", denied: "bad", expired: "mute", cancelled: "mute",
  active: "ok", checked_in: "mute", revoked: "bad", open: "warn", done: "ok", dismissed: "mute",
  Critical: "crit", High: "bad", Medium: "warn", Low: "mute",
};
const STATE_TEXT = { auto_approved: "Auto-approved", checked_in: "Checked in" };
export function Badge({ value }) {
  if (!value) return null;
  const text = STATE_TEXT[value] || value.charAt(0).toUpperCase() + value.slice(1).replace(/_/g, " ");
  return <span className={`badge badge-${STATE_CLASS[value] || "mute"}`}>{text}</span>;
}

export function Dot({ on, label }) {
  return <span className={`dot ${on ? "dot-on" : ""}`} title={on ? "Online" : "Offline"} aria-label={label || (on ? "online" : "offline")} />;
}

export function Countdown({ until, ended }) {
  const now = useNow();
  if (ended) return null;
  const left = until - now;
  if (left <= 0) return <span className="countdown countdown-done">Ended</span>;
  return <span className={`countdown ${left < 600 ? "countdown-soon" : ""}`}>{duration(left)} left</span>;
}

// --- list view ---------------------------------------------------------------
export function ListView({ title, columns, rows, onRow, actions, empty = "No records to display.", filterable = true }) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState(null);
  const shown = useMemo(() => {
    let xs = rows || [];
    if (q) {
      const needle = q.toLowerCase();
      xs = xs.filter((r) => columns.some((c) => String(c.text ? c.text(r) : r[c.key] ?? "").toLowerCase().includes(needle)));
    }
    if (sort) {
      const c = columns.find((x) => x.key === sort.key);
      const val = (r) => (c.sortValue ? c.sortValue(r) : c.text ? c.text(r) : r[c.key]) ?? "";
      xs = [...xs].sort((a, b) => (val(a) > val(b) ? 1 : val(a) < val(b) ? -1 : 0) * sort.dir);
    }
    return xs;
  }, [rows, q, sort, columns]);
  return (
    <section className="list">
      <header className="list-head">
        <h2>{title}</h2>
        {filterable && (
          <input className="list-search" type="search" placeholder="Search this list" value={q}
                 onChange={(e) => setQ(e.target.value)} aria-label={`Search ${title}`} />
        )}
        <div className="list-actions">{actions}</div>
      </header>
      <div className="breadcrumb">
        <button className="link" onClick={() => setQ("")}>All</button>
        {q && <><span aria-hidden="true">&gt;</span><span>Contains "{q}"</span></>}
        <span className="count">{rows ? `${shown.length} record${shown.length === 1 ? "" : "s"}` : "Loading"}</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.key} style={c.width ? { width: c.width } : undefined}>
                  <button className="th-sort" onClick={() =>
                    setSort((s) => (s?.key === c.key ? { key: c.key, dir: -s.dir } : { key: c.key, dir: 1 }))}>
                    {c.label}{sort?.key === c.key ? (sort.dir > 0 ? " ▲" : " ▼") : ""}
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((r, i) => (
              <tr key={r.id || r.seq || r.fpr || i} className={onRow ? "clickable" : ""}
                  onClick={onRow ? () => onRow(r) : undefined}>
                {columns.map((c) => <td key={c.key}>{c.render ? c.render(r) : r[c.key]}</td>)}
              </tr>
            ))}
            {rows && shown.length === 0 && (
              <tr><td colSpan={columns.length} className="empty">{empty}</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// --- forms --------------------------------------------------------------------
export function Field({ label, hint, children, wide }) {
  return (
    <label className={`field ${wide ? "field-wide" : ""}`}>
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  );
}

export function ReadField({ label, children, wide }) {
  return (
    <div className={`field ${wide ? "field-wide" : ""}`}>
      <span className="field-label">{label}</span>
      <div className="field-read">{children || <span className="muted">Empty</span>}</div>
    </div>
  );
}

export function Tabs({ tabs }) {
  const [active, setActive] = useState(0);
  return (
    <section className="related">
      <div className="tabs" role="tablist">
        {tabs.map((t, i) => (
          <button key={t.label} role="tab" aria-selected={i === active} className={i === active ? "tab tab-on" : "tab"}
                  onClick={() => setActive(i)}>
            {t.label}{t.count !== undefined ? ` (${t.count})` : ""}
          </button>
        ))}
      </div>
      <div className="tab-body">{tabs[active]?.body}</div>
    </section>
  );
}

export function Modal({ title, children, onClose, footer }) {
  useEffect(() => {
    const on = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, [onClose]);
  return (
    <div className="modal-back" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <header className="modal-head"><h3>{title}</h3>
          <button className="icon-btn" onClick={onClose} aria-label="Close">×</button></header>
        <div className="modal-body">{children}</div>
        {footer && <footer className="modal-foot">{footer}</footer>}
      </div>
    </div>
  );
}

/** Masked secret with reveal + copy. `reveal(copy)` returns the secret and logs the access server-side. */
export function Secret({ reveal }) {
  const [value, setValue] = useState(null);
  const act = useAction();
  const toast = useToast();
  useEffect(() => {
    if (!value) return;
    const t = setTimeout(() => setValue(null), 30000);
    return () => clearTimeout(t);
  }, [value]);
  const copy = async () => {
    const s = value || (await act(() => reveal(true)));
    if (!s) return;
    try {
      await navigator.clipboard.writeText(s);
      toast("Copied. The clipboard is yours to clear.");
    } catch {
      setValue(s);
      toast("Clipboard is blocked here; the secret is shown instead.", "err");
    }
  };
  return (
    <div className="secret">
      <code className="secret-value">{value || "••••••••••••••••"}</code>
      {value
        ? <button className="btn btn-quiet" onClick={() => setValue(null)}>Hide</button>
        : <button className="btn btn-quiet" onClick={async () => { const s = await act(() => reveal(false)); if (s) setValue(s); }}>Reveal</button>}
      <button className="btn btn-quiet" onClick={copy}>Copy</button>
    </div>
  );
}

export const revealer = (path) => async (copy) => (await post(path, { copy })).secret;
