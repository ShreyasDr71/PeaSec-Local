import { useEffect, useRef, useState, useCallback } from "react";
import { api } from "./api.js";

export function useHashRoute() {
  const read = () => (window.location.hash.slice(1) || "/dashboard");
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const on = () => setRoute(read());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export const go = (path) => { window.location.hash = path; };

/** Fetch `path` now and every `every` ms. Returns [data, reload, error]. */
export function usePoll(path, every = 5000) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const alive = useRef(true);
  const load = useCallback(async () => {
    if (!path) return;
    try {
      const d = await api(path);
      if (alive.current) { setData(d); setError(null); }
    } catch (e) {
      if (alive.current) setError(e);
    }
  }, [path]);
  useEffect(() => {
    alive.current = true;
    load();
    const t = every ? setInterval(load, every) : null;
    return () => { alive.current = false; if (t) clearInterval(t); };
  }, [load, every]);
  return [data, load, error];
}

export function useNow(every = 1000) {
  const [now, setNow] = useState(Date.now() / 1000);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now() / 1000), every);
    return () => clearInterval(t);
  }, [every]);
  return now;
}

const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
export const fmtTime = (ts) => (ts ? dtf.format(new Date(ts * 1000)) : "");

export function ago(ts, now = Date.now() / 1000) {
  if (!ts) return "";
  const d = Math.round(now - ts);
  if (d < 60) return "just now";
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
  return `${Math.floor(d / 86400)} d ago`;
}

export function duration(seconds) {
  const s = Math.max(0, Math.round(seconds));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), r = s % 60;
  if (h) return `${h} h ${String(m).padStart(2, "0")} min`;
  if (m) return `${m} min ${String(r).padStart(2, "0")} s`;
  return `${r} s`;
}

export const minutesLabel = (m) => (m >= 60 ? `${+(m / 60).toFixed(1)} h` : `${m} min`);

// short, human record numbers derived from ids (ServiceNow-style)
export function recNo(prefix, id) {
  if (!id) return "";
  const hex = id.replace(/[^0-9a-f]/gi, "");
  const n = hex ? parseInt(hex.slice(0, 7), 16) % 10000000 : [...id].reduce((a, c) => a * 31 + c.charCodeAt(0), 7) % 10000000;
  return `${prefix}${String(n).padStart(7, "0")}`;
}

const EVENT_WORDS = { LEASE: "checkout", CRED: "credential", REQUEST: "request", PAIR: "pairing", PAIRED: "paired",
  RECEIPT: "receipt", ROTATION: "rotation", AUTO: "auto", GROUP: "group", LOG: "log", AUTH: "authentication" };
export function eventLabel(t) {
  const words = t.split("_").map((w) => EVENT_WORDS[w] || w.toLowerCase());
  const s = words.join(" ").replace("checkout granted", "checkout granted").replace("vault created", "vault created");
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function shortFpr(fpr) {
  return fpr ? fpr.split(" ").slice(0, 2).join(" ") : "";
}

export function generatePassword(len = 24) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";
  const out = new Uint32Array(len);
  crypto.getRandomValues(out);
  return Array.from(out, (v) => chars[v % chars.length]).join("");
}
