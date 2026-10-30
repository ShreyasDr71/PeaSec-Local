// "/" for your own node, "/demo/<id>/" when this page belongs to a demo-team node
export const BASE = (window.location.pathname.match(/^\/demo\/[a-z]+\//) || ["/"])[0];

let csrf = null;
let onLocked = () => {};

export const setCsrf = (t) => { csrf = t; };
export const setOnLocked = (fn) => { onLocked = fn; };

export class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

export async function api(path, { method = "GET", body } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (method !== "GET" && csrf) headers["X-CSRF"] = csrf;
  const r = await fetch(`${BASE}api${path}`, {
    method, headers, credentials: "same-origin", body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401 && !["/unlock", "/settings/password"].includes(path)) {
    csrf = null;
    onLocked();
  }
  if (!r.ok) throw new ApiError(typeof data.detail === "string" ? data.detail : r.statusText, r.status);
  return data;
}

export const post = (path, body = {}) => api(path, { method: "POST", body });
export const put = (path, body = {}) => api(path, { method: "PUT", body });
export const del = (path) => api(path, { method: "DELETE" });
