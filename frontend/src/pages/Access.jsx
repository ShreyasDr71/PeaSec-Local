import { useState } from "react";
import { post } from "../api.js";
import { fmtTime, go, usePoll } from "../util.js";
import { Badge, Countdown, Field, ListView, Modal, useAction } from "../components/ui.jsx";

export function Access() {
  const [rows, reload] = usePoll("/access", 4000);
  const act = useAction();
  return (
    <div className="page">
      <ListView title="Who has access" rows={rows}
                empty="No checkouts from you or your groups yet."
                onRow={(r) => go(`/credentials/${encodeURIComponent(r.cred_id)}`)}
                columns={[
                  { key: "cred_name", label: "Credential", render: (r) => <>{r.cred_name} <Badge value={r.criticality} /></> },
                  { key: "holder_name", label: "Held by" },
                  { key: "grantor_name", label: "Granted by", text: (r) => r.grantor_name + (r.direction === "sync" ? " (co-custodian)" : "") },
                  { key: "ticket", label: "Ticket" },
                  { key: "granted_at", label: "Checked out", sortValue: (r) => r.granted_at, render: (r) => fmtTime(r.granted_at) },
                  { key: "status", label: "State", render: (r) => <Badge value={r.status} /> },
                  { key: "expires_at", label: "Ends", sortValue: (r) => r.expires_at,
                    render: (r) => (r.status === "active" ? <Countdown until={r.expires_at} /> : fmtTime(r.ended_at || r.expires_at)) },
                  { key: "act", label: "", render: (r) => r.status === "active" && (
                    <button className="btn btn-danger" onClick={async (e) => {
                      e.stopPropagation();
                      if (confirm(`Revoke ${r.holder_name}'s checkout of ${r.cred_name}? Their node deletes it as soon as it is reachable.`)
                          && await act(() => post(`/leases/out/${r.id}/revoke`), "Checkout revoked")) reload();
                    }}>Revoke</button>) },
                ]} />
      <p className="page-note">A revoked or expired checkout is deleted from the holder's machine, but they may have
        copied it. That is why every ended checkout raises a rotation task.</p>
    </div>
  );
}

export function Rotations() {
  const [rows, reload] = usePoll("/rotations", 6000);
  const [dismissing, setDismissing] = useState(null);
  const [note, setNote] = useState("");
  const act = useAction();
  return (
    <div className="page">
      <ListView title="Rotation tasks" rows={rows} empty="No rotation tasks. Nothing has been shared and returned yet."
                onRow={(r) => go(`/credentials/${encodeURIComponent(r.cred_id)}`)}
                columns={[
                  { key: "cred_name", label: "Credential" },
                  { key: "reason", label: "Why" },
                  { key: "status", label: "State", render: (r) => <Badge value={r.status} /> },
                  { key: "created_at", label: "Raised", sortValue: (r) => r.created_at, render: (r) => fmtTime(r.created_at) },
                  { key: "closed_by", label: "Closed by", text: (r) => [r.closed_by, r.note].filter(Boolean).join(": ") },
                  { key: "act", label: "", render: (r) => r.status === "open" && (
                    <span className="row-actions">
                      <a className="btn btn-primary" href={`#/credentials/${encodeURIComponent(r.cred_id)}`} onClick={(e) => e.stopPropagation()}>Rotate</a>
                      <button className="btn" onClick={(e) => { e.stopPropagation(); setDismissing(r); }}>Dismiss</button>
                    </span>) },
                ]} />
      {dismissing && (
        <Modal title="Dismiss rotation task" onClose={() => setDismissing(null)}
               footer={<><button className="btn" onClick={() => setDismissing(null)}>Cancel</button>
                 <button className="btn btn-primary" form="dismiss">Dismiss task</button></>}>
          <form id="dismiss" onSubmit={async (e) => {
            e.preventDefault();
            if (await act(() => post(`/rotations/${dismissing.id}/dismiss`, { note }), "Task dismissed")) { setDismissing(null); setNote(""); reload(); }
          }}>
            <Field label="Why no rotation is needed" hint="Recorded in the audit log.">
              <textarea rows={3} value={note} onChange={(e) => setNote(e.target.value)} required autoFocus />
            </Field>
          </form>
        </Modal>
      )}
    </div>
  );
}
