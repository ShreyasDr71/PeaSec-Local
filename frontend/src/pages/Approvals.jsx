import { useState } from "react";
import { post } from "../api.js";
import { fmtTime, minutesLabel, recNo, usePoll } from "../util.js";
import { Badge, Field, ListView, Modal, useAction } from "../components/ui.jsx";

export function Approvals({ history }) {
  const [rows, reload] = usePoll(`/approvals?state_=${history ? "history" : "pending"}`, 4000);
  const [creds] = usePoll("/credentials", 0);
  const [deciding, setDeciding] = useState(null);
  const act = useAction();

  const columns = [
    { key: "id", label: "Number", text: (r) => recNo("REQ", r.id) },
    { key: "requester_name", label: "Requested by" },
    { key: "cred_name", label: "Credential", render: (r) => <>{r.cred_name} <Badge value={r.criticality} /></> },
    { key: "ticket", label: "Ticket" },
    { key: "reason", label: "Justification" },
    { key: "minutes", label: "Duration", render: (r) => minutesLabel(r.minutes) },
    { key: "created_at", label: "Opened", sortValue: (r) => r.created_at, render: (r) => fmtTime(r.created_at) },
  ];
  if (history) {
    columns.push({ key: "status", label: "State", render: (r) => <Badge value={r.status} /> },
                 { key: "decided_by", label: "Decided by" }, { key: "comment", label: "Comment" });
  } else {
    columns.push({ key: "where", label: "Queue", text: (r) => (r.direction === "sync" ? "Co-custodian's queue" : "Yours") },
                 { key: "act", label: "", render: (r) => (
                   <span className="row-actions">
                     <button className="btn btn-primary" onClick={(e) => { e.stopPropagation(); setDeciding({ r, mode: "approve" }); }}>Approve</button>
                     <button className="btn" onClick={(e) => { e.stopPropagation(); setDeciding({ r, mode: "deny" }); }}>Deny</button>
                   </span>) });
  }

  return (
    <div className="page">
      <ListView title={history ? "Approval history" : "Waiting for my approval"} rows={rows} columns={columns}
                empty={history ? "No decisions yet." : "Nothing is waiting for you."} />
      {deciding && (
        <Decide {...deciding} personalCreds={(creds || []).filter((c) => c.scope === "personal")}
                onClose={() => setDeciding(null)}
                onDone={() => { setDeciding(null); reload(); }} act={act} />
      )}
    </div>
  );
}

function Decide({ r, mode, personalCreds, onClose, onDone, act }) {
  const [minutes, setMinutes] = useState(r.minutes);
  const [credId, setCredId] = useState("");
  const [comment, setComment] = useState("");
  const personal = !r.group_id;
  const submit = async (e) => {
    e.preventDefault();
    const ok = mode === "approve"
      ? await act(() => post(`/approvals/${r.id}/approve`, { minutes: +minutes, cred_id: credId || undefined }),
                  `Approved. ${r.requester_name} receives the credential for ${minutesLabel(+minutes)}.`)
      : await act(() => post(`/approvals/${r.id}/deny`, { comment }), "Request denied");
    if (ok) onDone();
  };
  const options = [5, 15, 30, 60, 120, 240, 480, 720, 1440].filter((m) => m <= r.minutes);
  if (!options.includes(r.minutes)) options.push(r.minutes);
  return (
    <Modal title={`${mode === "approve" ? "Approve" : "Deny"} ${recNo("REQ", r.id)}`} onClose={onClose}
           footer={<><button className="btn" onClick={onClose}>Cancel</button>
             <button className={`btn ${mode === "approve" ? "btn-primary" : "btn-danger"}`} form="decide">
               {mode === "approve" ? "Approve" : "Deny"}</button></>}>
      <form id="decide" onSubmit={submit}>
        <dl className="facts">
          <dt>Requested by</dt><dd>{r.requester_name}</dd>
          <dt>{personal ? "Asked for" : "Credential"}</dt><dd>{r.cred_name}</dd>
          <dt>Ticket</dt><dd>{r.ticket}</dd>
          <dt>Justification</dt><dd>{r.reason}</dd>
        </dl>
        {mode === "approve" ? (
          <>
            {personal && (
              <Field label="Credential to share">
                <select value={credId} onChange={(e) => setCredId(e.target.value)} required>
                  <option value="">Choose one of your credentials</option>
                  {personalCreds.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </Field>
            )}
            <Field label="Checkout duration" hint="You can shorten what was asked for, not extend it.">
              <select value={minutes} onChange={(e) => setMinutes(e.target.value)}>
                {options.sort((a, b) => a - b).map((m) => <option key={m} value={m}>{minutesLabel(m)}</option>)}
              </select>
            </Field>
          </>
        ) : (
          <Field label="Reason for denying" hint="The requester sees this.">
            <textarea rows={3} value={comment} onChange={(e) => setComment(e.target.value)} required autoFocus />
          </Field>
        )}
      </form>
    </Modal>
  );
}
