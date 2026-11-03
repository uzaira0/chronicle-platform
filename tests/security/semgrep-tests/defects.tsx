// ruleid: dashboard-polling-activity
useQuery(studyId, { pollingInterval: 30_000, headers: { [USER_ACTIVITY_HEADER]: elapsed } });

// ok: dashboard-polling-activity
useQuery(studyId, { pollingInterval: 30_000, skipPollingIfUnfocused: true });



// ruleid: unbounded-response-buffer
async function Component(reply) { const bytes = await reply['arrayBuffer'](); return <div>{bytes.byteLength}</div>; }

// ok: unbounded-response-buffer
function download(url) { const a = document.createElement('a'); a.href = url; a.download = ''; a.click(); }
async function metadata(reply) { return reply.json(); }

