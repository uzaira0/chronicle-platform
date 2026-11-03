// ruleid: create-route-without-idempotency-key
http.post(`${BASE}/chronicle/v3/study/${study}/api-keys`, body, { headers });

// ok: create-route-without-idempotency-key
http.post(`${BASE}/chronicle/v3/study/${study}/api-keys`, body, { headers: Object.assign({}, headers, { 'Idempotency-Key': key }) });

// ok: create-route-without-idempotency-key
http.post(`${BASE}/chronicle/v3/study/${study}/participant`, body, { headers });
