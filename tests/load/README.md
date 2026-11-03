# Chronicle load testing

Run the pilot ingest workload against an isolated clean stack with synthetic study data.
Each virtual user represents one enrolled device and starts an upload every 60 seconds.
At 1,000 devices this produces 60,000 usage requests/hour, plus sensor requests on 30% of
iterations. Ramp cohorts through 25, 50 and `MAX_VUS` (default 125) devices, then drain connections.

## Prepare synthetic fixtures

Create a study with active dates and versioned collection settings enabling usage events
and the tested Android sensors. Create synthetic participants, complete normal invitation
and per-module consent enrollment, and acknowledge the current collection settings. Keep
one distinct enrolled device credential per virtual user in a private mode-0600 JSON file:

```json
[
  {"participant_id":"synthetic-1", "random_device_id":"<source random device ID used at enrollment>", "api_key":"<enrollment-issued device key>"}
]
```

Set `DEVICE_FIXTURES_FILE` to its absolute path. The test sends `X-Api-Key` and
`X-Chronicle-Random-Device-Id`; it validates fixture shape before starting and never prints keys.
Use study-approved synthetic credentials; never export real participant keys into fixtures.
The payload uses the current usage-event class discriminator and sensor enum values.
Enrollment happens before measurement so invitation failures cannot masquerade as capacity.

## Run and retain evidence

Install k6 v0.57.0 or newer and Docker. Older k6 releases, such as v0.50.0, cannot parse the
scripts, and the runner refuses them. Start the exact release images on a newly created database,
and set these variables in the runner environment:

```bash
export BASE_URL=https://synthetic-pilot.example.test
export STUDY_ID=<synthetic-study-uuid>
export DEVICE_FIXTURES_FILE=/private/synthetic-devices.json
export COMPOSE_PROJECT_NAME=<isolated-project-name>
export MAX_VUS=125 # 5x the owner's 25 simultaneous pilot participants
export CHRONICLE_LOAD_REPORT_DIR=/private/pilot-run-001
scripts/chronicle-pilot-load.sh
```

Use a fresh report directory for each run. The runner retains k6 samples, the full summary
and redacted web edge logs. `UPLOAD_INTERVAL_SECONDS` changes the default 60-second
start-to-start interval. Tagged response counters distinguish acceptance, throttling,
authentication, server, transport and rejected requests. Any authentication or payload
rejection invalidates the fixture and must be resolved before reporting capacity.

The current budgets are p95 upload latency below 500 ms, p99 below 2,000 ms, and an error
rate below 1%. They are provisional budgets; the committed baseline is unmeasured.
Review `http_req_duration`, `http_req_failed`, `http_reqs`, `upload_duration` and
`sensor_upload_duration` alongside accepted event/sample counts and edge response classes.

The expected peak is 25 simultaneous participants; hundreds
may enroll over the study lifetime. Run twice on a disposable stack at 50 and 125 VUs
(2x and 5x the simultaneous peak). Record image/source digests,
host CPU/RAM/storage, encryption/monitoring configuration, participant/event/sample counts,
throughput, p95/p99 latency and errors. Record the first VU level that exceeds the
thresholds if one occurs within this range.
Replace `tests/perf/k6-baselines.json` with the measured summary and a `measurement` object
containing `verified: true`, `runs`, `source_revision`, `environment` and `fixtures`. The release regression gate rejects the unmeasured budget.
An explicitly local budget check can set `K6_ALLOW_UNMEASURED_BUDGET=true`.

## Performance ingestion fixtures

`make perf-load` and `make perf-stress` register disposable participants, issue enrollment
invitations, preview the disclosure, bind a proposed device API key, and acknowledge
consent before generating uploads. They share the invitation fixture with the race probes.
Use an explicitly configured disposable `STUDY_ID` with usage events and the generated
accelerometer, gyroscope, light and proximity sensors enabled. Set `JWT_TOKEN` for the
researcher control plane, `BASE_URL` for the public mobile origin, `MANAGEMENT_URL` for
the researcher origin when separate, and `MOBILE_SIGNING_SECRET` for HMAC headers.
Uploads authenticate with each enrolled device's API key, carry fresh signed request
identities, and must acknowledge every generated sample. Sample timestamps follow consent.

The baseline is 25 simultaneous phones. Run `tests/performance/load.js`
for 50 VUs and `tests/performance/stress.js` with `MAX_VUS=125` for five times that peak.
Run these only on a disposable stack; record its revision, fixture settings
and measured summaries with the baseline. A mocked client check is not a capacity measurement.
