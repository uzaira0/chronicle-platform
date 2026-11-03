# Capability ownership

Generated from `contracts/selfhost-capabilities.json`; run `python3 scripts/check-selfhost-capabilities.py --write`.
Infrastructure diagnostics intentionally belong to `./chronicle doctor` and Grafana, not the React application.

| Capability | Backend operation | User-facing owner |
|---|---|---|
| `participant-export` | StudyController: download participant data | `researcher-web` |
| `participant-enrollment-health` | StudyController: participant, device, sensor, upload, and compliance status | `researcher-web`, `mobile-client` |
| `verified-deletion` | DataDeletionController and StudyController: request, inspect and explicitly run verified deletion | `researcher-web`, `participant-web` |
| `study-lifecycle-deletion` | StudyLifecycleController: request, status, and cancel a study deletion | `researcher-web` |
| `failed-background-operations` | Deletion workers expose job state | `researcher-web`, `operator-cli`, `grafana` |
| `backup-visibility` | Self-host backup receipts and verification state | `operator-cli`, `grafana` |
| `deployment-diagnostics` | Compose services, probes, configuration guard, and operational events | `operator-cli`, `grafana` |
| `monitoring-viewers` | Grafana Viewer account administration | `operator-cli` |
| `participant-forms` | SurveyController and TimeUseDiaryController participant forms | `participant-web` |
| `mobile-data-collection` | StudyController v4 enrollment and upload APIs | `mobile-client` |
