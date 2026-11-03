# Chronicle Deployment Guide

Chronicle has two maintained deployment paths:

1. `selfhost/` for a study operator deploying from a public source clone or a
   digest-pinned release bundle. Start with [`../selfhost/README.md`](../selfhost/README.md).
2. The immutable-image Traefik deployment driven by `../scripts/deploy.sh` for operators
   who already maintain that platform (images are built and signed locally; no hosted CI).

The historical standalone nginx deployment is not supported. Do not copy its
`/api/mobile` routing or deployment-wide app-key design into a new installation.

## Public mobile contract

The public Android app is not rebuilt for each study and does not contain a server
credential. One active enrollment selects one researcher-operated HTTPS root origin:

1. The researcher issues a short-lived, one-time enrollment invitation from the
   dashboard.
2. The participant opens or scans that invitation. It identifies the HTTPS server,
   study, participant, and one-time code.
3. The app fetches the authoritative study disclosure, shows the requested collection
   scope and policy links, and records explicit consent before enrollment.
4. A successful enrollment exchanges the one-time code for a per-device API key bound
   to that study, participant, and device.
5. Subsequent uploads use the configured HTTPS origin and per-device credential. They
   do not use `X-Chronicle-App-Key` or a secret shared by every installation.

Current mobile routes are exposed directly under the Chronicle API namespace, including:

- `/chronicle/v4/mobile/reviewer-enrollment` for the narrowly scoped Play reviewer bootstrap;
- `/chronicle/v4/study/{studyId}/participant/{participantId}/enrollment-preview`;
- `/chronicle/v4/study/{studyId}/participant/{participantId}/enroll`;
- `/chronicle/v4/study/{studyId}/participant/{participantId}/...` for authenticated
  collection, acknowledgment, status, reminder, and withdrawal operations;
- current researcher `/chronicle/v3/*` and device `/chronicle/v4/*` routes. Retired API prefixes return 404.

Do not edit `UploadWorker.kt`, replace a production constant, append `/api/mobile`, or
compile an operator secret into an APK/AAB. Server selection is enrollment state.

## Source-clone self-hosting

From the repository root:

```bash
git submodule update --init --recursive
cd selfhost
./chronicle setup
./chronicle up
./chronicle verify
./chronicle doctor
```

`./chronicle setup` writes a mode-0600 `.env`. Production modes require a public HTTPS
origin. Keep the researcher dashboard on its private listener and publish only the
participant/mobile routes documented by the self-host guide.

The source-clone path builds only the backend, dashboard, and proxy tags managed by the
checkout. Operator-provided image references are pulled by Compose and are never replaced
with locally built source.

## Immutable-image Traefik deployment

The platform deployment uses `docker-compose.traefik.yml` plus the production override.
Images must be immutable references selected by the deployment workflow. Review the
rendered Compose configuration and run the repository deployment/security guardrails
before promotion; do not deploy mutable `latest`, branch, environment, or placeholder
tags.

The public Traefik router exposes only the explicit Chronicle mobile paths. Researcher
web APIs and dashboards remain on authenticated/internal routes. Direct datastore,
principal, import, compliance, metrics, and other administrative aliases must remain
blocked at the edge and authorized independently by the backend.

## Secrets and operational evidence

- Never commit `.env`, TLS private keys, database dumps, signing material, reviewer
  credentials, real inventory values, or production evidence.
- The Play reviewer secret is server-side configuration submitted only in the
  `X-Chronicle-Reviewer-Secret` header to the exact reviewer endpoint.
- `MOBILE_SIGNING_SECRET` is a server-side compatibility mechanism for controlled legacy
  research clients. It is not part of the generally distributed app contract.
- Keep hostnames, addresses, operator accounts, exact compliance results, and incident
  evidence in the operator's private system of record.

For deployment modes, backups, restore, monitoring, privacy-policy routes, reviewer
configuration, and upgrades, use the maintained [`../selfhost/README.md`](../selfhost/README.md)
and its `docs/` directory.
