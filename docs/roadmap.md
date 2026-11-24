# Roadmap

1. **Schema and docs (current):** define desired-state contract, architecture, and local workflow.
2. **Managed agent:** UAPI diff/apply, metrics, and Docker image based on `amneziawg-go` v3.1. Test syncconf-like behavior and old-client compatibility on a test host.
3. **Orchestrator MVP:** done (3.1 data model + renderer, 3.3 SSH push transport, 3.4 reconciler, 3.5 REST API + image, 3.6 e2e against a real agent over SSH via `scripts/e2e-orch.sh`).
4.1 **Hop orchestration:** orchestrator-side API, active backend switching, and reconciliation complete; end-to-end 4.1c verified on a real host (`make e2e-orch-hop`).
4. **Connectivity and monitoring:** pull mode (node-initiated SSH), hop control (DNAT backend switching, conntrack flush), monitoring, synthetic probe peer, and alerts. Control transport is SSH, not a management WireGuard.
   - 4.2a Orchestrator `/metrics`: done.
    - 4.2b Per-peer handshake metrics via agent metrics scrape: done.
   - 4.3b-API Probe REST API and hidden system peers: done.
   - 4.3b-3 Synthetic-probe status evaluation, API, metrics, and transition events: done. 
   - 4.3c End-to-end probe through a real hop to a real node (`make e2e-orch-probe`, 21 PASS): done. It found and fixed: SQLite busy timeout, adoption of an already-applied revision, client-mode handshake keeper, conntrack flush for added hop routes.
   - 4.5 Pull mode (node-initiated SSH reverse tunnel, `mgmt_mode` push|pull|auto): done — agent client, orchestrator SSH endpoint, API/metrics, and real-host e2e through `ssh -R` (`make e2e-orch-pull`, 29 PASS).
   - 4.4 Telegram notifications for node/probe/switch events, flap suppression, and rate limiting: done. Confirmation buttons for promotion are part of the failover stage.
4a. **Parameter generation (adopt from [VAIPROG/Any-Tech-ARCHITECT](https://github.com/VAIPROG/Any-Tech-ARCHITECT), MIT):** complete — 4a-1 generation of Jc/Jmin/Jmax, S1-S4 and ranged H1-H4; 4a-2 I1-I5 CPS profiles; 4a-3 additional 3.x fields (including RandomTrailers/DisableCookies). 1.0/1.5 are intentionally unsupported in 4a-1. Related: awg-containers-and-tools / `awg-tool` (UAPI-direct deployment).
 5. **Operations:** bot using orchestrator API and import of existing instances. 5.4a import tooling done; applying to real DB + cutover pending.
6. **Failover:** in progress — 5.1a engine, 5.1b API/lifecycle, 5.2 Telegram confirmation buttons and 5.3 real-host e2e (34 PASS) done. Confirmed active/standby failover, then active-active if needed.
   - 6.2 Legacy Telegram `users.db` importer: done.

The data plane must remain independent of orchestrator availability. Back up the orchestrator store; node backups are not required. Active-active would use hop-side nftables `jhash` selection by client source IP.
# Stage 3.5 — REST API and container

REST API, in-process reconciler lifecycle, and container packaging are complete. Tests, coverage, lint, image, smoke, and repository hygiene gates pass.

    - 6.1 Bot users/requests/devices API in orchestrator: done. 6.2 `import-users` of the old bot DB: done. 6.3a Bot module (`bot/`, ru/en, user flows: access/limit requests, own devices, config delivery): done; 6.3b admin screens (all devices, users, requests view, admin commands): done.
7. **Admin web UI and unattended setup:** design in [web-ui.md](web-ui.md) — 7.1 bootstrap YAML (done), 7.2 SSH provisioning from the orchestrator, 7.3 web auth (local + OIDC groups to roles), 7.4 Jinja+HTMX admin pages.
