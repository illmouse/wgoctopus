# Roadmap

1. **Schema and docs (current):** define desired-state contract, architecture, and local workflow.
2. **Managed agent:** UAPI diff/apply, metrics, and Docker image based on `amneziawg-go` v3.1. Test syncconf-like behavior and old-client compatibility on a test host.
3. **Orchestrator MVP:** done (3.1 data model + renderer, 3.3 SSH push transport, 3.4 reconciler, 3.5 REST API + image, 3.6 e2e against a real agent over SSH via `scripts/e2e-orch.sh`).
4.1 **Hop orchestration:** orchestrator-side API, active backend switching, and reconciliation complete; end-to-end 4.1c remains pending.
4. **Connectivity and monitoring:** pull mode (node-initiated SSH), hop control (DNAT backend switching, conntrack flush), monitoring, synthetic probe peer, and alerts. Control transport is SSH, not a management WireGuard.
4a. **Parameter generation (adopt from [VAIPROG/Any-Tech-ARCHITECT](https://github.com/VAIPROG/Any-Tech-ARCHITECT), MIT):** borrow its mechanisms for choosing optimal obfuscation values instead of our naive random generator: per-protocol-version rules (1.0/1.5/2.0/3.0/3.1), valid and mutually compatible Jc/Jmin/Jmax, S1-S4 (incl. merged S), H1-H4 ranges without overlap or a WireGuard-like fingerprint, CPS I1-I5 profiles (e.g. QUIC/STUN), 3.1 flags (RandomTrailers, DisableCookies), recommended MTU 1280 for 3.1, uniqueness per instance so instances do not look identical to DPI, unbiased randomness with rejection sampling. Related: awg-containers-and-tools / `awg-tool` (UAPI-direct deployment). Study the source (`src/`), port the rules to Python in the orchestrator renderer, add tests; keep attribution per MIT.
5. **Operations:** bot using orchestrator API and import of existing instances.
6. **Failover:** confirmed active/standby failover, then active-active if needed.

The data plane must remain independent of orchestrator availability. Back up the orchestrator store; node backups are not required. Active-active would use hop-side nftables `jhash` selection by client source IP.
# Stage 3.5 — REST API and container

REST API, in-process reconciler lifecycle, and container packaging are complete. Tests, coverage, lint, image, smoke, and repository hygiene gates pass.
