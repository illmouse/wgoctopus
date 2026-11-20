# Roadmap

1. **Schema and docs (current):** define desired-state contract, architecture, and local workflow.
2. **Managed agent:** UAPI diff/apply, metrics, and Docker image based on `amneziawg-go` v3.1. Test syncconf-like behavior and old-client compatibility on a test host.
3. **Orchestrator MVP:** 3.1 data model + renderer, 3.3 SSH push transport/single-node delivery, and 3.4 reconciliation loop done; REST API remains.
4. **Connectivity and monitoring:** management-WireGuard sidecar, hop control, monitoring, synthetic probe peer, and alerts.
5. **Operations:** bot using orchestrator API and import of existing instances.
6. **Failover:** confirmed active/standby failover, then active-active if needed.

The data plane must remain independent of orchestrator availability. Back up the orchestrator store; node backups are not required. Active-active would use hop-side nftables `jhash` selection by client source IP.
# Stage 3.5 — REST API and container

REST API, in-process reconciler lifecycle, and container packaging are complete. Tests, coverage, lint, image, smoke, and repository hygiene gates pass.
