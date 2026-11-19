# Roadmap

1. **Schema and docs (current):** define desired-state contract, architecture, and local workflow.
2. **Managed agent:** UAPI diff/apply, metrics, and Docker image based on `amneziawg-go` v3.1. Test syncconf-like behavior and old-client compatibility on a test host.
3. **Orchestrator MVP:** store, renderer, reconciler, and state delivery to agents.
4. **Connectivity and monitoring:** management-WireGuard sidecar, hop control, monitoring, synthetic probe peer, and alerts.
5. **Operations:** bot using orchestrator API and import of existing instances.
6. **Failover:** confirmed active/standby failover, then active-active if needed.

The data plane must remain independent of orchestrator availability. Back up the orchestrator store; node backups are not required. Active-active would use hop-side nftables `jhash` selection by client source IP.
