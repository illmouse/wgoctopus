<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="img/logo_black.png">
    <img src="img/logo.png" alt="wgoctopus" width="240">
  </picture>
</p>

# wgoctopus

An early-stage orchestrator for fleets of AmneziaWG (AWG 3.1) nodes and UDP hop forwarders. It keeps the desired configuration centrally, renders and reconciles node state, and monitors liveness. Nodes are stateless: a fresh node receives its complete desired state from the orchestrator.

**Status: early development, local only.** No production deployment is supported yet.

## Components

- **Agent** — Go service colocated with `amneziawg-go`; manages multiple AWG interfaces through UAPI and exposes an authenticated management API.
- **Orchestrator** — Python/FastAPI service and SQLite store; owns configuration, rendering, reconciliation, monitoring, and the initial bot module.
- **Management WireGuard** — planned sidecar for management connectivity to nodes and hops.
- **Hop** — planned UDP DNAT forwarder, controlled by the orchestrator.

```text
                     +---------------------------+
                     | Orchestrator              |
                     | API / store / reconciler  |
                     +-------------+-------------+
                                   | desired state (management network)
                  +----------------+----------------+
                  |                                 |
          +-------v--------+                 +------v-------+
          | Node: agent +  |                 | UDP hop      |
          | AWG daemon     |                 | forwarder    |
          +-------+--------+                 +------+-------+
                  |                                  |
                  +--------- client UDP path --------+
```

## Development

Requirements: Make, Python 3, and optionally `jsonschema` for schema validation. See [docs/dev.md](docs/dev.md).

```sh
make help
make schema-check
make agent-image                 # placeholder until implementation
make orchestrator-image          # placeholder until implementation
make ship IMAGE=example:tag HOST=user@host
```

## Repository layout

- `agent/` — planned Go agent
- `orchestrator/` — planned API and control plane
- `schema/` — desired-state contract and example
- `docs/` — architecture, schema, development, and roadmap
- `deploy/` — future deployment assets
- `scripts/` — local development helpers

## License

MIT; see [LICENSE](LICENSE).

## Credits

The AWG parameter generator (algorithms, I1–I5 profiles, parameter descriptions) is adapted from
[Any-Tech-ARCHITECT](https://github.com/VAIPROG/Any-Tech-ARCHITECT) by VAI_PROG (Vadim), MIT License.
See [NOTICE](NOTICE) and [docs/third-party-awg-generator.md](docs/third-party-awg-generator.md).
