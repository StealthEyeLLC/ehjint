# Contributing to EHJINT

EHJINT is a deliberately small sovereign system. Changes must preserve its power contract and remove avoidable friction rather than add platform machinery.

## Canonical authority

The documents under `docs/` define the product. When prose conflicts, precedence is:

1. `docs/INVARIANTS.md`
2. `docs/ANTI-INVARIANTS.md`
3. `docs/V1-SCOPE.md`
4. `docs/ARCHITECTURE.md`
5. `docs/BUILD.md`
6. `docs/IMPLEMENTATION.md`
7. `docs/CERTIFICATION.md`
8. `docs/DECISIONS.md`

A code change that violates a higher-precedence document is invalid even if tests pass.

## Repository discipline

- Keep one controller, one canonical operation registry, and one source of durable local truth.
- Do not import implementation code from SMP, Baby, Baby-X, or archived EHJINT repositories.
- Do not add Kubernetes, Docker, containerd, Redis, PostgreSQL, a message broker, a vector database, or an agent framework as a mandatory dependency.
- Do not commit VM disks, memory snapshots, credentials, private keys, generated release bundles, or host-specific state.
- Do not add a service, daemon, database, abstraction, or dependency unless the existing core cannot correctly own the requirement.
- Prefer full-file changes with deterministic tests and exact failure behavior.
- Keep optional capabilities outside the sovereign core.

## Change protocol

Every behavior-changing pull request must state:

- The governing invariant or accepted variant.
- Why the change belongs in the core rather than a capability pack or adapter.
- Restart, rollback, and cleanup behavior.
- CLI and MCP parity impact.
- New dependencies and their licenses.
- Tests and certification evidence.

Canonical scope changes require an explicit update to the relevant document in the same commit series. Silent scope expansion is prohibited.

## Commit standard

Use focused commits with imperative messages. Do not rewrite preserved public history, force-push shared branches, or mix unrelated cleanup with behavior changes.

## Licensing

No repository-wide open-source license has been selected. Do not copy third-party code into this repository without explicit license review and recorded provenance.
