# EHJINT

EHJINT is StealthEye's sovereign, full-power Linux computer system for local CLI and ChatGPT-controlled execution.

This repository is the canonical source for EHJINT architecture, scope, build, implementation, and certification requirements.

## Status

Architecture is complete and frozen for v1 implementation. Mission 1 now provides the standalone Go foundation, canonical operation registry, generated API surfaces, strict contracts, reproducible build, and repository gates. Machine execution begins in a later mission.

## Product contract

EHJINT provides an unrestricted root Linux guest on user-owned KVM compute with no model API dependency, no hosted sandbox requirement, no mandatory cloud control plane, and no capability tax on ordinary use.

## Canonical documents

- [System Architecture](docs/ARCHITECTURE.md)
- [Invariants](docs/INVARIANTS.md)
- [Variants](docs/VARIANTS.md)
- [Anti-Invariants](docs/ANTI-INVARIANTS.md)
- [Frozen v1 Scope](docs/V1-SCOPE.md)
- [Build Specification](docs/BUILD.md)
- [Implementation Missions](docs/IMPLEMENTATION.md)
- [Mission 1 Foundation](docs/MISSION-1.md)
- [Certification Standard](docs/CERTIFICATION.md)
- [Decision Record](docs/DECISIONS.md)

## Command surface

Mission 1 implements only non-mutating foundation diagnostics:

```bash
ehjint version --json
ehjint doctor --json
ehjint registry list --json
ehjint registry describe system.version --json
```

`ej` is the optional shorthand alias. Both names resolve to the same multicall binary and canonical operation registry. Commands such as `up`, `run`, `fork`, and `snapshot` remain target v1 operations for later implementation missions; Mission 1 does not simulate them.

## Repository law

This repository remains clean and tight. No speculative frameworks, duplicate authorities, generated dependency sprawl, unrelated experiments, or imported SMP/Baby implementation code belong here.

See [CONTRIBUTING.md](CONTRIBUTING.md) before changing canonical behavior.
