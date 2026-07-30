# EHJINT

EHJINT is StealthEye's sovereign, full-power Linux computer system for local CLI and ChatGPT-controlled execution.

This repository is the canonical source for EHJINT architecture, scope, build, implementation, and certification requirements.

## Status

Architecture complete and frozen for v1 implementation.

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
- [Certification Standard](docs/CERTIFICATION.md)
- [Decision Record](docs/DECISIONS.md)

## Command surface

```bash
ehjint
ehjint up
ehjint run -- uname -a
ehjint fork
ehjint snapshot
```

`ej` is the optional shorthand alias. Both resolve to the same binary and canonical operation registry.

## Repository law

This repository remains clean and tight. No speculative frameworks, duplicate authorities, generated dependency sprawl, unrelated experiments, or imported SMP/Baby implementation code belong here.

See [CONTRIBUTING.md](CONTRIBUTING.md) before changing canonical behavior.
