# EHJINT v1 Mission 1 certification result

Certification date: 2026-07-30
Branch: `build/ehjint-v1`

## Canonical source identity

- Source commit: `f2da9ce93285d4f8766b043fdc882af01c0b3f91`
- Source tree: `a8bb849a5bcf60caaebe47049578e022dee064af`

## Certified checkpoint history

| Checkpoint | Commit | Tree | Purpose |
|---:|---|---|---|
| 1 | `c28d92b738fe992fcd7281a7fed2ca89bc912b47` | `4012b4a466924cd6ce8a206bee77035778522d0a` | Deterministic Mission 1 foundation |
| 2 | `6d0053c816cb0b08f0e2abcddd5e0aabfe494646` | `9a32f91152875f0fc0a9e258799a4fbdcbd80873` | Registry, contract, schema, parity, and negative tests |
| 3 | `c3d424afc053119a837f23fd77380c95ded2c983` | `767895df78df01156ee1fc79d50f7c82c6969063` | Standalone repository policy verifier |
| 4 | `94fa6298d92850ac343250c60d3294c4971c72f6` | `d2919eb00a1e31d11258c0cbe919733f632e04ab` | CI, documentation, and complete certification gate |

The evidence-only checkpoint containing this record is the final Mission 1 checkpoint. The four implementation checkpoints above are preserved as exact Git commit objects and are published together with this record.

## Deterministic identities

- Product version: `0.0.0-dev`
- Go toolchain: `go1.26.5` for `linux/amd64`
- Official Go archive SHA-256: `5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053`
- Canonical operation-registry SHA-256: `6f21efb11d0998a3888ae2b49bf63a19b6befb407fd10cdbc615aa5042c2504a`
- Reproducible `ehjint` binary SHA-256: `4538a8fc8c75359880e344f7aa22a61e1f9d71aa101df6064c005dfd0ed6f68d`
- Generated artifact count: `32`
- Certified repository file count before this evidence record: `94`

## Implemented foundation

Mission 1 provides one multicall Go binary, `ehjint`, with optional alias `ej`. Its public runtime surface is deliberately limited to four non-mutating diagnostics derived from one canonical operation registry:

- `system.version`
- `system.diagnose`
- `registry.list`
- `registry.describe`

The same registry generates typed Go identifiers, CLI metadata, one MCP tool named `ehjint`, strict operation schemas, frozen compatibility data, provider contracts, generated documentation, parity data, a registry digest, and a generated-artifact digest manifest.

The frozen version 1 contracts cover namespaced identifiers, operation state transitions, cooperative cancellation intent, result and error envelopes, canonical idempotency binding, explicit machine manifests, exact release manifests, dependency and toolchain locks, and contract-only provider boundaries.

## Verification result

The clean canonical gate completed successfully and verified:

- exact pinned public toolchain bootstrap;
- Go formatting and vet;
- deterministic generated output and tamper detection;
- strict registry, schema, CLI, and MCP parity;
- dependency, license, action-pin, and toolchain-lock agreement;
- secret, private-path, large-file, binary-artifact, import, workflow-authority, and runtime-entrypoint policy;
- all unit and negative tests;
- all race tests;
- two independent reproducible binary builds with identical SHA-256;
- `ehjint` and `ej` alias parity;
- four positive diagnostic paths and three fail-closed CLI paths.

## Mission boundary

No VMM, guest, machine lifecycle, networking, storage activation, snapshot, fork, device attachment, browser pack, protocol server, installation, deployment, or release activation was implemented or activated. The diagnostic contract reports `foundation_only=true` and `later_runtime_activated=false`.
