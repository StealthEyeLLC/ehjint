# EHJINT v1 Mission 1 foundation

Mission 1 establishes the standalone implementation spine and freezes the contracts that later EHJINT missions must consume. It does not create, boot, attach, network, snapshot, fork, or mutate a virtual machine.

## Implemented runtime surface

One Go command is built: `ehjint`. The optional `ej` name is a symbolic alias to the same multicall binary. The implemented commands are deliberately limited to non-mutating diagnostics:

```text
ehjint version [--json]
ehjint doctor [--json]
ehjint registry list [--json]
ehjint registry describe <operation> [--json]
```

A bare invocation and every undeclared command fail closed with stable exit statuses and versioned public errors. `doctor` reports `foundation_only=true` and `later_runtime_activated=false`.

## Canonical and generated authority

`registry/operations.json` is the single human-authored operation registry. It declares semantic names, versions, strict input and output schemas, error sets, classification, idempotency, streaming, cancellation, CLI mapping, MCP mapping, availability, and deprecation state.

The standard-library-only generator validates that source and produces:

- typed Go operation identifiers and the compiled catalog;
- the CLI descriptor;
- exactly one MCP tool descriptor named `ehjint`;
- operation and contract JSON Schemas;
- compatibility and provider-contract data;
- generated operation and contract documentation;
- CLI/MCP parity data;
- a registry digest and generated-artifact digest manifest.

Generated files carry a generated marker. `scripts/check-generated.sh` regenerates in memory and requires byte-for-byte agreement. It also rejects unexpected files inside generated-output ownership.

## Frozen contracts

Mission 1 freezes version 1 contracts for:

- namespaced operation, machine, release, snapshot, job, PTY, and capability-pack identifiers;
- durable operation states and legal terminal transitions;
- cooperative cancellation intent;
- strict error and result envelopes;
- canonical request digests and idempotency create/replay/conflict decisions;
- machine manifests with explicit disk formats, exact component identities, network topology, workspace mode, device bindings, snapshot lineage, and creating-release identity;
- release manifests with exact source commit and tree, target, toolchain, binary, registry, component, dependency, compatibility, and provenance identities;
- provider boundaries for VMM, guest image, storage, network, workspace, device, browser capability packs, and protocol edges.

Provider entries remain `contract_only`. They establish data and lifecycle expectations without claiming implementation or authority.

## Pinned standalone build

The reference build uses the official Go `linux/amd64` archive named in `config/toolchain.lock.json`. The archive is downloaded from its public source and verified by SHA-256 before extraction. No external Go module is permitted.

`scripts/build.sh` compiles the binary twice with path, VCS, and build-ID variability removed, requires identical SHA-256 digests, installs the first result as `build/bin/ehjint`, and creates `build/bin/ej` as its alias.

The complete dependency lock records purpose, source, immutable digest, license, scope, distribution status, target platform, and verification method for every dependency actually used by this mission.

## Verification

Run the complete local gate from a clean checkout:

```bash
./scripts/bootstrap-tools.sh
./scripts/check.sh
```

The gate verifies formatting, vet, generated freshness, repository hygiene, secrets, private-path absence, large/binary file absence, standalone imports, dependency-lock agreement, immutable CI action pins, minimal workflow permissions, one runtime entrypoint, unit and negative tests, race tests, reproducible builds, alias behavior, JSON diagnostics, and stable failure exits.

The only workflow performs the same gate on an Ubuntu runner. It has read-only repository permission, uses one full-commit-pinned checkout action, disables persisted credentials, and bootstraps the same digest-pinned public toolchain.

## Mission boundary

Machine lifecycle, VMM launch, guest execution, networking, storage activation, snapshots, forks, device attachment, browser packs, protocol serving, installation, release activation, and deployment belong to later missions. Adding any of them here would violate the Mission 1 boundary.
