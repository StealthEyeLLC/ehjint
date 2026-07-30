# EHJINT Implementation Missions

Status: canonical execution sequence. The six missions produce v1; intermediate checkpoints are not v1.

## Global execution rules

- Build only from this clean repository and the pinned upstream sources declared by EHJINT.
- Do not import SMP, Baby, Baby-X, or archived EHJINT implementation code.
- Preserve the invariants, anti-invariants, and frozen v1 scope.
- Use small fast-forward checkpoints with exact commit and tree identities.
- No deployment to an unrelated production host during implementation.
- No hidden manual steps, fabricated success, or claims based on architecture alone.
- Every mission ends with code, tests, evidence, a clean tree, and an updated compatibility manifest.

## Mission 1: Freeze and bootstrap

### Objective

Create the smallest trustworthy source foundation and make later divergence difficult.

### Required work

- Initialize the Go module and multicall `ehjint` entrypoint.
- Establish the compact repository layout.
- Define the canonical operation registry format and generator.
- Generate initial CLI, MCP schema, documentation, and parity-test artifacts.
- Define stable identifiers, error envelopes, operation states, idempotency semantics, and compatibility versions.
- Define the machine manifest, release manifest, dependency lock, and provider contracts.
- Pin upstream toolchains and free/legal dependencies.
- Build formatting, lint, unit, race, generation-drift, secret-scan, and large-file gates.
- Implement a no-op or diagnostic CLI proving registry dispatch through both `ehjint` and `ej`.

### Exit gates

- One binary builds reproducibly on the reference host.
- Registry generation is deterministic and drift-checked.
- CLI and MCP schemas derive from the same declarations.
- Unknown operations, versions, fields where strictness is required, and conflicting idempotency inputs fail deterministically.
- Dependency and license manifests are complete for the foundation.
- Repository is clean and searchable.

## Mission 2: Sovereign execution spine

### Objective

Create, start, control, stop, and recover an unrestricted root Linux VM using the sovereign core.

### Required work

- Implement release and host state layouts.
- Implement SQLite WAL metadata and atomic authoritative file writes.
- Build the minimal Ubuntu guest image recipe and verified prepared image.
- Implement guest-agent mode and authenticated framed vsock protocol.
- Implement Cloud Hypervisor adapter, exact version binding, API lifecycle, and readiness.
- Implement explicit disk-type validation, immutable base, overlay creation, and managed backing policy.
- Implement dedicated VMM identities, privileged resource setup, descriptor transfer where supported, seccomp, Landlock, `no_new_privs`, and bounded paths.
- Implement structured root commands with exact streams, status, cancellation, timeouts, and terminality.
- Implement convergent `ehjint up`, bare `ehjint`, bare `ej`, stop, status, inspect, and remove.
- Implement controller restart and host-reboot adoption from durable truth.

### Exit gates

- A clean host can install and open a root guest shell with the documented normal path.
- Controller kill at each lifecycle boundary does not duplicate or orphan a machine.
- Disk-format confusion, unknown types, escaping backing paths, wrong ownership, and unavailable KVM fail closed.
- VM removal leaves no owned process, API socket, TAP, mount, port, identity, or runtime directory.
- Local use requires no external account or service.

## Mission 3: Complete workstation

### Objective

Turn the execution spine into a persistent full-computer work environment.

### Required work

- Persistent reconnectable root PTYs.
- Detached guest-systemd jobs, bounded logs, cancellation, signals, and adoption.
- Exact file and directory operations, transfers, metadata, bounded search, and atomic writes.
- Virtio-fs direct workspaces with restart recovery.
- Private workspace forks using the best available reflink, filesystem snapshot, or Git worktree mechanism.
- Guest-contained workspace mode.
- Project-to-machine association and working-directory restoration.
- Automatic NAT networking, DNS, owned TAP lifecycle, and TCP/UDP port publication.
- Capability-pack contract, installer, verifier, layer reuse, and rollback/discard behavior.
- Browser Pack baseline with persistent Chromium, Playwright, profiles, screenshots, uploads, downloads, console, network events, and traces.
- Optional shared-memory visual prototype and benchmark harness; retain it only if admission thresholds are met.

### Exit gates

- PTYs, jobs, files, workspaces, ports, and browser sessions survive controller and client loss.
- Direct host files remain authoritative and are not silently copied or mutated through an unintended path.
- Network cleanup affects only EHJINT-owned objects.
- Browser work persists without a paid browser API.
- Unused packs add no ordinary startup or setup friction.

## Mission 4: Machine power

### Objective

Complete the machine lifecycle, instant environment branching, hardware reach, and unbreakable release management.

### Required work

- Machine clone and `ehjint fork` with independent identity, overlay, workspace lineage, terminals, jobs, browser state, and ports.
- Snapshot manifests binding exact VMM, firmware, guest image, topology, disks, memory, packs, and lineage.
- Sparse memory and disk preservation across snapshot, copy, export, import, and restore.
- Cloud Hypervisor offloaded restore, userfaultfd demand paging, background prefault, fallback selection, and detailed latency measurements.
- VMM compatibility selection and retention of required historical binaries.
- CPU, memory, disk, and supported device hotplug where upstream supports it.
- Hardware discovery and planning for IOMMU, groups, drivers, reset, conflicts, VFIO cdev, iommufd, GPU, and nested KVM.
- Failure-safe device attach, detach, restart adoption, and restoration of prior host ownership.
- Side-by-side release installation, temporary self-test, atomic activation, guest compatibility, and automatic rollback.
- Fast release build and sovereign source-build convergence.

### Exit gates

- Forks are independent, fast, cleanly discardable, and promotable where supported.
- Snapshot restore selects a compatible VMM and never silently consumes an incompatible snapshot.
- Demand paging is enabled only where measured results beat eager restore without unacceptable tail latency.
- Hardware claims match actual tested devices and host capabilities.
- Failed update returns to the prior healthy release without recreating machines.

## Mission 5: ChatGPT product

### Objective

Expose complete EHJINT power through private and published ChatGPT integrations without making either part of the sovereign core.

### Required work

- Stable MCP transport generated from the operation registry.
- Current stateless MCP protocol lane and official Go SDK integration.
- Narrow removable compatibility edge for the exact target ChatGPT client where needed.
- Streaming, cancellation, operation lookup, wait, resume, and bounded artifact retrieval.
- Private connection through the supported private tunnel.
- Published BYOH integration.
- Stateless relay performing only authentication, authorization, signed host routing, bounds, and forwarding.
- Host enrollment and key rotation without relay-owned workload state.
- Durable host-side operation creation before mutation.
- Duplicate request replay returning the existing operation.
- CLI, private, and published semantic parity suite.

### Exit gates

- Relay restart or replacement does not lose or duplicate host work.
- Dropped responses are recoverable without assuming automatic ChatGPT retries.
- The relay contains no VM, job, snapshot, workspace, browser, or operation database authority.
- Published integration can perform the same guest actions as CLI subject only to user authentication and actual host capability.
- Local and private paths function with the public relay absent.

## Mission 6: Convergence and certification

### Objective

Remove residual friction, prove the product, and create the first canonical v1 checkpoint.

### Required work

- Clean-host fast installation from the release bundle.
- Clean-host sovereign build from source and pinned inputs.
- Full unit, race, integration, destructive, recovery, protocol, security-boundary, compatibility, and cleanup suites.
- Fault injection at every durable lifecycle transition.
- Restore, fork, command, PTY, job, file, workspace, port, browser, and plugin benchmarks.
- Dependency, license, secret, artifact-size, and repository-tightness audits.
- Point-of-use diagnostics and removal of avoidable setup steps.
- Direct EHJINT-versus-SMP comparison using frozen comparable workloads and stated exemptions.
- Fresh documentation generated from the canonical registry.
- Final compatibility manifest, evidence index, exact commit, tree, release digests, known limitations, and rollback instructions.

### Exit gates

- Every item in `docs/CERTIFICATION.md` passes or is explicitly recorded as a truthful hardware-dependent limitation allowed by v1 scope.
- Fast and sovereign bundles pass the same functional suite.
- No undocumented recurring manual step remains in the normal path.
- No speculative post-v1 feature has entered the core.
- Repository, host, and test fixtures are clean after certification.
- Only this completed convergence checkpoint may be called EHJINT v1.

## Implementation completeness rule

The missions are implementation containers, not prompts that may stop after planning. A mission is complete only when its required behavior exists, is tested, is evidenced, and is remotely checkpointed. The six-mission structure remains fixed unless an unavoidable external platform limit requires a separately documented adapter certification.
