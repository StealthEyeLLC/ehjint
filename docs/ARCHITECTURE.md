# EHJINT System Architecture

Status: canonical and frozen for v1 implementation.

## 1. Mission

EHJINT is a sovereign, full-power Linux computer controlled through a local CLI and, optionally, ChatGPT. It gives the operator unrestricted root inside an independent KVM guest while making machine creation, execution, persistence, forking, networking, browser use, hardware attachment, recovery, and updates require the least unavoidable friction.

EHJINT is not a hosted sandbox, a model provider, a generic cloud platform, or a safety-policy framework. ChatGPT supplies reasoning when that interface is used; EHJINT supplies deterministic execution on user-owned compute.

## 2. Product laws

EHJINT must exceed SMP in power ceiling, general capability, ease of construction, and ordinary usability. SMP's scale, maturity, and existing evidence are not v1 requirements, but EHJINT may not claim superiority until direct certification passes.

The product follows the least-theater law: retain only friction imposed by physics, the host kernel, hardware ownership, upstream protocols, or unavoidable security boundaries. Remove ceremony created by the product itself.

## 3. Three layers

### Layer 1: Sovereign Core

Always installed:

- One Go multicall binary named `ehjint`.
- Optional shorthand alias `ej` resolving to the same binary.
- One host controller and canonical operation registry.
- Cloud Hypervisor adapter and pinned VMM releases.
- Minimal Ubuntu LTS guest baseline.
- Root guest agent over virtio-vsock.
- SQLite WAL metadata plus content-addressed files.
- Immutable base images and copy-on-write machine overlays.
- Commands, files, PTYs, detached jobs, workspaces, networking, ports, fork, snapshot, restore, reconciliation, upgrade, and rollback.
- MCP endpoint generated from the same operation registry as the CLI.

The core alone is a complete unrestricted Linux computer.

### Layer 2: Power Packs

Installed only when requested and never required by the base system:

- Browser and visual computer control.
- GUI desktop.
- GPU, VFIO, PCI, SR-IOV, mediated devices, and nested virtualization.
- Language toolchains and development environments.
- Local-model runtimes.
- Windows or alternate guest support.
- Advanced migration and networking.

A pack may add guest packages, prepared layers, or narrowly scoped helpers. It may not add another controller, durable scheduler, operation registry, or mandatory external service.

### Layer 3: Distribution

Optional access surfaces:

- Local CLI.
- Private ChatGPT connection through a private tunnel.
- Published BYOH ChatGPT integration through a thin relay.
- Self-hosted relay.

Layer 1 never depends on Layer 3. Loss of ChatGPT, the relay, the tunnel, or the internet cannot disable local operation.

## 4. Runtime architecture

The host controller owns machine construction and host integration. It creates runtime directories, overlays, TAP devices, port rules, workspace exports, device handles, and machine identities. Cloud Hypervisor runs as a dedicated unprivileged per-machine identity with only authorized file descriptors and paths.

The guest agent runs as unrestricted UID 0 inside the VM. It exposes a framed, multiplexed, resumable protocol over virtio-vsock for structured commands, exact stdout and stderr, exit status, PTYs, jobs, file operations, health, and control signals.

Virtio-fs is the default workspace transport. Direct host workspaces are authoritative for ordinary development. Fork mode creates a private reflink, filesystem snapshot, or Git worktree. Contained mode stores the workspace only inside the guest.

SQLite WAL stores compact controller metadata. Authoritative machine assets remain explicit files and directories. No external database or queue is required.

## 5. Machine behavior

`ehjint` with no arguments opens the default machine's root shell. `ehjint up` is convergent:

- Create if absent.
- Restore if suspended.
- Start if stopped.
- Adopt if already running.
- Repair only EHJINT-owned stale resources.
- Reattach the current project.
- Reopen or create the expected terminal.
- Return immediately when already ready.

Detached work is guest-systemd-owned and survives client, tunnel, relay, and controller loss. Interactive PTYs survive disconnection and can be reattached by stream cursor and terminal identity.

## 6. Machine identity and portability

Every machine has a canonical manifest binding:

- Architecture.
- VMM version and digest.
- Firmware and guest-image digests.
- Guest-agent and schema versions.
- CPU, memory, disk, network, and device topology.
- Capability packs.
- Workspace mode and references.
- Snapshot lineage.
- Required host capabilities.

The manifest is a technical recreation and compatibility contract, not a receipt framework. Existing machines must remain usable with retained compatible binaries even after newer releases are installed.

## 7. Fork, snapshot, and restore

`ehjint fork` creates an independent machine identity, guest overlay, workspace fork, terminals, jobs, browser state, and ports. A fork is a machine plus lineage, not a separate transaction platform.

Snapshots are bound to the exact compatible VMM and machine manifest. Sparse guest-memory files must preserve holes end to end. Cloud Hypervisor's offloaded snapshot and restore path and userfaultfd on-demand paging are used when supported and measurably beneficial. Eager restore remains the fallback.

Performance claims are evidence-driven. Sub-30-ms restore may be a reference-host target but is not a universal contract.

## 8. Hardware power

The controller may use host root only for required construction and hardware operations. A hardware planner discovers IOMMU state, groups, drivers, dependencies, reset behavior, conflicts, and guest requirements before attachment.

Supported resources are opened or created by the privileged controller and passed to the unprivileged VMM using inherited descriptors or SCM_RIGHTS where the VMM supports it. Failed attachment and machine deletion must restore prior host ownership when technically possible.

Hardware-dependent capabilities are reported honestly. EHJINT cannot promise passthrough, reset, migration, or nested acceleration unsupported by the actual host.

## 9. VMM hardening and disk law

Every Cloud Hypervisor process uses:

- A dedicated per-machine UID and GID, never a human UID such as 1000.
- `no_new_privs` and zero ambient capabilities.
- Upstream seccomp filtering.
- Landlock path restrictions when supported.
- A private runtime directory.
- Only required inherited file descriptors and device access.

Every disk declares an explicit image type. Unknown or unspecified types fail before launch. Imported and untrusted QCOW2 backing chains are rejected or flattened. Backing files are allowed only for EHJINT-created, content-addressed, path-normalized, digest-verified objects inside the managed store.

## 10. Browser and visuals

The Browser Pack provides a persistent browser computer inside the guest. Structured Playwright operations, screenshots, traces, console output, network inspection, downloads, uploads, and profiles use the normal control path.

An optional accelerated visual plane may use Cloud Hypervisor ivshmem as a guest-to-host frame ring while vsock carries control and notifications. A guest capture bridge is required; Chromium is not assumed to render directly into ivshmem. Remote viewing still uses encoded transport such as WebRTC. The accelerated path ships only if benchmarks prove meaningful CPU or latency improvement and always has a conventional fallback.

## 11. MCP and public relay

CLI, private integration, published integration, and documentation are generated from one canonical operation registry.

The preferred public relay is a stateless HTTP router under the current stateless MCP protocol. It performs authentication and host routing only. It does not execute workloads, store durable operation state, retain output history, provide reasoning, or become required for private or local use.

Correctness never depends on transport retries. Every mutation is host-durable and idempotent. Duplicate requests return the existing operation. Long work is resumed by operation identity. A narrow removable compatibility adapter may support older MCP clients until the target ChatGPT surface passes the current protocol suite.

## 12. Recovery

Recovery is part of every mutation rather than a separate service:

1. Observe current state.
2. Record the desired transition.
3. Perform the smallest owned mutation.
4. Re-observe.
5. Adopt the resulting state.

The controller must survive termination between any two steps. On restart it reconstructs truth from SQLite, machine directories, VMM API sockets, process identity, guest-agent state, systemd units, virtio-fs processes, TAP devices, port rules, manifests, and snapshots.

## 13. Installation, sovereignty, and updates

EHJINT has two supported paths:

- Fast path: download and verify pinned release components, then run `ehjint up`.
- Sovereign path: rebuild redistributable components and guest assets from pinned source and package snapshots, producing a behaviorally equivalent release bundle.

A release is installed beside previous releases and activated through an atomic pointer. Upgrade performs compatibility checks, metadata backup, temporary self-test, atomic activation, health verification, and automatic rollback on failure. Running machines are not recreated merely because the controller is upgraded.

EHJINT remains fully usable offline through the local CLI after installation. No account, subscription, activation server, telemetry endpoint, model API, hosted sandbox, or remote license check may gate local operation.

## 14. Scope discipline

New functionality enters the core only when it is necessary to power, compatibility, durability, performance, or ordinary ease; the core is the only technically correct owner; no second permanent service is required; the behavior remains invisible during ordinary use; restart, rollback, and cleanup are proven; and the implementation is smaller than the ceremony it removes.

Otherwise it becomes a power pack, adapter, future proposal, or rejected scope.
