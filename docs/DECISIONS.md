# EHJINT Canonical Decisions

Status: locked decisions as of 2026-07-30. This file summarizes decisions; higher-precedence governing documents control conflicts.

## Product identity

- Product name: EHJINT.
- Public repository: `StealthEyeLLC/ehjint`.
- Canonical command: `ehjint`.
- Optional shorthand: `ej`.
- Bare command opens the default guest root shell.
- The name has no required public expansion or origin story.

## Product definition

- EHJINT is a sovereign full-computer execution system, not merely an agent framework.
- The guest is a real KVM virtual machine with its own kernel and unrestricted root.
- ChatGPT is an optional reasoning and control interface, not an execution dependency.
- Local CLI operation is permanently first-class.

## Primary substrate

- Primary VMM: Cloud Hypervisor.
- Default guest: minimal Ubuntu LTS.
- Primary control transport: virtio-vsock.
- Default workspace transport: virtio-fs.
- Default storage: immutable base plus copy-on-write overlay.
- Mandatory state: SQLite WAL plus explicit managed files.
- Detached execution authority: guest systemd.

## Core organization

- One Go multicall binary.
- One host controller.
- One canonical operation registry.
- Three layers: Sovereign Core, optional Power Packs, optional Distribution.
- No mandatory container platform, external database, broker, scheduler, or model service.

## Sovereignty

- Fast verified binary installation is the default.
- A maintained sovereign source-build path is required.
- Installed versions continue operating offline indefinitely.
- No activation, subscription, account, telemetry, or hosted service may gate local use.
- External network components are replaceable and self-hostable.

## Machine behavior

- `ehjint up` creates, restores, starts, or adopts as needed.
- Controller recovery is observe, declare, mutate minimally, re-observe, and adopt.
- Durable operations are idempotent and survive transport loss.
- Fork is a native machine-plus-workspace lineage primitive, not a transaction subsystem.
- Snapshots bind exact compatible machine and VMM identities.

## Security boundary

- Host root performs only required construction, networking, device, ownership, and cleanup work.
- The VMM runs under a dedicated unprivileged per-machine identity.
- `no_new_privs`, zero ambient capabilities, seccomp, and Landlock are required where supported.
- Privileged resources are opened or created by the controller and passed to the VMM when upstream interfaces support it.
- Arbitrary remote host-root shell is not a default operation.
- Guest root remains unrestricted.

## Disk policy

- Every disk format is explicit.
- Launch-time autodetection is prohibited.
- Unknown or unspecified formats fail closed.
- Untrusted QCOW2 backing chains are rejected or flattened.
- Managed backing chains are content-addressed, digest-bound, normalized, and confined to the managed store.
- Sparse semantics are preserved end to end.

## Browser and visual policy

- Browser execution occurs inside the guest.
- Chromium plus Playwright is the v1 Browser Pack baseline.
- Browser profiles and work survive interface disconnection.
- Ivshmem frame-ring acceleration is optional and benchmark-gated.
- Vsock remains the control plane.
- Remote viewing still uses an encoded transport and no false universal zero-copy claim is made.

## MCP and relay

- CLI and MCP derive from the same operation registry.
- Preferred published transport follows the current stateless MCP protocol.
- The relay is an HTTP authentication and routing layer only.
- The relay stores no durable execution state and runs no workloads.
- Host durability, not automatic client retry, guarantees correctness.
- A narrow protocol compatibility adapter may temporarily support an exact target client and must remain removable.

## Restore policy

- Use Cloud Hypervisor offloaded snapshot and restore facilities.
- Use userfaultfd demand paging and background prefault when supported and measurably beneficial.
- Preserve sparse memory files using hole-aware paths.
- Keep eager restore as fallback.
- Treat sub-30-ms restore as a benchmark target, not a universal promise.

## Hardware policy

- VFIO, GPU, PCI, SR-IOV, mediated devices, hotplug, and nested KVM are optional power lanes.
- The planner must explain actual IOMMU, grouping, driver, reset, and conflict truth.
- Failed operations restore prior host state where technically possible.
- Unsupported hardware claims are prohibited.

## Release policy

- Releases install side by side.
- Activation uses an atomic pointer.
- Upgrade includes compatibility inspection, metadata protection, temporary self-test, health verification, and automatic rollback.
- Existing machines are not recreated due solely to controller upgrade.
- Required historical VMM binaries remain available while referenced.

## Scope policy

- V1 is exactly the scope in `V1-SCOPE.md`.
- The larger world-class upgrade inventory is architectural possibility, not the v1 backlog.
- Refinements fit inside the six missions unless an unavoidable external platform limit requires separate adapter certification.
- Live migration, Windows, full GUI productization, multi-host scheduling, broad LSP/notebook platforms, marketplaces, and most packs are post-v1.

## Evidence policy

- Architecture is complete, but the product is not complete until implemented.
- The 10/10 assessment is a design target, not a current implementation claim.
- EHJINT cannot claim to exceed SMP until the direct certification standard passes.
- Only the completed Mission 6 convergence checkpoint may be called EHJINT v1.
