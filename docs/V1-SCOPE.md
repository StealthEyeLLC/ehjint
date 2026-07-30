# EHJINT Frozen v1 Scope

Status: canonical and frozen. Items outside this document cannot block v1 unless required to satisfy an invariant or repair a demonstrated correctness defect.

## Required v1 product

1. One Go multicall binary named `ehjint`.
2. Optional `ej` alias resolving to the same executable.
3. One host controller and one canonical operation registry.
4. Cloud Hypervisor machine lifecycle with pinned compatible VMM binaries.
5. Minimal Ubuntu LTS guest baseline.
6. Unrestricted root guest agent over virtio-vsock.
7. Structured command execution with exact stdout, stderr, exit status, timing, cancellation, and termination truth.
8. Persistent root PTYs with reconnect and resize.
9. Detached guest-systemd jobs with restart-safe adoption.
10. Exact file read, write, transfer, metadata, directory, and bounded search operations.
11. Virtio-fs direct workspaces.
12. Private workspace fork through reflink, filesystem snapshot, or Git worktree where supported.
13. Guest-contained workspace mode.
14. Automatic guest networking with outbound access.
15. Explicit TCP and UDP port publication with owned cleanup.
16. Immutable base images and writable copy-on-write overlays.
17. Explicit disk-format binding and verified QCOW2 backing policy.
18. Machine manifest and exact component compatibility binding.
19. Machine clone and independent fork.
20. Snapshot, sparse memory preservation, restore, and compatible VMM selection.
21. Cloud Hypervisor offloaded restore and userfaultfd demand paging when supported and measurably beneficial.
22. Controller restart recovery and host-reboot recovery.
23. Dedicated unprivileged per-machine VMM identities.
24. Privileged setup with supported TAP, VFIO, and iommufd descriptor passing.
25. `no_new_privs`, zero ambient capabilities, seccomp, and Landlock where supported.
26. Browser capability pack with persistent Chromium, Playwright control, profiles, screenshots, downloads, uploads, console, network inspection, and traces.
27. Benchmark-gated ivshmem visual acceleration with a conventional fallback; it may be deferred without blocking headless browser certification if it fails the admission benchmark.
28. VFIO and GPU framework with honest hardware-dependent certification on available reference hardware.
29. One MCP operation surface generated from the canonical registry.
30. Private ChatGPT integration through a private tunnel.
31. Published BYOH ChatGPT integration through a thin stateless relay.
32. Host-durable idempotent operations independent of client retries.
33. Fast verified binary installation path.
34. Maintained sovereign source-build path.
35. Side-by-side releases, atomic activation, compatibility checks, and automatic rollback.
36. Clean-host, destructive, performance, protocol, sovereignty, and direct SMP certification.

## Required ordinary experience

The supported normal path is:

```bash
ehjint up
```

or simply:

```bash
ehjint
```

The system automatically creates, restores, starts, or adopts the default machine and opens a root shell. No custom kernel build, rootfs assembly, networking questionnaire, cloud account, model API key, or dashboard is required.

## Required repository outputs

- Source for the one Go module and generated registry artifacts.
- Guest image recipe and pinned package inputs.
- Reproducible release and sovereign-build tooling.
- Narrow relay source or separately versioned relay component generated from the same protocol contract.
- Unit, integration, restart, destructive, protocol, and benchmark tests.
- Machine-readable compatibility manifest.
- Human-readable build, operation, and certification documentation.

## Explicitly post-v1

The following are architecturally enabled but cannot delay v1:

- Live migration as a supported product workflow.
- Encrypted cross-host migration.
- Multi-host scheduling or fleet control.
- Windows guest certification.
- Full GUI desktop productization beyond what browser or visual certification requires.
- Multiple browser engines.
- Warm pools beyond a single local prepared template or snapshot.
- Distributed laboratories.
- Shared multi-user machine control.
- Template or capability marketplace.
- General persistent notebook or interpreter platform.
- General LSP or code-intelligence platform.
- Full Dev Container compatibility.
- Local-model runtime packs.
- Android, game-development, database, Kubernetes, and language packs beyond any minimal implementation test fixture.
- Cross-host snapshot catalog.
- Generic cloud provider abstraction.
- Automatic support for every VFIO device class.
- Advanced deterministic tuning engine beyond bounded measured defaults.

## Non-goals

EHJINT v1 does not provide its own model, reasoning service, hosted compute, billing platform, tenant scheduler, policy engine, receipt fabric, generic deployment system, or production orchestration platform.

## Scope-change rule

A proposed v1 addition must prove that omitting it would violate a governing invariant or make an existing required item technically incorrect. Desirability, industry fashion, or future convenience is insufficient.
