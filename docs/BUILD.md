# EHJINT Build Specification

Status: canonical build contract for v1.

## 1. Build objective

Produce a small, sovereign, installable EHJINT release that starts a full-power root Linux guest through Cloud Hypervisor, exposes the same operation registry to the CLI and MCP, survives controller loss, and does not require a model API or hosted control plane.

The standard path optimizes for minimum friction. The sovereign path optimizes for complete rebuildability. Both satisfy the same compatibility and behavior contract.

## 2. Supported reference host

The initial reference platform is:

- Linux x86_64.
- Hardware virtualization and `/dev/kvm` available.
- A modern kernel supporting the Cloud Hypervisor v1 API requirements used by the pinned release.
- systemd on the host and guest.
- Filesystem support for sparse files; reflink support is preferred but not required.
- Sufficient permission to install the binary, create a service, configure TAP/NAT/port rules, create managed identities, and access requested hardware.

A host without KVM is unsupported for the primary v1 execution mode and must fail clearly.

## 3. Mandatory upstream components

Pin by exact version and digest:

- Go toolchain.
- Cloud Hypervisor.
- Linux firmware or boot firmware required by the selected boot path.
- Ubuntu LTS minimal cloud image inputs and package snapshot.
- SQLite library used by the Go driver.
- Official Go MCP SDK version selected for the stable protocol lane.
- Browser Pack versions for Chromium and Playwright.
- Virtio-fs implementation selected for the host.

All dependencies must be free for the intended use and pass license review. Dependency versions and licenses are recorded in a machine-readable lock manifest.

## 4. Repository shape

The implementation should converge on this compact structure:

```text
cmd/ehjint/               multicall entrypoint
internal/controller/      host lifecycle and reconciliation
internal/guest/           guest-agent implementation
internal/registry/        canonical operations and generated surfaces
internal/machine/         manifests, compatibility, state, lifecycle
internal/vmm/             Cloud Hypervisor adapter
internal/storage/         images, overlays, snapshots, sparse handling
internal/workspace/       virtio-fs and fork modes
internal/network/         TAP, NAT, ports, ownership and cleanup
internal/device/          VFIO and hardware planner
internal/browser/         Browser Pack integration
internal/mcp/             MCP transport and compatibility edge
internal/relay/           optional thin relay mode or shared protocol code
internal/state/           SQLite and authoritative file layout
internal/release/         install, update, rollback and compatibility
api/                      generated stable operation schemas
assets/guest/             guest image recipe, pins and first-boot inputs
docs/                     canonical documents and later operator docs
scripts/                  narrow reproducible build and certification entrypoints
tests/                    integration and destructive fixtures
```

This is guidance, not permission to split the product into independent services.

## 5. One binary and modes

The `ehjint` executable dispatches by subcommand, argv0, or an explicit internal mode:

- CLI client.
- Host controller daemon.
- Guest agent.
- MCP server.
- Relay process where deployment chooses the same binary.
- Narrow installer, updater, doctor, and compatibility helpers.

A separate upstream VMM, virtio-fs daemon, browser, or system service is acceptable because it is not EHJINT authority. A second EHJINT controller binary is not.

The optional `ej` command is a symlink or equivalent alias to `ehjint`, never a forked implementation.

## 6. Canonical operation registry

Every public operation is declared once with:

- Stable semantic name.
- Input and output schemas.
- Mutation or read-only classification.
- Idempotency behavior.
- Streaming and cancellation behavior.
- Required machine state.
- Error codes.
- CLI mapping.
- MCP mapping.
- Compatibility version.

Generation produces CLI bindings, MCP schemas, documentation fragments, and parity tests. Generated outputs are reproducible and checked for drift.

## 7. Host state layout

Use explicit versioned paths, with final installation paths selected before Mission 2. The layout must separate:

- Side-by-side product releases.
- Mutable controller metadata.
- Immutable base images.
- Content-addressed prepared layers.
- Per-machine manifests, overlays, runtime state, and snapshots.
- Per-operation bounded output or artifact files.
- Temporary files confined to an owned runtime directory.

No secret is stored in a manifest or log. Credential references and host-protected secret files are separate.

## 8. Guest image

The default guest is built from an official minimal Ubuntu LTS image or package snapshot. Standard installation downloads a verified prepared image. The sovereign build recreates it from pinned inputs.

The guest contains only what the core requires:

- systemd.
- The `ehjint` guest-agent mode.
- Virtio and vsock support supplied by the distribution kernel.
- Basic shell and file utilities.
- Trust material required to authenticate the host-to-guest channel.

Browser, GUI, GPU, language, container, and development tooling remain power packs.

A custom kernel or rootfs is not required for the normal path. The build must record the exact kernel and package identities used by each prepared image.

## 9. Fast build and install path

The release pipeline produces a signed or digest-verifiable bundle containing:

- `ehjint` binary.
- Compatible Cloud Hypervisor binary.
- Required firmware.
- Prepared minimal guest image.
- Compatibility manifest.
- Dependency and license manifest.
- Installation metadata.

The installer:

1. Verifies host prerequisites.
2. Verifies all component digests.
3. Installs the release beside existing releases.
4. Creates managed directories, identities, and service definitions.
5. Performs a non-destructive self-test.
6. Atomically activates the release.
7. Runs `ehjint up` or prints the exact blocking host limitation.

No interactive wizard is required for defaults.

## 10. Sovereign build path

The sovereign path is one top-level command that:

1. Verifies the source tree and lock manifest.
2. Builds the Go binary with reproducible flags.
3. Builds or verifies Cloud Hypervisor from the pinned upstream source and toolchain.
4. Produces the guest image from pinned package inputs.
5. Produces Browser Pack and optional reference-pack metadata without making them core dependencies.
6. Generates the compatibility, dependency, and license manifests.
7. Runs unit and deterministic integration tests.
8. Produces the same release-bundle format as the fast path.

Behavioral equivalence means both paths pass the same compatibility and certification suite; bit-for-bit identity is preferred where practical but is not required when upstream toolchains prevent it.

## 11. Cloud Hypervisor launch contract

The controller:

1. Validates the machine manifest and exact disk type.
2. Creates a dedicated per-machine UID/GID and runtime directory.
3. Opens required storage, TAP, KVM, VFIO cdev, iommufd, API, and event resources.
4. Configures ownership and the minimum required access.
5. Launches Cloud Hypervisor with inherited descriptors or supported SCM_RIGHTS transfer.
6. Drops privileges before untrusted guest execution.
7. Enables `no_new_privs`, zero ambient capabilities, seccomp, and Landlock where supported.
8. Re-observes process, API socket, device, disk, and guest-agent readiness before reporting success.

The VMM never receives broad access to the host or arbitrary device paths.

## 12. Disk and snapshot implementation

- Every managed disk specifies `raw`, `qcow2`, or another explicitly supported type.
- Autodetection is not used for launch authority.
- QCOW2 backing files default off.
- EHJINT-created chains bind normalized managed paths and content digests.
- Imported chains are flattened or rejected.
- Base images are read-only.
- Machine writes target overlays.
- Fork selects reflink, filesystem snapshot, Git worktree, or overlay according to the object being forked.
- Snapshot manifests bind VMM, firmware, guest image, machine configuration, disks, memory, and lineage.
- Sparse copying uses hole-preserving mechanisms and verifies the result.
- Demand-paged restore is selected only when supported and better under the certification workload.

## 13. Networking

The default network is automatic NAT with outbound access. EHJINT owns narrowly named TAP, address, route, and firewall objects. Port publication is explicit, idempotent, discoverable, and removed when its owning machine or registration is removed.

Implementation must not flush or broadly replace host firewall policy. A bridge adapter may be added without changing the default path.

## 14. Capability packs

A pack declares:

- Pack name and version.
- Supported guest image and distribution constraints.
- Package and repository pins.
- Installation and verification steps.
- Services, environment, cache, and artifact paths.
- Resulting prepared-layer digest.
- Rollback or discard behavior.

First use may build a reusable layer or warm snapshot. Later machines reuse the verified result. Pack failure cannot corrupt the immutable base or controller core.

## 15. MCP and relay build

Pin the stable official Go MCP SDK and isolate protocol-specific translation behind a narrow edge. The registry remains protocol-independent.

The public relay build contains only what routing requires:

- Authentication and authorization verification.
- Signed host-route token validation.
- Request-size and timeout bounds.
- Stateless forwarding.
- No workload execution or durable operation database.

The user-owned host records operations before mutation. Retries return existing operation identity.

## 16. Update and rollback

Each release is immutable after installation. Update installs a new directory, backs up compatible metadata, starts the new controller on a temporary socket, runs host and guest compatibility tests, switches an atomic active pointer, and verifies health.

Failure restores the prior pointer and controller. Existing machines and retained VMM binaries remain untouched. Database migrations are forward-safe, tested against rollback requirements, and never make the immediately previous supported release unable to read required state unless an explicit irreversible major upgrade is separately authorized.

## 17. Build gates

A build is not releasable unless:

- Source formatting, vetting, linting, generation drift, unit tests, and race tests pass.
- Fast and sovereign bundles pass the same compatibility suite.
- A clean reference host installs without undocumented manual steps.
- The default root shell, command, PTY, job, file, workspace, network, port, fork, snapshot, restore, restart, update, rollback, MCP, and cleanup paths pass.
- Dependency and license manifests are complete.
- No secrets or large machine artifacts are tracked.
- Repository status is clean after generation and tests.

## 18. Build non-goals

Do not build every optional pack, alternate guest, migration mode, visual accelerator, or hardware adapter before the core is certified. Architecture support is not an instruction to implement the entire upgrade universe.
