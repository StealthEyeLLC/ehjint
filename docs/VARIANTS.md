# EHJINT Variants

Status: canonical. These are permitted forms of EHJINT that do not change its sovereign core.

## Machine lifecycle

- Persistent machine.
- Disposable machine.
- Suspended warm machine.
- Snapshot restore.
- Independent fork.
- Workspace-only fork.
- Full machine export and import.
- Cold start or warm start.

## Workspaces

- Direct virtio-fs mount of an authoritative host project.
- Private reflink or filesystem-snapshot fork.
- Git worktree fork.
- Guest-contained workspace.
- Read-only reference mount.
- Multiple explicitly named workspace mounts.

## Guest profiles

- Minimal headless Linux.
- Development workstation.
- Browser computer.
- GUI desktop.
- GPU workstation.
- PCI/VFIO appliance.
- Nested-virtualization laboratory.
- Alternate Linux distribution.
- Custom kernel guest.
- Windows guest as a post-v1 power pack.

## Execution forms

- Structured one-shot command.
- Interactive root PTY.
- Detached systemd job.
- Long-running service.
- File transfer or mutation.
- Browser or desktop interaction.
- Host-authorized hardware operation.

## Networking

- Automatic NAT with outbound access.
- Bridged networking.
- Static guest addressing.
- Private host-only network.
- Explicitly published TCP or UDP ports.
- HTTP or HTTPS preview endpoints.
- Unix-socket forwarding.
- User-provided tunnel.
- Offline guest.

## Access surfaces

- Canonical `ehjint` CLI.
- Optional `ej` alias.
- Private ChatGPT integration.
- Published BYOH ChatGPT integration.
- Direct local MCP client.
- Self-hosted relay.
- StealthEye-operated thin relay.

All access surfaces use the same operation registry and must preserve semantic parity.

## Host environments

- Physical Linux workstation.
- Linux laptop with KVM.
- User-owned VPS with nested KVM available.
- Dedicated server.
- Single-host laboratory.
- Air-gapped host.

Unsupported host capabilities must fail explicitly rather than silently selecting a weaker security or execution model.

## Storage

- QCOW2 overlay.
- Raw sparse image.
- Reflink clone.
- ZFS dataset or snapshot adapter.
- Btrfs subvolume or snapshot adapter.
- Content-addressed prepared layer.
- Local encrypted storage supplied by the host.

The system must explicitly bind formats and preserve sparse semantics regardless of adapter.

## Hardware

- CPU-only.
- Whole GPU passthrough.
- Multiple GPU passthrough.
- SR-IOV virtual function.
- Mediated device.
- USB or other supported PCI device.
- Nested KVM.
- Huge pages.
- NUMA-aware placement.
- CPU or memory hotplug where supported.

Each hardware variant remains optional and cannot complicate the standard CPU-only path.

## Browser and visuals

- Structured headless Playwright control.
- Persistent visible browser.
- Screenshot-driven interaction.
- Encoded video stream.
- WebRTC desktop takeover.
- Benchmark-qualified ivshmem frame ring with encoded remote transport.

The ordinary structured browser path remains valid without shared-memory acceleration.

## Distribution and updates

- Verified binary release.
- Sovereign source build.
- Online installer.
- Offline release bundle.
- Stable release channel.
- Explicit experimental component pin.
- Automatic rollback to the prior installed release.

## Capability packs

Permitted packs include languages, browser, GUI, databases, container tools inside the guest, local-model runtimes, Android tooling, kernel development, game development, infrastructure tooling, and hardware adapters.

A capability pack is a reproducible guest layer and verification contract. It is not permission to expand the core or add a permanent external service.
