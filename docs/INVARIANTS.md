# EHJINT Invariants

Status: canonical. An implementation violating any invariant is not EHJINT.

## Product and sovereignty

1. EHJINT provides an unrestricted root Linux guest with an independent kernel on user-owned KVM compute.
2. Local CLI operation never requires ChatGPT, a model API, a hosted sandbox, a cloud control plane, a vendor account, or internet access after installation.
3. The installed system continues operating indefinitely without contacting StealthEye or an activation service.
4. All durable machine state, workspaces, snapshots, manifests, and controller metadata remain locally controllable and exportable.
5. External interfaces are optional and replaceable without redesigning the core.

## Core shape

6. One Go multicall binary provides the controller, CLI, guest agent, MCP server, and narrow helper modes unless an upstream process must remain separate.
7. One canonical operation registry generates CLI behavior, MCP exposure, schemas, documentation, and parity tests.
8. One host controller owns machine lifecycle and EHJINT-created host resources.
9. SQLite WAL plus explicit files are the only mandatory durable local state mechanisms.
10. No external database, message queue, scheduler, container platform, or service mesh is required.
11. Optional power packs cannot create a second controller, durable scheduler, operation registry, or authority.

## Execution

12. The guest agent runs as unrestricted UID 0 inside the guest.
13. Bare `ehjint` and bare `ej` open the default guest root shell.
14. Commands return exact stdout, stderr, exit status, timing, and termination truth.
15. Mutating operations are durable and idempotent; conflicting reuse of an idempotency key fails.
16. Detached jobs are guest-systemd-owned and survive controller, client, tunnel, and relay loss.
17. PTYs are persistent, identifiable, reconnectable, and resumable without replaying prior input.
18. Controller restart and host reboot recovery adopt existing work rather than duplicate it.
19. No operation reports success before its resulting state is re-observed.

## Virtualization and storage

20. Cloud Hypervisor is the primary VMM until a replacement demonstrably improves the complete EHJINT contract without weakening an invariant.
21. Virtio-vsock is the primary control transport. SSH is recovery-only and not the execution spine.
22. Virtio-fs is the default direct workspace transport.
23. Base images are immutable. Machines use copy-on-write overlays.
24. Every disk declares an explicit format. Unknown or unspecified formats fail closed.
25. Imported or untrusted QCOW2 backing chains are rejected or flattened.
26. Snapshots bind the exact machine manifest and compatible VMM identity.
27. Compatible historical VMM binaries are retained while snapshots or machines require them.
28. Sparse disk and memory semantics are preserved through copy, fork, export, import, and restore.

## VMM boundary

29. Each VMM runs under a dedicated unprivileged per-machine identity, never a normal human account.
30. The privileged controller opens or creates required host resources and passes supported descriptors to the VMM.
31. VMM processes use `no_new_privs`, zero ambient capabilities, seccomp, and Landlock when supported.
32. Host root is used only for required construction, networking, device, ownership, and cleanup operations.
33. Arbitrary remote host-root shell access is not a default product capability.
34. Unrestricted guest root is never weakened to simplify host hardening.

## Networking and hardware

35. Ordinary guest networking and outbound access are automatic.
36. Inbound ports can be published without manually editing host networking.
37. EHJINT cleans only resources it owns and does not weaken unrelated host firewall or network policy.
38. GPU, VFIO, PCI, SR-IOV, mediated devices, and nested virtualization are optional, hardware-dependent power lanes.
39. Hardware limitations and reset requirements are reported honestly; unsupported capability is never fabricated.
40. Failed device preparation and machine removal restore prior host ownership when technically possible.

## Interfaces

41. CLI and MCP have the same machine power and canonical semantics.
42. The published integration is not intentionally weaker than the private integration or CLI.
43. The public relay performs authentication and routing only; it never becomes execution authority or durable workload storage.
44. The preferred public relay is stateless at the MCP application layer.
45. Correctness never depends on a client automatically retrying a dropped request.
46. A compatibility adapter may exist only at the protocol edge and must remain removable.

## Browser and visuals

47. Browser execution occurs inside the guest and does not require a paid browser API.
48. Browser sessions and artifacts survive ChatGPT and relay disconnection.
49. Shared-memory visual acceleration is optional, benchmark-gated, and never the only visual path.
50. Vsock remains the visual control plane even when ivshmem carries frame data.

## Installation and upgrades

51. Standard installation and first machine startup require one normal command path with no mandatory wizard.
52. Ordinary installation does not require building a custom kernel or root filesystem.
53. A maintained sovereign source-build path recreates redistributable components and guest assets from pinned inputs.
54. Fast and sovereign builds are behaviorally equivalent under the same compatibility contract.
55. Releases install side by side and activate atomically.
56. Failed upgrades roll back automatically without invalidating existing machines.
57. Existing machines are not recreated solely because EHJINT is upgraded.

## Discipline and claims

58. Advanced capability never adds ceremony to the ordinary path.
59. No power is removed merely to make the implementation look smaller.
60. Reproducibility requirements cannot become recurring user friction.
61. The upgrade universe is not the v1 backlog.
62. No checkpoint, prototype, or partial mission is marketed as v1.
63. No claim that EHJINT exceeds SMP is valid until the direct certification gates pass.
64. Every v1 feature has restart, cleanup, rollback, parity, and failure tests.
