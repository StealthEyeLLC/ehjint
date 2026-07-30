# EHJINT Anti-Invariants

Status: canonical. The following outcomes are prohibited even when they appear convenient.

## Dependency and platform sprawl

1. No model API is required for EHJINT execution.
2. No hosted sandbox, paid browser API, hosted interpreter, or managed agent runtime is required.
3. No Kubernetes, Docker, containerd, Incus, Kata, Redis, PostgreSQL, message broker, service mesh, vector database, or workflow engine is a mandatory dependency.
4. No agent-framework pile substitutes for the operation registry and deterministic controller.
5. No second scheduler, worker authority, machine authority, artifact authority, or recovery authority is introduced.
6. No generic cloud-control-plane ambitions enter v1.
7. EHJINT does not become an Incus, Daytona, E2B, or Kubernetes clone.

## Architecture drift

8. No separate CLI and MCP implementations.
9. No duplicate schemas or hand-maintained operation lists.
10. No giant catch-all MCP schema that makes ordinary calls difficult to validate or use.
11. No SSH-based execution spine.
12. No relay-owned workloads, durable execution state, reasoning, or machine storage.
13. No mandatory public relay for CLI or private use.
14. No feature may require rewriting the sovereign core when it could be a power pack or adapter.
15. No capability pack may become a hidden permanent controller.

## Power reduction

16. No reduction of unrestricted guest root for cosmetic simplicity.
17. No replacement of the independent VM kernel with a process container as the default isolation boundary.
18. No removal of networking, raw sockets, inbound ports, hardware passthrough, browser use, GUI potential, or nested virtualization merely to reduce code paths.
19. No intentionally weaker published plugin.
20. No arbitrary prohibition on tools the guest root user could legally install and run.

## Host boundary failures

21. No arbitrary remote host-root shell as a default operation.
22. No VMM running as a normal human UID such as 1000.
23. No broad host filesystem access for the VMM.
24. No disabling unrelated host firewall, network, security, or ownership controls.
25. No cleanup of host resources EHJINT cannot positively identify as its own.
26. No silent fallback from a requested secure or hardware-backed mode to a weaker one.

## Disk and snapshot hazards

27. No disk-format autodetection for managed launch.
28. No unspecified image type.
29. No untrusted QCOW2 backing chain.
30. No backing path escaping the managed content store.
31. No mutation of immutable base images.
32. No full disk copy when a safe overlay, reflink, or filesystem snapshot is available.
33. No snapshot restore with an incompatible VMM selected by convenience.
34. No copy or export path that silently inflates sparse memory or disk files without warning and justification.
35. No universal latency promise derived from a single benchmark host.

## Durability failures

36. No duplicate work after a retried request.
37. No success based solely on a process launch or accepted request.
38. No lost detached job when a client, controller, tunnel, or relay disconnects.
39. No loss of PTY identity on reconnect.
40. No correctness dependency on automatic ChatGPT retries.
41. No recovery implementation that relies on an in-memory controller map as truth.
42. No stale TAP, port, mount, process, or device object left without bounded reconciliation and owned cleanup.

## User friction

43. No mandatory setup wizard for the normal path.
44. No default questionnaire for advanced CPU, storage, network, or device options.
45. No requirement to manually build a kernel, rootfs, network bridge, cloud-init image, vsock CID, or guest agent for standard installation.
46. No dashboard or account requirement for local use.
47. No recurring reproducibility ceremony during ordinary operation.
48. No advanced feature allowed to slow or complicate `ehjint` and `ehjint up` when unused.

## Scope and evidence

49. No import or reuse of SMP, Baby, Baby-X, or archived EHJINT implementation code in the clean build.
50. No enormous upgrade inventory treated as immediate implementation scope.
51. No new mission for a refinement that fits cleanly inside the frozen six.
52. No feature admitted without restart, failure, rollback, cleanup, and parity tests.
53. No public claim of 10/10, sovereignty, or superiority based only on architecture prose.
54. No v1 declaration before clean-host, destructive, protocol, performance, and direct SMP certification gates pass.
55. No safety, policy, receipt, or enterprise theater introduced as the product's organizing architecture.
56. No secrets, credentials, VM images, snapshots, generated bundles, or host state committed to this repository.
