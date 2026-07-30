# EHJINT Certification Standard

Status: canonical. Architecture scores and implementation claims are provisional until these gates pass.

## 1. Certification principles

- Test the product users receive, not isolated components alone.
- Prefer destructive and restart testing over optimistic happy-path checks.
- Measure from the external interface through final observed state.
- Report unsupported hardware and kernel limitations honestly.
- A failed cleanup, rollback, parity, or durability gate blocks v1.
- Post-v1 capabilities are not required unless implementation work accidentally makes them part of the product contract.

## 2. Repository and supply-chain gates

- Canonical documents are present, internally consistent, and linked from the README.
- Source tree contains no imported SMP, Baby, Baby-X, or archived EHJINT implementation code.
- No credentials, private keys, tokens, VM disks, memory images, or generated release bundles are tracked.
- Dependency versions, source locations, digests, and licenses are complete.
- All mandatory dependencies are free for the intended use.
- Formatting, lint, vet, race tests, generation drift, secret scan, large-file scan, and clean-tree checks pass.
- Release artifacts are reproducible to the documented level and match the compatibility manifest.

## 3. Clean-host installation gates

On a supported fresh reference host:

- Fast installation requires no undocumented manual step.
- Host prerequisite failures identify the exact missing kernel, KVM, permission, filesystem, or hardware capability.
- `ehjint up` creates and reaches a verified ready machine.
- Bare `ehjint` and bare `ej` enter the default guest as UID 0.
- The installation works without a ChatGPT account, model API key, hosted sandbox account, or public relay.
- Uninstall or complete removal leaves no EHJINT-owned service, identity, TAP, port rule, mount, process, runtime directory, or active release pointer.

## 4. Sovereign-build gates

- One documented top-level command rebuilds the release from pinned source and package inputs.
- The source build creates the same release-bundle and compatibility-manifest formats as the fast build.
- Fast and sovereign bundles pass the same functional suite.
- The sovereign bundle can install and operate with the network unavailable after all declared source inputs are present.
- No hidden StealthEye service, activation endpoint, or signing oracle is required for local operation.

## 5. Root execution gates

- Structured commands preserve byte-exact stdout and stderr separation.
- Exit status, signal death, timeout, cancellation, and guest loss are distinguishable.
- Environment, working directory, user identity, stdin, and terminal allocation behave as declared.
- Large outputs are bounded or externalized without truncation being reported as success.
- Duplicate mutating requests return the same operation and do not repeat side effects.
- Conflicting idempotency reuse fails deterministically.
- Operation status survives controller restart and host reboot.

## 6. PTY and job gates

- PTY identity survives client, tunnel, relay, and controller disconnect.
- Reattach resumes at the correct output cursor without replaying input.
- Resize, input, signals, foreground process truth, and exit state work.
- Detached jobs are owned by guest systemd and continue while all EHJINT clients are absent.
- Job logs, status, cancellation, failure, and terminality remain available after recovery.
- Controller restart does not duplicate jobs or convert unknown state into success.

## 7. File and workspace gates

- Atomic write, append, metadata, directory, transfer, and bounded search operations return exact outcomes.
- Direct virtio-fs workspaces preserve the host project as authority.
- Controller and virtio-fs process restarts restore expected mounts without duplicate mounts or stale sockets.
- Workspace fork produces an independent mutation surface through the best supported mechanism.
- Contained mode does not expose undeclared host paths.
- Wrong path, traversal, symlink escape, unavailable mount, and permission failures fail explicitly.
- Workspace deletion or machine removal leaves no owned mount or helper process.

## 8. Networking gates

- Default outbound networking and DNS work without manual host setup.
- TCP and UDP port publication is idempotent, discoverable, and removable.
- WebSocket and long-lived TCP flows survive ordinary controller restart where the VM and host networking remain alive.
- EHJINT never flushes or broadly replaces unrelated host firewall policy.
- Duplicate, conflicting, wildcard, unavailable, and already-owned ports return exact truth.
- Machine removal deletes only its owned network objects.

## 9. VMM security-boundary gates

- Each machine VMM runs under a dedicated managed UID/GID, not root and not a normal human account.
- The process has zero ambient capabilities and `no_new_privs`.
- Upstream seccomp is active.
- Landlock confines declared paths where the host supports it.
- VMM access outside the per-machine and explicitly shared paths is denied.
- TAP, VFIO cdev, iommufd, KVM, disk, API, and event resources follow the declared descriptor and ownership model.
- Killing the privileged controller does not grant the VMM new host authority.

## 10. Disk and image gates

- Every launch specifies an image type.
- Unknown, omitted, mismatched, malformed, and unsupported image types fail before guest execution.
- A raw image rewritten with a QCOW2 header cannot cause host-file access.
- Imported QCOW2 backing chains are rejected or flattened.
- Managed chains cannot escape the content store through absolute paths, traversal, symlinks, or races.
- Immutable bases remain byte-identical after guest use, fork, snapshot, failure, and cleanup.
- Sparse disk files remain sparse across supported copy, fork, export, and import paths.

## 11. Fork, snapshot, and restore gates

- Fork creates independent machine, disk, workspace, terminal, job, browser, network, and operation identities.
- Parent mutation after fork cannot silently alter the child except for explicitly shared read/write mounts.
- Child mutation cannot alter immutable parent layers.
- Snapshot manifest binds exact VMM, firmware, guest image, topology, disks, memory, packs, and lineage.
- Restore selects a compatible retained VMM or fails explicitly.
- Sparse memory regions are preserved.
- Eager and userfaultfd restore paths both pass functional tests where available.
- Demand-paged restore is selected only after repeatable workload measurements show benefit.
- Measurements include VMM creation, vCPU resume, guest-agent response, first-command completion, first-command tail latency, and background-prefault completion.
- No universal sub-30-ms claim is published without corresponding supported-platform evidence.

## 12. Hardware gates

On each certified reference device:

- Planner reports IOMMU state, group composition, current driver, dependencies, reset behavior, conflicts, and required guest support.
- Attach uses the declared VFIO cdev and iommufd paths where supported.
- Guest receives the intended device and no undeclared sibling device.
- Controller restart adopts the attachment truth.
- Failed attach restores the prior host driver and ownership when technically possible.
- Detach and machine removal restore the host state.
- Unsupported reset, migration, isolation, or nested acceleration is reported rather than hidden.

Hardware not present on the reference host is not certified merely because the architecture supports it.

## 13. Browser and visual gates

- Persistent Chromium profiles, tabs, downloads, uploads, console output, network events, screenshots, and traces work inside the guest.
- Browser state survives ChatGPT, relay, tunnel, and controller disconnection.
- Large artifacts are stored and retrieved without forcing them through unbounded tool responses.
- Human takeover and structured Playwright control do not corrupt each other's state.
- The ordinary browser path works without ivshmem.
- The shared-memory visual path, if shipped, demonstrates a material measured CPU, copy, or latency improvement and has a tested fallback.
- Remote live view uses encoded transport; zero-copy claims are limited to the guest-to-host frame plane actually measured.

## 14. MCP and relay gates

- CLI, private MCP, and published MCP operations derive from one registry and pass parity tests.
- The preferred stateless protocol path does not require relay session persistence or sticky routing.
- Relay process restart loses no host operation and creates no duplicate operation.
- Dropped response recovery works without assuming client automatic replay.
- Duplicate request replay returns the existing durable host operation.
- Authentication, authorization, host routing, request bounds, and key rotation work.
- Relay storage contains no VM, job, workspace, snapshot, browser, output-history, or durable execution authority.
- Local CLI and private integration work with the public relay absent.

## 15. Recovery and fault-injection gates

Kill or crash the controller before and after every durable transition in:

- Machine create, start, stop, suspend, restore, and remove.
- Disk and overlay creation.
- TAP and port creation.
- Workspace mount and fork.
- PTY and detached job creation.
- Snapshot creation and restore.
- Device attach and detach.
- Capability-pack installation.
- Update activation and rollback.

For each boundary, restart must adopt the completed result, resume a safe incomplete result, fail into explicit recoverable truth, or cleanly roll back. It must never duplicate work, fabricate success, or destroy unrelated host state.

## 16. Update and rollback gates

- New release installs beside the active release.
- Temporary controller self-test uses the current host and compatible guest.
- Atomic pointer activation is verified.
- Failure after each update step restores the prior healthy release.
- Running machines are not recreated merely due to controller update.
- Required historical VMM releases remain available.
- Guest-agent compatibility covers the declared current and previous controller window.
- Metadata migrations honor the documented rollback contract.

## 17. Performance gates

Measure at minimum:

- Cold first boot.
- Warm restore.
- Root shell ready time.
- One-shot command overhead.
- PTY attach and reattach.
- File transfer and workspace I/O.
- Fork creation.
- Snapshot creation and restore.
- Port publication.
- Browser screenshot and live-view latency.
- Controller memory and idle CPU.
- Relay overhead independent of host execution.

Results must identify host CPU, memory, kernel, storage, VMM, guest image, and workload. Autotuning may select only measured bounded settings and must expose its decision.

## 18. Friction gates

A new user on a supported host must not have to manually:

- Build a kernel or rootfs.
- Create TAP or bridge devices.
- Assign a vsock CID.
- Install the guest agent by hand.
- Configure ordinary NAT or DNS.
- Select disk queues, memory prefault threads, or snapshot formats.
- Create a cloud account or dashboard project.
- Understand machine internal states before running `ehjint`.

Diagnostics appear at the point of failure and describe the minimum corrective action. Advanced options remain available but absent from ordinary setup.

## 19. Direct SMP comparison

Use frozen, comparable reference workloads for:

- Installation effort.
- Time to first unrestricted root shell.
- Command and PTY use.
- Detached-job survival.
- Workspace access.
- Fork and snapshot workflows.
- Browser capability.
- Networking and port exposure.
- Hardware passthrough reach.
- Controller restart recovery.
- Source rebuild effort.
- Runtime component count and idle overhead.

Report SMP advantages honestly, including narrower VMM surface, deterministic asset ownership, or proven maturity. EHJINT passes the superiority claim only if it demonstrates materially greater power and lower ordinary friction without violating its sovereignty or repository laws.

## 20. Final v1 evidence

The final release record contains:

- Exact source commit and tree.
- Release and component digests.
- Compatibility manifest.
- Dependency and license manifest.
- Fast and sovereign build results.
- Full test and fault-injection results.
- Benchmark environment and results.
- Certified hardware matrix.
- Cleanup and absence verification.
- Known limitations.
- Rollback instructions.
- Direct SMP comparison.

Only a release satisfying this standard may be designated EHJINT v1.
