# process-mcp — Implementation Plan

A read-only MCP server exposing per-process state from `/proc/<pid>/*`, designed as a sister to `cgroup-mcp`. The two compose through cgroup paths: agents go from "which cgroup is heavy" (cgroup-mcp) to "which processes inside it are heavy" (process-mcp).

## 1. Directory structure

Mirror cgroup-mcp one-for-one. The `collector/` three-layer split (pure parsers, IO wrappers, rate calculations) translates cleanly to `/proc`.

```
~/code/process-mcp/
  Cargo.toml
  Cargo.lock
  README.md
  .github/workflows/ci.yml         # copy verbatim, swap binary name
  .gitignore
  src/
    main.rs                        # stdio transport, --proc-root flag
    lib.rs                         # pub mod collector; pub mod mcp;
    collector/
      mod.rs
      proc.rs                      # parse /proc/<pid>/{stat,status,cmdline,comm}
      smaps.rs                     # parse /proc/<pid>/smaps_rollup (RSS/PSS/USS)
      fd.rs                        # count entries in /proc/<pid>/fd
      cgroup_link.rs               # parse /proc/<pid>/cgroup -> normalized path
      walk.rs                      # iterate /proc/<pid> directories safely
      rate.rs                      # CPU rate = (utime+stime delta) / dt
      io.rs                        # /proc/<pid>/io if readable
    mcp/
      mod.rs
      server.rs                    # ProcessServer, #[tool_router]
      util.rs                      # pid validation; cgroup path normalization
      tools/
        mod.rs
        pids_in_cgroup.rs
        top_processes.rs
        process_info.rs
        process_tree.rs            # phase 2
  tests/
    mcp_server.rs                  # tool_list_snapshot + per-tool tests
    snapshots/                     # insta yaml
    fixtures/
      synthetic_proc/              # programmatically built per-test (tempdir helper)
      real_arch/                   # sanitized capture of one host's /proc snapshot
```

## 2. Cargo.toml (verbatim, copyable)

```toml
[package]
name = "process-mcp"
version = "0.1.0"
edition = "2021"

[lib]
name = "process_mcp"
path = "src/lib.rs"

[[bin]]
name = "process-mcp"
path = "src/main.rs"

[dependencies]
anyhow = "1"
rmcp = { version = "1", features = ["server", "macros", "schemars", "transport-io"] }
schemars = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "io-std", "signal"] }

[dev-dependencies]
tempfile = "3"
insta = { version = "1", features = ["yaml"] }
```

No new deps over cgroup-mcp. Resist adding `procfs` or `nix` — `/proc` parsing is small and the manual parsers double as documentation of which kernel fields we trust.

## 3. MVP tool roadmap (ranked)

These four close the dogfooding gap. Ship 1 and 2 first; they are sufficient on their own.

**1. `pids_in_cgroup`** — *the bridge tool, must ship first.*
Given a relative cgroup path like `user.slice/user-1000.slice/session-1.scope`, return every PID currently inside it, with `comm`, `cmdline` (curated, see Q5), `state`, `rss_bytes`, `cgroup_path` (echoed back), and the parent PID. This is the literal answer to the dogfooding question: cgroup-mcp identified `session-1.scope` as 2.2 GB, this tool says "here are the 47 PIDs inside it and what they are." Backed by reading `cgroup.procs` inside the cgroup directory plus per-PID `/proc` reads. Sort by RSS desc by default.

**2. `top_processes`** — *the system-wide ranker.*
Walks `/proc`, ranks PIDs by either `memory` (default, RSS from `/proc/<pid>/status` `VmRSS` or `smaps_rollup` Pss for shared accuracy) or `cpu` (rate, sampling pattern below). Optional `cgroup_prefix` filter so an agent can ask "top processes under `system.slice`" without first listing the cgroup. Each entry exposes the same identifier set as `pids_in_cgroup`. Default `n = 10`.

**3. `process_info`** — *the per-PID drill-down.*
Single PID in, full bundle out: `comm`, `cmdline`, `state`, `ppid`, `uid/gid`, `start_time`, `num_threads`, `fd_count`, full smaps_rollup breakdown (Rss/Pss/Shared/Private/Anon), `io` counters when readable, `cgroup_path`. Mirrors `get_unit_stats` in cgroup-mcp — point-in-time snapshot, every field nullable since /proc readability is permission-gated.

**4. `process_tree`** *(phase 2, ship after dogfooding the first three).*
Walk PPIDs to render a parent/child forest under a root PID or under a cgroup. Useful when a "process" is really a supervisor with children (systemd user units, browsers, language runtimes). Punt this until the first three are stable — building it on top of `pids_in_cgroup` + cached `ppid` is cheap once those land.

## 4. Identifier conventions

Every process entry — across every tool — exposes this exact field set so agents can pipe results between tools without re-anchoring:

| Field | Source | Notes |
|---|---|---|
| `pid` | `/proc/<pid>` directory name | u32. This is the TGID, never a TID. |
| `comm` | `/proc/<pid>/comm` | 15-char kernel name. Always present. |
| `cmdline` | `/proc/<pid>/cmdline` | Curated by default (Q5). |
| `state` | `/proc/<pid>/status` `State` | First char only: `R/S/D/Z/T/I`. |
| `ppid` | `/proc/<pid>/status` `PPid` | u32; 0 for init. |
| `cgroup_path` | `/proc/<pid>/cgroup` | **Normalized identical to cgroup-mcp**: relative to `/sys/fs/cgroup`, no leading slash, empty string for the root cgroup. cgroup v2 unified line is `0::/path`; strip `0::` and the leading `/`. This is the load-bearing invariant — an agent must be able to take any `cgroup_path` from process-mcp and pass it straight into cgroup-mcp's tools verbatim. |

Snapshot-lock the schema for these fields in the tool-list test so any drift is a deliberate diff.

## 5. Testing strategy

Three layers, mirroring cgroup-mcp:

1. **Pure parsers** — unit tests inline in `collector/proc.rs` etc. Feed in literal `/proc/<pid>/stat` strings, assert struct values. No filesystem.

2. **Synthetic `/proc` tempdirs** — a `synthetic_proc_tree(&[(pid, ProcSpec)])` test helper that builds `tempdir/<pid>/{stat,status,cmdline,cgroup,smaps_rollup,fd/}` files programmatically. This is how cgroup-mcp tests `top_cpu` (rewriting `cpu.stat` mid-window via a tokio task) and the same trick handles per-PID rate sampling. Deterministic, no real PIDs.

3. **Real captures** (`tests/fixtures/real_arch/`) — a sanitized snapshot of `/proc` from one machine. PID instability is the real concern here. **Mitigation**: don't assert on PID values, assert on `comm` + `cgroup_path` + structural properties ("at least one process under `system.slice/dbus-broker.service`", "every entry has a non-empty cgroup_path"). Treat PIDs as opaque tokens within a single test run, never as fixture-stable identifiers. The capture script should also strip uid/gid and overwrite `cmdline` with a placeholder unless the test specifically needs it.

4. **`tool_list_snapshot`** via insta — locks tool names, descriptions, and JSON schemas. Sort tools by name before snapshotting so order is stable.

## 6. Sampling for CPU rate

Use the same blocking-sample pattern as `top_cpu`: read `/proc/<pid>/stat` (utime + stime fields 14, 15 in jiffies) for every candidate PID, `tokio::time::sleep(window_ms)` (default 500ms), read again, compute `delta_jiffies / (window_ms * sysconf(_SC_CLK_TCK) / 1000)` per PID. Same `reset_detected` flag for the case where a PID got recycled (counter went backwards or `start_time` changed between reads — the start_time check is the robust one for /proc since PIDs wrap).

For MVP, default `top_processes` to `sort=memory` so the first ship has zero blocking. CPU mode is opt-in via param. Memory snapshots dominate the dogfooding use case anyway — the original gap was "what's holding this 2.2 GB."

Don't expose a system-wide CPU rate tool yet; `top_processes(sort="cpu")` covers it.

## 7. Open design questions (need user input before code)

1. **Threads vs processes.** `/proc/<pid>/task/<tid>/` exposes per-thread state. MVP should ignore TIDs entirely and report only TGIDs (one entry per process), but `process_info` could optionally include `thread_count` and a `threads: []` array. Confirm: TGIDs only for v0, threads behind a flag in `process_info` later?

2. **`cmdline` curation vs verbatim.** `/proc/<pid>/cmdline` can leak secrets passed as CLI args (DB URLs with passwords, API keys in `--token=...`). Three options: (a) verbatim always — fastest, leakiest; (b) verbatim with a `redact_args=true` default that masks anything matching `*key*=*`, `*token*=*`, `*password*=*`, `*secret*=*` patterns; (c) `comm` + first non-flag arg only by default, full cmdline behind `verbose=true`. Recommendation: (b) — the default protects against accidental exposure but the unredacted form is one parameter away.

3. **Transient processes.** A PID can vanish between the directory walk and the per-PID read. Match cgroup-mcp's `top_cpu` behavior: silently skip ENOENT, never fail the whole call. Should the response carry a `skipped: u32` count so the agent knows the snapshot wasn't exhaustive, or stay silent like cgroup-mcp does? Recommendation: expose a count.

4. **Permissions.** Many `/proc/<pid>/io` and `/proc/<pid>/smaps_rollup` reads require ptrace capability or matching uid. Behavior when running as non-root: every per-field value becomes nullable, no error surfaced. Confirm this is the right trade — alternative is a top-level `degraded: true` flag when any read was blocked.

5. **`--proc-root` flag.** Mirror `--cgroup-root` exactly: default `/proc`, override for tests. Confirm naming (`--proc-root` vs `--proc-path`).

## 8. Risks and pitfalls specific to /proc

- **Racy reads.** A PID disappears mid-walk; a `cmdline` read returns half-written bytes during exec. Always wrap per-PID reads in "treat NotFound as skip, treat partial read as skip with a debug log." Never `?` propagate from a per-PID read in a ranking tool.
- **TID/PID confusion.** `/proc/<pid>` includes thread directories under `/proc/<pid>/task/`. The top-level `/proc` listing is *only* TGIDs, but if any code recurses into `task/` it will start counting threads as processes. Centralize the walk in `collector/walk.rs` and never walk `task/` from there.
- **Permission boundaries.** `cmdline`, `io`, `smaps_rollup` may EACCES even for the same uid in a different user namespace. Treat EACCES like NotFound for collection purposes; surface it via nullable fields, not errors.
- **Very large `/proc`.** A box with 5000 PIDs means 5000 directory reads minimum. For `top_processes`, read `comm` + `status:VmRSS` first (one open + one short read per PID), rank, *then* read smaps_rollup for the top N only. Avoid the seductive "read everything for every PID" path.
- **`smaps_rollup` cost.** Reading it forces the kernel to walk the page tables for the target process — measurably expensive on huge processes (multi-ms each on a JVM). Only read it for the final top-N or when the user asks via `process_info`, never for every PID in the walk.
- **Clock-tick units.** `/proc/<pid>/stat` reports times in jiffies (`USER_HZ`), not microseconds. Need `sysconf(_SC_CLK_TCK)` once at startup. Document this in the rate module — it's the single biggest "looks wrong" footgun.
- **PID recycling.** Across the 500ms sample window, a PID can be reaped and reissued to a different process. Compare `start_time` (field 22 of `/proc/<pid>/stat`) between the two reads; if it changed, set `reset_detected` and zero the rate, exactly like `top_cpu` does for cgroup recreation.
- **uid/gid in `status`.** Four space-separated values (real, effective, saved, fs). Parse all four; expose at least the real uid.
