# process-mcp

A read-only MCP server exposing per-process Linux state (`/proc/<pid>/*`) as structured tools for AI agents.

## Installation

```sh
curl -sSf https://raw.githubusercontent.com/joemckenney/process-mcp/main/install.sh | sh
```

Linux only. Pre-built binaries for `x86_64` and `aarch64`.

## Setup

Add the MCP server to Claude Code:

```sh
claude mcp add --transport stdio --scope user process -- process-mcp
```

The proc root defaults to `/proc`. Override with `--proc-root <path>` if needed (useful for testing against captured trees).

## Usage

Sister project to [cgroup-mcp](https://github.com/joemckenney/cgroup-mcp): cgroup-mcp answers "which cgroups," process-mcp answers "which processes." The two compose through cgroup paths. Both tools use the same normalized identifier (relative to `/sys/fs/cgroup`, no leading slash, empty string for the root), so any cgroup path from one server can be passed verbatim to the other.

The motivating case: cgroup-level state tells you "this 2.2 GB scope is the heaviest" but stops at leaf scopes. process-mcp drills in.

```
> What's holding the 2 GB inside session-1.scope?
```

Claude calls `pids_in_cgroup("user.slice/user-1000.slice/session-1.scope")`, gets back the processes inside, and ranks them by RSS. Each entry carries the cgroup path so further drilling stays composable.

```
> What's using the most memory under user.slice?
```

Claude calls `top_processes(cgroup_prefix="user.slice")`, gets a system-wide ranking scoped to that subtree. Path-aware matching keeps `user.slice2` out of the results.

```
> Tell me everything about PID 4815.
```

Claude calls `process_info(pid=4815)` for the full drill-down: cmdline, fd count, smaps_rollup memory breakdown (RSS, PSS, shared, private, anon, swap), cumulative IO counters, parent PID, thread count, uid, cgroup path. `pss_bytes` in particular is the fairest single number for "this process's memory cost" when pages are shared across processes (browser tabs, JVM workers).

## Tools

| Tool             | Purpose                                                                       |
| ---------------- | ----------------------------------------------------------------------------- |
| `pids_in_cgroup` | Processes inside a given cgroup, sorted by RSS                                |
| `top_processes`  | Top N processes by RSS system-wide, optionally scoped to a cgroup subtree     |
| `process_info`   | Full per-PID drill-down (memory breakdown, fd count, IO counters, uid)        |

Cmdline arguments matching `*key=*`, `*token=*`, `*password=*`, `*secret=*` (case-insensitive) are redacted by default to avoid leaking secrets passed on the command line. Pass `redact_args=false` to receive them verbatim. Permission-gated fields (`fd_count`, `memory`, `io` on `process_info`) are null when the kernel rejects the read; this is common when running as non-root or across user namespaces.

## Requirements

- Linux with a procfs mount at `/proc`. Default on every distro.
- Kernel 4.20 or newer for `smaps_rollup` (required by `process_info`'s memory breakdown).

Does not run on macOS, Windows, or BSD. `/proc` formats are Linux-specific.

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                            process-mcp                              │
│                                                                     │
│  ┌─────────────┐   parse    ┌──────────────┐   wrap   ┌──────────┐  │
│  │  /proc/     │──────────▶ │  Collector   │────────▶ │   MCP    │  │
│  │  <pid>/*    │   typed    │  (pure fns)  │  tools   │  Server  │  │
│  └─────────────┘   structs  └──────────────┘          └────┬─────┘  │
│                                                            │ stdio  │
└────────────────────────────────────────────────────────────┼────────┘
                                                             │
                                                             ▼
                                                      ┌─────────────┐
                                                      │   Claude    │
                                                      │    Code     │
                                                      └─────────────┘
```

Three layers: a pure-function collector that reads `/proc/<pid>/*` and returns typed Rust structs, a thin MCP wrapper that exposes collector output as tools, and stdio transport. Each tool call is a point-in-time snapshot.

Per-process listings walk `/proc` and filter by `cgroup_path`. PIDs that vanish or are unreadable mid-walk are counted into a `skipped` field rather than failing the whole call, so a busy box with churning processes still gets a useful snapshot.

Read-only by design. No write paths, no signal-sending, no priority changes.

## Building from Source

```sh
git clone https://github.com/joemckenney/process-mcp
cd process-mcp
cargo build --release
# binary at ./target/release/process-mcp
```

## Tests

```sh
cargo test
```

Unit tests cover every parser (smaps_rollup, status, io, cgroup link, cmdline redaction). Integration tests use a synthetic `/proc` tempdir helper so the suite is hermetic and deterministic. A `tool_list_snapshot` test locks the public tool surface (names, descriptions, JSON schemas) against drift since tool descriptions are how the LLM picks tools.

## Releases

Driven by [release-plz](https://release-plz.dev) reading [conventional commits](https://www.conventionalcommits.org/). On push to `main`, the workflow inspects commits since the last `v*` tag. If any imply a version bump (`feat:` minor, `fix:` patch, `feat!:` or `BREAKING CHANGE:` major; pre-1.0, breaking changes bump minor), it opens a `chore: release vX.Y.Z` PR. Merging that PR tags the commit and triggers the binary workflow, which builds `x86_64` and `aarch64` tarballs via `cross` and uploads them to the GitHub Release. This repo does not publish to crates.io.
