# process-mcp

A read-only MCP server that exposes per-process Linux state from `/proc/<pid>/*` as structured tool calls for AI agents.

## What it does

Per-process drill-down for AI agents. Given a PID or a cgroup path, return what a process is doing: command line, resident memory, file descriptors, parent/child relationships, CPU and IO activity. Sister project to [cgroup-mcp](https://github.com/joemckenney/cgroup-mcp), which answers "which cgroups" while this one answers "which processes." The two compose through cgroup paths: every process entry from process-mcp carries a `cgroup_path` field normalized identically to cgroup-mcp's identifiers, so an agent can take any output from one and feed it into the other.

The motivating case: cgroup-level state tells you "this 2.2 GB scope is the heaviest" but stops at leaf scopes. process-mcp drills in and says "and inside that scope, these are the processes."

## Status

Early. One tool shipped. See [PLAN.md](./PLAN.md) for the full design document and tool roadmap.

## Planned tools

Driven by [PLAN.md](./PLAN.md), sequenced by dogfooding feedback.

Shipped:

- `pids_in_cgroup`: given a cgroup path, list the processes inside it with `comm`, `cmdline` (redacted by default), `state`, `ppid`, `rss_bytes`

Next up:

- `top_processes`: rank PIDs by memory (default) or CPU rate, with optional `cgroup_prefix` filter
- `process_info`: full per-PID drill-down bundle, peer of cgroup-mcp's `get_unit_stats`
- `process_tree`: parent/child forest under a root PID or cgroup (phase 2)

## Installation

Once the first release ships, install via:

```sh
curl -sSf https://raw.githubusercontent.com/joemckenney/process-mcp/main/install.sh | sh
```

Linux only. Pre-built binaries for `x86_64` and `aarch64`. Until v0.1.0 lands, build from source (see below).

## Requirements

- Linux with a procfs mount at `/proc`. Default on every distro.
- Rust toolchain if building from source.

Does not run on macOS, Windows, or BSD. `/proc` formats are Linux-specific.

## Building from Source

```sh
git clone https://github.com/joemckenney/process-mcp
cd process-mcp
cargo build --release
# binary at ./target/release/process-mcp
```

The proc root defaults to `/proc`. Override with `--proc-root <path>` if needed (useful for testing against captured fixtures).

## Tools

### pids_in_cgroup

Takes a cgroup path in process-mcp's normalized form (relative to `/sys/fs/cgroup`, no leading slash, empty string for the root cgroup) and returns the processes inside it. Each entry carries `pid`, `comm`, `cmdline`, `state`, `ppid`, `rss_bytes`, and `cgroup_path`. Results are sorted by `rss_bytes` descending with `null` (kernel threads) last. Cmdline args matching `*key=*`, `*token=*`, `*password=*`, `*secret=*` are redacted by default; pass `redact_args=false` to receive them verbatim. A `skipped` count surfaces PIDs that vanished or were unreadable mid-walk so the agent knows when the snapshot may be incomplete.

This is the bridge tool between process-mcp and [cgroup-mcp](https://github.com/joemckenney/cgroup-mcp): take a cgroup path from any cgroup-mcp result and pass it here verbatim. Both servers use the same identifier convention.

## Tests

```sh
cargo test
```

The crate ships with a `tool_list_snapshot` test that locks the public tool surface against drift. Tool descriptions are how the LLM picks tools, so the snapshot is intentionally noisy on change.

## Releases

Driven by [release-plz](https://release-plz.dev) reading [conventional commits](https://www.conventionalcommits.org/). On push to `main`, the workflow inspects commits since the last `v*` tag. If any imply a version bump (`feat:` for minor, `fix:` for patch, `feat!:` or `BREAKING CHANGE:` for major; pre-1.0, breaking changes bump minor), it opens a `chore: release vX.Y.Z` PR with version + changelog. Merging that PR tags the commit and triggers the binary workflow, which builds `x86_64` and `aarch64` tarballs via `cross` and uploads them to the GitHub Release.

This repo does not publish to crates.io. Releases are GitHub Releases only.

## Design notes

Three-layer architecture matching cgroup-mcp: a pure-function collector that reads `/proc/<pid>/*` and returns typed Rust structs, a thin MCP wrapper that exposes collector output as tools, and stdio transport. The collector has no MCP dependency and could be reused as a library.

Read-only by intent. No write paths, no signal-sending, no priority changes. Mixing read and write is the failure mode that bites every system tool.

Snapshot, not stream. Each tool call is a point-in-time read. For time-series, the agent takes multiple snapshots and reasons about deltas.
