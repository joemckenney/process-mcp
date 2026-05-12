# process-mcp

A read-only MCP server that exposes per-process Linux state from `/proc/<pid>/*` as structured tool calls for AI agents.

## What it does

Per-process drill-down for AI agents. Given a PID or a cgroup path, return what a process is doing: command line, resident memory, file descriptors, parent/child relationships, CPU and IO activity. Sister project to [cgroup-mcp](https://github.com/joemckenney/cgroup-mcp), which answers "which cgroups" while this one answers "which processes." The two compose through cgroup paths: every process entry from process-mcp carries a `cgroup_path` field normalized identically to cgroup-mcp's identifiers, so an agent can take any output from one and feed it into the other.

The motivating case: cgroup-level state tells you "this 2.2 GB scope is the heaviest" but stops at leaf scopes. process-mcp drills in and says "and inside that scope, these are the processes."

## Status

Early development. No tools shipped yet. The scaffold establishes the MCP server skeleton, CI pipeline, and snapshot-locked tool catalog. See [PLAN.md](./PLAN.md) for the design document and tool roadmap.

## Planned tools

Driven by [PLAN.md](./PLAN.md), sequenced by dogfooding feedback once the first tool lands.

Next up:

- `pids_in_cgroup`: given a cgroup path, list the processes inside it with `comm`, `cmdline`, `rss_bytes`, `ppid`
- `top_processes`: rank PIDs by memory (default) or CPU rate, with optional `cgroup_prefix` filter
- `process_info`: full per-PID drill-down bundle, peer of cgroup-mcp's `get_unit_stats`
- `process_tree`: parent/child forest under a root PID or cgroup (phase 2)

## Requirements

- Linux with a procfs mount at `/proc`. Default on every distro.
- Rust toolchain to build.

Does not run on macOS, Windows, or BSD. `/proc` formats are Linux-specific.

## Building from Source

```sh
git clone https://github.com/joemckenney/process-mcp
cd process-mcp
cargo build --release
# binary at ./target/release/process-mcp
```

The proc root defaults to `/proc`. Override with `--proc-root <path>` if needed (useful for testing against captured fixtures).

## Tests

```sh
cargo test
```

The scaffold ships with a `tool_list_snapshot` test that locks the public tool surface against drift. Tool descriptions are how the LLM picks tools, so the snapshot is intentionally noisy on change.

## Design notes

Three-layer architecture matching cgroup-mcp: a pure-function collector that reads `/proc/<pid>/*` and returns typed Rust structs, a thin MCP wrapper that exposes collector output as tools, and stdio transport. The collector has no MCP dependency and could be reused as a library.

Read-only by intent. No write paths, no signal-sending, no priority changes. Mixing read and write is the failure mode that bites every system tool.

Snapshot, not stream. Each tool call is a point-in-time read. For time-series, the agent takes multiple snapshots and reasons about deltas.
