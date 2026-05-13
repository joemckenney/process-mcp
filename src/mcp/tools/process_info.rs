use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::collector::fd::count_fds;
use crate::collector::io::{read_io, IoCounters};
use crate::collector::proc::read_process;
use crate::collector::smaps::{read_smaps_rollup, MemoryBreakdown};
use crate::mcp::process_entry::ProcessEntry;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ProcessInfoParams {
    /// PID of the process to drill into. Must currently exist in
    /// `/proc/<pid>/`.
    pub pid: u32,

    /// If true (the default), command-line arguments whose key matches
    /// `*key*=*`, `*token*=*`, `*password*=*`, `*secret*=*`
    /// (case-insensitive) are replaced with `key=REDACTED`.
    #[serde(default)]
    pub redact_args: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ProcessInfoResponse {
    /// Identifier fields shared with `pids_in_cgroup` and `top_processes`:
    /// pid, comm, cmdline, state, ppid, rss_bytes, cgroup_path. The wire
    /// shape is flat (no nested `base` object); these fields appear at
    /// the top level alongside the per-`process_info` fields below.
    #[serde(flatten)]
    pub base: ProcessEntry,

    /// Real uid that owns the process.
    pub uid: u32,
    /// Number of threads in the process group.
    pub num_threads: u32,
    /// Count of entries in `/proc/<pid>/fd/`. Null if the directory was
    /// unreadable due to permissions (common for non-root callers).
    pub fd_count: Option<u32>,
    /// Memory breakdown from `/proc/<pid>/smaps_rollup`. Null for kernel
    /// threads (no userspace memory map) or when EACCES.
    pub memory: Option<MemoryBreakdown>,
    /// Cumulative IO counters from `/proc/<pid>/io`. Null when the file
    /// is unreadable (EACCES is very common as non-root).
    pub io: Option<IoCounters>,
}

pub fn run(proc_root: &Path, params: ProcessInfoParams) -> Result<ProcessInfoResponse> {
    let redact = params.redact_args.unwrap_or(true);

    // read_process bails if the PID directory is gone or core files are
    // unreadable. That's the right behavior here: process_info on a
    // missing PID should be an error, not a successful null response.
    let snap = read_process(proc_root, params.pid)?;

    let uid = snap.uid;
    let num_threads = snap.num_threads;

    let dir = proc_root.join(params.pid.to_string());
    let fd_count = count_fds(&dir)?;
    let memory = read_smaps_rollup(&dir)?;
    let io = read_io(&dir)?;

    Ok(ProcessInfoResponse {
        base: ProcessEntry::from_snapshot(snap, redact),
        uid,
        num_threads,
        fd_count,
        memory,
        io,
    })
}
