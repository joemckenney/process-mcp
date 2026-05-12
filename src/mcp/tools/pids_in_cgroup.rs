use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::collector::walk::{walk_processes, WalkResult};
use crate::mcp::process_entry::ProcessEntry;
use crate::mcp::util::validate_cgroup_path;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct PidsInCgroupParams {
    /// Cgroup path to filter by, in normalized form: relative to
    /// `/sys/fs/cgroup`, no leading slash, empty string for the root
    /// cgroup. Example: `"system.slice/nginx.service"`. Take this value
    /// verbatim from any cgroup-mcp tool output that returns cgroup
    /// paths. Must not be absolute and must not contain `..` segments.
    pub cgroup_path: String,

    /// If true (the default), command-line arguments whose key matches
    /// `*key*=*`, `*token*=*`, `*password*=*`, `*secret*=*`
    /// (case-insensitive) are replaced with `key=REDACTED` in the
    /// returned `cmdline`. Set to false to receive verbatim cmdlines at
    /// the risk of leaking secrets that were passed as CLI args.
    #[serde(default)]
    pub redact_args: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PidsInCgroupResponse {
    /// Echoes the queried cgroup_path.
    pub cgroup_path: String,
    /// Processes in the cgroup, sorted descending by `rss_bytes` (null
    /// values last).
    pub results: Vec<ProcessEntry>,
    /// Count of PIDs encountered in `/proc` that could not be fully read
    /// (transient process death, permission denied, etc.). Non-zero
    /// means the snapshot may be incomplete.
    pub skipped: u32,
}

pub fn run(proc_root: &Path, params: PidsInCgroupParams) -> Result<PidsInCgroupResponse> {
    validate_cgroup_path(&params.cgroup_path)?;
    let target = params.cgroup_path.clone();
    let redact = params.redact_args.unwrap_or(true);

    let WalkResult {
        mut processes,
        skipped,
    } = walk_processes(proc_root, |snap| snap.cgroup_path == target)?;

    // None last, then larger rss first within the Some group.
    processes.sort_by_key(|s| {
        (
            s.rss_bytes.is_none(),
            std::cmp::Reverse(s.rss_bytes.unwrap_or(0)),
        )
    });

    let results: Vec<ProcessEntry> = processes
        .into_iter()
        .map(|snap| ProcessEntry::from_snapshot(snap, redact))
        .collect();

    Ok(PidsInCgroupResponse {
        cgroup_path: target,
        results,
        skipped,
    })
}
