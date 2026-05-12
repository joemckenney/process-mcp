use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::collector::walk::{walk_processes, WalkResult};
use crate::mcp::process_entry::ProcessEntry;
use crate::mcp::util::validate_cgroup_path;

const DEFAULT_N: usize = 10;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct TopProcessesParams {
    /// Maximum number of processes to return. Defaults to 10.
    #[serde(default)]
    pub n: Option<usize>,

    /// If supplied, only consider processes whose cgroup path equals
    /// this prefix or is a descendant of it. Path-aware matching:
    /// `system.slice` matches `system.slice` itself and any path
    /// starting with `system.slice/`, but never `system.slice2/...`.
    /// Empty string and omitted both mean "consider all processes."
    /// Must not be absolute or contain `..` segments.
    #[serde(default)]
    pub cgroup_prefix: Option<String>,

    /// If true (the default), command-line arguments whose key matches
    /// `*key*=*`, `*token*=*`, `*password*=*`, `*secret*=*`
    /// (case-insensitive) are replaced with `key=REDACTED`.
    #[serde(default)]
    pub redact_args: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TopProcessesResponse {
    /// Echoes the cgroup_prefix filter (or null if not provided).
    pub cgroup_prefix: Option<String>,
    /// Top processes, sorted descending by `rss_bytes`, with null values
    /// (kernel threads) at the end.
    pub results: Vec<ProcessEntry>,
    /// Count of PIDs encountered in `/proc` that could not be fully read
    /// (transient process death, permission denied, etc.). Non-zero
    /// means the snapshot may be incomplete.
    pub skipped: u32,
}

pub fn run(proc_root: &Path, params: TopProcessesParams) -> Result<TopProcessesResponse> {
    if let Some(prefix) = &params.cgroup_prefix {
        validate_cgroup_path(prefix)?;
    }
    let n = params.n.unwrap_or(DEFAULT_N).max(1);
    let redact = params.redact_args.unwrap_or(true);
    let prefix = params.cgroup_prefix.clone();

    let filter_prefix = prefix.clone();
    let WalkResult {
        mut processes,
        skipped,
    } = walk_processes(proc_root, |snap| match &filter_prefix {
        None => true,
        Some(p) if p.is_empty() => true,
        Some(p) => matches_cgroup_prefix(&snap.cgroup_path, p),
    })?;

    processes.sort_by_key(|s| {
        (
            s.rss_bytes.is_none(),
            std::cmp::Reverse(s.rss_bytes.unwrap_or(0)),
        )
    });
    processes.truncate(n);

    let results: Vec<ProcessEntry> = processes
        .into_iter()
        .map(|snap| ProcessEntry::from_snapshot(snap, redact))
        .collect();

    Ok(TopProcessesResponse {
        cgroup_prefix: prefix,
        results,
        skipped,
    })
}

/// Path-aware prefix match. `system.slice` matches `system.slice` and
/// anything starting with `system.slice/`, but NOT `system.slice2/...`.
fn matches_cgroup_prefix(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    if let Some(rest) = path.strip_prefix(prefix) {
        return rest.starts_with('/');
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_matches_path_equal_to_prefix() {
        assert!(matches_cgroup_prefix("system.slice", "system.slice"));
    }

    #[test]
    fn prefix_matches_descendant() {
        assert!(matches_cgroup_prefix(
            "system.slice/nginx.service",
            "system.slice"
        ));
        assert!(matches_cgroup_prefix(
            "system.slice/nested.slice/foo.service",
            "system.slice"
        ));
    }

    #[test]
    fn prefix_does_not_match_sibling_with_shared_string_prefix() {
        // The whole reason for path-aware matching.
        assert!(!matches_cgroup_prefix(
            "system.slice2/foo.service",
            "system.slice"
        ));
        assert!(!matches_cgroup_prefix("system.slicefoo", "system.slice"));
    }

    #[test]
    fn prefix_does_not_match_unrelated_path() {
        assert!(!matches_cgroup_prefix(
            "user.slice/user-1000.slice",
            "system.slice"
        ));
    }
}
