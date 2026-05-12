use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::collector::walk::{walk_processes, WalkResult};
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
pub struct ProcessEntry {
    pub pid: u32,
    /// 15-character kernel name from `/proc/<pid>/comm`.
    pub comm: String,
    /// Space-joined cmdline from `/proc/<pid>/cmdline`. Empty for kernel
    /// threads. Subject to `redact_args`.
    pub cmdline: String,
    /// Single-character state code from `/proc/<pid>/status`:
    /// `R`unning, `S`leeping, `D`isk-wait, `Z`ombie, `T`raced/stopped,
    /// `I`dle (kernel threads). Returned as a string for JSON portability.
    pub state: String,
    pub ppid: u32,
    /// Resident set size in bytes. Null for kernel threads (which have no
    /// userspace memory map). Sort key: results are returned descending
    /// by this value, with nulls last.
    pub rss_bytes: Option<u64>,
    /// Normalized cgroup path. Equal to the requested `cgroup_path`;
    /// echoed for parity with other identifier-bearing tools.
    pub cgroup_path: String,
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
        .map(|snap| ProcessEntry {
            pid: snap.pid,
            comm: snap.comm,
            cmdline: format_cmdline(&snap.cmdline_raw, redact),
            state: snap.state.to_string(),
            ppid: snap.ppid,
            rss_bytes: snap.rss_bytes,
            cgroup_path: snap.cgroup_path,
        })
        .collect();

    Ok(PidsInCgroupResponse {
        cgroup_path: target,
        results,
        skipped,
    })
}

/// `/proc/<pid>/cmdline` is null-separated. Convert to a space-joined
/// string, applying redaction if requested.
fn format_cmdline(raw: &str, redact: bool) -> String {
    raw.split('\0')
        .filter(|s| !s.is_empty())
        .map(|p| if redact { redact_arg(p) } else { p.to_string() })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Redact a single arg if its key looks secret-ish.
/// Returns `key=REDACTED` for matching args, the input verbatim otherwise.
fn redact_arg(arg: &str) -> String {
    let Some((k, _)) = arg.split_once('=') else {
        return arg.to_string();
    };
    let k_lower = k.to_lowercase();
    const PATTERNS: &[&str] = &["key", "token", "password", "secret"];
    if PATTERNS.iter().any(|p| k_lower.contains(p)) {
        format!("{k}=REDACTED")
    } else {
        arg.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secret_args() {
        assert_eq!(redact_arg("--api-key=abc123"), "--api-key=REDACTED");
        assert_eq!(
            redact_arg("DATABASE_PASSWORD=hunter2"),
            "DATABASE_PASSWORD=REDACTED"
        );
        assert_eq!(redact_arg("auth_token=xyz"), "auth_token=REDACTED");
        assert_eq!(redact_arg("client_secret=abc"), "client_secret=REDACTED");
    }

    #[test]
    fn passes_through_non_secret_args() {
        assert_eq!(redact_arg("--port=8080"), "--port=8080");
        assert_eq!(redact_arg("worker"), "worker");
        assert_eq!(redact_arg("--verbose"), "--verbose");
    }

    #[test]
    fn redaction_is_case_insensitive() {
        assert_eq!(redact_arg("API_KEY=foo"), "API_KEY=REDACTED");
        assert_eq!(redact_arg("MyToken=foo"), "MyToken=REDACTED");
    }

    #[test]
    fn format_cmdline_joins_null_separated_parts() {
        let raw = "nginx\0worker process\0";
        assert_eq!(format_cmdline(raw, false), "nginx worker process");
    }

    #[test]
    fn format_cmdline_redacts_when_requested() {
        let raw = "myapp\0--api-key=abc123\0--port=8080\0";
        assert_eq!(
            format_cmdline(raw, true),
            "myapp --api-key=REDACTED --port=8080"
        );
    }

    #[test]
    fn empty_cmdline_is_empty_string() {
        assert_eq!(format_cmdline("", true), "");
        assert_eq!(format_cmdline("\0", true), "");
    }
}
