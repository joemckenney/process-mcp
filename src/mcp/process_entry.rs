//! Wire-shape projection of a `ProcessSnapshot` from the collector layer
//! into a JSON-serializable entry exposed by tools. Multiple tools return
//! lists of processes; sharing the entry shape keeps responses consistent
//! and lets the agent move identifiers (pid, cgroup_path) between tools
//! without re-shaping.

use crate::collector::proc::ProcessSnapshot;
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ProcessEntry {
    pub pid: u32,
    /// 15-character kernel name from `/proc/<pid>/comm`.
    pub comm: String,
    /// Space-joined cmdline from `/proc/<pid>/cmdline`. Empty for kernel
    /// threads. Subject to the redaction flag the tool was called with.
    pub cmdline: String,
    /// Single-character state code from `/proc/<pid>/status`:
    /// `R`unning, `S`leeping, `D`isk-wait, `Z`ombie, `T`raced/stopped,
    /// `I`dle (kernel threads). Returned as a string for JSON portability.
    pub state: String,
    pub ppid: u32,
    /// Resident set size in bytes. Null for kernel threads, which have
    /// no userspace memory map.
    pub rss_bytes: Option<u64>,
    /// Normalized cgroup path. Same convention as cgroup-mcp: relative to
    /// `/sys/fs/cgroup`, no leading slash, empty string for the root.
    pub cgroup_path: String,
}

impl ProcessEntry {
    /// Project a raw collector snapshot into the wire shape, applying
    /// cmdline formatting and the cmdline redaction policy.
    pub fn from_snapshot(snap: ProcessSnapshot, redact: bool) -> Self {
        Self {
            pid: snap.pid,
            comm: snap.comm,
            cmdline: format_cmdline(&snap.cmdline_raw, redact),
            state: snap.state.to_string(),
            ppid: snap.ppid,
            rss_bytes: snap.rss_bytes,
            cgroup_path: snap.cgroup_path,
        }
    }
}

/// `/proc/<pid>/cmdline` stores args as NUL-separated bytes. Convert to a
/// space-joined string, optionally redacting args whose key looks secret.
pub fn format_cmdline(raw: &str, redact: bool) -> String {
    raw.split('\0')
        .filter(|s| !s.is_empty())
        .map(|p| if redact { redact_arg(p) } else { p.to_string() })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Replace `key=value` with `key=REDACTED` if the key (case-insensitive)
/// contains any of: `key`, `token`, `password`, `secret`. Returns the
/// input verbatim otherwise.
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
