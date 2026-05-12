use anyhow::{bail, Context, Result};
use std::path::Path;

/// Parse `/proc/<pid>/cgroup` content into a normalized cgroup path matching
/// cgroup-mcp's identifier convention: relative to `/sys/fs/cgroup`, no
/// leading slash, empty string for the root cgroup.
///
/// cgroup v2 lines look like `0::/system.slice/nginx.service`. Hybrid
/// cgroup v1/v2 systems include additional `N:subsystem:path` lines which
/// we ignore. v2-only systems (the common case on modern distros) emit
/// just the `0::` line.
pub fn parse_cgroup_path(s: &str) -> Result<String> {
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            return Ok(rest.strip_prefix('/').unwrap_or(rest).to_string());
        }
    }
    bail!("no cgroup v2 entry (line starting with `0::`) found")
}

pub fn read_cgroup_path(proc_pid_dir: &Path) -> Result<String> {
    let path = proc_pid_dir.join("cgroup");
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    parse_cgroup_path(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v2_unified_line() {
        let s = "0::/system.slice/nginx.service\n";
        assert_eq!(parse_cgroup_path(s).unwrap(), "system.slice/nginx.service");
    }

    #[test]
    fn root_cgroup_normalizes_to_empty_string() {
        assert_eq!(parse_cgroup_path("0::/\n").unwrap(), "");
    }

    #[test]
    fn picks_v2_line_among_v1_legacy_lines() {
        let s = "12:freezer:/\n11:cpu,cpuacct:/foo\n0::/system.slice/nginx.service\n";
        assert_eq!(parse_cgroup_path(s).unwrap(), "system.slice/nginx.service");
    }

    #[test]
    fn fails_when_no_v2_line_present() {
        let err = parse_cgroup_path("11:cpu,cpuacct:/foo\n").unwrap_err();
        assert!(err.to_string().contains("0::"), "got: {err}");
    }

    #[test]
    fn handles_nested_paths_with_escaped_systemd_names() {
        // systemd escapes hyphens in unit names as \x2d
        let s = "0::/system.slice/system-systemd\\x2dcoredump.slice/foo.service\n";
        assert_eq!(
            parse_cgroup_path(s).unwrap(),
            "system.slice/system-systemd\\x2dcoredump.slice/foo.service"
        );
    }
}
