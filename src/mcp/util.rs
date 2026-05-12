use anyhow::{bail, Result};

/// Validate a cgroup path supplied to a process-mcp tool. String-level
/// checks only, since process-mcp never resolves the path against the
/// filesystem; it only matches against normalized cgroup paths derived
/// from `/proc/<pid>/cgroup`. The empty string is valid (root cgroup).
pub fn validate_cgroup_path(rel: &str) -> Result<()> {
    if rel.starts_with('/') {
        bail!("cgroup_path must be relative (no leading `/`), got: {rel:?}");
    }
    if rel.split('/').any(|seg| seg == "..") {
        bail!("cgroup_path must not contain `..` segments: {rel:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_valid_root_cgroup() {
        validate_cgroup_path("").unwrap();
    }

    #[test]
    fn normal_relative_path_is_valid() {
        validate_cgroup_path("system.slice/nginx.service").unwrap();
    }

    #[test]
    fn rejects_absolute() {
        let err = validate_cgroup_path("/etc/passwd").unwrap_err();
        assert!(format!("{err}").contains("relative"));
    }

    #[test]
    fn rejects_dotdot_segment() {
        let err = validate_cgroup_path("system.slice/../etc").unwrap_err();
        assert!(format!("{err}").contains(".."));
    }
}
