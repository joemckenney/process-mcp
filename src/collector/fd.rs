use anyhow::{Context, Result};
use std::io::ErrorKind;
use std::path::Path;

/// Count entries in `/proc/<pid>/fd/`. Each entry is one open file
/// descriptor for the target process. Returns `None` if the directory is
/// absent (process gone) or unreadable due to permissions (EACCES is
/// common when not running as root or in the same user namespace as the
/// target).
pub fn count_fds(proc_pid_dir: &Path) -> Result<Option<u32>> {
    let fd_dir = proc_pid_dir.join("fd");
    let entries = match std::fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound || e.kind() == ErrorKind::PermissionDenied => {
            return Ok(None);
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", fd_dir.display())),
    };

    let mut count: u32 = 0;
    for entry in entries {
        // Per-entry errors (e.g. one fd vanishing mid-walk) shouldn't
        // collapse the count to None. Skip the unreadable one.
        if entry.is_ok() {
            count += 1;
        }
    }
    Ok(Some(count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn counts_entries_in_fd_dir() {
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().to_path_buf();
        let fd_dir = pid_dir.join("fd");
        fs::create_dir(&fd_dir).unwrap();
        // 5 synthetic fd entries
        for i in 0..5 {
            fs::write(fd_dir.join(i.to_string()), "").unwrap();
        }
        assert_eq!(count_fds(&pid_dir).unwrap(), Some(5));
    }

    #[test]
    fn returns_none_when_fd_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(count_fds(dir.path()).unwrap(), None);
    }

    #[test]
    fn returns_zero_for_empty_fd_dir() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("fd")).unwrap();
        assert_eq!(count_fds(dir.path()).unwrap(), Some(0));
    }
}
