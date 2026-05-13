use anyhow::{Context, Result};
use serde::Serialize;
use std::io::ErrorKind;
use std::path::Path;

/// IO counters from `/proc/<pid>/io`. Cumulative since process start.
/// Reading this file typically requires ptrace capability or matching
/// uid; non-root callers commonly hit EACCES.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct IoCounters {
    /// Bytes read from disk (after the page cache). Matches kernel
    /// `read_bytes`.
    pub read_bytes: u64,
    /// Bytes written to disk. Matches kernel `write_bytes`.
    pub write_bytes: u64,
    /// Number of read syscalls. Matches kernel `syscr`.
    pub read_syscalls: u64,
    /// Number of write syscalls. Matches kernel `syscw`.
    pub write_syscalls: u64,
}

/// Read and parse `/proc/<pid>/io`. Returns `None` for missing file or
/// EACCES, propagates other errors.
pub fn read_io(proc_pid_dir: &Path) -> Result<Option<IoCounters>> {
    let path = proc_pid_dir.join("io");
    match std::fs::read_to_string(&path) {
        Ok(raw) => parse_io(&raw).map(Some),
        Err(e) if e.kind() == ErrorKind::NotFound || e.kind() == ErrorKind::PermissionDenied => {
            Ok(None)
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

pub fn parse_io(s: &str) -> Result<IoCounters> {
    let mut read_bytes = None;
    let mut write_bytes = None;
    let mut syscr = None;
    let mut syscw = None;

    for line in s.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value: u64 = match value.trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        match key.trim() {
            "read_bytes" => read_bytes = Some(value),
            "write_bytes" => write_bytes = Some(value),
            "syscr" => syscr = Some(value),
            "syscw" => syscw = Some(value),
            _ => {}
        }
    }

    Ok(IoCounters {
        read_bytes: read_bytes.context("missing read_bytes in /proc/<pid>/io")?,
        write_bytes: write_bytes.context("missing write_bytes")?,
        read_syscalls: syscr.context("missing syscr")?,
        write_syscalls: syscw.context("missing syscw")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "rchar: 4428
wchar: 8
syscr: 8
syscw: 1
read_bytes: 1048576
write_bytes: 2048
cancelled_write_bytes: 0
";

    #[test]
    fn parses_realistic_io_file() {
        let io = parse_io(SAMPLE).unwrap();
        assert_eq!(io.read_bytes, 1_048_576);
        assert_eq!(io.write_bytes, 2_048);
        assert_eq!(io.read_syscalls, 8);
        assert_eq!(io.write_syscalls, 1);
    }

    #[test]
    fn fails_on_missing_required_field() {
        let s = "rchar: 1\nwchar: 1\n"; // no read_bytes etc.
        assert!(parse_io(s).is_err());
    }

    #[test]
    fn ignores_unknown_lines() {
        let s = "read_bytes: 0\nwrite_bytes: 0\nsyscr: 0\nsyscw: 0\nfuture_field: 999\n";
        let io = parse_io(s).unwrap();
        assert_eq!(io.read_bytes, 0);
    }
}
