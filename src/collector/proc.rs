use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

use crate::collector::cgroup_link::read_cgroup_path;

/// Point-in-time snapshot of one process. The collector keeps the raw,
/// untransformed forms (`cmdline_raw` as null-separated bytes) so callers
/// can shape the output (e.g. redaction, formatting) without re-reading.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub comm: String,
    pub cmdline_raw: String,
    pub state: char,
    pub ppid: u32,
    /// Real uid from `/proc/<pid>/status` `Uid:` (first of four values).
    pub uid: u32,
    /// Number of threads in the process group.
    pub num_threads: u32,
    /// Resident set size in bytes. `None` for kernel threads (which have
    /// no userspace memory map and no `VmRSS:` line in status).
    pub rss_bytes: Option<u64>,
    pub cgroup_path: String,
}

pub fn read_process(proc_root: &Path, pid: u32) -> Result<ProcessSnapshot> {
    let dir = proc_root.join(pid.to_string());

    let cgroup_path = read_cgroup_path(&dir)?;

    let comm = std::fs::read_to_string(dir.join("comm"))
        .with_context(|| format!("reading comm for pid {pid}"))?
        .trim()
        .to_string();

    let status_raw = std::fs::read_to_string(dir.join("status"))
        .with_context(|| format!("reading status for pid {pid}"))?;
    let parsed =
        parse_status(&status_raw).with_context(|| format!("parsing status for pid {pid}"))?;

    let cmdline_raw = std::fs::read_to_string(dir.join("cmdline"))
        .with_context(|| format!("reading cmdline for pid {pid}"))?;

    Ok(ProcessSnapshot {
        pid,
        comm,
        cmdline_raw,
        state: parsed.state,
        ppid: parsed.ppid,
        uid: parsed.uid,
        num_threads: parsed.num_threads,
        rss_bytes: parsed.rss_bytes,
        cgroup_path,
    })
}

/// The subset of `/proc/<pid>/status` we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusFields {
    pub state: char,
    pub ppid: u32,
    /// Real uid (first of the four values on the `Uid:` line).
    pub uid: u32,
    pub num_threads: u32,
    /// `None` if no `VmRSS:` line was present (kernel threads).
    pub rss_bytes: Option<u64>,
}

/// Parse the subset of `/proc/<pid>/status` we care about. `State`,
/// `PPid`, `Uid`, `Threads` are required; `VmRSS` is optional (kernel
/// threads omit it).
pub fn parse_status(s: &str) -> Result<StatusFields> {
    let mut state: Option<char> = None;
    let mut ppid: Option<u32> = None;
    let mut uid: Option<u32> = None;
    let mut threads: Option<u32> = None;
    let mut rss_kb: Option<u64> = None;

    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("State:") {
            state = rest.trim().chars().next();
        } else if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("Uid:") {
            // Format: "Uid:  real effective saved fs". We want real.
            uid = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u32>().ok());
        } else if let Some(rest) = line.strip_prefix("Threads:") {
            threads = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            // Format: "VmRSS:   1234 kB"
            rss_kb = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok());
        }
    }

    Ok(StatusFields {
        state: state.context("missing or unparseable `State:` line")?,
        ppid: ppid.context("missing or unparseable `PPid:` line")?,
        uid: uid.context("missing or unparseable `Uid:` line")?,
        num_threads: threads.context("missing or unparseable `Threads:` line")?,
        // status reports kilobytes; bytes is what the wire shape promises.
        rss_bytes: rss_kb.map(|k| k * 1024),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_user_process_status() {
        let s = "Name:\tnginx\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t1234\nPid:\t1234\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nThreads:\t4\nVmRSS:\t  10240 kB\n";
        let f = parse_status(s).unwrap();
        assert_eq!(f.state, 'S');
        assert_eq!(f.ppid, 1);
        assert_eq!(f.uid, 1000);
        assert_eq!(f.num_threads, 4);
        assert_eq!(f.rss_bytes, Some(10 * 1024 * 1024));
    }

    #[test]
    fn kernel_thread_has_no_vmrss() {
        // kthreadd-style: no VmRSS line at all, but still has the others.
        let s = "Name:\tkthreadd\nState:\tS (sleeping)\nPPid:\t0\nUid:\t0\t0\t0\t0\nThreads:\t1\n";
        let f = parse_status(s).unwrap();
        assert_eq!(f.state, 'S');
        assert_eq!(f.ppid, 0);
        assert_eq!(f.uid, 0);
        assert_eq!(f.num_threads, 1);
        assert!(f.rss_bytes.is_none());
    }

    #[test]
    fn rejects_status_missing_state() {
        let s = "Name:\tfoo\nPPid:\t1\nUid:\t0\t0\t0\t0\nThreads:\t1\n";
        assert!(parse_status(s).is_err());
    }

    #[test]
    fn rejects_status_missing_ppid() {
        let s = "State:\tS (sleeping)\nUid:\t0\t0\t0\t0\nThreads:\t1\n";
        assert!(parse_status(s).is_err());
    }

    #[test]
    fn rejects_status_missing_uid() {
        let s = "State:\tS (sleeping)\nPPid:\t1\nThreads:\t1\n";
        assert!(parse_status(s).is_err());
    }

    #[test]
    fn rejects_status_missing_threads() {
        let s = "State:\tS (sleeping)\nPPid:\t1\nUid:\t0\t0\t0\t0\n";
        assert!(parse_status(s).is_err());
    }

    #[test]
    fn vmrss_with_extra_whitespace_still_parses() {
        let s =
            "State:\tR (running)\nPPid:\t1\nUid:\t0\t0\t0\t0\nThreads:\t1\nVmRSS:\t       42 kB\n";
        let f = parse_status(s).unwrap();
        assert_eq!(f.rss_bytes, Some(42 * 1024));
    }

    #[test]
    fn uid_picks_real_not_effective() {
        // real=1000, effective=0 (setuid binary)
        let s = "State:\tR\nPPid:\t1\nUid:\t1000\t0\t1000\t0\nThreads:\t1\n";
        let f = parse_status(s).unwrap();
        assert_eq!(f.uid, 1000);
    }
}
