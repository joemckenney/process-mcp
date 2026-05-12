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
    let (state, ppid, rss_bytes) =
        parse_status(&status_raw).with_context(|| format!("parsing status for pid {pid}"))?;

    let cmdline_raw = std::fs::read_to_string(dir.join("cmdline"))
        .with_context(|| format!("reading cmdline for pid {pid}"))?;

    Ok(ProcessSnapshot {
        pid,
        comm,
        cmdline_raw,
        state,
        ppid,
        rss_bytes,
        cgroup_path,
    })
}

/// Parse the subset of `/proc/<pid>/status` we care about: `State`,
/// `PPid`, `VmRSS` (kB → bytes). Other lines are ignored. `State` and
/// `PPid` are required; `VmRSS` is optional (kernel threads omit it).
pub fn parse_status(s: &str) -> Result<(char, u32, Option<u64>)> {
    let mut state: Option<char> = None;
    let mut ppid: Option<u32> = None;
    let mut rss_kb: Option<u64> = None;

    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("State:") {
            state = rest.trim().chars().next();
        } else if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            // Format: "VmRSS:   1234 kB"
            rss_kb = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok());
        }
    }

    Ok((
        state.context("missing or unparseable `State:` line")?,
        ppid.context("missing or unparseable `PPid:` line")?,
        // status reports kilobytes; bytes is what the wire shape promises.
        rss_kb.map(|k| k * 1024),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_user_process_status() {
        let s = "Name:\tnginx\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t1234\nPid:\t1234\nPPid:\t1\nVmRSS:\t  10240 kB\n";
        let (state, ppid, rss) = parse_status(s).unwrap();
        assert_eq!(state, 'S');
        assert_eq!(ppid, 1);
        assert_eq!(rss, Some(10 * 1024 * 1024));
    }

    #[test]
    fn kernel_thread_has_no_vmrss() {
        // kthreadd-style: no VmRSS line at all.
        let s = "Name:\tkthreadd\nState:\tS (sleeping)\nPPid:\t0\n";
        let (state, ppid, rss) = parse_status(s).unwrap();
        assert_eq!(state, 'S');
        assert_eq!(ppid, 0);
        assert!(rss.is_none());
    }

    #[test]
    fn rejects_status_missing_state() {
        let s = "Name:\tfoo\nPPid:\t1\n";
        assert!(parse_status(s).is_err());
    }

    #[test]
    fn rejects_status_missing_ppid() {
        let s = "State:\tS (sleeping)\n";
        assert!(parse_status(s).is_err());
    }

    #[test]
    fn vmrss_with_extra_whitespace_still_parses() {
        let s = "State:\tR (running)\nPPid:\t1\nVmRSS:\t       42 kB\n";
        let (_, _, rss) = parse_status(s).unwrap();
        assert_eq!(rss, Some(42 * 1024));
    }
}
