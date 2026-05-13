use anyhow::{Context, Result};
use serde::Serialize;
use std::io::ErrorKind;
use std::path::Path;

/// Memory breakdown from `/proc/<pid>/smaps_rollup`. All values in bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct MemoryBreakdown {
    /// Resident set size: physical memory currently mapped to this process.
    pub rss_bytes: u64,
    /// Proportional set size: each shared page is counted in proportion to
    /// the number of processes mapping it. The fairest single number for
    /// "this process's memory cost" when pages are shared across processes
    /// (browser tabs, JVM workers, etc.).
    pub pss_bytes: u64,
    /// `Shared_Clean + Shared_Dirty`: pages mapped by multiple processes.
    pub shared_bytes: u64,
    /// `Private_Clean + Private_Dirty`: pages mapped only by this process.
    pub private_bytes: u64,
    /// Anonymous (non-file-backed) memory: heap, stacks, malloc'd regions.
    pub anon_bytes: u64,
    /// Swapped-out pages.
    pub swap_bytes: u64,
}

/// Read and parse `/proc/<pid>/smaps_rollup`. Returns `None` if the file
/// is absent (kernel threads have no userspace memory map) or unreadable
/// due to permissions (EACCES is common across user namespaces).
/// Propagates other errors (parse failures, unexpected IO errors).
pub fn read_smaps_rollup(proc_pid_dir: &Path) -> Result<Option<MemoryBreakdown>> {
    let path = proc_pid_dir.join("smaps_rollup");
    match std::fs::read_to_string(&path) {
        Ok(raw) => parse_smaps_rollup(&raw).map(Some),
        Err(e) if e.kind() == ErrorKind::NotFound || e.kind() == ErrorKind::PermissionDenied => {
            Ok(None)
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

pub fn parse_smaps_rollup(s: &str) -> Result<MemoryBreakdown> {
    // smaps_rollup format:
    //   <address range> ---p ... [rollup]
    //   Key: <number> kB
    //   ...
    let mut rss_kb = 0u64;
    let mut pss_kb = 0u64;
    let mut shared_clean_kb = 0u64;
    let mut shared_dirty_kb = 0u64;
    let mut private_clean_kb = 0u64;
    let mut private_dirty_kb = 0u64;
    let mut anon_kb = 0u64;
    let mut swap_kb = 0u64;
    let mut seen_rss = false;

    for line in s.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(value_kb) = parse_kb(rest) else {
            continue;
        };
        match key.trim() {
            "Rss" => {
                rss_kb = value_kb;
                seen_rss = true;
            }
            "Pss" => pss_kb = value_kb,
            "Shared_Clean" => shared_clean_kb = value_kb,
            "Shared_Dirty" => shared_dirty_kb = value_kb,
            "Private_Clean" => private_clean_kb = value_kb,
            "Private_Dirty" => private_dirty_kb = value_kb,
            "Anonymous" => anon_kb = value_kb,
            "Swap" => swap_kb = value_kb,
            _ => {}
        }
    }

    // A smaps_rollup that doesn't even have an Rss line is malformed; treat
    // as a parse error rather than silently returning zeros for everything.
    if !seen_rss {
        anyhow::bail!("smaps_rollup parse: no Rss line found");
    }

    Ok(MemoryBreakdown {
        rss_bytes: rss_kb * 1024,
        pss_bytes: pss_kb * 1024,
        shared_bytes: (shared_clean_kb + shared_dirty_kb) * 1024,
        private_bytes: (private_clean_kb + private_dirty_kb) * 1024,
        anon_bytes: anon_kb * 1024,
        swap_bytes: swap_kb * 1024,
    })
}

/// Parse a value of the form ` <number> kB` (with optional leading
/// whitespace). Returns the number; the kB unit is implicit and consumed
/// by the caller.
fn parse_kb(rest: &str) -> Option<u64> {
    rest.split_whitespace().next().and_then(|n| n.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str =
        "55e682908000-7ffd6aff2000 ---p 00000000 00:00 0                          [rollup]
Rss:                3828 kB
Pss:                 158 kB
Pss_Dirty:           104 kB
Pss_Anon:            104 kB
Pss_File:             54 kB
Pss_Shmem:             0 kB
Shared_Clean:       3724 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:       104 kB
Referenced:         3828 kB
Anonymous:           104 kB
KSM:                   0 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
";

    #[test]
    fn parses_realistic_smaps_rollup() {
        let m = parse_smaps_rollup(SAMPLE).unwrap();
        assert_eq!(m.rss_bytes, 3828 * 1024);
        assert_eq!(m.pss_bytes, 158 * 1024);
        assert_eq!(m.shared_bytes, 3724 * 1024); // Shared_Clean + Shared_Dirty
        assert_eq!(m.private_bytes, 104 * 1024); // Private_Clean + Private_Dirty
        assert_eq!(m.anon_bytes, 104 * 1024);
        assert_eq!(m.swap_bytes, 0);
    }

    #[test]
    fn parses_with_swap_used() {
        let s = "Rss:    1024 kB\nPss:    512 kB\nShared_Clean: 0 kB\nShared_Dirty: 0 kB\nPrivate_Clean: 0 kB\nPrivate_Dirty: 1024 kB\nAnonymous: 1024 kB\nSwap: 256 kB\n";
        let m = parse_smaps_rollup(s).unwrap();
        assert_eq!(m.swap_bytes, 256 * 1024);
    }

    #[test]
    fn rejects_malformed_without_rss() {
        let s = "Pss: 100 kB\nAnonymous: 50 kB\n";
        assert!(parse_smaps_rollup(s).is_err());
    }

    #[test]
    fn ignores_unknown_keys_forward_compat() {
        // Future kernels might add lines we don't know about. Don't break.
        let s = "Rss: 100 kB\nNewKernelField: 42 kB\nPss: 50 kB\n";
        let m = parse_smaps_rollup(s).unwrap();
        assert_eq!(m.rss_bytes, 100 * 1024);
        assert_eq!(m.pss_bytes, 50 * 1024);
    }
}
