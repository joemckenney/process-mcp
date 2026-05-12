use anyhow::{Context, Result};
use std::path::Path;

use crate::collector::proc::{read_process, ProcessSnapshot};

pub struct WalkResult {
    pub processes: Vec<ProcessSnapshot>,
    /// PIDs we saw in `/proc` but couldn't fully read. Most commonly: the
    /// PID vanished between the directory walk and our open() (transient
    /// process death), or one of its files denied access. Surfaced so the
    /// agent knows the snapshot isn't necessarily exhaustive.
    pub skipped: u32,
}

/// Iterate `/proc/<pid>` subdirectories (numeric names only, since `/proc`
/// also contains non-PID entries like `cpuinfo`, `meminfo`, etc.), read
/// each as a `ProcessSnapshot`, and keep only those matching `filter`.
///
/// Per-PID read errors do not propagate. Failing the whole call because
/// one process exited mid-walk would make this tool useless on a busy
/// system. Instead we count those into `skipped`.
///
/// Threads are not visited: `/proc/<pid>/task/<tid>` is reachable from
/// the per-PID directory but the top-level `/proc` walk only lists TGIDs.
pub fn walk_processes<F>(proc_root: &Path, filter: F) -> Result<WalkResult>
where
    F: Fn(&ProcessSnapshot) -> bool,
{
    let mut processes = Vec::new();
    let mut skipped: u32 = 0;

    let entries = std::fs::read_dir(proc_root)
        .with_context(|| format!("reading proc root at {}", proc_root.display()))?;

    for entry in entries {
        let Ok(entry) = entry else {
            skipped += 1;
            continue;
        };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Non-numeric entries are not processes (cpuinfo, meminfo, sys/, etc.).
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };

        match read_process(proc_root, pid) {
            Ok(snap) => {
                if filter(&snap) {
                    processes.push(snap);
                }
            }
            Err(_) => skipped += 1,
        }
    }

    Ok(WalkResult { processes, skipped })
}
