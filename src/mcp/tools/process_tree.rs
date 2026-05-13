use anyhow::{bail, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::collector::proc::ProcessSnapshot;
use crate::collector::walk::{walk_processes, WalkResult};
use crate::mcp::process_entry::ProcessEntry;
use crate::mcp::util::validate_cgroup_path;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ProcessTreeParams {
    /// Root the tree at this PID. Returns a single-element forest with
    /// `root_pid` at top and every descendant (transitively) nested under
    /// it. Mutually exclusive with `cgroup_path`.
    #[serde(default)]
    pub root_pid: Option<u32>,

    /// Root the tree at this cgroup. Returns a forest of all PIDs in the
    /// cgroup, organized by parent/child relationships among PIDs in the
    /// same cgroup. A PID whose parent is outside the cgroup becomes a
    /// forest root. Mutually exclusive with `root_pid`. Path must not be
    /// absolute and must not contain `..` segments.
    #[serde(default)]
    pub cgroup_path: Option<String>,

    /// If true (the default), command-line arguments whose key matches
    /// `*key*=*`, `*token*=*`, `*password*=*`, `*secret*=*` are redacted.
    #[serde(default)]
    pub redact_args: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TreeNode {
    /// All identifier fields are flat at the top level (pid, comm, cmdline,
    /// state, ppid, rss_bytes, cgroup_path) alongside `children`.
    #[serde(flatten)]
    pub base: ProcessEntry,
    /// Children of this node within the tree, sorted descending by
    /// `rss_bytes` (nulls last).
    pub children: Vec<TreeNode>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ProcessTreeResponse {
    /// Echoes `root_pid` if that mode was used.
    pub root_pid: Option<u32>,
    /// Echoes `cgroup_path` if that mode was used.
    pub cgroup_path: Option<String>,
    /// Roots of the forest. For `root_pid` mode this is always a
    /// single-element vec (or empty if the PID has no children and we
    /// only included root). For `cgroup_path` mode this can contain
    /// multiple roots if the cgroup holds disjoint process trees.
    pub forest: Vec<TreeNode>,
    /// Count of PIDs that couldn't be fully read during the walk.
    pub skipped: u32,
}

pub fn run(proc_root: &Path, params: ProcessTreeParams) -> Result<ProcessTreeResponse> {
    // Exactly one of the two modes must be set.
    let mode = match (&params.root_pid, &params.cgroup_path) {
        (Some(_), Some(_)) => {
            bail!("provide exactly one of `root_pid` or `cgroup_path`, not both");
        }
        (None, None) => {
            bail!("must provide one of `root_pid` or `cgroup_path`");
        }
        (Some(pid), None) => Mode::RootPid(*pid),
        (None, Some(path)) => {
            validate_cgroup_path(path)?;
            Mode::Cgroup(path.clone())
        }
    };

    let redact = params.redact_args.unwrap_or(true);

    let WalkResult { processes, skipped } = walk_processes(proc_root, |_| true)?;

    // Index: pid -> snapshot, pid -> children-pids.
    let by_pid: HashMap<u32, ProcessSnapshot> = processes.into_iter().map(|s| (s.pid, s)).collect();
    let mut children_of: HashMap<u32, Vec<u32>> = HashMap::new();
    for snap in by_pid.values() {
        children_of.entry(snap.ppid).or_default().push(snap.pid);
    }

    let forest = match mode {
        Mode::RootPid(pid) => {
            if !by_pid.contains_key(&pid) {
                bail!("pid {pid} not found in /proc");
            }
            let mut visited = HashSet::new();
            vec![build_node_unfiltered(
                pid,
                &by_pid,
                &children_of,
                &mut visited,
                redact,
            )]
        }
        Mode::Cgroup(ref target) => {
            // PIDs in the target cgroup.
            let in_cgroup: HashSet<u32> = by_pid
                .values()
                .filter(|s| s.cgroup_path == *target)
                .map(|s| s.pid)
                .collect();
            // A forest root is any in-cgroup PID whose parent is NOT in
            // the same cgroup.
            let mut roots: Vec<u32> = in_cgroup
                .iter()
                .copied()
                .filter(|pid| {
                    let snap = &by_pid[pid];
                    !in_cgroup.contains(&snap.ppid)
                })
                .collect();
            // Stable ordering before tree building so output is
            // deterministic. RSS sort happens per-level inside the
            // builder.
            roots.sort_unstable();
            let mut visited = HashSet::new();
            roots
                .into_iter()
                .map(|pid| {
                    build_node_filtered(
                        pid,
                        &in_cgroup,
                        &by_pid,
                        &children_of,
                        &mut visited,
                        redact,
                    )
                })
                .collect()
        }
    };

    Ok(ProcessTreeResponse {
        root_pid: params.root_pid,
        cgroup_path: params.cgroup_path,
        forest,
        skipped,
    })
}

enum Mode {
    RootPid(u32),
    Cgroup(String),
}

/// Build a TreeNode for `pid` following all children (no cgroup filtering).
/// Used by root_pid mode.
fn build_node_unfiltered(
    pid: u32,
    by_pid: &HashMap<u32, ProcessSnapshot>,
    children_of: &HashMap<u32, Vec<u32>>,
    visited: &mut HashSet<u32>,
    redact: bool,
) -> TreeNode {
    // Defensive against /proc inconsistency (e.g., a ppid cycle). Track
    // visited so we never recurse into the same PID twice.
    visited.insert(pid);
    let snap = by_pid[&pid].clone();
    // Collect child PIDs to recurse into before recursing, to keep the
    // immutable borrow of children_of from clashing with the mutable
    // borrow of visited inside the recursive call.
    let child_pids: Vec<u32> = children_of
        .get(&pid)
        .into_iter()
        .flatten()
        .copied()
        .filter(|cpid| !visited.contains(cpid) && by_pid.contains_key(cpid))
        .collect();
    let mut child_nodes: Vec<TreeNode> = child_pids
        .into_iter()
        .map(|cpid| build_node_unfiltered(cpid, by_pid, children_of, visited, redact))
        .collect();
    sort_children_by_rss_desc(&mut child_nodes);
    TreeNode {
        base: ProcessEntry::from_snapshot(snap, redact),
        children: child_nodes,
    }
}

/// Build a TreeNode for `pid` following only children whose pid is in the
/// `in_set` filter. Used by cgroup_path mode so the tree contains only
/// in-cgroup PIDs.
fn build_node_filtered(
    pid: u32,
    in_set: &HashSet<u32>,
    by_pid: &HashMap<u32, ProcessSnapshot>,
    children_of: &HashMap<u32, Vec<u32>>,
    visited: &mut HashSet<u32>,
    redact: bool,
) -> TreeNode {
    visited.insert(pid);
    let snap = by_pid[&pid].clone();
    let child_pids: Vec<u32> = children_of
        .get(&pid)
        .into_iter()
        .flatten()
        .copied()
        .filter(|cpid| in_set.contains(cpid) && !visited.contains(cpid))
        .collect();
    let mut child_nodes: Vec<TreeNode> = child_pids
        .into_iter()
        .map(|cpid| build_node_filtered(cpid, in_set, by_pid, children_of, visited, redact))
        .collect();
    sort_children_by_rss_desc(&mut child_nodes);
    TreeNode {
        base: ProcessEntry::from_snapshot(snap, redact),
        children: child_nodes,
    }
}

fn sort_children_by_rss_desc(nodes: &mut [TreeNode]) {
    nodes.sort_by_key(|n| {
        (
            n.base.rss_bytes.is_none(),
            std::cmp::Reverse(n.base.rss_bytes.unwrap_or(0)),
        )
    });
}
