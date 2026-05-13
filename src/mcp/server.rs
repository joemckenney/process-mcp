use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, Json, ServerHandler};
use std::path::PathBuf;

use crate::mcp::tools::pids_in_cgroup::{self, PidsInCgroupParams, PidsInCgroupResponse};
use crate::mcp::tools::process_info::{self, ProcessInfoParams, ProcessInfoResponse};
use crate::mcp::tools::process_tree::{self, ProcessTreeParams, ProcessTreeResponse};
use crate::mcp::tools::top_processes::{self, TopProcessesParams, TopProcessesResponse};

#[derive(Debug, Clone)]
pub struct ProcessServer {
    proc_root: PathBuf,
    tool_router: ToolRouter<Self>,
}

impl ProcessServer {
    pub fn new(proc_root: PathBuf) -> Self {
        Self {
            proc_root,
            tool_router: Self::tool_router(),
        }
    }

    /// Tool catalog as it would be returned from `tools/list`. Used by tests
    /// to snapshot the public schema surface.
    pub fn list_tools(&self) -> Vec<rmcp::model::Tool> {
        self.tool_router.list_all()
    }
}

#[tool_router(router = tool_router)]
impl ProcessServer {
    /// Returns the processes inside a given cgroup, each enriched with
    /// `comm`, `cmdline`, `state`, `ppid`, `rss_bytes`, and the
    /// `cgroup_path` itself (matching cgroup-mcp's identifier
    /// normalization). This is the bridge tool between cgroup-mcp and
    /// process-mcp: take a cgroup path from any cgroup-mcp result and
    /// pass it here verbatim to drill into the actual processes.
    #[tool(
        name = "pids_in_cgroup",
        description = "Returns the processes inside a given cgroup. Takes a cgroup_path \
            in normalized form (relative to /sys/fs/cgroup, no leading slash, empty \
            string for the root cgroup) and returns each process with comm, cmdline, \
            state, ppid, and rss_bytes. \
            \
            Use this to drill into a cgroup identified via cgroup-mcp's tools. The \
            cgroup_path from any cgroup-mcp output can be passed here verbatim; both \
            servers use the same identifier convention. \
            \
            Results are sorted descending by rss_bytes, with null values (kernel \
            threads with no userspace memory map) last. cmdline args matching \
            *key*=*, *token*=*, *password*=*, *secret*=* are redacted by default; \
            set redact_args=false to receive them verbatim. \
            \
            The `skipped` field counts PIDs encountered in /proc that could not be \
            fully read (transient process death, permission denied). Non-zero means \
            the snapshot may be incomplete."
    )]
    pub async fn pids_in_cgroup(
        &self,
        Parameters(params): Parameters<PidsInCgroupParams>,
    ) -> Result<Json<PidsInCgroupResponse>, McpError> {
        pids_in_cgroup::run(&self.proc_root, params)
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("{e:#}"), None))
    }

    /// Returns the top N processes system-wide, ranked by resident
    /// memory. Optionally scoped to a cgroup subtree via cgroup_prefix.
    /// Sort is by memory only for now; CPU rate sampling is planned but
    /// not yet implemented.
    #[tool(
        name = "top_processes",
        description = "Returns the top N processes ranked by resident memory (rss_bytes), \
            descending. Use this to answer 'what's using the most memory on this box.' \
            \
            Pass `cgroup_prefix` to scope the search to a cgroup subtree. The match is \
            path-aware: `system.slice` matches `system.slice` itself and any descendant \
            (e.g. `system.slice/nginx.service`), but NOT siblings like `system.slice2`. \
            Take cgroup paths verbatim from any cgroup-mcp tool output. \
            \
            Results are returned with the same shape as `pids_in_cgroup`: pid, comm, \
            cmdline (redacted by default; pass `redact_args=false` for verbatim), \
            state, ppid, rss_bytes, and cgroup_path. Kernel threads (null rss_bytes) \
            sort last. Default n is 10. \
            \
            CPU-based ranking is planned but not yet implemented; current sort is \
            memory only."
    )]
    pub async fn top_processes(
        &self,
        Parameters(params): Parameters<TopProcessesParams>,
    ) -> Result<Json<TopProcessesResponse>, McpError> {
        top_processes::run(&self.proc_root, params)
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("{e:#}"), None))
    }

    /// Single-PID drill-down. Returns the same identifier fields as
    /// pids_in_cgroup and top_processes, plus uid, num_threads, fd_count,
    /// a memory breakdown from smaps_rollup (Rss/Pss/Shared/Private/Anon/
    /// Swap), and IO counters. Permission-gated fields are nullable.
    #[tool(
        name = "process_info",
        description = "Returns the full per-PID drill-down bundle for one process. Includes the \
            same identifier fields as pids_in_cgroup (pid, comm, cmdline, state, ppid, \
            rss_bytes, cgroup_path) plus uid, num_threads, fd_count, a smaps_rollup \
            memory breakdown (Rss/Pss/Shared/Private/Anon/Swap), and IO counters. \
            \
            Use this after identifying a PID of interest via pids_in_cgroup or \
            top_processes. The `memory.pss_bytes` field is the fairest single number \
            for 'this process's memory cost' when pages are shared with other \
            processes (browser tabs, JVM workers, etc.). \
            \
            Permission-gated fields are nullable when the kernel rejects the read: \
            `fd_count` and `io` typically require ptrace capability or matching uid; \
            `memory` is null for kernel threads. Cmdline args matching *key=*, \
            *token=*, *password=*, *secret=* are redacted by default; pass \
            `redact_args=false` to receive them verbatim. Errors if the PID does not \
            exist."
    )]
    pub async fn process_info(
        &self,
        Parameters(params): Parameters<ProcessInfoParams>,
    ) -> Result<Json<ProcessInfoResponse>, McpError> {
        process_info::run(&self.proc_root, params)
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("{e:#}"), None))
    }

    /// Returns a parent/child process forest, either rooted at a single
    /// PID (and all its descendants) or scoped to a cgroup (showing
    /// in-cgroup parent/child relationships).
    #[tool(
        name = "process_tree",
        description = "Returns a parent/child process forest. Two mutually exclusive modes: \
            \
            1. Pass `root_pid` to root the tree at one PID. The result is a single-element \
            forest with that PID at top, every descendant nested underneath. Useful for \
            unpacking Chrome's main + renderer + GPU process model, systemd-managed \
            supervisor trees, language runtimes that fork many workers, etc. \
            \
            2. Pass `cgroup_path` to get the forest of processes inside a cgroup, \
            organized by in-cgroup parent/child relationships. A PID whose parent is \
            outside the cgroup becomes a forest root. Useful for understanding the \
            structure of a heavy cgroup identified via cgroup-mcp. \
            \
            Each node carries the same identifier fields as other tools (pid, comm, \
            cmdline, state, ppid, rss_bytes, cgroup_path) plus a `children` array. \
            Children are sorted by rss_bytes desc with nulls last. Cmdline redaction \
            and the `skipped` count work the same as the other tools."
    )]
    pub async fn process_tree(
        &self,
        Parameters(params): Parameters<ProcessTreeParams>,
    ) -> Result<Json<ProcessTreeResponse>, McpError> {
        process_tree::run(&self.proc_root, params)
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("{e:#}"), None))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ProcessServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Read-only access to per-process Linux state via /proc. Sister to \
                 cgroup-mcp: process-mcp answers 'which processes,' cgroup-mcp \
                 answers 'which cgroups.' Tools return structured JSON; the agent \
                 does prose. Each call is a point-in-time snapshot.",
        )
    }
}
