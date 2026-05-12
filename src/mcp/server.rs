use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, Json, ServerHandler};
use std::path::PathBuf;

use crate::mcp::tools::pids_in_cgroup::{self, PidsInCgroupParams, PidsInCgroupResponse};
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
