use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{tool_handler, tool_router, ServerHandler};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ProcessServer {
    #[allow(dead_code)] // used by tools as they land
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
    // Tools land here as they're built. The router is intentionally empty
    // in the scaffold so the MCP handshake works end-to-end before any
    // data plane exists.
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
