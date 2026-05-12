use process_mcp::mcp::server::ProcessServer;
use std::path::PathBuf;

#[tokio::test]
async fn tool_list_snapshot() {
    // Locks the public tool surface (names, descriptions, schemas) against
    // unintentional drift. Tool descriptions are how the LLM picks tools,
    // so any change should be a deliberate, reviewable diff. Empty on
    // scaffold; every future tool produces a deliberate snapshot diff.
    let server = ProcessServer::new(PathBuf::from("/proc"));
    let mut tools = server.list_tools();
    tools.sort_by(|a, b| a.name.cmp(&b.name));

    let summary: Vec<_> = tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
                "output_schema": t.output_schema,
            })
        })
        .collect();
    insta::assert_yaml_snapshot!(summary);
}
