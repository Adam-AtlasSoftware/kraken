//! `kraken mcp` as a real child process speaking MCP over stdio (no project, no Ghidra).

use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};

#[tokio::test(flavor = "multi_thread")]
async fn kraken_mcp_serves_the_registry_over_stdio() {
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_kraken")).configure(|c| {
            c.arg("mcp").env_remove("KRAKEN_PROJECT");
        }),
    )
    .expect("spawn kraken mcp");
    let client = ().serve(transport).await.expect("initialise");

    let info = client.peer_info().expect("server info");
    assert_eq!(
        info.server_info.as_ref().map(|i| i.name.clone()),
        Some("kraken".to_string())
    );

    let tools = client.list_all_tools().await.expect("tools");
    assert_eq!(tools.len(), 24);
    assert!(tools.iter().any(|t| t.name == "decompile"));

    let r = client
        .call_tool(CallToolRequestParams::new("list_functions"))
        .await
        .expect("call");
    assert_eq!(r.is_error, Some(true));
    let text = r
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text");
    let err: serde_json::Value = serde_json::from_str(&text).expect("ProtoError JSON");
    assert_eq!(err["code"], "not_found");

    client.cancel().await.expect("shutdown");
}
