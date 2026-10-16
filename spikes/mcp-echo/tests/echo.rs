use rmcp::{
    ServiceExt,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt, TokioChildProcess},
};

#[tokio::test]
async fn echo_over_child_process_stdio() -> anyhow::Result<()> {
    let bin = env!("CARGO_BIN_EXE_mcp-echo");
    let transport = TokioChildProcess::new(tokio::process::Command::new(bin).configure(|_| {}))?;
    let client = ().serve(transport).await?;

    let tools = client.list_all_tools().await?;
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "echo");
    let schema = serde_json::to_value(&*tools[0].input_schema)?;
    assert_eq!(schema["properties"]["message"]["type"], "string");

    let args = serde_json::json!({ "message": "hello kraken" });
    let result = client
        .call_tool(
            CallToolRequestParams::new("echo")
                .with_arguments(args.as_object().cloned().unwrap_or_default()),
        )
        .await?;
    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str());
    assert_eq!(text, Some("hello kraken"));

    client.cancel().await?;
    Ok(())
}
