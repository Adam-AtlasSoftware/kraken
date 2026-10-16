use rmcp::{ServiceExt, handler::server::wrapper::Parameters, tool, tool_router, transport::stdio};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
struct EchoArgs {
    /// Text to echo back.
    message: String,
}

#[derive(Debug, Clone)]
struct Echo;

#[tool_router(server_handler)]
impl Echo {
    #[tool(description = "Echo the message back")]
    fn echo(&self, Parameters(args): Parameters<EchoArgs>) -> String {
        args.message
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Echo.serve(stdio()).await?.waiting().await?;
    Ok(())
}
