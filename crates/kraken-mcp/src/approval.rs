//! Approval of dangerous commands through MCP elicitation (decision 77).

use std::time::Duration;

use async_trait::async_trait;
use kraken_registry::{ApprovalDecision, ApprovalRequest, ApprovalRequester};
use rmcp::RoleServer;
use rmcp::service::{ElicitationError, Peer};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// How long the person has to answer.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

/// The form shown to the person.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ApprovalForm {
    /// Allow this command to run.
    approve: bool,
}

rmcp::elicit_safe!(ApprovalForm);

/// Asks the connected client's user through `elicitation/create`; denies when the client did not
/// declare the capability.
pub struct McpApprover {
    peer: Peer<RoleServer>,
}

impl McpApprover {
    /// An approver bound to one connection.
    pub fn new(peer: Peer<RoleServer>) -> Self {
        McpApprover { peer }
    }
}

fn deny(reason: impl Into<String>) -> ApprovalDecision {
    ApprovalDecision::Deny {
        reason: reason.into(),
    }
}

#[async_trait]
impl ApprovalRequester for McpApprover {
    async fn request(&self, req: ApprovalRequest) -> ApprovalDecision {
        let message = format!(
            "KRAKEN: the agent asks to run the dangerous command `{}`.\n{}\nArguments: {}",
            req.command, req.summary, req.args
        );
        match self
            .peer
            .elicit_with_timeout::<ApprovalForm>(message, Some(APPROVAL_TIMEOUT))
            .await
        {
            Ok(Some(form)) if form.approve => ApprovalDecision::Allow,
            Ok(_) => deny(format!("the user did not approve `{}`", req.command)),
            Err(ElicitationError::CapabilityNotSupported) => deny(format!(
                "`{}` is a dangerous command and this MCP client cannot ask the user (no \
                 elicitation capability); run it from the KRAKEN CLI or GUI instead",
                req.command
            )),
            Err(ElicitationError::UserDeclined | ElicitationError::UserCancelled) => {
                deny(format!("the user declined `{}`", req.command))
            }
            Err(e) => deny(format!("approval for `{}` failed: {e}", req.command)),
        }
    }
}
