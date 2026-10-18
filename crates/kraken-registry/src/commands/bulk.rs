//! `apply_edits`: many renames, comments and types in one call, one run id.

use async_trait::async_trait;
use kraken_engine::Cap;
use kraken_proto::{CommentKind, ErrorCode, Hex64, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::Session;
use crate::views::{MutationOutput, MutationStatus};

use super::edit::{
    RenameSymbol, RenameSymbolArgs, SetComment, SetCommentArgs, SetType, SetTypeArgs,
};

/// Most edits one `apply_edits` call takes.
pub const MAX_BULK_EDITS: usize = 200;

/// What one edit does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BulkOp {
    /// Rename a function or label (needs `name`).
    Rename,
    /// Set or clear a comment (needs `text`).
    Comment,
    /// Set the type of a function or data item (needs `type`, the name of a type).
    SetType,
}

/// One edit of `apply_edits`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BulkEdit {
    /// `rename`, `comment` or `set_type`.
    pub op: BulkOp,
    /// Address the edit is about, as `0x...`.
    pub address: Hex64,
    /// New name (`rename`).
    #[serde(default)]
    pub name: Option<String>,
    /// Comment text (`comment`); empty clears the comment.
    #[serde(default)]
    pub text: Option<String>,
    /// Comment slot for `comment`: `plate` (default), `pre`, `eol`, `post` or `repeatable`.
    #[serde(default)]
    pub kind: Option<CommentKind>,
    /// Name of an existing type (`set_type`).
    #[serde(default, rename = "type")]
    pub type_name: Option<String>,
    /// Module id (MVID) of a .NET entity; leave out for native code.
    #[serde(default)]
    pub module: Option<String>,
}

/// Arguments of `apply_edits`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyEditsArgs {
    /// The edits, at most 200, applied in order.
    pub edits: Vec<BulkEdit>,
}

/// What happened to one edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BulkOutcome {
    /// Logged and pushed to the engine.
    Applied,
    /// Logged, pushed when analysis finishes.
    Queued,
    /// Waiting for a person to accept it.
    Proposed,
    /// Refused; see `reason`.
    Rejected,
}

/// Result of one edit.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BulkItemResult {
    /// Position in the request.
    pub index: u32,
    /// `applied`, `queued`, `proposed` or `rejected`.
    pub outcome: BulkOutcome,
    /// Log entry id (applied and queued).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<u64>,
    /// Proposal id (proposed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal_id: Option<u64>,
    /// Why the edit became a proposal or was refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Result of `apply_edits`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApplyEditsOut {
    /// One entry per edit, in request order.
    pub results: Vec<BulkItemResult>,
    /// Edits applied or queued.
    pub applied: u32,
    /// Edits that became proposals.
    pub proposed: u32,
    /// Edits refused.
    pub rejected: u32,
}

/// Applies several edits.
pub struct ApplyEdits;

fn missing(field: &str, op: &str) -> ProtoError {
    ProtoError::new(
        ErrorCode::InvalidArgument,
        format!("`{op}` needs `{field}`"),
    )
}

async fn apply_one(
    s: &Session,
    ctx: &CallContext,
    e: BulkEdit,
) -> Result<MutationOutput, ProtoError> {
    match e.op {
        BulkOp::Rename => {
            let new_name = e.name.ok_or_else(|| missing("name", "rename"))?;
            RenameSymbol
                .run(
                    s,
                    ctx,
                    RenameSymbolArgs {
                        address: e.address,
                        new_name,
                        module: e.module,
                        expect_versions: None,
                    },
                )
                .await
        }
        BulkOp::Comment => {
            let text = e.text.ok_or_else(|| missing("text", "comment"))?;
            SetComment
                .run(
                    s,
                    ctx,
                    SetCommentArgs {
                        address: e.address,
                        kind: e.kind.unwrap_or(CommentKind::Plate),
                        text,
                        module: e.module,
                        expect_versions: None,
                    },
                )
                .await
        }
        BulkOp::SetType => {
            let type_name = e.type_name.ok_or_else(|| missing("type", "set_type"))?;
            SetType
                .run(
                    s,
                    ctx,
                    SetTypeArgs {
                        address: e.address,
                        prototype: None,
                        type_name: Some(type_name),
                        data_type: None,
                        expect_versions: None,
                    },
                )
                .await
        }
    }
}

#[async_trait]
impl Command for ApplyEdits {
    type Args = ApplyEditsArgs;
    type Output = ApplyEditsOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "apply_edits",
            "Rename, comment and retype many items in one call",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Applies up to 200 renames, comments and types in one run, each through the same \
             checks as `rename_symbol`, `set_comment` and `set_type`: an agent's edit applies at \
             once only when it is additive and the run is under its cap; the rest become \
             proposals. One bad item does not stop the others; each gets `applied`, `queued`, \
             `proposed` or `rejected` with a reason.\n\
             Example: apply_edits {\"edits\": [{\"op\": \"rename\", \"address\": \"0x401136\", \"name\": \"parse_header\"}, {\"op\": \"comment\", \"address\": \"0x401136\", \"text\": \"Parses the header\"}]}",
        )
        .details(
            "Items: `rename` takes `name`; `comment` takes `text` and optional `kind` (default \
             `plate`); `set_type` takes `type`, the name of an existing type. Edits are applied \
             in order, so a later edit sees the earlier ones.",
        )
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: ApplyEditsArgs,
    ) -> Result<ApplyEditsOut, ProtoError> {
        if args.edits.is_empty() {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "`edits` is empty",
            ));
        }
        if args.edits.len() > MAX_BULK_EDITS {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "{} edits is over the limit of {MAX_BULK_EDITS} per call; send them in batches",
                    args.edits.len()
                ),
            ));
        }
        let mut out = ApplyEditsOut {
            results: Vec::with_capacity(args.edits.len()),
            applied: 0,
            proposed: 0,
            rejected: 0,
        };
        for (i, edit) in args.edits.into_iter().enumerate() {
            if ctx.cancel.is_cancelled() {
                return Err(ProtoError::new(ErrorCode::Cancelled, "call cancelled"));
            }
            let index = u32::try_from(i).unwrap_or(u32::MAX);
            let item = match apply_one(s, ctx, edit).await {
                Ok(m) => {
                    let outcome = match m.status {
                        MutationStatus::Applied => BulkOutcome::Applied,
                        MutationStatus::Queued => BulkOutcome::Queued,
                        MutationStatus::Proposed => BulkOutcome::Proposed,
                    };
                    if outcome == BulkOutcome::Proposed {
                        out.proposed += 1;
                    } else {
                        out.applied += 1;
                    }
                    BulkItemResult {
                        index,
                        outcome,
                        entry_id: m.entry_id,
                        proposal_id: m.proposal_id,
                        reason: m.reason,
                    }
                }
                Err(e) => {
                    out.rejected += 1;
                    BulkItemResult {
                        index,
                        outcome: BulkOutcome::Rejected,
                        entry_id: None,
                        proposal_id: None,
                        reason: Some(format!("{:?}: {}", e.code, e.message)),
                    }
                }
            };
            out.results.push(item);
        }
        Ok(out)
    }
}
