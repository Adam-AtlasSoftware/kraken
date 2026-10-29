//! The mutation pipeline (decisions 27-29, 34, 57-58, 61).
//!
//! Every edit goes through [`submit`]: build the read-set, validate, classify (agents only),
//! append to the log, push to the engine, then mark pushed or engine-rejected. Edits made while
//! analysis runs stay pending (`queued`) and are pushed when it finishes.

use std::collections::BTreeMap;

use kraken_model::{
    AuthorKind, Classification, EntryDraft, EntryId, NewProposal, ProposalId, RunId, classify,
    op_key,
};
use kraken_proto::{
    Anchor, ErrorCode, FunctionSummary, Hex64, Locator, LogOp, ProtoError, Provenance,
    VersionedLogOp,
};
use serde_json::json;

use crate::context::CallContext;
use crate::session::{Project, Session};
use crate::views::{MutationOutput, MutationStatus};

/// Run id used for cap accounting and grouping when an agent gives none.
pub(crate) fn effective_run(ctx: &CallContext) -> Option<RunId> {
    match (&ctx.run_id, ctx.author.kind) {
        (Some(r), _) => Some(r.clone()),
        (None, AuthorKind::Agent) => Some(RunId(format!("adhoc-{}", ctx.author.id))),
        (None, AuthorKind::User) => None,
    }
}

/// An anchor plus the function the engine found at the address, if any.
pub(crate) struct Resolved {
    pub anchor: Anchor,
    pub function: Option<FunctionSummary>,
}

/// Builds the anchor for `address`: the containing function's entry and hash when the engine
/// knows one, otherwise an offset-only anchor (entry = offset, empty hash).
pub(crate) async fn anchor_for(
    project: &Project,
    ctx: &CallContext,
    address: Hex64,
) -> Result<Resolved, ProtoError> {
    if project.meta().engine_kind == crate::session::EngineKind::Dotnet {
        return Err(kraken_engine::unsupported(
            "this edit by address for a .NET assembly; renames and comments name a method, type, \
             field or parameter by its token in `address` plus the `module` id",
        ));
    }
    let engine = project.engine();
    let locator = Locator::ram(address.0);
    if let Some(lister) = engine.function_lister() {
        match lister.get_function(&locator, &ctx.cancel).await {
            Ok(f) => {
                let (_, entry) = crate::views::locator_parts(&f.locator);
                return Ok(Resolved {
                    anchor: Anchor::Native {
                        space: kraken_proto::DEFAULT_SPACE.into(),
                        offset: address,
                        fn_entry: entry,
                        fn_hash: f.fn_hash.clone().unwrap_or_default(),
                    },
                    function: Some(f),
                });
            }
            Err(e) if e.code == ErrorCode::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Resolved {
        anchor: Anchor::Native {
            space: kraken_proto::DEFAULT_SPACE.into(),
            offset: address,
            fn_entry: address,
            fn_hash: String::new(),
        },
        function: None,
    })
}

/// Like [`anchor_for`] for a managed entity: `address` is a metadata token and `module` the
/// module id. Tokens that are not methods (types, fields, parameters) have no function; the
/// engine checks them when the edit is pushed.
pub(crate) async fn managed_anchor_for(
    project: &Project,
    ctx: &CallContext,
    address: Hex64,
    module: &str,
) -> Result<Resolved, ProtoError> {
    let locator = crate::commands::locator_in(address, Some(module))?;
    let Locator::Managed { token, .. } = &locator else {
        return Err(ProtoError::new(
            ErrorCode::Internal,
            "not a managed locator",
        ));
    };
    let anchor = Anchor::managed(module, *token);
    let mut function = None;
    if let Some(lister) = project.engine().function_lister() {
        match lister.get_function(&locator, &ctx.cancel).await {
            Ok(f) => function = Some(f),
            Err(e) if e.code == ErrorCode::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Resolved { anchor, function })
}

/// A project on the .NET engine takes renames and comments on managed anchors; everything else is
/// refused before it reaches the log.
fn check_engine_supports(project: &Project, op: &LogOp) -> Result<(), ProtoError> {
    if project.meta().engine_kind != crate::session::EngineKind::Dotnet {
        return Ok(());
    }
    let managed = kraken_model::op_anchor(op).is_some_and(|a| a.managed_parts().is_some());
    match op {
        LogOp::Rename { .. } | LogOp::SetComment { .. } if managed => Ok(()),
        LogOp::Rename { .. } | LogOp::SetComment { .. } => Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            "this is a .NET project: name the method by its token with `address` and add \
             `module` (the module id from `list_functions`)",
        )),
        _ => Err(kraken_engine::unsupported(
            "this edit for .NET assemblies (only renames and comments on methods, types, \
             fields and parameters are available)",
        )),
    }
}

enum Appended {
    Entry { id: EntryId, version: u64 },
    Proposed { id: ProposalId, reason: String },
}

/// Result of pushing entries to the engine.
pub(crate) struct Settlement {
    pub status: MutationStatus,
    pub pushed: Vec<EntryId>,
    pub failed: Vec<(EntryId, ProtoError)>,
    pub pending: Vec<EntryId>,
}

/// Pushes pending entries (older ones first) unless analysis is running, and sorts `ids` into
/// pushed, failed and still pending. The caller holds the write lock.
pub(crate) async fn settle(
    project: &Project,
    ctx: &CallContext,
    ids: &[EntryId],
) -> Result<Settlement, ProtoError> {
    if project.analysis_running() {
        return Ok(Settlement {
            status: MutationStatus::Queued,
            pushed: Vec::new(),
            failed: Vec::new(),
            pending: ids.to_vec(),
        });
    }
    let report = project.flush_pending(&ctx.cancel).await?;
    let mut out = Settlement {
        status: MutationStatus::Applied,
        pushed: Vec::new(),
        failed: Vec::new(),
        pending: Vec::new(),
    };
    for id in ids {
        if report.pushed.contains(id) {
            out.pushed.push(*id);
        } else if let Some((_, e)) = report.rejected.iter().find(|(r, _)| r == id) {
            out.failed.push((*id, e.clone()));
        } else {
            out.pending.push(*id);
        }
    }
    Ok(out)
}

/// The error returned to the caller when the engine refused an entry.
pub(crate) fn engine_rejected(id: EntryId, e: &ProtoError) -> ProtoError {
    ProtoError::new(ErrorCode::EngineRejected, e.message.clone()).with_details(json!({
        "entry_id": id.0,
        "engine_code": e.code.as_str(),
    }))
}

/// Submits one edit. See the module docs. `expect` is the caller's read-set (entity key to
/// version); absent means "the current version of the written key".
pub(crate) async fn submit(
    s: &Session,
    ctx: &CallContext,
    op: LogOp,
    expect: Option<BTreeMap<String, u64>>,
) -> Result<MutationOutput, ProtoError> {
    submit_as(s, ctx, op, expect, effective_run(ctx)).await
}

/// [`submit`] with an explicit run id (accepting a proposal keeps the proposal's run).
pub(crate) async fn submit_as(
    s: &Session,
    ctx: &CallContext,
    op: LogOp,
    expect: Option<BTreeMap<String, u64>>,
    run_id: Option<RunId>,
) -> Result<MutationOutput, ProtoError> {
    let project = s.project()?;
    if project.engine().mutator().is_none() {
        return Err(kraken_engine::unsupported("mutator"));
    }
    check_engine_supports(&project, &op)?;
    let key = op_key(&op)?;
    let _write = project.write_lock.lock().await;
    let author = ctx.author.clone();
    let cap = u64::from(project.config().per_run_cap);
    let is_agent = author.kind == AuthorKind::Agent;
    // The identity the daemon counts an agent under survives a reconnect, unlike the run id.
    let quota_key = ctx.quota_key.clone();
    let quota_used = quota_key.as_deref().map_or(0, |k| project.quota_used(k));
    let op = VersionedLogOp::new(op);
    let draft_key = key.clone();
    let appended = project
        .with_store(move |st| {
            let read_set = match expect {
                Some(m) => m,
                None => BTreeMap::from([(draft_key.clone(), st.entity_version(&draft_key)?)]),
            };
            let draft = EntryDraft {
                op: op.clone(),
                provenance: if is_agent {
                    Provenance::Agent
                } else {
                    Provenance::User
                },
                author: author.clone(),
                run_id: run_id.clone(),
                read_set,
            };
            if is_agent {
                if let Err(err) = st.validate_draft(&draft) {
                    // Record the refusal for audit; its error carries `rejected_entry_id`.
                    return Err(st.append(draft).err().unwrap_or(err));
                }
                let state = st.current_state()?;
                let used = match &run_id {
                    Some(r) => st.count_applied_agent_entries(r)?,
                    None => 0,
                };
                let reason = if classify(&op.op, &state) == Classification::Overwrite {
                    Some("changes an existing annotation or the program structure; needs user approval".to_string())
                } else if used >= cap || quota_used >= cap {
                    Some(format!(
                        "per-run limit of {cap} auto-applied edits reached; needs user approval"
                    ))
                } else {
                    None
                };
                if let Some(reason) = reason {
                    let id = st.add_proposal(NewProposal {
                        run_id,
                        author,
                        op,
                        reason: reason.clone(),
                    })?;
                    return Ok(Appended::Proposed { id, reason });
                }
            }
            let id = st.append(draft)?;
            let version = st.entity_version(&draft_key)?;
            Ok(Appended::Entry { id, version })
        })
        .await?;
    match appended {
        Appended::Proposed { id, reason } => Ok(MutationOutput {
            status: MutationStatus::Proposed,
            entry_id: None,
            proposal_id: Some(id.0),
            key,
            versions: BTreeMap::new(),
            reason: Some(reason),
        }),
        Appended::Entry { id, version } => {
            if is_agent && let Some(k) = &quota_key {
                project.quota_add(k);
            }
            let settled = settle(&project, ctx, &[id]).await?;
            if let Some((_, e)) = settled.failed.first() {
                return Err(engine_rejected(id, e));
            }
            if settled.status == MutationStatus::Applied && !settled.pending.is_empty() {
                return Err(ProtoError::new(
                    ErrorCode::Cancelled,
                    "cancelled while pushing to the engine; the edit is logged and stays pending",
                )
                .with_details(json!({ "entry_id": id.0 })));
            }
            Ok(MutationOutput {
                status: settled.status,
                entry_id: Some(id.0),
                proposal_id: None,
                versions: BTreeMap::from([(key.clone(), version)]),
                key,
                reason: None,
            })
        }
    }
}
