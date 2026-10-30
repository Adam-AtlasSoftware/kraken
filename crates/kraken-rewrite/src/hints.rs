//! Hints that steer a translation: the service side of `rewrite_hint_set` and `rewrite_hint_get`,
//! and loading them into the task a translation is made from.

use std::path::Path;

use kraken_model::AuthorKind;
use kraken_proto::{Hex64, ProtoError};
use kraken_registry::commands::{
    RewriteHintGetArgs, RewriteHintSetArgs, RewriteHints, RewriteHintsOut,
};
use kraken_registry::{CallContext, Session};

use crate::lift::Lift;
use crate::service::{RewriteService, proto, with_store};
use crate::task::RewriteTask;

impl RewriteService {
    async fn entry_of(
        s: &Session,
        ctx: &CallContext,
        address: Hex64,
    ) -> Result<(String, String), ProtoError> {
        let lift = Lift::new(s, ctx);
        let (sha, _) = lift.program().map_err(proto)?;
        let f = lift.listed(address.0).await.map_err(proto)?;
        Ok((sha, format!("{:#x}", f.address)))
    }

    pub(crate) async fn hint_get_unit(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteHintGetArgs,
    ) -> Result<RewriteHintsOut, ProtoError> {
        let dir = s.project()?.dir().to_path_buf();
        let (sha, addr) = Self::entry_of(s, ctx, args.address).await?;
        let a2 = addr.clone();
        let stored = with_store(dir, move |st| st.hints(&sha, &a2)).await?;
        Ok(out(&addr, stored))
    }

    pub(crate) async fn hint_set_unit(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteHintSetArgs,
    ) -> Result<RewriteHintsOut, ProtoError> {
        let dir = s.project()?.dir().to_path_buf();
        let (sha, addr) = Self::entry_of(s, ctx, args.address).await?;
        let (actor, by_agent) = (ctx.author.id.clone(), ctx.author.kind != AuthorKind::User);
        let hints = args.hints;
        let a2 = addr.clone();
        let stored = with_store(dir, move |st| {
            st.put_hints(&sha, &a2, &hints, &actor, by_agent)?;
            st.hints(&sha, &a2)
        })
        .await?;
        Ok(out(&addr, stored))
    }
}

fn out(addr: &str, stored: Option<crate::store::StoredHints>) -> RewriteHintsOut {
    let address = Hex64(u64::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap_or(0));
    match stored {
        Some(h) => RewriteHintsOut {
            address,
            hints: h.hints,
            updated_by: Some(h.updated_by),
        },
        None => RewriteHintsOut {
            address,
            hints: RewriteHints::default(),
            updated_by: None,
        },
    }
}

/// Gives `task` the stored hints of its function. Returns whether it has hints.
pub(crate) async fn add_hints(dir: &Path, task: &mut RewriteTask) -> Result<bool, ProtoError> {
    let sha = task.function.program_sha256.clone();
    let addr = format!("{:#x}", task.function.address);
    let stored = with_store(dir.to_path_buf(), move |st| st.hints(&sha, &addr)).await?;
    if let Some(h) = stored {
        task.hints = Some(h.hints);
        task.hints_from_agent = h.by_agent;
    }
    Ok(task.hints.is_some())
}
