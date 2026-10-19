//! `--serve-local`: hold the local models the assistant and rewriting use for as long as the
//! command runs (`kraken mcp --serve-local` runs until the client goes away).
//!
//! With a daemon the models are held on this command's connection, so they stop (after the
//! grace period) when it ends and keep running for anyone else who holds them. Without one
//! this process runs them and stops them at exit.

use std::io::Write;
use std::sync::Arc;

use clap::ArgMatches;
use kraken_host::infer::{ServingApi, hold_role_models};
use kraken_ipc::ClientKind;

use crate::app::{CliEnv, DaemonMode, emit};

/// Models held for the length of one command.
pub(crate) struct ServeLocal {
    api: Arc<dyn ServingApi>,
    held: Vec<String>,
}

impl ServeLocal {
    /// Gives the holds up (a daemon stops the models after the grace period).
    pub(crate) async fn finish(self) {
        for id in &self.held {
            let _ = self.api.release(id).await;
        }
    }
}

/// Holds the role-assigned models when `--serve-local` was given. Problems are warnings: the
/// command still runs, and a request that needs the model says what is wrong.
pub(crate) async fn start(
    env: &CliEnv,
    sm: &ArgMatches,
    err: &mut dyn Write,
) -> Option<ServeLocal> {
    if sm
        .try_get_one::<bool>("serve-local")
        .ok()
        .flatten()
        .copied()
        != Some(true)
    {
        return None;
    }
    let api = match api_for(env, sm, err).await {
        Ok(a) => a,
        Err(e) => {
            emit(err, &format!("warning: cannot serve local models: {e}\n"));
            return None;
        }
    };
    match hold_role_models(api.as_ref()).await {
        Ok(r) => {
            for id in &r.started {
                emit(err, &format!("serving local model {id}\n"));
            }
            for s in &r.skipped {
                emit(
                    err,
                    &format!(
                        "warning: not serving local model {}: {}\n",
                        s.model, s.reason
                    ),
                );
            }
            Some(ServeLocal {
                api,
                held: r.started,
            })
        }
        Err(e) => {
            emit(
                err,
                &format!("warning: cannot serve local models: {}\n", e.message),
            );
            None
        }
    }
}

/// The daemon (started when needed), else the manager of this process.
async fn api_for(
    env: &CliEnv,
    sm: &ArgMatches,
    err: &mut dyn Write,
) -> Result<Arc<dyn ServingApi>, String> {
    let owner = || -> Arc<dyn ServingApi> {
        Arc::new(
            env.owner_manager()
                .holder(kraken_host::infer::Holder::Owner),
        )
    };
    if env.session.is_some() || env.no_daemon(sm) {
        return Ok(owner());
    }
    match &env.daemon {
        DaemonMode::Direct => Ok(owner()),
        DaemonMode::Connected(c) => Ok(c.clone()),
        DaemonMode::Auto(auto) => match auto.connect(ClientKind::Cli).await {
            Ok(c) => Ok(Arc::new(c)),
            Err(e) if e.restart_required() => {
                Err(format!("{e}; run `kraken daemon stop` and retry"))
            }
            Err(e) => {
                emit(
                    err,
                    &format!(
                        "warning: cannot use krakend ({e}); the models will run inside this \
                         command only\n"
                    ),
                );
                Ok(owner())
            }
        },
    }
}
