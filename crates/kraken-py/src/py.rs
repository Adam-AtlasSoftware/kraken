//! The PyO3 module `kraken._native`: thin wrappers over [`crate::conn`].
//!
//! Arguments and results cross as JSON text. The Python layer (`kraken/`) builds the Pythonic
//! objects; keeping the boundary this narrow keeps the unsafe-adjacent surface small and the GIL
//! story simple: every blocking call goes through [`drive`], which releases the GIL while it
//! waits and looks at signals between short waits.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kraken_proto::{ErrorCode, ProtoError};
use pyo3::prelude::*;
use pyo3::types::{PyList, PyTuple};
use serde_json::Value;

use crate::conn::{self, Author, ConnectOptions};
use crate::runtime::{Pending, Wait};

/// How long the GIL stays released between looks at pending signals (Ctrl-C latency).
const SLICE: Duration = Duration::from_millis(50);
/// How long a cancelled call gets to wind down before the interrupt is raised anyway.
const CANCEL_GRACE: Duration = Duration::from_secs(3);

/// Converts a protocol error into the matching `kraken.errors` exception.
fn to_pyerr(py: Python<'_>, e: ProtoError) -> PyErr {
    let details = e
        .details
        .as_ref()
        .and_then(|d| serde_json::to_string(d).ok());
    let build = || -> PyResult<PyErr> {
        let errors = py.import("kraken.errors")?;
        let inst =
            errors
                .getattr("from_wire")?
                .call1((e.code.as_str(), e.message.as_str(), details))?;
        Ok(PyErr::from_value(inst))
    };
    match build() {
        Ok(err) | Err(err) => err,
    }
}

fn internal(msg: &str) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, msg)
}

/// Waits for a call on the runtime with the GIL released. On `KeyboardInterrupt` (or any other
/// pending signal handler error) the call is cancelled, given a moment to wind down, and the
/// signal's exception is raised.
fn drive<T: Send + 'static>(
    py: Python<'_>,
    pending: Pending<Result<T, ProtoError>>,
) -> PyResult<T> {
    loop {
        match py.detach(|| pending.wait(SLICE)) {
            Wait::Done(r) => return r.map_err(|e| to_pyerr(py, e)),
            Wait::Pending => {
                if let Err(signal) = py.check_signals() {
                    pending.cancel();
                    let deadline = std::time::Instant::now() + CANCEL_GRACE;
                    while std::time::Instant::now() < deadline {
                        if !matches!(py.detach(|| pending.wait(SLICE)), Wait::Pending) {
                            break;
                        }
                    }
                    return Err(signal);
                }
            }
            Wait::Lost => return Err(to_pyerr(py, internal("the runtime stopped mid-call"))),
        }
    }
}

/// A connection to `krakend`, or the in-process engine factory.
#[pyclass(module = "kraken._native", frozen)]
struct Connection {
    inner: Arc<conn::Connection>,
}

#[pymethods]
impl Connection {
    /// `"daemon"` or `"local"`.
    #[getter]
    fn mode(&self) -> &'static str {
        self.inner.mode().as_str()
    }

    /// Notices from connecting.
    #[getter]
    fn warnings(&self) -> Vec<String> {
        self.inner.warnings().to_vec()
    }

    /// The daemon's process id, or None in-process.
    #[getter]
    fn daemon_pid(&self) -> Option<u32> {
        self.inner.daemon_pid()
    }

    /// Every command with its spec and JSON Schemas, as JSON text.
    fn commands_json(&self) -> PyResult<String> {
        let list: Vec<Value> = self
            .inner
            .registry()
            .iter()
            .map(|e| {
                serde_json::json!({
                    "name": e.spec().name,
                    "summary": e.spec().summary,
                    "doc": e.spec().doc,
                    "kind": e.spec().kind,
                    "permission": e.spec().permission,
                    "args_schema": e.args_schema(),
                    "output_schema": e.output_schema(),
                })
            })
            .collect();
        serde_json::to_string(&list)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// A handle for one project. `agent` makes its writes follow agent policy.
    #[pyo3(signature = (project_dir=None, agent=None, run_id=None))]
    fn handle(
        &self,
        project_dir: Option<PathBuf>,
        agent: Option<&str>,
        run_id: Option<String>,
    ) -> Handle {
        let author = match agent {
            Some(id) => Author::agent(id, run_id),
            None => Author::current_user(),
        };
        Handle {
            inner: self.inner.handle(project_dir.as_deref(), author),
        }
    }

    /// Asks the daemon to exit; False when running in-process.
    fn stop_daemon(&self, py: Python<'_>) -> PyResult<bool> {
        let inner = self.inner.clone();
        let pending = Pending::spawn(move |_| async move { inner.stop_daemon().await })
            .map_err(|e| to_pyerr(py, e))?;
        drive(py, pending)
    }

    /// Stops engines started by this process; a daemon keeps running.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let inner = self.inner.clone();
        let pending = Pending::spawn(move |_| async move {
            inner.shutdown().await;
            Ok::<(), ProtoError>(())
        })
        .map_err(|e| to_pyerr(py, e))?;
        drive(py, pending)
    }
}

/// Runs commands of one project as one author.
#[pyclass(module = "kraken._native", frozen)]
struct Handle {
    inner: conn::Handle,
}

#[pymethods]
impl Handle {
    /// `"user"` or `"agent"`.
    #[getter]
    fn author_kind(&self) -> &'static str {
        self.inner.author().kind()
    }

    /// The user name or agent id.
    #[getter]
    fn author_id(&self) -> String {
        self.inner.author().id().to_string()
    }

    /// The agent run id, or None for the user.
    #[getter]
    fn run_id(&self) -> Option<String> {
        self.inner.author().run_id().map(str::to_string)
    }

    /// Runs one command. `args_json` is the argument object as JSON text. Returns
    /// `(result_json, warnings)`. Blocks with the GIL released; Ctrl-C cancels the call.
    #[pyo3(signature = (command, args_json, approve=false))]
    fn call<'py>(
        &self,
        py: Python<'py>,
        command: &str,
        args_json: &str,
        approve: bool,
    ) -> PyResult<Bound<'py, PyTuple>> {
        let args: Value = serde_json::from_str(args_json).map_err(|e| {
            to_pyerr(
                py,
                ProtoError::new(
                    ErrorCode::InvalidArgument,
                    format!("arguments are not JSON: {e}"),
                ),
            )
        })?;
        let handle = self.inner.clone();
        let command = command.to_string();
        let pending = Pending::spawn(move |cancel| async move {
            handle.call(&command, args, cancel, approve).await
        })
        .map_err(|e| to_pyerr(py, e))?;
        let (value, warnings) = drive(py, pending)?;
        let text = serde_json::to_string(&value)
            .map_err(|e| to_pyerr(py, internal(&format!("unserialisable result: {e}"))))?;
        PyTuple::new(
            py,
            [
                text.into_pyobject(py)?.into_any(),
                PyList::new(py, warnings)?.into_any(),
            ],
        )
    }
}

/// Connects to `krakend` (starting it if needed) or to the in-process engine.
#[pyfunction]
#[pyo3(signature = (daemon=None, runtime_dir=None, krakend=None))]
fn connect(
    py: Python<'_>,
    daemon: Option<bool>,
    runtime_dir: Option<PathBuf>,
    krakend: Option<PathBuf>,
) -> PyResult<Connection> {
    let opts = ConnectOptions {
        daemon,
        runtime_dir,
        krakend,
    };
    let pending = Pending::spawn(move |cancel| async move {
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(ProtoError::new(ErrorCode::Cancelled, "connect cancelled")),
            r = conn::Connection::connect(&opts) => r,
        }
    })
    .map_err(|e| to_pyerr(py, e))?;
    let inner = drive(py, pending)?;
    Ok(Connection {
        inner: Arc::new(inner),
    })
}

/// `[(error code, exception class name)]`, for the Python side to check its table against.
#[pyfunction]
fn error_codes() -> Vec<(&'static str, &'static str)> {
    conn::ALL_CODES
        .iter()
        .map(|c| (c.as_str(), conn::exception_name(*c)))
        .collect()
}

/// An in-process connection over the fixture at `fixture` (feature `testing`).
#[cfg(feature = "testing")]
#[pyfunction]
fn fake_connection(py: Python<'_>, fixture: PathBuf) -> PyResult<Connection> {
    let inner = crate::testing::fake_connection(&fixture).map_err(|e| to_pyerr(py, e))?;
    Ok(Connection {
        inner: Arc::new(inner),
    })
}

/// True when built with the hidden test hook.
#[pyfunction]
fn has_testing() -> bool {
    cfg!(feature = "testing")
}

#[pymodule(name = "_native")]
mod native {
    #[pymodule_export]
    use super::{Connection, Handle, connect, error_codes, has_testing};

    #[cfg(feature = "testing")]
    #[pymodule_export]
    use super::fake_connection;

    #[pymodule_init]
    fn init(m: &pyo3::Bound<'_, pyo3::types::PyModule>) -> pyo3::PyResult<()> {
        use pyo3::types::PyModuleMethods;
        m.add("BUILD", crate::conn::BUILD)
    }
}
