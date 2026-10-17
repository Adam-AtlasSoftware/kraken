//! Approvals that wait for a person.
//!
//! An agent-class connection cannot approve anything: its `approved` claim is ignored. What needs
//! approval (opening a project on an agent's behalf, a dangerous command, writing outside the
//! project) waits here instead. The request is published as an `approval_requested` event, which
//! the GUI shows as a dialog and the CLI lists (`kraken daemon approvals`), and a user-class
//! connection answers with `approval_decide`. No answer in time is a denial.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kraken_host::daemon::event_kind;
use kraken_proto::sanitize_capped;
use kraken_registry::{ApprovalDecision, ApprovalRequest, ApprovalRequester};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::oneshot;

use crate::events::EventHub;

/// How long a person has to answer.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

/// Approvals waiting at once; more are denied at once, so an agent cannot bury the person's
/// screen in questions.
pub const MAX_PENDING: usize = 16;

/// One approval waiting for an answer.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PendingApproval {
    /// Id to answer with.
    pub id: u64,
    /// Command asking.
    pub command: String,
    /// What it wants to do, in one line.
    pub summary: String,
    /// The arguments, as shown to the person.
    pub args: Value,
    /// The agent asking.
    pub author_id: String,
    /// The project directory the request came with.
    pub project_dir: String,
}

struct Waiting {
    view: PendingApproval,
    tx: oneshot::Sender<bool>,
}

struct Inner {
    next: AtomicU64,
    pending: Mutex<HashMap<u64, Waiting>>,
    timeout: Mutex<Duration>,
    hub: EventHub,
}

/// The daemon's list of approvals waiting for a person. Cheap to clone.
#[derive(Clone)]
pub struct ApprovalBoard {
    inner: Arc<Inner>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn trim(s: &str, max: usize) -> String {
    sanitize_capped(s, max)
}

impl ApprovalBoard {
    /// An empty board publishing its events on `hub`.
    pub fn new(hub: EventHub) -> Self {
        ApprovalBoard {
            inner: Arc::new(Inner {
                next: AtomicU64::new(1),
                pending: Mutex::new(HashMap::new()),
                timeout: Mutex::new(DEFAULT_APPROVAL_TIMEOUT),
                hub,
            }),
        }
    }

    /// Changes how long a person has to answer (tests shorten it).
    pub fn set_timeout(&self, timeout: Duration) {
        *lock(&self.inner.timeout) = timeout;
    }

    /// The approvals waiting, oldest first.
    pub fn pending(&self) -> Vec<PendingApproval> {
        let mut all: Vec<_> = lock(&self.inner.pending)
            .values()
            .map(|w| w.view.clone())
            .collect();
        all.sort_by_key(|v| v.id);
        all
    }

    /// Answers approval `id`; false when it is not waiting any more.
    pub fn decide(&self, id: u64, allow: bool) -> bool {
        let waiting = lock(&self.inner.pending).remove(&id);
        match waiting {
            Some(w) => w.tx.send(allow).is_ok(),
            None => false,
        }
    }

    /// Asks for approval and waits for the answer: denied when nobody answers in time, when the
    /// board is full, or when the asking call goes away.
    pub async fn ask(
        &self,
        project_dir: &Path,
        author_id: &str,
        req: ApprovalRequest,
    ) -> ApprovalDecision {
        let (tx, rx) = oneshot::channel();
        let id = self.inner.next.fetch_add(1, Ordering::Relaxed);
        let view = PendingApproval {
            id,
            command: trim(&req.command, 64),
            summary: trim(&req.summary, 1024),
            args: kraken_proto::sanitize_value(req.args),
            author_id: trim(author_id, 64),
            project_dir: trim(&project_dir.display().to_string(), 512),
        };
        {
            let mut pending = lock(&self.inner.pending);
            if pending.len() >= MAX_PENDING {
                return ApprovalDecision::Deny {
                    reason: format!(
                        "{MAX_PENDING} approvals are already waiting for a person; answer or \
                         wait for them first"
                    ),
                };
            }
            pending.insert(
                id,
                Waiting {
                    view: view.clone(),
                    tx,
                },
            );
        }
        self.inner.hub.publish(
            project_dir,
            event_kind::APPROVAL_REQUESTED,
            json!({
                "approval_id": id,
                "command": view.command,
                "summary": view.summary,
                "args": view.args,
                "author_id": view.author_id,
            }),
        );
        // If the asking call is dropped (the agent hung up), take the question off the board.
        let mut guard = Cleanup {
            board: self.clone(),
            id,
            dir: project_dir.to_path_buf(),
            outcome: "abandoned",
        };
        let timeout = *lock(&self.inner.timeout);
        let decision = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(true)) => {
                guard.outcome = "allowed";
                ApprovalDecision::Allow
            }
            Ok(Ok(false)) => {
                guard.outcome = "denied";
                ApprovalDecision::Deny {
                    reason: format!("the user did not approve `{}`", view.command),
                }
            }
            Ok(Err(_)) => ApprovalDecision::Deny {
                reason: "the approval was withdrawn".into(),
            },
            Err(_) => {
                guard.outcome = "timed_out";
                ApprovalDecision::Deny {
                    reason: format!(
                        "nobody approved `{}` in {} seconds. Approve it from the KRAKEN window or \
                         with `kraken daemon approvals`, or open the project from the GUI or CLI \
                         first",
                        view.command,
                        timeout.as_secs()
                    ),
                }
            }
        };
        drop(guard);
        decision
    }
}

struct Cleanup {
    board: ApprovalBoard,
    id: u64,
    dir: PathBuf,
    outcome: &'static str,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        lock(&self.board.inner.pending).remove(&self.id);
        self.board.inner.hub.publish(
            &self.dir,
            event_kind::APPROVAL_RESOLVED,
            json!({"approval_id": self.id, "outcome": self.outcome}),
        );
    }
}

/// The approval requester of an agent-class call: puts the question on the [`ApprovalBoard`].
pub struct BoardApprover {
    board: ApprovalBoard,
    project_dir: PathBuf,
    author_id: String,
}

impl BoardApprover {
    /// An approver for calls of `author_id` on `project_dir`.
    pub fn new(board: ApprovalBoard, project_dir: PathBuf, author_id: String) -> Self {
        BoardApprover {
            board,
            project_dir,
            author_id,
        }
    }
}

#[async_trait]
impl ApprovalRequester for BoardApprover {
    async fn request(&self, req: ApprovalRequest) -> ApprovalDecision {
        self.board
            .ask(&self.project_dir, &self.author_id, req)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_model::Author;
    use kraken_registry::Surface;

    fn req(command: &str) -> ApprovalRequest {
        ApprovalRequest {
            command: command.into(),
            summary: "open \u{E0041}the\u{200B} thing".into(),
            args: json!({"p": "x\u{202E}y"}),
            author: Author::agent("bot"),
            surface: Surface::Mcp,
        }
    }

    #[tokio::test]
    async fn a_person_answers_through_decide() {
        let hub = EventHub::new();
        let board = ApprovalBoard::new(hub.clone());
        let asker = {
            let board = board.clone();
            tokio::spawn(
                async move { board.ask(Path::new("/p"), "bot", req("project_open")).await },
            )
        };
        let mut waiting = Vec::new();
        for _ in 0..200 {
            waiting = board.pending();
            if !waiting.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(waiting.len(), 1);
        let w = &waiting[0];
        assert_eq!(w.command, "project_open");
        assert_eq!(w.summary, "open the thing", "shown text is sanitised");
        assert_eq!(w.args, json!({"p": "xy"}));
        let (events, _) = hub.since(0, 10);
        assert_eq!(events[0]["kind"], "approval_requested");
        assert_eq!(events[0]["approval_id"], w.id);
        assert!(board.decide(w.id, true));
        assert_eq!(asker.await.unwrap(), ApprovalDecision::Allow);
        assert!(board.pending().is_empty());
        assert!(!board.decide(w.id, true), "answered once");
        let (events, _) = hub.since(0, 10);
        assert_eq!(events[1]["kind"], "approval_resolved");
        assert_eq!(events[1]["outcome"], "allowed");
    }

    #[tokio::test]
    async fn no_answer_is_a_denial() {
        let board = ApprovalBoard::new(EventHub::new());
        board.set_timeout(Duration::from_millis(30));
        let d = board.ask(Path::new("/p"), "bot", req("project_open")).await;
        assert!(
            matches!(d, ApprovalDecision::Deny { reason } if reason.contains("nobody approved"))
        );
        assert!(board.pending().is_empty());
    }

    #[tokio::test]
    async fn a_dropped_question_leaves_the_board() {
        let board = ApprovalBoard::new(EventHub::new());
        let b2 = board.clone();
        let asker =
            tokio::spawn(async move { b2.ask(Path::new("/p"), "bot", req("project_open")).await });
        for _ in 0..200 {
            if !board.pending().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(board.pending().len(), 1);
        asker.abort();
        let _ = asker.await;
        assert!(board.pending().is_empty());
    }

    #[tokio::test]
    async fn the_board_is_bounded() {
        let board = ApprovalBoard::new(EventHub::new());
        board.set_timeout(Duration::from_secs(30));
        let mut askers = Vec::new();
        for _ in 0..MAX_PENDING {
            let b = board.clone();
            askers.push(tokio::spawn(async move {
                b.ask(Path::new("/p"), "bot", req("project_open")).await
            }));
        }
        for _ in 0..200 {
            if board.pending().len() == MAX_PENDING {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let d = board.ask(Path::new("/p"), "bot", req("project_open")).await;
        assert!(
            matches!(d, ApprovalDecision::Deny { reason } if reason.contains("already waiting"))
        );
        for a in askers {
            a.abort();
        }
    }
}
