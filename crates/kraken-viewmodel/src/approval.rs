//! Hands dangerous-command approvals from a backend task to the UI thread and back.

use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use tokio::sync::oneshot;

use crate::backend::{ApprovalPrompt, Approver};

struct Pending {
    id: u64,
    prompt: ApprovalPrompt,
    tx: oneshot::Sender<bool>,
}

#[derive(Default)]
struct State {
    next: u64,
    queue: Vec<Pending>,
}

type Repaint = Arc<dyn Fn() + Send + Sync>;

/// An [`Approver`] whose questions are answered by the UI: the window shows
/// [`ApprovalBroker::current`] as a dialog and calls [`ApprovalBroker::respond`].
#[derive(Clone, Default)]
pub struct ApprovalBroker {
    state: Arc<Mutex<State>>,
    repaint: Arc<Mutex<Option<Repaint>>>,
}

impl ApprovalBroker {
    /// A broker with no question waiting.
    pub fn new() -> Self {
        Self::default()
    }

    /// Called whenever a question arrives so the window can repaint.
    pub fn set_repaint(&self, f: Repaint) {
        *self.repaint.lock().unwrap_or_else(PoisonError::into_inner) = Some(f);
    }

    /// The oldest unanswered question, with its id.
    pub fn current(&self) -> Option<(u64, ApprovalPrompt)> {
        let s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        s.queue.first().map(|p| (p.id, p.prompt.clone()))
    }

    /// Answers question `id`. An unknown id is ignored.
    pub fn respond(&self, id: u64, allow: bool) {
        let pending = {
            let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            s.queue
                .iter()
                .position(|p| p.id == id)
                .map(|i| s.queue.remove(i))
        };
        if let Some(p) = pending {
            let _ = p.tx.send(allow);
        }
    }
}

#[async_trait]
impl Approver for ApprovalBroker {
    async fn approve(&self, prompt: ApprovalPrompt) -> bool {
        let (tx, rx) = oneshot::channel();
        {
            let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            s.next += 1;
            let id = s.next;
            s.queue.push(Pending { id, prompt, tx });
        }
        let f = self
            .repaint
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(f) = f {
            f();
        }
        rx.await.unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn a_question_waits_for_the_ui_answer() {
        let broker = ApprovalBroker::new();
        let b2 = broker.clone();
        let task = tokio::spawn(async move {
            b2.approve(ApprovalPrompt {
                command: "wipe".into(),
                summary: "Wipe".into(),
                args: json!({}),
            })
            .await
        });
        let id = loop {
            if let Some((id, p)) = broker.current() {
                assert_eq!(p.command, "wipe");
                break id;
            }
            tokio::task::yield_now().await;
        };
        broker.respond(id, true);
        assert!(task.await.unwrap());
        assert!(broker.current().is_none());
    }
}
