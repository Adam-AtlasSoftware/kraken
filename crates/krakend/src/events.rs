//! The change event stream (decision 34).
//!
//! Every event is a JSON object `{seq, project_dir, kind, ...}` with a daemon-wide, strictly
//! increasing `seq`. Connected clients receive each event as an `event` notification; the last
//! few hundred are also kept so a client that missed some (or just connected) can catch up with
//! the `events` method and its cursor.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Map, Value};
use tokio::sync::broadcast;

/// Events kept for catch-up.
pub const RING_CAPACITY: usize = 1024;

struct Inner {
    ring: Mutex<Ring>,
    tx: broadcast::Sender<Value>,
}

struct Ring {
    last_seq: u64,
    events: VecDeque<Value>,
}

/// Assigns sequence numbers, remembers recent events and fans them out. Cheap to clone.
#[derive(Clone)]
pub struct EventHub {
    inner: Arc<Inner>,
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHub {
    /// An empty hub.
    pub fn new() -> Self {
        EventHub {
            inner: Arc::new(Inner {
                ring: Mutex::new(Ring {
                    last_seq: 0,
                    events: VecDeque::new(),
                }),
                tx: broadcast::channel(4096).0,
            }),
        }
    }

    /// Publishes an event. `fields` (an object; anything else is ignored) is merged under the
    /// fixed `seq`, `project_dir` and `kind`. Returns the assigned sequence number.
    pub fn publish(&self, project_dir: &Path, kind: &str, fields: Value) -> u64 {
        let mut ring = self
            .inner
            .ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        ring.last_seq += 1;
        let seq = ring.last_seq;
        let mut obj = match fields {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        obj.insert("seq".into(), seq.into());
        obj.insert(
            "project_dir".into(),
            project_dir.to_string_lossy().into_owned().into(),
        );
        obj.insert("kind".into(), kind.into());
        let event = Value::Object(obj);
        ring.events.push_back(event.clone());
        while ring.events.len() > RING_CAPACITY {
            ring.events.pop_front();
        }
        // Sending under the lock keeps the broadcast order equal to the sequence order.
        let _ = self.inner.tx.send(event);
        seq
    }

    /// Events with `seq > after`, oldest first, at most `limit`; and the newest sequence number.
    pub fn since(&self, after: u64, limit: usize) -> (Vec<Value>, u64) {
        let ring = self
            .inner
            .ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let events = ring
            .events
            .iter()
            .filter(|e| e["seq"].as_u64().is_some_and(|s| s > after))
            .take(limit)
            .cloned()
            .collect();
        (events, ring.last_seq)
    }

    /// The newest sequence number (0 when nothing happened yet).
    pub fn last_seq(&self) -> u64 {
        self.inner
            .ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last_seq
    }

    /// A receiver of every event published from now on.
    pub fn subscribe(&self) -> broadcast::Receiver<Value> {
        self.inner.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sequence_numbers_increase_and_catch_up_works() {
        let hub = EventHub::new();
        let p = Path::new("/p");
        assert_eq!(hub.publish(p, "a", json!({"x": 1})), 1);
        assert_eq!(hub.publish(p, "b", json!(null)), 2);
        assert_eq!(
            hub.publish(p, "c", json!({"seq": 99, "kind": "spoofed"})),
            3
        );
        let (all, last) = hub.since(0, 10);
        assert_eq!(last, 3);
        assert_eq!(all.len(), 3);
        assert_eq!(
            all[0],
            json!({"seq": 1, "project_dir": "/p", "kind": "a", "x": 1})
        );
        assert_eq!(all[2]["seq"], 3, "fixed fields cannot be overridden");
        assert_eq!(all[2]["kind"], "c");
        let (rest, _) = hub.since(2, 10);
        assert_eq!(rest.len(), 1);
        assert_eq!(hub.since(0, 2).0.len(), 2);
    }

    #[test]
    fn the_ring_is_bounded() {
        let hub = EventHub::new();
        for _ in 0..(RING_CAPACITY + 10) {
            hub.publish(Path::new("/p"), "k", json!({}));
        }
        let (events, last) = hub.since(0, usize::MAX);
        assert_eq!(events.len(), RING_CAPACITY);
        assert_eq!(last, (RING_CAPACITY + 10) as u64);
        assert_eq!(events[0]["seq"], 11);
    }

    #[tokio::test]
    async fn subscribers_see_events_in_order() {
        let hub = EventHub::new();
        let mut rx = hub.subscribe();
        hub.publish(Path::new("/p"), "one", json!({}));
        hub.publish(Path::new("/p"), "two", json!({}));
        assert_eq!(rx.recv().await.unwrap()["kind"], "one");
        assert_eq!(rx.recv().await.unwrap()["kind"], "two");
    }
}
