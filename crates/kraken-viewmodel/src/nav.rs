//! Back/forward navigation history over function addresses.

/// A browser-style history of visited addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NavHistory {
    entries: Vec<u64>,
    pos: usize,
}

const MAX_ENTRIES: usize = 200;

impl NavHistory {
    /// An empty history.
    pub fn new() -> Self {
        Self::default()
    }

    /// The address currently shown.
    pub fn current(&self) -> Option<u64> {
        self.entries.get(self.pos).copied()
    }

    /// Visits `addr`, dropping any forward entries. Re-visiting the current address is a no-op.
    pub fn visit(&mut self, addr: u64) {
        if self.current() == Some(addr) {
            return;
        }
        if !self.entries.is_empty() {
            self.entries.truncate(self.pos + 1);
        }
        self.entries.push(addr);
        if self.entries.len() > MAX_ENTRIES {
            self.entries.remove(0);
        }
        self.pos = self.entries.len() - 1;
    }

    /// True when there is an earlier entry.
    pub fn can_back(&self) -> bool {
        self.pos > 0
    }

    /// True when there is a later entry.
    pub fn can_forward(&self) -> bool {
        self.pos + 1 < self.entries.len()
    }

    /// Steps back and returns the new current address.
    pub fn back(&mut self) -> Option<u64> {
        if self.can_back() {
            self.pos -= 1;
            self.current()
        } else {
            None
        }
    }

    /// Steps forward and returns the new current address.
    pub fn forward(&mut self) -> Option<u64> {
        if self.can_forward() {
            self.pos += 1;
            self.current()
        } else {
            None
        }
    }

    /// Forgets everything (a new project was opened).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.pos = 0;
    }

    /// All entries oldest first, and the index of the current one.
    pub fn entries(&self) -> (&[u64], usize) {
        (&self.entries, self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn back_forward_and_truncation() {
        let mut h = NavHistory::new();
        assert_eq!(h.current(), None);
        assert!(!h.can_back() && !h.can_forward());
        h.visit(1);
        h.visit(2);
        h.visit(3);
        assert_eq!(h.back(), Some(2));
        assert_eq!(h.back(), Some(1));
        assert_eq!(h.back(), None);
        assert_eq!(h.forward(), Some(2));
        h.visit(9);
        assert!(!h.can_forward());
        assert_eq!(h.entries(), (&[1, 2, 9][..], 2));
    }

    #[test]
    fn revisiting_current_is_noop() {
        let mut h = NavHistory::new();
        h.visit(5);
        h.visit(5);
        assert_eq!(h.entries().0, &[5]);
    }

    #[test]
    fn history_is_capped() {
        let mut h = NavHistory::new();
        for i in 0..(MAX_ENTRIES as u64 + 20) {
            h.visit(i);
        }
        assert_eq!(h.entries().0.len(), MAX_ENTRIES);
        assert_eq!(h.current(), Some(MAX_ENTRIES as u64 + 19));
    }
}
