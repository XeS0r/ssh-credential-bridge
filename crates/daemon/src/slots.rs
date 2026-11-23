//! Connection budgets per server on `agent-forward.sock`.
//!
//! Every agent channel a server opens makes the local ssh client connect to the forward
//! socket. Without a budget per server, one server could hold all connection slots of
//! the socket and block agent forwarding, tokens and gpg for every other session. A
//! connection counts against the host key of its server bind (a verified forwarding
//! bind that is the connection's first message), or against "no bind" if it has none.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// At most this many connections per host key (and per "no bind") at once.
pub const MAX_PER_SERVER: usize = 64;

/// Counts open forward connections per key.
#[derive(Debug, Default)]
pub struct ServerSlots {
    /// Open connections per key (a host key fingerprint, or "" for no bind yet).
    counts: Mutex<HashMap<String, usize>>,
}

/// One counted connection; dropping it gives the slot back.
#[derive(Debug)]
pub struct ServerSlot {
    /// The budget it was taken from.
    slots: Arc<ServerSlots>,
    /// The key it counts against.
    key: String,
}

impl ServerSlots {
    /// Takes a slot for `key`, or `None` if `key` already has [`MAX_PER_SERVER`].
    pub fn acquire(self: &Arc<Self>, key: &str) -> Option<ServerSlot> {
        let mut counts = crate::sync::lock(&self.counts);
        let count = counts.entry(key.to_owned()).or_insert(0);
        if *count >= MAX_PER_SERVER {
            return None;
        }
        *count += 1;
        Some(ServerSlot { slots: Arc::clone(self), key: key.to_owned() })
    }

    /// Open connections counted against `key`.
    pub fn count(&self, key: &str) -> usize {
        let counts = crate::sync::lock(&self.counts);
        counts.get(key).copied().unwrap_or(0)
    }
}

impl ServerSlot {
    /// Moves this connection to `key`: takes a slot there first and gives the old one
    /// back only if that worked. Returns `false` (keeping the old slot) if `key` has no
    /// room.
    pub fn move_to(&mut self, key: &str) -> bool {
        if self.key == key {
            return true;
        }
        let Some(new) = self.slots.acquire(key) else { return false };
        *self = new;
        true
    }
}

impl Drop for ServerSlot {
    fn drop(&mut self) {
        let mut counts = crate::sync::lock(&self.slots.counts);
        if let Some(count) = counts.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_per_key() {
        let slots = Arc::new(ServerSlots::default());
        let held: Vec<_> = (0..MAX_PER_SERVER).map(|_| slots.acquire("a").unwrap()).collect();
        assert!(slots.acquire("a").is_none(), "the budget of a is used up");
        let mut other = slots.acquire("").unwrap();
        assert!(!other.move_to("a"));
        assert_eq!((slots.count(""), slots.count("a")), (1, MAX_PER_SERVER));
        assert!(other.move_to("b"));
        assert_eq!((slots.count(""), slots.count("b")), (0, 1));
        drop(held);
        assert_eq!(slots.count("a"), 0);
        assert!(slots.acquire("a").is_some());
        drop(other);
        assert_eq!(slots.count("b"), 0);
    }
}
