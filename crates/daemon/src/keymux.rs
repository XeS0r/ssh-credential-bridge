//! The key mux: merges upstream identity lists and routes sign requests.

use credential_bridge_proto::agent::Identity;

/// Which upstream listed a key; index into the configuration's upstream list.
pub type UpstreamIndex = usize;

/// The merged identity list of one connection, rebuilt on every
/// `SSH_AGENTC_REQUEST_IDENTITIES`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyMap {
    /// Identities in answer order with their upstream.
    entries: Vec<(Identity, UpstreamIndex)>,
}

impl KeyMap {
    /// Merges per-upstream lists in upstream order, keeping only upstreams for which
    /// `visible` is true. A key listed by several upstreams appears once and routes to
    /// the first.
    pub fn merge(
        mut lists: Vec<(UpstreamIndex, Vec<Identity>)>,
        visible: impl Fn(UpstreamIndex) -> bool,
    ) -> KeyMap {
        lists.sort_by_key(|(index, _)| *index);
        let mut entries: Vec<(Identity, UpstreamIndex)> = Vec::new();
        for (index, identities) in lists {
            if !visible(index) {
                continue;
            }
            for identity in identities {
                if !entries.iter().any(|(known, _)| known.key_blob == identity.key_blob) {
                    entries.push((identity, index));
                }
            }
        }
        KeyMap { entries }
    }

    /// The identities to answer with.
    pub fn identities(&self) -> Vec<Identity> {
        self.entries.iter().map(|(identity, _)| identity.clone()).collect()
    }

    /// The identities with their upstreams, in answer order.
    pub fn entries(&self) -> &[(Identity, UpstreamIndex)] {
        &self.entries
    }

    /// The upstream that listed `key_blob`, or `None` (the request then fails: a key not
    /// in the last answer is never signed with).
    pub fn route(&self, key_blob: &[u8]) -> Option<UpstreamIndex> {
        self.entries.iter().find(|(identity, _)| identity.key_blob == key_blob).map(|(_, index)| *index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(blob: u8, comment: &str) -> Identity {
        Identity { key_blob: vec![blob], comment: comment.as_bytes().to_vec() }
    }

    #[test]
    fn merges_in_upstream_order_and_deduplicates() {
        let lists = vec![(1, vec![id(3, "c"), id(1, "dup")]), (0, vec![id(1, "a"), id(2, "b")])];
        let map = KeyMap::merge(lists, |_| true);
        assert_eq!(map.identities(), vec![id(1, "a"), id(2, "b"), id(3, "c")]);
        assert_eq!(map.route(&[1]), Some(0));
        assert_eq!(map.route(&[3]), Some(1));
        assert_eq!(map.route(&[9]), None);
    }

    #[test]
    fn hidden_upstreams_are_left_out() {
        let lists = vec![(0, vec![id(1, "a")]), (1, vec![id(1, "a"), id(2, "b")])];
        let map = KeyMap::merge(lists, |index| index == 1);
        assert_eq!(map.identities(), vec![id(1, "a"), id(2, "b")]);
        assert_eq!(map.route(&[1]), Some(1), "routes to the visible upstream");
        let none = KeyMap::merge(vec![(0, vec![id(1, "a")])], |_| false);
        assert!(none.identities().is_empty());
        assert_eq!(none.route(&[1]), None);
    }
}
