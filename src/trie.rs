use std::collections::HashMap;

#[derive(Debug, Clone)]
struct DomainTrieNode<V> {
    children: HashMap<Box<str>, DomainTrieNode<V>>,
    value: Option<V>,
}

impl<T> Default for DomainTrieNode<T> {
    fn default() -> Self {
        DomainTrieNode {
            children: HashMap::new(),
            value: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DomainTrie<V> {
    root: DomainTrieNode<V>,
}

impl<V> DomainTrie<V> {
    pub fn new() -> Self {
        Self {
            root: DomainTrieNode::default(),
        }
    }

    pub fn insert(&mut self, domain: &str, value: V) {
        let labels = domain.split('.').rev();
        let mut node = &mut self.root;

        for label in labels {
            node = node.children.entry(Box::from(label)).or_default();
        }
        node.value = Some(value);
    }

    pub fn get(&self, domain: &str) -> Option<&V> {
        let mut node = &self.root;
        let mut last_match = None;

        for label in domain.split('.').rev() {
            match node.children.get(label) {
                Some(next_node) => {
                    node = next_node;
                    if node.value.is_some() {
                        last_match = node.value.as_ref();
                    }
                }
                None => break,
            }
        }
        last_match
    }
}
