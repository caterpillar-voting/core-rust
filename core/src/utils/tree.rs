use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
pub enum BooleanTree<T> {
    Leaf(T),
    And(Vec<BooleanTree<T>>),
    Or(Vec<BooleanTree<T>>),
}

pub struct BooleanTreeLeafValuesIter<'a, T> {
    stack: Vec<&'a BooleanTree<T>>,
}

impl<'a, T> BooleanTreeLeafValuesIter<'a, T> {
    pub fn new(tree: &'a BooleanTree<T>) -> Self {
        Self { stack: vec![tree] }
    }
}

impl<'a, T> Iterator for BooleanTreeLeafValuesIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            match node {
                BooleanTree::Leaf(value) => return Some(value),
                BooleanTree::And(children) | BooleanTree::Or(children) => {
                    for child in children.iter().rev() {
                        self.stack.push(child);
                    }
                }
            }
        }

        None
    }
}

impl<'a, T> IntoIterator for &'a BooleanTree<T> {
    type Item = &'a T;
    type IntoIter = BooleanTreeLeafValuesIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        BooleanTreeLeafValuesIter::new(self)
    }
}
