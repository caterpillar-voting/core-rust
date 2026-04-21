use crate::foundation::group::Group;
use std::ops;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, PartialEq, Eq)]
pub struct HomomorphicCommitment<G: Group>(pub G::Point);

#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HomomorphicOpening<G: Group>(pub G::Scalar);

impl<G: Group> ops::Add<&HomomorphicCommitment<G>> for &HomomorphicCommitment<G> {
    type Output = HomomorphicCommitment<G>;
    fn add(self, rhs: &HomomorphicCommitment<G>) -> Self::Output {
        HomomorphicCommitment(self.0 + &rhs.0)
    }
}

impl<G: Group> ops::Sub<&HomomorphicCommitment<G>> for &HomomorphicCommitment<G> {
    type Output = HomomorphicCommitment<G>;

    fn sub(self, rhs: &HomomorphicCommitment<G>) -> Self::Output {
        HomomorphicCommitment(self.0 - &rhs.0)
    }
}

impl<G: Group> ops::Add<&HomomorphicOpening<G>> for &HomomorphicOpening<G> {
    type Output = HomomorphicOpening<G>;
    fn add(self, rhs: &HomomorphicOpening<G>) -> Self::Output {
        HomomorphicOpening(self.0 + &rhs.0)
    }
}

impl<G: Group> ops::Sub<&HomomorphicOpening<G>> for &HomomorphicOpening<G> {
    type Output = HomomorphicOpening<G>;
    fn sub(self, rhs: &HomomorphicOpening<G>) -> Self::Output {
        HomomorphicOpening(self.0 - &rhs.0)
    }
}
