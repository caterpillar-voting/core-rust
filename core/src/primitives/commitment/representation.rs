use crate::foundation::group::Group;
use std::ops;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, PartialEq, Eq)]
pub struct Commitment<G: Group>(pub G::Point);

#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Opening<G: Group>(pub G::Scalar);

impl<G: Group> ops::Add<&Commitment<G>> for &Commitment<G> {
    type Output = Commitment<G>;
    fn add(self, rhs: &Commitment<G>) -> Self::Output {
        Commitment(self.0 + &rhs.0)
    }
}

impl<G: Group> ops::Sub<&Commitment<G>> for &Commitment<G> {
    type Output = Commitment<G>;

    fn sub(self, rhs: &Commitment<G>) -> Self::Output {
        Commitment(self.0 - &rhs.0)
    }
}

impl<G: Group> ops::Add<&Opening<G>> for &Opening<G> {
    type Output = Opening<G>;
    fn add(self, rhs: &Opening<G>) -> Self::Output {
        Opening(self.0 + &rhs.0)
    }
}

impl<G: Group> ops::Sub<&Opening<G>> for &Opening<G> {
    type Output = Opening<G>;
    fn sub(self, rhs: &Opening<G>) -> Self::Output {
        Opening(self.0 - &rhs.0)
    }
}
