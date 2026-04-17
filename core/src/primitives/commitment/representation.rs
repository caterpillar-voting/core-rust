use std::ops;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::foundation::group::Group;

#[derive(Debug, PartialEq, Eq)]
pub struct Commitment<G: Group> {
    pub inner: G::Point,
}
#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Opening<G: Group> {
    pub inner: G::Scalar,
}

impl<G: Group> ops::Add<&Commitment<G>> for &Commitment<G> {
    type Output = Commitment<G>;
    fn add(self, rhs: &Commitment<G>) -> Self::Output {
        Commitment {
            inner: self.inner + &rhs.inner,
        }
    }
}

impl<G: Group> ops::Sub<&Commitment<G>> for &Commitment<G> {
    type Output = Commitment<G>;

    fn sub(self, rhs: &Commitment<G>) -> Self::Output {
        Commitment {
            inner: self.inner - &rhs.inner,
        }
    }
}

impl<G: Group> ops::Add<&Opening<G>> for &Opening<G> {
    type Output = Opening<G>;
    fn add(self, rhs: &Opening<G>) -> Self::Output {
        Opening {
            inner: self.inner + &rhs.inner,
        }
    }
}

impl<G: Group> ops::Sub<&Opening<G>> for &Opening<G> {
    type Output = Opening<G>;
    fn sub(self, rhs: &Opening<G>) -> Self::Output {
        Opening {
            inner: self.inner - &rhs.inner,
        }
    }
}