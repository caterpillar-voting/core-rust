use std::ops;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::foundation::group::Group;

#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<G: Group> {
    pub inner: G::Scalar,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey<G: Group> {
    pub inner: G::Point,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ciphertext<G: Group> {
    pub alpha: G::Point,
    pub beta: G::Point,
    // TODO: include ZKP for CCA2
}


#[derive(Clone, Debug, PartialEq)]
pub struct HomomorphicCiphertext<G: Group> {
    pub alpha: G::Point,
    pub beta: G::Point,
    // TODO: include ZKP for CCA2
}

impl<G: Group> ops::Add<&HomomorphicCiphertext<G>> for &HomomorphicCiphertext<G> {
    type Output = HomomorphicCiphertext<G>;
    fn add(self, rhs: &HomomorphicCiphertext<G>) -> Self::Output {
        HomomorphicCiphertext {
            alpha: self.alpha + &rhs.alpha,
            beta: self.beta + &rhs.beta,
        }
    }
}

impl<G: Group> ops::Sub<&HomomorphicCiphertext<G>> for &HomomorphicCiphertext<G> {
    type Output = HomomorphicCiphertext<G>;

    fn sub(self, rhs: &HomomorphicCiphertext<G>) -> Self::Output {
        HomomorphicCiphertext {
            alpha: self.alpha - &rhs.alpha,
            beta: self.beta - &rhs.beta,
        }
    }
}