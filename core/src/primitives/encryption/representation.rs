use crate::foundation::group::Group;
use std::ops;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<G: Group>(pub G::Scalar);

#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey<G: Group>(pub G::Point);

#[derive(Clone, Debug, PartialEq)]
pub struct Ciphertext<G: Group>(pub G::Point, pub G::Point);
// TODO: include ZKP for CCA2

#[derive(Clone, Debug, PartialEq)]
pub struct HomomorphicCiphertext<G: Group>(pub G::Point, pub G::Point);
// TODO: include ZKP for CCA2

impl<G: Group> ops::Add<&HomomorphicCiphertext<G>> for &HomomorphicCiphertext<G> {
    type Output = HomomorphicCiphertext<G>;
    fn add(self, rhs: &HomomorphicCiphertext<G>) -> Self::Output {
        HomomorphicCiphertext {
            0: self.0 + &rhs.0,
            1: self.1 + &rhs.1,
        }
    }
}

impl<G: Group> ops::Mul<&G::Scalar> for &HomomorphicCiphertext<G> {
    type Output = HomomorphicCiphertext<G>;
    fn mul(self, rhs: &G::Scalar) -> Self::Output {
        HomomorphicCiphertext {
            0: self.0 * &rhs,
            1: self.1 * &rhs,
        }
    }
}

impl<G: Group> ops::Sub<&HomomorphicCiphertext<G>> for &HomomorphicCiphertext<G> {
    type Output = HomomorphicCiphertext<G>;

    fn sub(self, rhs: &HomomorphicCiphertext<G>) -> Self::Output {
        HomomorphicCiphertext {
            0: self.0 - &rhs.0,
            1: self.1 - &rhs.1,
        }
    }
}
