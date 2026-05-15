use crate::foundation::group::Group;
use std::ops;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::primitives::zkp::proof::ProofResponse;

#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<G: Group>(pub G::Scalar);

#[allow(type_alias_bounds)]
pub type PublicKey<G: Group> = G::Point;

#[allow(type_alias_bounds)]
pub type Ciphertext<G: Group> = ((G::Point, G::Point), G::Point, ProofResponse<G>);

#[derive(Clone, Debug, PartialEq)]
pub struct HomomorphicCiphertext<G: Group>(pub G::Point, pub G::Point);
// TODO: include ZKP for CCA2
// TODO: what ZKP to include for reencryption?

impl<G: Group> ops::Add<&HomomorphicCiphertext<G>> for &HomomorphicCiphertext<G> {
    type Output = HomomorphicCiphertext<G>;
    fn add(self, rhs: &HomomorphicCiphertext<G>) -> Self::Output {
        HomomorphicCiphertext(self.0 + &rhs.0, self.1 + &rhs.1)
    }
}

impl<G: Group> ops::Mul<&G::Scalar> for &HomomorphicCiphertext<G> {
    type Output = HomomorphicCiphertext<G>;
    fn mul(self, rhs: &G::Scalar) -> Self::Output {
        HomomorphicCiphertext(self.0 * rhs, self.1 * rhs)
    }
}

impl<G: Group> ops::Sub<&HomomorphicCiphertext<G>> for &HomomorphicCiphertext<G> {
    type Output = HomomorphicCiphertext<G>;

    fn sub(self, rhs: &HomomorphicCiphertext<G>) -> Self::Output {
        HomomorphicCiphertext(self.0 - &rhs.0, self.1 - &rhs.1)
    }
}
