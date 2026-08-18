use crate::foundation::group::Group;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<G: Group>(pub G::Scalar);

#[allow(type_alias_bounds)]
pub type PublicKey<G: Group> = G::Point;

#[allow(type_alias_bounds)]
pub type Context = Vec<u8>;

#[allow(type_alias_bounds)]
pub type Ciphertext<G: Group> = ((G::Point, G::Point), (G::Point, G::Scalar, G::Scalar));
