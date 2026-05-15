use crate::foundation::group::Group;
use crate::primitives::zkp::proof::ProofResponse;
use std::ops;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey<G: Group>(pub G::Scalar);

#[allow(type_alias_bounds)]
pub type PublicKey<G: Group> = G::Point;

#[allow(type_alias_bounds)]
pub type Ciphertext<G: Group> = ((G::Point, G::Point), G::Point, ProofResponse<G>);
