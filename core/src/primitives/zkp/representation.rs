use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::foundation::group::Group;
use crate::primitives::zkp::proof::Knowledge;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKnowledge<G: Group>(pub Knowledge<G>);
