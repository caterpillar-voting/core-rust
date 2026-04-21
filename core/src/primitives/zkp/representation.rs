use crate::foundation::group::Group;
use crate::primitives::zkp::proof::Knowledge;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKnowledge<G: Group>(pub Knowledge<G>);
