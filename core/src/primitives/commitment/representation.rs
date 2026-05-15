use crate::foundation::group::Group;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[allow(type_alias_bounds)]
pub type Commit<G: Group> = G::Point;

#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretOpening<G: Group>(pub G::Scalar);
