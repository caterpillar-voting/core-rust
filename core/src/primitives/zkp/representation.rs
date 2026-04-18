use crate::foundation::group::Group;

pub struct Commitment<G: Group>(pub Box<[Commitment<G>]>, pub Box<[G::Point]>);

pub struct Proof<G: Group>(pub Box<[Proof<G>]>, pub Box<[Argument<G>]>);
pub struct Argument<G: Group>(pub G::Scalar, pub Box<[G::Point]>);


