use crate::foundation::group::Group;

#[allow(type_alias_bounds)]
pub type Message<G: Group> = G::Scalar;

#[allow(type_alias_bounds)]
pub type EncodedMessage<G: Group> = G::Point;
