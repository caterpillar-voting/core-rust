use crate::foundation::group::Group;

#[allow(type_alias_bounds)]
pub type Message<G: Group> = G::Scalar;

pub type EncodedMessage<G: Group> = G::Point;
