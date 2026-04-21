use crate::foundation::group::Group;

#[allow(type_alias_bounds)]
pub type Message<G: Group> = G::Scalar;

#[derive(Clone, Debug, PartialEq)]
pub struct EncodedMessage<G: Group>(pub G::Point);

impl<G: Group> EncodedMessage<G> {}
