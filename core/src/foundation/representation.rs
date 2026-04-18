use crate::foundation::group::Group;
use std::ops;

#[derive(Clone, Debug, PartialEq)]
pub struct Message<G: Group>(pub G::Scalar);

impl<G: Group> From<u64> for Message<G> {
    fn from(value: u64) -> Self {
        Self(G::Scalar::from(value))
    }
}

impl<G> TryFrom<Message<G>> for u64
where
    G: Group,
    u64: TryFrom<G::Scalar>,
{
    type Error = <u64 as TryFrom<G::Scalar>>::Error;

    fn try_from(value: Message<G>) -> Result<Self, Self::Error> {
        u64::try_from(value.0)
    }
}

impl<G: Group> ops::Add<&Message<G>> for &Message<G> {
    type Output = Message<G>;
    fn add(self, rhs: &Message<G>) -> Self::Output {
        Message(self.0 + &rhs.0)
    }
}

impl<G: Group> ops::Sub<&Message<G>> for &Message<G> {
    type Output = Message<G>;

    fn sub(self, rhs: &Message<G>) -> Self::Output {
        Message(self.0 - &rhs.0)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncodedMessage<G: Group>(pub G::Point);

impl<G: Group> EncodedMessage<G> {}
