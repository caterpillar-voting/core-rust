use crate::foundation::group::Group;
use std::ops;

#[derive(Clone, Debug, PartialEq)]
pub struct Message<G: Group> {
    pub inner: G::Scalar,
}

impl<G: Group> Message<G> {
    pub fn new(message: G::Scalar) -> Self {
        Self { inner: message }
    }
}

impl<G: Group> ops::Add<&Message<G>> for &Message<G> {
    type Output = Message<G>;
    fn add(self, rhs: &Message<G>) -> Self::Output {
        Message {
            inner: self.inner + &rhs.inner,
        }
    }
}

impl<G: Group> ops::AddAssign<&Message<G>> for Message<G> {
    fn add_assign(&mut self, rhs: &Message<G>) {
        self.inner += rhs.inner;
    }
}

impl<G: Group> ops::Sub<&Message<G>> for &Message<G> {
    type Output = Message<G>;

    fn sub(self, rhs: &Message<G>) -> Self::Output {
        Message {
            inner: self.inner - &rhs.inner,
        }
    }
}

impl<G: Group> ops::SubAssign<&Message<G>> for Message<G> {
    fn sub_assign(&mut self, rhs: &Message<G>) {
        self.inner -= rhs.inner;
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MessageRange<G: Group> {
    pub start: G::Scalar,
    pub end: G::Scalar,
}

impl<G: Group> MessageRange<G> {
    pub fn new(start: G::Scalar, end: G::Scalar) -> Self {
        Self { start, end }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncodedMessage<G: Group> {
    pub inner: G::Point,
}

impl<G: Group> EncodedMessage<G> {
    pub fn new(message: G::Point) -> Self {
        Self { inner: message }
    }
}
