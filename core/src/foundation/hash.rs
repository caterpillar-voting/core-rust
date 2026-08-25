use crate::foundation::group::{ByteNormalize, Group};

pub trait ContextHash<G: Group> {
    fn get_context(&self) -> Vec<u8>;
}

pub trait GroupContextHash<G: Group> {
    fn add_point(&mut self, p: &G::Point);
    fn add_scalar(&mut self, s: &G::Scalar);
}

#[derive(Clone)]
pub struct VectorContextHash {
    context: Vec<u8>,
}

impl Default for VectorContextHash {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl VectorContextHash {
    pub fn new(context: Vec<u8>) -> Self {
        Self { context }
    }

    pub fn add(&mut self, context: &[u8]) {
        self.context.extend_from_slice(context);
    }
}

impl<G: Group> ContextHash<G> for VectorContextHash {
    fn get_context(&self) -> Vec<u8> {
        self.context.clone()
    }
}

impl<G: Group> GroupContextHash<G> for VectorContextHash {
    fn add_point(&mut self, p: &G::Point) {
        let bytes = p.normalize();
        self.context.extend_from_slice(&bytes[..]);
    }
    fn add_scalar(&mut self, s: &G::Scalar) {
        let bytes = s.normalize();
        self.context.extend_from_slice(&bytes[..]);
    }
}
