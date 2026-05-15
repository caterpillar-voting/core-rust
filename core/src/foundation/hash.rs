use crate::foundation::group::{ByteSerialize, Group};

pub trait ContextHash<G: Group> {
    fn add_point(&mut self, p: &G::Point);
    fn add_scalar(&mut self, s: &G::Scalar);
    fn hash_to_scalar(&self) -> G::Scalar;
    fn hash_to_point(&self) -> G::Point;
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
    fn add_point(&mut self, p: &G::Point) {
        let mut bytes = vec![0u8; G::Point::BUFFER_SIZE];
        p.to_bytes(&mut bytes[..]);
        self.context.extend_from_slice(&bytes[..]);
    }
    fn add_scalar(&mut self, s: &G::Scalar) {
        let mut bytes = vec![0u8; G::Scalar::BUFFER_SIZE];
        s.to_bytes(&mut bytes[..]);
        self.context.extend_from_slice(&bytes[..]);
    }

    fn hash_to_scalar(&self) -> G::Scalar {
        G::hash_to_scalar(&self.context[..])
    }

    fn hash_to_point(&self) -> G::Point {
        G::hash_to_point(&self.context[..])
    }
}
