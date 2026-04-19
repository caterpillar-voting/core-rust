use crate::foundation::group::{ByteSerialize, Group};

pub trait ContextAwareHash<G: Group> {
    fn add_context(&mut self, p: &G::Point);
    fn hash(&self) -> G::Scalar;
}

pub struct VectorContextHash<G: Group> {
    context: Vec<u8>,
    _marker: core::marker::PhantomData<G>,
}

impl<G: Group> VectorContextHash<G> {
    pub fn new(global: Vec<G::Point>) -> Self {
        let mut own = Self {
            context: Vec::new(),
            _marker: core::marker::PhantomData,
        };

        global.iter().for_each(|p| own.add_context(p));

        own
    }
}

impl<G: Group> Default for VectorContextHash<G> {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl<G: Group> ContextAwareHash<G> for VectorContextHash<G> {
    fn add_context(&mut self, p: &G::Point) {
        let mut bytes = vec![0u8; G::Point::BUFFER_SIZE];
        p.to_bytes(&mut bytes[..]);
        self.context.extend_from_slice(&bytes[..]);
    }

    fn hash(&self) -> G::Scalar {
        G::hash_to_scalar(&self.context[..])
    }
}
