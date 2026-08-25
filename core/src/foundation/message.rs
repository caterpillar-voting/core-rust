use crate::foundation::discrete_log::{DiscreteLog, PrecomputedDiscreteLog};
use crate::foundation::group::Group;

#[allow(type_alias_bounds)]
pub type Message<G: Group> = G::Scalar;

#[allow(type_alias_bounds)]
pub type EncodedMessage<G: Group> = G::Point;

pub struct ScalarMessageEncoder<G: Group> {
    pub decoder: Box<dyn DiscreteLog<G>>,
}

impl<G: Group + 'static> ScalarMessageEncoder<G> {
    pub fn new(range: (G::Scalar, usize)) -> Self {
        let log = PrecomputedDiscreteLog::<G>::new(range);
        Self { decoder: Box::new(log) }
    }

    pub fn encode(&self, value: &G::Scalar) -> EncodedMessage<G> {
        G::basepoint() * value
    }
    pub fn decode(&self, value: &EncodedMessage<G>) -> Option<G::Scalar> {
        self.decoder.log(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::foundation::message::ScalarMessageEncoder;

    type G = RistrettoGroup;
    type Scalar = <G as Group>::Scalar;

    #[test]
    fn scalar_encoder_reversible() {
        let encoder = ScalarMessageEncoder::<G>::new((Scalar::from(0u64), 2));

        let value = Scalar::from(0u64);
        let encoded = encoder.encode(&value);
        let recovered_value = encoder.decode(&encoded);

        assert_eq!(Some(value), recovered_value);
    }
}
