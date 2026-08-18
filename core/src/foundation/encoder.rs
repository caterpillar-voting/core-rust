use crate::foundation::discrete_log::{DiscreteLog, PrecomputedDiscreteLog};
use crate::foundation::group::Group;

pub struct ScalarEncoder<G: Group> {
    pub g: G::Point,
    pub decoder: Box<dyn DiscreteLog<G>>,
}

impl<G: Group + 'static> ScalarEncoder<G> {
    pub fn new(range: (G::Scalar, usize)) -> Self {
        let g = G::basepoint();
        let log = PrecomputedDiscreteLog::<G>::new(range);
        Self { g, decoder: Box::new(log) }
    }

    pub fn encode(&self, value: &G::Scalar) -> G::Point {
        G::basepoint() * value
    }
    pub fn decode(&self, value: &G::Point) -> Option<G::Scalar> {
        self.decoder.log(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::foundation::encoder::ScalarEncoder;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;

    type G = RistrettoGroup;
    type Scalar = <G as Group>::Scalar;

    #[test]
    fn scalar_encoder_reversible() {
        let encoder = ScalarEncoder::<G>::new((Scalar::from(0u64), 2));

        let value = Scalar::from(0u64);
        let encoded = encoder.encode(&value);
        let recovered_value = encoder.decode(&encoded);

        assert_eq!(Some(value), recovered_value);
    }
}
