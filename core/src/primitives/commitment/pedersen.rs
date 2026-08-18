use crate::foundation::group::Group;

#[derive(Clone, Debug, PartialEq)]
pub struct Pedersen<G: Group> {
    pub h: Vec<G::Point>,
}

impl<G: Group> Default for Pedersen<G> {
    fn default() -> Self {
        Self::new(1)
    }
}

impl<G: Group> Pedersen<G> {
    pub fn new(size: usize) -> Self {
        Self::new_with_generators(G::independent_generators(size, b"Pedersen"))
    }

    pub fn new_with_generators(h: Vec<G::Point>) -> Self {
        Self { h }
    }

    pub fn commit(&self, r: &G::Scalar, m: &[G::Scalar]) -> G::Point {
        assert!(m.len() <= self.h.len());

        let hiding_factor = G::basepoint() * r;

        m.iter().zip(self.h.iter()).fold(hiding_factor, |acc, (m, h)| acc + &(*m * h))
    }

    pub fn verify(&self, r: &G::Scalar, m: &[G::Scalar], commitment: &G::Point) -> bool {
        let recomputed_commitment = self.commit(r, m);

        recomputed_commitment == *commitment
    }
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::commitment::_test_utils::new_pedersen_sample;
    use rand::rngs::ThreadRng;
    use rand::thread_rng;

    type G = RistrettoGroup;
    type Scalar = <G as Group>::Scalar;

    #[test]
    fn commit_and_open() {
        let mut rng = thread_rng();
        let pedersen = Pedersen::<G>::default();
        let (randomness, messages) = new_pedersen_sample::<ThreadRng>(1, &mut rng);

        let commitment = pedersen.commit(&randomness, &messages);
        assert!(pedersen.verify(&randomness, &messages, &commitment));

        let (randomness, messages) = new_pedersen_sample::<ThreadRng>(1, &mut rng);
        assert_eq!(pedersen.verify(&randomness, &messages, &commitment), false);
    }

    #[test]
    fn homomorphic_properties() {
        let mut rng = thread_rng();
        let pedersen = Pedersen::<G>::new(5);

        let (r_1, m_1) = new_pedersen_sample::<ThreadRng>(5, &mut rng);
        let (r_2, m_2) = new_pedersen_sample::<ThreadRng>(5, &mut rng);

        let commitment_1 = pedersen.commit(&r_1, &m_1);
        let commitment_2 = pedersen.commit(&r_2, &m_2);

        let summed_messages: Vec<Scalar> = m_1.iter().zip(&m_2).map(|(a, b)| *a + b).collect();
        let summed_randomness = r_1 + &r_2;

        let expected = pedersen.commit(&summed_randomness, &summed_messages);

        assert_eq!(commitment_1 + &commitment_2, expected);
        assert!(pedersen.verify(&summed_randomness, &summed_messages, &expected));
        assert_eq!(pedersen.verify(&summed_randomness, &m_1, &expected), false);
        assert_eq!(pedersen.verify(&r_1, &summed_messages, &expected), false);
        assert_eq!(pedersen.verify(&r_1, &m_1, &expected), false);
    }
}

// endregion: --- Tests
