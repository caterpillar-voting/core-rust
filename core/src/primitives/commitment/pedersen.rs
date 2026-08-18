use crate::foundation::group::Group;

#[derive(Clone, Debug, PartialEq)]
pub struct Pedersen<G: Group, const N: usize = 1> {
    pub g: G::Point,
    pub h: Box<[G::Point; N]>,
}

impl<G: Group, const N: usize> Default for Pedersen<G, N> {
    fn default() -> Self {
        Self::new(G::basepoint(), G::independent_generators::<N>(b"Pedersen"))
    }
}

impl<G: Group, const N: usize> Pedersen<G, N> {
    pub fn new(g: G::Point, h: Box<[G::Point; N]>) -> Self {
        Self { g, h }
    }

    pub fn commit(&self, r: &G::Scalar, m: &[G::Scalar]) -> G::Point {
        assert!(m.len() <= self.h.len());

        let hiding_factor = self.g * r;

        m.iter().zip(self.h.iter()).fold(hiding_factor, |acc, (m, h)| acc + &(*m * h))
    }

    pub fn verify(&self, r: &G::Scalar, m: &[G::Scalar], commitment: &G::Point) -> bool {
        // TODO remove; exposes implementation details of commit()
        assert!(m.len() <= self.h.len());

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
        let pedersen = Pedersen::<G, 1>::default();
        let (randomness, messages) = new_pedersen_sample::<ThreadRng, 1>(&mut rng);

        let commitment = pedersen.commit(&randomness, &messages);
        assert!(pedersen.verify(&randomness, &messages, &commitment));

        let (randomness, messages) = new_pedersen_sample::<ThreadRng, 1>(&mut rng);
        assert_eq!(pedersen.verify(&randomness, &messages, &commitment), false);
    }

    #[test]
    fn homomorphic_properties() {
        let mut rng = thread_rng();
        let pedersen = Pedersen::<G, 5>::default();

        let (r_1, m_1) = new_pedersen_sample::<ThreadRng, 5>(&mut rng);
        let (r_2, m_2) = new_pedersen_sample::<ThreadRng, 5>(&mut rng);

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
