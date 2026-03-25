use crate::foundation::group::Group;

#[derive(Clone, Debug, PartialEq)]
pub struct Pedersen<G: Group> {
    pub g: G::Point,
    pub h: Vec<G::Point>,
}

impl<G: Group> Pedersen<G> {
    pub fn new(g: G::Point, h: Vec<G::Point>) -> Self {
        Self { g, h }
    }

    pub fn commit(&self, r: &G::Scalar, m: &[G::Scalar]) -> G::Point {
        assert!(m.len() <= self.h.len());

        let hiding_factor = self.g * r;
        let commitment = m
            .iter()
            .zip(self.h.iter())
            .fold(hiding_factor, |acc, (m, h)| acc + &(*m * h));

        commitment
    }

    pub fn verify(&self, r: &G::Scalar, m: &[G::Scalar], commitment: &G::Point) -> bool {
        assert!(m.len() <= self.h.len()); // TODO discuss: remove; exposes implementation details of commit(), duplicates code

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
    use rand::thread_rng;
    use rand_core::{CryptoRng, RngCore};

    type Curve = RistrettoGroup;
    type Scalar = <Curve as Group>::Scalar;

    fn new_pedersen(n: usize) -> Pedersen<Curve> {
        Pedersen::new(
            Curve::basepoint(),
            Curve::independent_generators(b"Pedersen", n),
        )
    }

    fn new_pedersen_sample<R: RngCore + CryptoRng>(n: usize, rng: &mut R) -> (Scalar, Vec<Scalar>) {
        let randomness = Curve::scalar_random(rng);
        let messages: Vec<Scalar> = (0..n).map(|_| Curve::scalar_random(rng)).collect();

        (randomness, messages)
    }

    #[test]
    fn commit_and_open() {
        let mut rng = thread_rng();
        let pedersen = new_pedersen(5);
        let (randomness, messages) = new_pedersen_sample(5, &mut rng);

        let commitment = pedersen.commit(&randomness, &messages);
        assert_eq!(pedersen.verify(&randomness, &messages, &commitment), true);

        let (randomness, messages) = new_pedersen_sample(5, &mut rng);
        assert_eq!(pedersen.verify(&randomness, &messages, &commitment), false);
    }

    #[test]
    fn homomorphic_properties() {
        let mut rng = thread_rng();
        let pedersen = new_pedersen(5);

        let (r_1, m_1) = new_pedersen_sample(5, &mut rng);
        let (r_2, m_2) = new_pedersen_sample(5, &mut rng);

        let commitment_1 = pedersen.commit(&r_1, &m_1);
        let commitment_2 = pedersen.commit(&r_2, &m_2);

        let summed_messages: Vec<Scalar> = m_1.iter().zip(&m_2).map(|(a, b)| *a + b).collect();
        let summed_randomness = r_1 + &r_2;

        let expected = pedersen.commit(&summed_randomness, &summed_messages);

        assert_eq!(commitment_1 + &commitment_2, expected);
        assert_eq!(
            pedersen.verify(&summed_randomness, &summed_messages, &expected),
            true
        );
        assert_eq!(pedersen.verify(&summed_randomness, &m_1, &expected), false);
        assert_eq!(pedersen.verify(&r_1, &summed_messages, &expected), false);
        assert_eq!(pedersen.verify(&r_1, &m_1, &expected), false);
    }
}

// endregion: --- Tests
