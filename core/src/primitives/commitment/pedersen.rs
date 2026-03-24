use crate::foundation::group::Group;

/// A Pedersen commitment: `C = [r]g + Σ [mᵢ]hᵢ`.
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

    pub fn verify(
        &self,
        r: &G::Scalar,
        m: &[G::Scalar],
        commitment: &G::Point,
    ) -> bool {
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
    use rand::{SeedableRng, rngs::StdRng};

    type Curve = RistrettoGroup;
    type Scalar = <Curve as Group>::Scalar;

    fn seeded_rng() -> StdRng {
        let mut seed = [0u8; 32];
        seed[..5].copy_from_slice(b"hello");
        StdRng::from_seed(seed)
    }

    fn new_pedersen(n: usize, rng: &mut StdRng) -> Pedersen<Curve> {
        let point = Curve::point_random(rng);
        let generators = (0..n).map(|_| Curve::point_random(rng)).collect();
        Pedersen::new(point, generators) // TODO: instead insert verifiable generators
    }

    #[test]
    fn commit_and_open() {
        let mut rng = seeded_rng();
        let pedersen = new_pedersen(5, &mut rng);

        let messages: Vec<Scalar> = (0..5).map(|_| Curve::scalar_random(&mut rng)).collect();
        let randomness = Curve::scalar_random(&mut rng);

        let commitment = pedersen.commit(&randomness, &messages);

        assert!(pedersen.verify(&randomness, &messages, &commitment));
    }

    #[test]
    fn homomorphic_properties() {
        let mut rng = seeded_rng();
        let pedersen = new_pedersen(4, &mut rng);

        let messages1: Vec<Scalar> = (0..4).map(|_| Curve::scalar_random(&mut rng)).collect();
        let messages2: Vec<Scalar> = (0..4).map(|_| Curve::scalar_random(&mut rng)).collect();
        let r1 = Curve::scalar_random(&mut rng);
        let r2 = Curve::scalar_random(&mut rng);

        let c1 = pedersen.commit(&r1, &messages1);
        let c2 = pedersen.commit(&r2, &messages2);

        let summed_messages: Vec<Scalar> = messages1
            .iter()
            .zip(&messages2)
            .map(|(a, b)| *a + b)
            .collect();
        let summed_randomness = r1 + &r2;

        let expected = pedersen.commit(&summed_randomness, &summed_messages);

        assert_eq!(c1 + &c2, expected);
        assert!(pedersen.verify(&summed_randomness, &summed_messages, &expected));
    }
}

// endregion: --- Tests
