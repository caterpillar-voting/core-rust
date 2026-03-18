use crate::group::lib::group::Group;

/// A Pedersen commitment: `C = [r]H + Σ [mᵢ]Gᵢ`.
#[derive(Clone, Debug, PartialEq)]
pub struct Pedersen<G: Group> {
    pub point: G::Point, // blinding base
    pub generators: Vec<G::Point>,
}

impl<G: Group> Pedersen<G> {
    pub fn new(point: G::Point, generators: Vec<G::Point>) -> Self {
        Self { point, generators }
    }

    pub fn commit(
        &self,
        randomness: &G::Scalar,
        messages: &[G::Scalar],
    ) -> G::Point {
        assert!(messages.len() <= self.generators.len());

        let hiding_factor = self.point * randomness;
        self.generators.iter()
            .zip(messages.iter())
            .fold(hiding_factor, |acc, (g, m)| acc + &(*g * m))
    }

    pub fn verify(
        &self,
        messages: &[G::Scalar],
        randomness: &G::Scalar,
        commitment: &G::Point,
    ) -> bool {
        assert!(messages.len() <= self.generators.len());

        self.commit(randomness, messages) == *commitment
    }
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::lib::group::Group;
    use crate::group::ristretto::RistrettoGroup;
    use rand::{rngs::StdRng, SeedableRng};

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

        assert!(pedersen.verify(&messages, &randomness, &commitment));
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
        assert!(pedersen.verify(&summed_messages, &summed_randomness, &expected));
    }
}

// endregion: --- Tests
