#[cfg(test)]
mod _test_utils;
pub mod pedersen;
mod representation;

use crate::foundation::group::Group;
use crate::foundation::representation::Message;
use crate::primitives::commitment::pedersen::Pedersen;
pub use crate::primitives::commitment::representation::{Commit, SecretOpening};
use rand_core::{CryptoRng, RngCore};

/// A hiding commitment (Pedersen) with N messages.
#[derive(Debug, PartialEq)]
pub struct Commitment<G: Group, const N: usize = 1> {
    pub pedersen: Pedersen<G, N>,
}

impl<G: Group, const N: usize> Default for Commitment<G, N> {
    fn default() -> Self {
        let pedersen = Pedersen::new(G::basepoint(), G::independent_generators::<N>(b"PedersenParameters"));

        Self::new(pedersen)
    }
}

impl<G: Group, const N: usize> Commitment<G, N> {
    pub fn new(pedersen: Pedersen<G, N>) -> Self {
        Self { pedersen }
    }

    pub fn commit<R: RngCore + CryptoRng>(&self, rng: &mut R, messages: &[Message<G>; N]) -> (Commit<G>, SecretOpening<G>) {
        let randomness = G::scalar_random(rng);
        let scalar_messages: Vec<G::Scalar> = messages.iter().copied().collect();
        let commitment = self.pedersen.commit(&randomness, &scalar_messages);

        (commitment, SecretOpening(randomness))
    }

    pub fn open(&self, messages: &[Message<G>; N], commit: &Commit<G>, opening: &SecretOpening<G>) -> bool {
        let scalar_messages: Vec<G::Scalar> = messages.iter().copied().collect();

        self.pedersen.commit(&opening.0, &scalar_messages) == *commit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::thread_rng;

    type Curve = RistrettoGroup;
    type Scalar = <Curve as Group>::Scalar;

    fn new_messages<const N: usize>() -> [Message<Curve>; N] {
        std::array::from_fn(|i| Scalar::from(u64::try_from(i).unwrap()))
    }

    #[test]
    fn commit_and_open() {
        let mut rng = thread_rng();

        let hiding_commitment = Commitment::<Curve, 2>::default();

        let messages = new_messages::<2>();
        let (commitment, randomness) = hiding_commitment.commit(&mut rng, &messages);

        assert!(hiding_commitment.open(&messages, &commitment, &randomness));
    }

    #[test]
    fn commit_and_open_homomorphic() {
        let mut rng = thread_rng();

        let hiding_commitment = Commitment::<Curve, 2>::default();

        let messages1 = new_messages::<2>();
        let (commitment1, randomness1) = hiding_commitment.commit(&mut rng, &messages1);

        let messages2 = new_messages::<2>();
        let (commitment2, randomness2) = hiding_commitment.commit(&mut rng, &messages2);

        let messages = std::array::from_fn(|i| &messages1[i] + &messages2[i]);
        let commitment = &commitment1 + &commitment2;
        let randomness = &SecretOpening(randomness1.0 + &randomness2.0);

        assert!(hiding_commitment.open(&messages, &commitment, &randomness));
    }
}
