pub mod pedersen;

use crate::foundation::group::Group;
use crate::foundation::message::Message;
use crate::primitives::commitment::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[allow(type_alias_bounds)]
pub type Commit<G: Group> = G::Point;

#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretOpening<G: Group>(pub G::Scalar);

/// A hiding commitment (Pedersen) with N messages.
#[derive(Debug, PartialEq)]
pub struct Commitment<G: Group> {
    pub pedersen: Pedersen<G>,
}

impl<G: Group> Default for Commitment<G> {
    fn default() -> Self {
        Self::new(Pedersen::default())
    }
}

impl<G: Group> Commitment<G> {
    pub fn new(pedersen: Pedersen<G>) -> Self {
        Self { pedersen }
    }

    pub fn commit<R: RngCore + CryptoRng>(&self, rng: &mut R, messages: &[Message<G>]) -> (Commit<G>, SecretOpening<G>) {
        let randomness = G::scalar_random(rng);
        let scalar_messages: Vec<G::Scalar> = messages.to_vec();
        let commitment = self.pedersen.commit(&randomness, &scalar_messages);

        (commitment, SecretOpening(randomness))
    }

    pub fn open(&self, messages: &[Message<G>], commit: &Commit<G>, opening: &SecretOpening<G>) -> bool {
        let scalar_messages: Vec<G::Scalar> = messages.to_vec();

        self.pedersen.commit(&opening.0, &scalar_messages) == *commit
    }
}

#[cfg(test)]
mod _test_utils;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::thread_rng;

    type G = RistrettoGroup;
    type Scalar = <G as Group>::Scalar;

    fn new_messages(size: usize) -> Vec<Message<G>> {
        (0..size).map(|i| Scalar::from(u64::try_from(i).unwrap())).collect()
    }

    #[test]
    fn commit_and_open() {
        let mut rng = thread_rng();

        let hiding_commitment = Commitment::<G>::default();

        let messages = new_messages(1);
        let (commitment, randomness) = hiding_commitment.commit(&mut rng, &messages);

        assert!(hiding_commitment.open(&messages, &commitment, &randomness));
    }

    #[test]
    fn commit_and_open_homomorphic() {
        let mut rng = thread_rng();

        let hiding_commitment = Commitment::<G>::new(Pedersen::new(2));

        let messages1 = new_messages(2);
        let (commitment1, randomness1) = hiding_commitment.commit(&mut rng, &messages1);

        let messages2 = new_messages(2);
        let (commitment2, randomness2) = hiding_commitment.commit(&mut rng, &messages2);

        let messages: Vec<Scalar> = (0..messages2.len()).map(|i| messages1[i] + &messages2[i]).collect();
        let commitment = commitment1 + &commitment2;
        let randomness = &SecretOpening(randomness1.0 + &randomness2.0);

        assert!(hiding_commitment.open(&messages, &commitment, &randomness));
    }
}
