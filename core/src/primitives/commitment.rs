pub mod pedersen;
mod representation;

use crate::foundation::group::Group;
use crate::foundation::representation::Message;
use crate::primitives::commitment::pedersen::Pedersen;
pub use crate::primitives::commitment::representation::{Commitment, Opening};
use rand_core::{CryptoRng, RngCore};

/// A hiding commitment (Pedersen) with N messages.
#[derive(Debug, PartialEq)]
pub struct CommitmentHiding<G: Group, const N: usize = 1> {
    pedersen: Pedersen<G>,
}

impl<G: Group, const N: usize> Default for CommitmentHiding<G, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: Group, const N: usize> CommitmentHiding<G, N> {
    pub fn new() -> Self {
        // TODO: inconsistent with ElGamal, should take Pedersen as argument. however, then lose type safety with N
        let pedersen = Pedersen::new(
            G::basepoint(),
            G::independent_generators(b"PedersenParameters", N),
        );

        Self { pedersen }
    }

    pub fn commit<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        messages: &[Message<G>; N],
    ) -> (Commitment<G>, Opening<G>) {
        let randomness = G::scalar_random(rng);
        let scalar_messages: Vec<G::Scalar> = messages.iter().map(|m| m.0).collect();
        let commitment = self.pedersen.commit(&randomness, &scalar_messages);

        (Commitment(commitment), Opening(randomness))
    }

    pub fn open(
        &self,
        messages: &[Message<G>; N],
        commitment: &Commitment<G>,
        opening: &Opening<G>,
    ) -> bool {
        let scalar_messages: Vec<G::Scalar> = messages.iter().map(|m| m.0).collect();

        self.pedersen.commit(&opening.0, &scalar_messages) == commitment.0
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
        std::array::from_fn(|i| Message::<Curve>(Scalar::from(u64::try_from(i).unwrap())))
    }

    #[test]
    fn commit_and_open() {
        let mut rng = thread_rng();

        let hiding_commitment = CommitmentHiding::<Curve, 2>::new();

        let messages = new_messages::<2>();
        let (commitment, randomness) = hiding_commitment.commit(&mut rng, &messages);

        assert_eq!(
            hiding_commitment.open(&messages, &commitment, &randomness),
            true
        );
    }

    #[test]
    fn commit_and_open_homomorphic() {
        let mut rng = thread_rng();

        let hiding_commitment = CommitmentHiding::<Curve, 2>::new();

        let messages1 = new_messages::<2>();
        let (commitment1, randomness1) = hiding_commitment.commit(&mut rng, &messages1);

        let messages2 = new_messages::<2>();
        let (commitment2, randomness2) = hiding_commitment.commit(&mut rng, &messages2);

        let messages = std::array::from_fn(|i| &messages1[i] + &messages2[i]);
        let commitment = &commitment1 + &commitment2;
        let randomness = &randomness1 + &randomness2;

        assert_eq!(
            hiding_commitment.open(&messages, &commitment, &randomness),
            true
        );
    }
}
