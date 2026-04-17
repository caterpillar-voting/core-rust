pub mod pedersen;

use crate::foundation::group::Group;
use crate::foundation::representation::Message;
use crate::primitives::commitment::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A Pedersen commitment: `C = [r]H + Σ [mᵢ]Gᵢ`.
#[derive(Debug, PartialEq)]
pub struct HidingCommitment<G: Group, const N: usize = 1> {
    pedersen: Pedersen<G>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Commitment<G: Group> {
    inner: G::Point,
}
#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Opening<G: Group> {
    inner: G::Scalar,
}

impl<G: Group, const N: usize> Default for HidingCommitment<G, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: Group, const N: usize> HidingCommitment<G, N> {
    pub fn new() -> Self {
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
        let scalar_messages: Vec<G::Scalar> = messages.iter().map(|m| m.inner).collect();
        let commitment = self.pedersen.commit(&randomness, &scalar_messages);

        (
            Commitment { inner: commitment },
            Opening { inner: randomness },
        )
    }

    pub fn open(
        &self,
        messages: &[Message<G>; N],
        commitment: &Commitment<G>,
        opening: &Opening<G>,
    ) -> bool {
        let scalar_messages: Vec<G::Scalar> = messages.iter().map(|m| m.inner).collect();

        self.pedersen.commit(&opening.inner, &scalar_messages) == commitment.inner
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
        std::array::from_fn(|i| Message::<Curve>::new(Scalar::from(u32::try_from(i).unwrap())))
    }

    #[test]
    fn commit_and_open() {
        let mut rng = thread_rng();

        let hiding_commitment = HidingCommitment::<Curve, 2>::new();

        let messages = new_messages::<2>();
        let (commitment, randomness) = hiding_commitment.commit(&mut rng, &messages);

        assert_eq!(
            hiding_commitment.open(&messages, &commitment, &randomness),
            true
        );
    }
}
