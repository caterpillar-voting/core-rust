mod pedersen;

use crate::foundation::group::Group;
use crate::primitives::commitment::pedersen::Pedersen;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A Pedersen commitment: `C = [r]H + Σ [mᵢ]Gᵢ`.
#[derive(Debug, PartialEq)]
pub struct HidingCommitment<'a, G: Group, R: RngCore + CryptoRng> {
    pedersen: Pedersen<G>,
    rng: &'a mut R,
}

pub struct Message<G: Group> {
    inner: G::Scalar,
}
pub struct Commitment<G: Group> {
    inner: G::Point,
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretRandomness<G: Group> {
    inner: G::Scalar,
}

impl<'a, G: Group, R: RngCore + CryptoRng> HidingCommitment<'a, G, R> {
    pub fn new(point: G::Point, generators: Vec<G::Point>, rng: &'a mut R) -> Self {
        let pedersen = Pedersen::new(point, generators);
        Self { pedersen, rng }
    }

    pub fn commit(&mut self, messages: &[Message<G>]) -> (Commitment<G>, SecretRandomness<G>) {
        let randomness = G::scalar_random(self.rng);
        let scalar_messages: Vec<G::Scalar> = messages.iter().map(|m| m.inner).collect();
        let commitment = self
            .pedersen
            .commit(&G::scalar_random(self.rng), &scalar_messages);

        (
            Commitment { inner: commitment },
            SecretRandomness { inner: randomness },
        )
    }

    pub fn verify(
        &self,
        messages: &[Message<G>],
        commitment: &Commitment<G>,
        randomness: &SecretRandomness<G>,
    ) -> bool {
        let scalar_messages: Vec<G::Scalar> = messages.iter().map(|m| m.inner).collect();
        self.pedersen.commit(&randomness.inner, &scalar_messages) == commitment.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::{SeedableRng, rngs::StdRng};

    type Curve = RistrettoGroup;
    type Scalar = <Curve as Group>::Scalar;

    fn seeded_rng() -> StdRng {
        let mut seed = [0u8; 32];
        seed[..5].copy_from_slice(b"hello");
        StdRng::from_seed(seed)
    }

    #[test]
    fn commit_and_verify_round_trip() {
        let mut rng = seeded_rng();

        let point = Curve::point_random(&mut rng);
        let generators = vec![
            Curve::point_random(&mut rng),
            Curve::point_random(&mut rng),
            Curve::point_random(&mut rng),
        ];

        let messages = vec![
            Message::<Curve> {
                inner: Scalar::from(10u64),
            },
            Message::<Curve> {
                inner: Scalar::from(20u64),
            },
            Message::<Curve> {
                inner: Scalar::from(30u64),
            },
        ];

        let mut hiding = HidingCommitment::new(point, generators, &mut rng);
        let (commitment, randomness) = hiding.commit(&messages);

        assert!(hiding.verify(&messages, &commitment, &randomness));
    }
}
