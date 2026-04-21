use rand_core::{CryptoRng, RngCore};
use crate::foundation::group::Group;
use crate::foundation::group::ristretto::RistrettoGroup;

type Curve = RistrettoGroup;
type Scalar = <Curve as Group>::Scalar;


pub fn new_pedersen_sample<R: RngCore + CryptoRng, const N: usize>(
    rng: &mut R,
) -> (Scalar, [Scalar; N]) {
    let randomness = Curve::scalar_random(rng);
    let messages: Vec<Scalar> = (0..N).map(|_| Curve::scalar_random(rng)).collect();

    (
        randomness,
        messages.try_into().expect("incorrect number of messages"),
    )
}