use crate::foundation::group::Group;
use crate::foundation::group::ristretto::RistrettoGroup;
use crate::primitives::encryption::el_gamal::{ElGamal, ExponentialElGamal};
use rand_core::{CryptoRng, RngCore};

type G = RistrettoGroup;

type Scalar = <RistrettoGroup as Group>::Scalar;
type Point = <RistrettoGroup as Group>::Point;

pub fn new_el_gamal_sample<R: RngCore + CryptoRng>(rng: &mut R) -> (ElGamal<G>, Scalar, Point, Scalar, Point) {
    let el_gamal = ElGamal::<G>::default();
    let sk = el_gamal.generate_secret_key(rng);
    let pk = el_gamal.derive_public_key(&sk);
    let r = G::scalar_random(rng);
    let m = G::point_random(rng);

    (el_gamal, sk, pk, r, m)
}

pub fn new_exponential_el_gamal_sample<R: RngCore + CryptoRng>(rng: &mut R) -> (ExponentialElGamal<G>, Scalar, Point, Scalar, Scalar) {
    let exponential_el_gamal = ExponentialElGamal::<G>::default();

    let sk = exponential_el_gamal.0.generate_secret_key(rng);
    let pk = exponential_el_gamal.0.derive_public_key(&sk);
    let r = G::scalar_random(rng);
    let m = Scalar::from(2u64);

    (exponential_el_gamal, sk, pk, r, m)
}
