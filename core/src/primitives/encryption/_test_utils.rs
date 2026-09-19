use crate::foundation::group::Group;
use crate::foundation::group::ristretto::RistrettoGroup;
use crate::primitives::encryption::el_gamal::{ElGamal, ExponentialElGamal};
use rand_core::{CryptoRng, RngCore};

type G = RistrettoGroup;

type Scalar = <RistrettoGroup as Group>::Scalar;
type Point = <RistrettoGroup as Group>::Point;

pub fn new_el_gamal_sample<R: RngCore + CryptoRng>(rng: &mut R) -> (ElGamal<G>, Vec<Scalar>, Vec<Point>, Scalar, Vec<Point>) {
    let el_gamal = ElGamal::<G>::default();
    let (sk, pk) = el_gamal.keygen(rng);
    let r = G::scalar_random(rng);
    let m = (0..el_gamal.n).map(|_| G::point_random(rng)).collect::<Vec<_>>();

    (el_gamal, sk, pk, r, m)
}

pub fn new_exponential_el_gamal_sample<R: RngCore + CryptoRng>(rng: &mut R) -> (ExponentialElGamal<G>, Vec<Scalar>, Vec<Point>, Scalar, Vec<Scalar>, (Scalar, usize)) {
    let exponential_el_gamal = ExponentialElGamal::<G>::new(ElGamal::<G>::new(3));

    let (sk, pk) = exponential_el_gamal.0.keygen(rng);
    let r = G::scalar_random(rng);
    let m = (0..exponential_el_gamal.0.n).map(|i| Scalar::from(i as u64)).collect::<Vec<_>>();
    let range = (Scalar::from(0u64), exponential_el_gamal.0.n);

    (exponential_el_gamal, sk, pk, r, m, range)
}
