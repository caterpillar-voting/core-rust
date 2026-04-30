use crate::foundation::group::Group;
use rand_core::{CryptoRng, RngCore};
use std::hint::black_box;

#[derive(Clone, Debug, PartialEq)]
pub struct Statement<G: Group> {
    pub g: G::Point,
    pub z: G::Point,
}

/// naming according to https://crypto.ethz.ch/publications/files/Maurer09.pdf
impl<G: Group> Statement<G> {
    pub fn new(g: G::Point, z: G::Point) -> Self {
        Self { g, z }
    }

    pub fn commit<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (G::Scalar, G::Point) {
        let k = G::scalar_random(rng);
        let t = self.g * &k;

        (k, t)
    }

    pub fn response(&self, k: &G::Scalar, x: &G::Scalar, c: &G::Scalar) -> G::Scalar {
        let r = *k + &(*c * x);

        black_box(r) // prevent clippy from removing intermediate value
    }

    pub fn verify(&self, r: &G::Scalar, t: &G::Point, c: &G::Scalar) -> bool {
        let left = self.g * r;
        let right = *t + &(self.z * c);

        left == right
    }

    pub fn simulate<R: RngCore + CryptoRng>(&self, rng: &mut R, c: &G::Scalar) -> (G::Scalar, G::Point) {
        let r = G::scalar_random(rng);

        let t = self.g * &r - &(self.z * c);

        (r, t)
    }
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::thread_rng;

    type Curve = RistrettoGroup;
    type Scalar = <RistrettoGroup as Group>::Scalar;

    fn construct_statement<R: RngCore + CryptoRng>(rng: &mut R) -> (Statement<Curve>, Scalar) {
        let x = Scalar::random(rng);
        let z = Curve::basepoint() * x;
        let zkp = Statement::<Curve>::new(Curve::basepoint(), z);

        (zkp, x)
    }

    #[test]
    fn proof_statement() {
        let mut rng = thread_rng();
        let (zkp, x) = construct_statement(&mut rng);

        let (k, t) = zkp.commit(&mut rng);
        let c = Scalar::random(&mut rng);
        let r = zkp.response(&k, &x, &c);

        assert!(zkp.verify(&r, &t, &c));
    }

    #[test]
    fn simulate_statement() {
        let mut rng = thread_rng();
        let (zkp, _) = construct_statement(&mut rng);

        let c = Curve::scalar_random(&mut rng);
        let (r, t) = zkp.simulate(&mut rng, &c);
        assert!(zkp.verify(&r, &t, &c));
    }
}

// endregion: --- Tests
