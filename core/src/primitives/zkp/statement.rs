use crate::foundation::group::Group;
use rand_core::{CryptoRng, RngCore};

#[derive(Clone, Debug, PartialEq)]
pub struct Statement<G: Group> {
    g: G::Point,
    z: G::Point,
}

#[allow(type_alias_bounds)]
pub type Transcript<G: Group> = (G::Scalar, G::Point);
#[allow(type_alias_bounds)]
pub type Commit<G: Group> = (G::Scalar, G::Point);

/// naming according to https://crypto.ethz.ch/publications/files/Maurer09.pdf
impl<G: Group> Statement<G> {
    pub fn new(g: G::Point, z: G::Point) -> Self {
        Self { g, z }
    }

    pub fn commit<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Commit<G> {
        let k = G::scalar_random(rng);
        let t = self.g * &k;

        (k, t)
    }

    pub fn proof(&self, k: &G::Scalar, x: &G::Scalar, c: &G::Scalar) -> G::Scalar {
        *k + &(*c * x)
    }

    pub fn verify(&self, r: &G::Scalar, t: &G::Point, c: &G::Scalar) -> bool {
        let left = self.g * r;
        let right = *t + &(self.z * c);

        left == right
    }

    pub fn simulate<R: RngCore + CryptoRng>(&self, rng: &mut R, c: &G::Scalar) -> Transcript<G> {
        let r = G::scalar_random(rng);

        let t = self.g * &r - &(self.z * c);

        (r, t)
    }
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::foundation::group::{ByteSerialize, Group};
    use crate::foundation::hash::{ContextAwareHash, VectorContextHash};
    use crate::primitives::encryption::el_gamal::{ElGamal, ExponentialElGamal};
    use rand::thread_rng;

    type Curve = RistrettoGroup;

    type Scalar = <RistrettoGroup as Group>::Scalar;
    type Point = <RistrettoGroup as Group>::Point;

    #[test]
    fn proof_statement() {
        let mut rng = thread_rng();
        let x = Scalar::random(&mut rng);
        let z = Curve::basepoint() * x;
        let mut context = VectorContextHash::<Curve>::new(vec![z]);

        let zkp = Statement::<Curve>::new(Curve::basepoint(), z);

        let (k, t) = zkp.commit(&mut rng);
        context.add_context(&t);
        let c = context.hash();

        let r = zkp.proof(&k, &x, &c);
        assert!(zkp.verify(&r, &t, &c));
    }

    #[test]
    fn simulate_statement() {
        let mut rng = thread_rng();
        let z = Point::random(&mut rng);
        let zkp = Statement::<Curve>::new(Curve::basepoint(), z);

        let c = Curve::scalar_random(&mut rng);
        let (r, t) = zkp.simulate(&mut rng, &c);
        assert!(zkp.verify(&r, &t, &c));
    }
}

// endregion: --- Tests
