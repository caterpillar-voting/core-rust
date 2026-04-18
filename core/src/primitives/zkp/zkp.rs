use crate::foundation::group::Group;
use rand_core::{CryptoRng, RngCore};

#[derive(Clone, Debug, PartialEq)]
pub struct ZKP<G: Group> {
    z: G::Point,
}

/// https://crypto.ethz.ch/publications/files/Maurer09.pdf
impl<G: Group> ZKP<G> {
    pub fn new(z: G::Point) -> Self {
        Self { z }
    }

    pub fn commit<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (G::Scalar, G::Point) {
        let k = G::scalar_random(rng);
        let t = G::basepoint() * &k;

        (k, t)
    }

    pub fn proof(&self, k: &G::Scalar, c: &G::Scalar, x: &G::Scalar) -> G::Scalar {
        let r = *k + &(*c * x);

        r
    }

    pub fn verify(&self, r: &G::Scalar, t: &G::Point, c: &G::Scalar) -> bool {
        let left = G::basepoint() * r;
        let right = *t + &(self.z * c);

        left == right
    }

    pub fn simulate<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (G::Scalar, G::Scalar, G::Point) {
        let r = G::scalar_random(rng);
        let c = G::scalar_random(rng);

        let t = G::basepoint() * &r - &(self.z * &c);

        (c, r, t)
    }
}


// region: --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::group::{ByteSerialize, Group};
    use crate::foundation::group::ristretto::RistrettoGroup;
    use rand::thread_rng;
    use sha2::Sha512;

    type Curve = RistrettoGroup;

    type Scalar = <RistrettoGroup as Group>::Scalar;
    type Point = <RistrettoGroup as Group>::Point;

    #[test]
    fn proof() {
        let mut rng = thread_rng();
        let x = Scalar::random(&mut rng);
        let z = Curve::basepoint() * x;
        let zkp = ZKP::<Curve>::new(z);

        let (k, t) = zkp.commit(&mut rng);
        let mut context = [0u8; Point::BUFFER_SIZE + Point::BUFFER_SIZE];
        t.to_bytes(&mut context[0..Point::BUFFER_SIZE]);
        z.to_bytes(&mut context[Point::BUFFER_SIZE..2 * Point::BUFFER_SIZE]);
        let c = Scalar::hash_from_bytes::<Sha512>(&context);

        let r = zkp.proof(&k, &c, &x);
        assert!(zkp.verify(&r, &t, &c));
    }

    #[test]
    fn simulate() {
        let mut rng = thread_rng();
        let z = Point::random(&mut rng);
        let zkp = ZKP::<Curve>::new(z);

        let (c, r, t) = zkp.simulate(&mut rng);
        assert!(zkp.verify(&r, &t, &c));
    }
}

// endregion: --- Tests
