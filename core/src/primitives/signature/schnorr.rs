use crate::foundation::group::Group;
use crate::primitives::signature::hash::{Hash, hash_default};
use rand_core::{CryptoRng, RngCore};

#[derive(Clone, Debug)]
pub struct Schnorr<G: Group> {
    hash: Hash<G>,
}

impl<G: Group> Default for Schnorr<G> {
    fn default() -> Self {
        Self { hash: hash_default::<G> }
    }
}

impl<G: Group> Schnorr<G> {
    pub fn keygen<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (G::Scalar, G::Point) {
        let sk = G::scalar_random(rng);
        let pk = G::basepoint() * &sk;

        (sk, pk)
    }

    pub fn sign(&self, sk: &G::Scalar, k: &G::Scalar, m: &Vec<u8>) -> (G::Scalar, G::Scalar) {
        let r = G::basepoint() * k;
        let e = (self.hash)(&r, m);
        let s = *k + &(*sk * &e);

        (s, e)
    }

    pub fn verify(&self, pk: &G::Point, m: &Vec<u8>, s: &G::Scalar, e: &G::Scalar) -> bool {
        let r = G::basepoint() * s - &(*pk * e);
        let e_dash = (self.hash)(&r, m);

        *e == e_dash
    }
}

// region: --- Tests

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::signature::schnorr::Schnorr;
    use rand::thread_rng;

    type G = RistrettoGroup;

    #[test]
    fn sign_and_verify() {
        let mut rng = thread_rng();

        let schnorr = Schnorr::<G>::default();
        let (sk, pk) = schnorr.keygen(&mut rng);
        let k = G::scalar_random(&mut rng);
        let message = b"test message".to_vec();

        let (s, e) = schnorr.sign(&sk, &k, &message);

        assert!(schnorr.verify(&pk, &message, &s, &e));
    }

    #[test]
    fn invalid_s_or_e_do_not_verify() {
        let mut rng = thread_rng();

        let schnorr = Schnorr::<G>::default();
        let (sk, pk) = schnorr.keygen(&mut rng);
        let k = G::scalar_random(&mut rng);
        let message = b"test message".to_vec();

        let (s, e) = schnorr.sign(&sk, &k, &message);

        let random = G::scalar_random(&mut rng);
        assert!(!schnorr.verify(&pk, &message, &random, &e));
        assert!(!schnorr.verify(&pk, &message, &s, &random));
    }
}

// endregion: --- Tests
