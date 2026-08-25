use crate::foundation::group::Group;
use crate::primitives::zkp::get_challenge::{GetChallenge, get_challenge_default};
use rand_core::{CryptoRng, RngCore};

pub struct ZKPDiscreteLog<G: Group> {
    get_challenge: GetChallenge<G>,
}

impl<G: Group> Default for ZKPDiscreteLog<G> {
    fn default() -> Self {
        Self {
            get_challenge: get_challenge_default::<G>,
        }
    }
}

impl<G: Group> ZKPDiscreteLog<G> {
    pub fn new(get_challenge: GetChallenge<G>) -> Self {
        Self { get_challenge }
    }

    pub fn prove<R: RngCore + CryptoRng>(&self, h: &G::Point, x: &G::Scalar, ctx: &[u8], rng: &mut R) -> (G::Scalar, G::Scalar) {
        let k = G::scalar_random(rng);
        let t = G::basepoint() * &k;
        let c = (self.get_challenge)(&[*h, t], ctx);
        let r = k + &(*x * &c);

        (c, r)
    }

    pub fn verify(&self, h: &G::Point, c: &G::Scalar, r: &G::Scalar, ctx: &[u8]) -> bool {
        let t = G::basepoint() * r - &(*h * c);
        let c_dash = (self.get_challenge)(&[*h, t], ctx);

        *c == c_dash
    }
}

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::zkp::discrete_log::ZKPDiscreteLog;

    type G = RistrettoGroup;

    #[test]
    pub fn prove_verify() {
        let mut rng = rand::thread_rng();
        let x = G::scalar_random(&mut rng);
        let h = G::basepoint() * &x;
        let ctx = "test_zkp_discrete_log".as_bytes().to_vec();

        let zkp = ZKPDiscreteLog::<G>::default();
        let (c, r) = zkp.prove(&h, &x, &ctx, &mut rng);

        assert!(zkp.verify(&h, &c, &r, &ctx));
    }

    #[test]
    pub fn cannot_prove_invalid_x() {
        let mut rng = rand::thread_rng();
        let x = G::scalar_random(&mut rng);
        let h = G::basepoint() * &x;
        let ctx = "test_zkp_discrete_log".as_bytes().to_vec();
        let x_dash = G::scalar_random(&mut rng);

        let zkp = ZKPDiscreteLog::<G>::default();
        let (c, r) = zkp.prove(&h, &x_dash, &ctx, &mut rng);

        assert!(!zkp.verify(&h, &c, &r, &ctx));
    }

    #[test]
    pub fn cannot_verify_invalid_c_or_r() {
        let mut rng = rand::thread_rng();
        let x = G::scalar_random(&mut rng);
        let h = G::basepoint() * &x;
        let ctx = "test_zkp_discrete_log".as_bytes().to_vec();

        let zkp = ZKPDiscreteLog::<G>::default();
        let (c, r) = zkp.prove(&h, &x, &ctx, &mut rng);

        let random = G::scalar_random(&mut rng);
        assert!(!zkp.verify(&h, &random, &r, &ctx));
        assert!(!zkp.verify(&h, &c, &random, &ctx));
    }
}
