// ZKP of correct exponentiation.
// Public data is X, h, hx.
// Secret data is x such that X = g^x and hx = g^x.

use crate::foundation::group::Group;
use crate::primitives::zkp::get_challenge::{GetChallenge, get_challenge_default};
use rand_core::{CryptoRng, RngCore};

pub struct ZKPCorrectExp<G: Group> {
    get_challenge: GetChallenge<G>,
}

impl<G: Group> Default for ZKPCorrectExp<G> {
    fn default() -> Self {
        Self {
            get_challenge: get_challenge_default::<G>,
        }
    }
}

impl<G: Group> ZKPCorrectExp<G> {
    pub fn new(get_challenge: GetChallenge<G>) -> Self {
        Self { get_challenge }
    }

    pub fn prove<R: RngCore + CryptoRng>(&self, cap_x: &G::Point, h: &G::Point, hx: &G::Point, x: &G::Scalar, ctx: &[u8], rng: &mut R) -> (G::Scalar, G::Scalar) {
        let k = G::scalar_random(rng);
        let t = (G::basepoint() * &k, *h * &k);
        let c = (self.get_challenge)(&[*cap_x, *h, *hx, t.0, t.1], ctx);
        let r = k + &(*x * &c);
        (c, r)
    }

    pub fn verify(&self, cap_x: &G::Point, h: &G::Point, hx: &G::Point, c: &G::Scalar, r: &G::Scalar, ctx: &[u8]) -> bool {
        let t = (G::basepoint() * r - &(*cap_x * &c), *h * r - &(*hx * &c));
        let c_dash = (self.get_challenge)(&[*cap_x, *h, *hx, t.0, t.1], ctx);
        *c == c_dash
    }
}

#[cfg(test)]
mod tests {
    use crate::foundation::group::Group;
    use crate::foundation::group::ristretto::RistrettoGroup;
    use crate::primitives::zkp::correct_exp::ZKPCorrectExp;

    type G = RistrettoGroup;

    #[test]
    pub fn prove_verify() {
        let mut rng = rand::thread_rng();
        let logh = G::scalar_random(&mut rng);
        let h = G::basepoint() * &logh;
        let x = G::scalar_random(&mut rng);
        let hx = h * &x;
        let cap_x = G::basepoint() * &x;
        let ctx = "test_zkp_correct_exp".as_bytes().to_vec();

        let zkp = ZKPCorrectExp::<G>::default();
        let (c, r) = zkp.prove(&cap_x, &h, &hx, &x, &ctx, &mut rng);

        assert!(zkp.verify(&cap_x, &h, &hx, &c, &r, &ctx));
    }

    #[test]
    pub fn cannot_prove_invalid_x() {
        let mut rng = rand::thread_rng();
        let logh = G::scalar_random(&mut rng);
        let h = G::basepoint() * &logh;
        let x = G::scalar_random(&mut rng);
        let hx = h * &x;
        let cap_x = G::basepoint() * &x;
        let ctx = "test_zkp_correct_exp".as_bytes().to_vec();
        let x_dash = G::scalar_random(&mut rng);

        let zkp = ZKPCorrectExp::<G>::default();
        let (c, r) = zkp.prove(&cap_x, &h, &hx, &x_dash, &ctx, &mut rng);

        assert!(!zkp.verify(&cap_x, &h, &hx, &c, &r, &ctx));
    }

    #[test]
    pub fn cannot_verify_invalid_c_or_r() {
        let mut rng = rand::thread_rng();
        let logh = G::scalar_random(&mut rng);
        let h = G::basepoint() * &logh;
        let x = G::scalar_random(&mut rng);
        let hx = h * &x;
        let cap_x = G::basepoint() * &x;
        let ctx = "test_zkp_correct_exp".as_bytes().to_vec();

        let zkp = ZKPCorrectExp::<G>::default();
        let (c, r) = zkp.prove(&cap_x, &h, &hx, &x, &ctx, &mut rng);

        let random = G::scalar_random(&mut rng);
        assert!(!zkp.verify(&cap_x, &h, &hx, &random, &r, &ctx));
        assert!(!zkp.verify(&cap_x, &h, &hx, &c, &random, &ctx));
    }
}
